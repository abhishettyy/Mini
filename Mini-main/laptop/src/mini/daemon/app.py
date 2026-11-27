"""Mini Daemon FastAPI application.

Serves:
* ``/mcp``                     — Streamable HTTP MCP proxy (OpenClaw connects here)
* ``/api/v1/events``           — Audit log query
* ``/api/v1/events/stream``    — Real-time SSE stream for the Glass-Box Monitor
* ``/api/v1/audit/verify``     — Hash-chain + SQLite/JSONL consistency verification
* ``/api/v1/approvals``        — Pending/historical Approval Contracts + Evidence
* ``/api/v1/approvals/{id}/decide`` — Submit Ed25519-signed approval/rejection
* ``/api/v1/kill-switch``      — Emergency kill switch (+ ``/reset``)
* ``/api/v1/dev/*``            — Dev-mode local signer helpers for /mobile-mock
* ``/monitor`` & ``/mobile-mock`` — Static HTML UIs (Milestone 4)
"""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import json
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse
from starlette.routing import Route

from mini.config import MiniConfig, load_config
from mini.daemon.mcp_client_pool import MCPClientPool, PoolPausedError
from mini.daemon.mcp_proxy import MCPPolicyProxy
from mini.schemas import (
    AuditEvent,
    AuditEventType,
    ContractStatus,
    SignedApproval,
    TrustedDevice,
)
from mini.security._db import SQLiteDB
from mini.security.audit import AuditLogger
from mini.security.contracts import (
    ContractError,
    ContractStore,
    ContractVerifier,
    NonceStore,
    ReplayError,
    TrustedDeviceStore,
    generate_keypair,
    private_key_from_b64,
    private_key_to_b64,
    sign_contract,
)
from mini.security.path_guard import PathGuard
from mini.security.policy_engine import PolicyEngine
from mini.security.staging import StagingEngine, TOCTOUError

STATIC_DIR = Path(__file__).resolve().parent / "static"


class KillSwitchRequest(BaseModel):
    reason: str = "manual"


class ResetRequest(BaseModel):
    restart_workers: bool = True


class DevSignRequest(BaseModel):
    contract_id: str
    decision: str = "approve"
    confirm_destructive: bool = False
    reason: str | None = None


def _ensure_dev_device(cfg: MiniConfig, devices: TrustedDeviceStore) -> tuple[str, Path]:
    """Ensure a local dev Ed25519 keypair exists in ``~/.mini/`` for /mobile-mock."""
    key_path = cfg.mini_home / "dev_mobile_key.json"
    device_id = "mobile-mock-dev"
    if key_path.exists():
        data = json.loads(key_path.read_text(encoding="utf-8"))
        device_id = data["device_id"]
        if devices.public_key(device_id) is None:
            devices.add(TrustedDevice(device_id=device_id, label="Mock Mobile (Dev)",
                                      public_key_b64=data["public_key_b64"]))
        return device_id, key_path

    priv, pub_b64 = generate_keypair()
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_text(
        json.dumps({"device_id": device_id, "public_key_b64": pub_b64,
                    "private_key_b64": private_key_to_b64(priv)}, indent=2),
        encoding="utf-8",
    )
    devices.add(TrustedDevice(device_id=device_id, label="Mock Mobile (Dev)", public_key_b64=pub_b64))
    return device_id, key_path


class _BearerGuardASGI:
    """ASGI wrapper enforcing Bearer token auth on /mcp when configured."""

    def __init__(self, inner: Any, token: str | None, required: bool) -> None:
        self.inner = inner
        self.token = token
        self.required = required

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] == "http" and self.required:
            headers = {k.decode("latin1").lower(): v.decode("latin1") for k, v in scope.get("headers", [])}
            auth = headers.get("authorization", "")
            ok = (
                bool(self.token)
                and auth.startswith("Bearer ")
                and hmac.compare_digest(auth[7:], self.token)
            )
            if not ok:
                resp = JSONResponse({"error": "UNAUTHORIZED", "detail": "valid Bearer token required"},
                                    status_code=401)
                await resp(scope, receive, send)
                return
        await self.inner(scope, receive, send)


def create_app(
    cfg: MiniConfig | None = None,
    *,
    bearer_token: str | None = None,
    start_workers: bool = True,
) -> FastAPI:
    cfg = cfg or load_config()
    token = bearer_token if bearer_token is not None else os.environ.get("MINI_PROXY_TOKEN")

    db = SQLiteDB(cfg.state_db)
    audit = AuditLogger(db, cfg.audit_jsonl)
    devices = TrustedDeviceStore(cfg.trusted_devices)
    nonces = NonceStore(db)
    verifier = ContractVerifier(devices, nonces)
    contracts = ContractStore(db)
    guard = PathGuard(cfg)
    engine = PolicyEngine(cfg, guard)
    staging = StagingEngine(cfg, guard)
    pool = MCPClientPool(cfg, audit)
    proxy = MCPPolicyProxy(
        cfg=cfg, guard=guard, engine=engine, staging=staging,
        verifier=verifier, contracts=contracts, audit=audit, pool=pool,
    )

    # Streamable HTTP ASGI app + session manager (lifecycle entered below)
    mcp_starlette = proxy.mcp_server.streamable_http_app(
        streamable_http_path=cfg.mcp_path,
        host=cfg.host,
    )
    mcp_asgi = mcp_starlette.routes[0].endpoint
    guarded_mcp = _BearerGuardASGI(mcp_asgi, token=token, required=cfg.require_bearer_token)

    sse_queues: set[asyncio.Queue[AuditEvent]] = set()
    loop_ref: dict[str, asyncio.AbstractEventLoop] = {}

    def _on_audit(ev: AuditEvent) -> None:
        loop = loop_ref.get("loop")
        if loop is None:
            return
        for q in list(sse_queues):
            loop.call_soon_threadsafe(q.put_nowait, ev)

    audit.add_listener(_on_audit)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        loop_ref["loop"] = asyncio.get_running_loop()
        if start_workers:
            await pool.start()
        async with proxy.mcp_server.session_manager.run():
            audit.append(
                AuditEventType.DAEMON_STARTED,
                details={"host": cfg.host, "port": cfg.port, "dev_mode": cfg.dev_mode,
                         "start_workers": start_workers},
            )
            try:
                yield
            finally:
                await pool.stop()
                audit.remove_listener(_on_audit)
                db.close()

    app = FastAPI(title="Mini Daemon & MCP Policy Proxy", version="0.1.0", lifespan=lifespan)
    app.state.mini = {
        "cfg": cfg, "db": db, "audit": audit, "devices": devices, "nonces": nonces,
        "verifier": verifier, "contracts": contracts, "guard": guard,
        "engine": engine, "staging": staging, "pool": pool, "proxy": proxy,
    }
    app.router.routes.append(Route(cfg.mcp_path, endpoint=guarded_mcp, methods=["GET", "POST", "DELETE"]))

    # ------------------------------------------------------------------ #
    # REST / SSE API
    # ------------------------------------------------------------------ #
    @app.get("/api/v1/health")
    async def health() -> dict[str, Any]:
        return {
            "status": "paused" if pool.paused else "ok",
            "dev_mode": cfg.dev_mode,
            "workers": pool.status(),
            "pending_contracts": len(contracts.list(ContractStatus.PENDING)),
        }

    @app.get("/api/v1/events")
    async def list_events(
        since_seq: int = Query(0, ge=0),
        limit: int = Query(200, ge=1, le=2000),
        task_id: str | None = None,
    ) -> dict[str, Any]:
        return {"events": audit.events(since_seq=since_seq, limit=limit, task_id=task_id)}

    @app.get("/api/v1/events/stream")
    async def stream_events(request: Request, since_seq: int = Query(0, ge=0)) -> EventSourceResponse:
        q: asyncio.Queue[AuditEvent] = asyncio.Queue(maxsize=1000)
        sse_queues.add(q)

        async def gen() -> AsyncIterator[dict[str, str]]:
            try:
                last_seq = since_seq
                for raw in audit.events(since_seq=since_seq, limit=200):
                    last_seq = max(last_seq, raw["seq"])
                    yield {"event": "audit_event", "id": str(raw["seq"]),
                           "data": json.dumps(raw, ensure_ascii=False)}
                while True:
                    if await request.is_disconnected():
                        break
                    try:
                        ev = await asyncio.wait_for(q.get(), timeout=15.0)
                        if ev.seq <= last_seq:
                            continue
                        last_seq = ev.seq
                        yield {"event": "audit_event", "id": str(ev.seq),
                               "data": ev.model_dump_json()}
                    except asyncio.TimeoutError:
                        yield {"event": "ping", "data": "{}"}
            finally:
                sse_queues.discard(q)

        return EventSourceResponse(gen())

    @app.get("/api/v1/audit/verify")
    async def verify_audit() -> dict[str, Any]:
        return audit.verify_chain().as_dict()

    @app.get("/api/v1/approvals")
    async def list_approvals(status: ContractStatus | None = None) -> dict[str, Any]:
        contracts.expire_stale()
        items = [r.model_dump(mode="json") for r in contracts.list(status=status)]
        return {"approvals": items}

    @app.get("/api/v1/approvals/{contract_id}")
    async def get_approval(contract_id: str) -> dict[str, Any]:
        rec = contracts.get(contract_id)
        if rec is None:
            raise HTTPException(404, "unknown contract_id")
        return {
            "approval": rec.model_dump(mode="json"),
            "canonical_json": rec.contract.canonical_bytes().decode("utf-8"),
        }

    @app.post("/api/v1/approvals/{contract_id}/decide")
    async def decide_approval(contract_id: str, body: SignedApproval) -> dict[str, Any]:
        if body.contract_id != contract_id:
            raise HTTPException(400, "contract_id mismatch between URL and body")
        try:
            rec = await proxy.submit_decision(contract_id, body)
        except ReplayError as exc:
            raise HTTPException(409, {"error": exc.code, "detail": exc.detail}) from exc
        except TOCTOUError as exc:
            raise HTTPException(409, {"error": exc.code, "detail": exc.detail}) from exc
        except PoolPausedError as exc:
            raise HTTPException(503, {"error": exc.code, "detail": exc.detail}) from exc
        except ContractError as exc:
            code = 404 if exc.code == "UNKNOWN_CONTRACT" else (409 if exc.code == "BAD_STATE" else 400)
            raise HTTPException(code, {"error": exc.code, "detail": exc.detail}) from exc
        return {"approval": rec.model_dump(mode="json")}

    @app.post("/api/v1/kill-switch")
    async def kill_switch(body: KillSwitchRequest | None = None) -> dict[str, Any]:
        return await proxy.trigger_kill_switch(reason=(body.reason if body else "manual"))

    @app.post("/api/v1/kill-switch/reset")
    async def reset_kill_switch(body: ResetRequest | None = None) -> dict[str, Any]:
        return await proxy.reset_kill_switch(restart_workers=(body.restart_workers if body else True))

    # ------------------------------------------------------------------ #
    # Dev-mode-only local signer for /mobile-mock
    # ------------------------------------------------------------------ #
    @app.get("/api/v1/dev/signer-info")
    async def dev_signer_info() -> dict[str, Any]:
        if not cfg.dev_mode:
            raise HTTPException(403, "dev signer disabled (set MINI_DEV_MODE=true)")
        device_id, key_path = _ensure_dev_device(cfg, devices)
        data = json.loads(key_path.read_text(encoding="utf-8"))
        return {"device_id": device_id, "public_key_b64": data["public_key_b64"]}

    @app.post("/api/v1/dev/sign-and-decide")
    async def dev_sign_and_decide(req: DevSignRequest) -> dict[str, Any]:
        if not cfg.dev_mode:
            raise HTTPException(403, "dev signer disabled (set MINI_DEV_MODE=true)")
        rec = contracts.get(req.contract_id)
        if rec is None:
            raise HTTPException(404, "unknown contract_id")
        device_id, key_path = _ensure_dev_device(cfg, devices)
        if req.decision == "reject":
            sa = SignedApproval(contract_id=req.contract_id, decision="reject",
                                device_id=device_id, reason=req.reason)
        else:
            data = json.loads(key_path.read_text(encoding="utf-8"))
            priv = private_key_from_b64(data["private_key_b64"])
            sig = sign_contract(priv, rec.contract, confirm_destructive=req.confirm_destructive)
            sa = SignedApproval(
                contract_id=req.contract_id,
                decision="approve",
                device_id=device_id,
                signature_b64=sig,
                confirm_destructive=req.confirm_destructive,
                reason=req.reason,
            )
        return await decide_approval(req.contract_id, sa)

    # ------------------------------------------------------------------ #
    # Static UIs (full HTML delivered in Milestone 4)
    # ------------------------------------------------------------------ #
    def _serve_static(name: str) -> HTMLResponse:
        p = STATIC_DIR / name
        if p.is_file():
            return HTMLResponse(p.read_text(encoding="utf-8"))
        return HTMLResponse(f"<h1>{name} will be added in Milestone 4</h1>", status_code=501)

    @app.get("/monitor", response_class=HTMLResponse)
    async def monitor_page() -> HTMLResponse:
        return _serve_static("monitor.html")

    @app.get("/mobile-mock", response_class=HTMLResponse)
    async def mobile_mock_page() -> HTMLResponse:
        return _serve_static("mobile_mock.html")

    return app
