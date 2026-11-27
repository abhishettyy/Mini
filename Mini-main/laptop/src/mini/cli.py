"""Mini CLI: ``init-keys``, ``run-daemon``, ``verify-audit``, ``run-e2e``.

Usage::

    mini init-keys
    mini run-daemon
    mini verify-audit
    mini run-e2e [--auto-approve-dev]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import secrets
import sys
from pathlib import Path
from typing import Any

import httpx
import uvicorn
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client

from mini.config import DEFAULT_PROJECT_ROOT, MiniConfig, load_config
from mini.daemon.app import _ensure_dev_device, create_app
from mini.security._db import SQLiteDB
from mini.security.audit import AuditLogger, verify_jsonl
from mini.security.contracts import TrustedDeviceStore


def _load_dotenv(root: Path) -> None:
    env_file = root / ".env"
    if not env_file.is_file():
        return
    for raw in env_file.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip())


def _seed_demo_project(cfg: MiniConfig) -> Path:
    root = cfg.approved_roots[0]
    root.mkdir(parents=True, exist_ok=True)
    readme = root / "README.md"
    if not readme.exists():
        readme.write_text(
            "# Mini Demo Project\n\n"
            "- Milestone: Laptop Execution Runtime\n"
            "- Status: Draft\n"
            "- Notes: Initial project status before OpenClaw task execution.\n",
            encoding="utf-8",
        )
    notes = root / "notes" / "architecture_summary.md"
    notes.parent.mkdir(parents=True, exist_ok=True)
    if not notes.exists():
        notes.write_text(
            "# Architecture Summary\n\n"
            "All tool calls traverse Mini's MCP Policy Proxy, Staging Engine, "
            "and Ed25519 Approval Contract verifier.\n",
            encoding="utf-8",
        )
    env_secret = root / ".env"
    if not env_secret.exists():
        env_secret.write_text("DEMO_SECRET=never-readable-by-agent\n", encoding="utf-8")
    return root


def cmd_init_keys(args: argparse.Namespace) -> int:
    _load_dotenv(DEFAULT_PROJECT_ROOT)
    cfg = load_config(args.config)
    cfg.mini_home.mkdir(parents=True, exist_ok=True)
    cfg.secrets_dir.mkdir(parents=True, exist_ok=True)

    devices = TrustedDeviceStore(cfg.trusted_devices)
    device_id, key_path = _ensure_dev_device(cfg, devices)
    data = json.loads(key_path.read_text(encoding="utf-8"))

    env_path = cfg.project_root / ".env"
    token = os.environ.get("MINI_PROXY_TOKEN")
    if not env_path.exists():
        token = token or secrets.token_urlsafe(32)
        env_path.write_text(
            f"MINI_CONFIG=./config/policy.yaml\n"
            f"MINI_PROXY_TOKEN={token}\n"
            f"MINI_DEV_MODE=true\n"
            f"MINI_GMAIL_MOCK=true\n"
            f"MINI_APPROVAL_WAIT_SECONDS=120\n",
            encoding="utf-8",
        )
    else:
        _load_dotenv(cfg.project_root)
        token = os.environ.get("MINI_PROXY_TOKEN", "(see .env)")

    demo_root = _seed_demo_project(cfg)
    print(json.dumps({
        "status": "initialized",
        "device_id": device_id,
        "public_key_b64": data["public_key_b64"],
        "trusted_devices_path": str(cfg.trusted_devices),
        "dev_key_path": str(key_path),
        "env_file": str(env_path),
        "demo_project_root": str(demo_root),
    }, indent=2))
    return 0


def cmd_run_daemon(args: argparse.Namespace) -> int:
    _load_dotenv(DEFAULT_PROJECT_ROOT)
    overrides: dict[str, Any] = {}
    if args.host:
        overrides["host"] = args.host
    if args.port:
        overrides["port"] = args.port
    if args.dev:
        overrides["dev_mode"] = True
    cfg = load_config(args.config, **overrides)
    _seed_demo_project(cfg)
    if cfg.dev_mode:
        _ensure_dev_device(cfg, TrustedDeviceStore(cfg.trusted_devices))

    token = os.environ.get("MINI_PROXY_TOKEN")
    if cfg.require_bearer_token and not token:
        token = secrets.token_urlsafe(32)
        os.environ["MINI_PROXY_TOKEN"] = token
        print(f"[mini] Generated ephemeral MINI_PROXY_TOKEN={token}", file=sys.stderr)

    app = create_app(cfg, bearer_token=token, start_workers=True)
    print(
        f"[mini] Listening on http://{cfg.host}:{cfg.port}\n"
        f"       MCP endpoint : http://{cfg.host}:{cfg.port}{cfg.mcp_path}\n"
        f"       Glass-Box UI : http://{cfg.host}:{cfg.port}/monitor\n"
        f"       Mock Mobile  : http://{cfg.host}:{cfg.port}/mobile-mock (dev_mode={cfg.dev_mode})",
        file=sys.stderr,
    )
    uvicorn.run(app, host=cfg.host, port=cfg.port, log_level=args.log_level)
    return 0


def cmd_verify_audit(args: argparse.Namespace) -> int:
    _load_dotenv(DEFAULT_PROJECT_ROOT)
    cfg = load_config(args.config)
    if args.jsonl_only:
        rep = verify_jsonl(cfg.audit_jsonl)
    else:
        db = SQLiteDB(cfg.state_db)
        try:
            rep = AuditLogger(db, cfg.audit_jsonl).verify_chain()
        finally:
            db.close()
    print(json.dumps(rep.as_dict(), indent=2))
    return 0 if rep.ok else 1


async def _auto_Approver(base_url: str, stop_ev: asyncio.Event) -> None:
    seen: set[str] = set()
    async with httpx.AsyncClient(base_url=base_url, timeout=10.0) as client:
        while not stop_ev.is_set():
            try:
                r = await client.get("/api/v1/approvals?status=PENDING")
                if r.status_code == 200:
                    for item in r.json().get("approvals", []):
                        cid = item["contract"]["contract_id"]
                        if cid not in seen:
                            seen.add(cid)
                            is_l3 = item["contract"]["risk_level"] == "L3"
                            await client.post("/api/v1/dev/sign-and-decide", json={
                                "contract_id": cid,
                                "decision": "approve",
                                "confirm_destructive": is_l3,
                            })
            except Exception:
                pass
            await asyncio.sleep(0.25)


async def _run_e2e_async(args: argparse.Namespace) -> int:
    _load_dotenv(DEFAULT_PROJECT_ROOT)
    cfg = load_config(args.config)
    base = args.url or f"http://{cfg.host}:{cfg.port}"
    token = args.token or os.environ.get("MINI_PROXY_TOKEN", "")
    task_id = args.task_id

    headers = {"Authorization": f"Bearer {token}"} if token else {}
    stop_ev = asyncio.Event()
    approver_task = (
        asyncio.create_task(_auto_Approver(base, stop_ev))
        if args.auto_approve_dev
        else None
    )

    try:
        async with httpx.AsyncClient(headers=headers, timeout=190.0) as http_client:
            async with streamable_http_client(f"{base}{cfg.mcp_path}", http_client=http_client) as (r, w):
                async with ClientSession(r, w) as session:
                    await session.initialize()

                    async def call(tool: str, tool_args: dict[str, Any]) -> dict[str, Any]:
                        res = await session.call_tool(tool, tool_args)
                        data = json.loads(res.content[0].text)
                        print(f"[{tool}] -> status={data.get('status')} risk={data.get('risk_level')} verdict={data.get('verdict')}")
                        return data

                    # 1. Read project README (L0) & confirm .env is hard-blocked
                    read_res = await call("fs_read_file", {"path": "README.md"})
                    assert read_res["status"] == "OK", read_res
                    deny_res = await call("fs_read_file", {"path": ".env"})
                    assert deny_res["status"] == "DENIED", deny_res

                    # 2. Stage an update to README.md (L1)
                    updated_md = (
                        "# Mini Demo Project\n\n"
                        "- Milestone: Laptop Execution Runtime\n"
                        "- Status: Completed & Verified via Ed25519 Contract\n"
                        f"- Task ID: {task_id}\n"
                    )
                    stage_res = await call("fs_write_staged", {
                        "task_id": task_id,
                        "target_path": "README.md",
                        "content": updated_md,
                    })
                    assert stage_res["status"] == "OK", stage_res

                    # 3. Draft a summary email attaching architecture_summary.md (L1)
                    draft_res = await call("gmail_stage_draft", {
                        "task_id": task_id,
                        "to": ["advisor@university.edu"],
                        "subject": f"Mini Task {task_id} Summary",
                        "body": "Hello,\n\nREADME.md has been updated and verified.\n",
                        "attachment_paths": ["notes/architecture_summary.md"],
                    })
                    assert draft_res["status"] == "OK", draft_res
                    staged_draft_id = draft_res["result"]["staged_draft_id"]

                    if not args.auto_approve_dev:
                        print(
                            "\n>>> Open http://127.0.0.1:8765/mobile-mock in your browser and click "
                            "'Approve & Sign (Ed25519)' on the 2 L2 contracts as they appear...\n"
                        )

                    # 4. Commit the staged file update (L2)
                    commit_res = await call("fs_commit_staged", {
                        "task_id": task_id,
                        "target_path": "README.md",
                    })
                    assert commit_res["status"] == "OK", commit_res

                    # 5. Send the staged email draft (L2)
                    send_res = await call("gmail_send_staged", {
                        "task_id": task_id,
                        "staged_draft_id": staged_draft_id,
                    })
                    assert send_res["status"] == "OK", send_res
    finally:
        stop_ev.set()
        if approver_task:
            await approver_task

    async with httpx.AsyncClient(base_url=base, timeout=10.0) as client:
        audit_rep = (await client.get("/api/v1/audit/verify")).json()
    print("\n=== Audit Chain Verification ===")
    print(json.dumps(audit_rep, indent=2))
    return 0 if audit_rep.get("ok") else 1


def cmd_run_e2e(args: argparse.Namespace) -> int:
    return asyncio.run(_run_e2e_async(args))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="mini", description="Mini Laptop Execution Runtime CLI")
    p.add_argument("--config", default=None, help="Path to config/policy.yaml")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_init = sub.add_parser("init-keys", help="Initialize trusted_devices.json, dev keypair, .env, and demo_project/")
    p_init.set_defaults(func=cmd_init_keys)

    p_run = sub.add_parser("run-daemon", help="Launch Mini Daemon & MCP Policy Proxy")
    p_run.add_argument("--host", default=None)
    p_run.add_argument("--port", type=int, default=None)
    p_run.add_argument("--dev", action="store_true", help="Enable /mobile-mock local dev signer")
    p_run.add_argument("--log-level", default="info")
    p_run.set_defaults(func=cmd_run_daemon)

    p_ver = sub.add_parser("verify-audit", help="Verify SQLite WAL + logs/audit.jsonl hash chain")
    p_ver.add_argument("--jsonl-only", action="store_true")
    p_ver.set_defaults(func=cmd_verify_audit)

    p_e2e = sub.add_parser("run-e2e", help="Run end-to-end test task against Mini Daemon /mcp")
    p_e2e.add_argument("--url", default=None, help="Base URL (default http://127.0.0.1:8765)")
    p_e2e.add_argument("--token", default=None, help="MINI_PROXY_TOKEN override")
    p_e2e.add_argument("--task-id", default="e2e-demo-01")
    p_e2e.add_argument("--auto-approve-dev", action="store_true",
                       help="Auto-approve pending L2 contracts via /api/v1/dev/sign-and-decide")
    p_e2e.set_defaults(func=cmd_run_e2e)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
