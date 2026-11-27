"""Emergency Kill Switch & Credential Isolation tests:
* Verifies filesystem worker env never contains Gmail OAuth secrets or proxy token.
* Triggers POST /api/v1/kill-switch: terminates all child MCP worker processes
  (terminate() -> 500ms -> kill()), revokes all PENDING contracts, unblocks any
  awaiting tools/call as PAUSED, blocks new calls until reset, and logs the event.
* Verifies POST /api/v1/kill-switch/reset restarts workers and restores execution.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import socket
import subprocess
import sys
import threading
import time

import httpx
import pytest
import uvicorn
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client

from mini.daemon.app import create_app
from mini.daemon.mcp_client_pool import is_pid_alive, kill_pid, terminate_pid
from mini.schemas import AuditEventType, ContractStatus, ProxyStatus


async def _mcp_call(base: str, token: str, tool: str, args: dict) -> dict:
    headers = {"Authorization": f"Bearer {token}"}
    async with httpx.AsyncClient(headers=headers, timeout=30.0) as http_client:
        async with streamable_http_client(f"{base}/mcp", http_client=http_client) as (r, w):
            async with ClientSession(r, w) as session:
                await session.initialize()
                res = await session.call_tool(tool, args)
                return json.loads(res.content[0].text)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@contextlib.contextmanager
def _run_daemon(cfg):
    port = _free_port()
    cfg = cfg.model_copy(update={"port": port})
    app = create_app(cfg, bearer_token="ks-token", start_workers=True)
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            if httpx.get(f"{base}/api/v1/health", timeout=0.5).status_code == 200:
                break
        except Exception:
            time.sleep(0.1)
    else:
        server.should_exit = True
        thread.join(timeout=5)
        raise RuntimeError("Daemon failed to start")
    try:
        yield base, app
    finally:
        server.should_exit = True
        thread.join(timeout=10)


def test_worker_env_credential_isolation(cfg, monkeypatch):
    monkeypatch.setenv("MINI_PROXY_TOKEN", "super-secret-proxy-token")
    monkeypatch.setenv("MINI_GMAIL_CLIENT_SECRETS", "/secret/client.json")
    monkeypatch.setenv("MINI_GMAIL_TOKEN", "/secret/token.json")
    monkeypatch.setenv("MINI_GIT_TOKEN", "github_pat_secret")
    app = create_app(cfg, bearer_token="super-secret-proxy-token", start_workers=False)
    pool = app.state.mini["pool"]

    fs_env = pool.worker_env("filesystem", cfg.workspaces_dir / "fs.pid")
    gm_env = pool.worker_env("gmail", cfg.workspaces_dir / "gm.pid")
    git_env = pool.worker_env("git", cfg.workspaces_dir / "git.pid")

    assert "MINI_PROXY_TOKEN" not in fs_env
    assert "MINI_PROXY_TOKEN" not in gm_env
    assert "MINI_PROXY_TOKEN" not in git_env
    assert "MINI_GMAIL_CLIENT_SECRETS" not in fs_env
    assert "MINI_GMAIL_TOKEN" not in fs_env
    assert "MINI_GMAIL_CLIENT_SECRETS" not in git_env
    assert "MINI_GMAIL_TOKEN" not in git_env
    assert "MINI_GMAIL_CLIENT_SECRETS" in gm_env
    assert "MINI_GMAIL_TOKEN" in gm_env
    assert "MINI_GIT_TOKEN" not in fs_env
    assert "MINI_GIT_TOKEN" not in gm_env
    assert git_env.get("MINI_GIT_TOKEN") == "github_pat_secret"


@pytest.mark.asyncio
async def test_kill_switch_terminates_workers_revokes_contracts_and_recovers(make_cfg, env_tree, monkeypatch):
    monkeypatch.setenv("MINI_GMAIL_MOCK", "true")
    monkeypatch.setenv("MINI_GMAIL_MOCK_DIR", str(env_tree.mini_root / "mock_gmail"))
    cfg = make_cfg(approval_wait_seconds=10.0, kill_switch_grace_ms=500)

    with _run_daemon(cfg) as (base, app):
        pool = app.state.mini["pool"]
        proxy = app.state.mini["proxy"]
        contracts = app.state.mini["contracts"]
        audit = app.state.mini["audit"]

        initial_status = pool.status()
        pids = [w["pid"] for w in initial_status["workers"].values()]
        assert len(pids) == 3 and all(pid and is_pid_alive(pid) for pid in pids)

        # Stage a change (L1) via real MCP Streamable HTTP then launch an L2 commit that blocks awaiting approval
        readme = env_tree.project / "README.md"
        stage_res = await _mcp_call(
            base,
            "ks-token",
            "fs_write_staged",
            {"task_id": "t-ks", "target_path": str(readme), "content": "updated\n"},
        )
        assert stage_res["status"] == ProxyStatus.OK.value

        # Launch blocking L2 call over /mcp
        pending_task = asyncio.create_task(
            _mcp_call(base, "ks-token", "fs_commit_staged", {"task_id": "t-ks", "target_path": str(readme)})
        )
        # Wait until the contract appears in PENDING state
        for _ in range(50):
            if contracts.list(ContractStatus.PENDING):
                break
            await asyncio.sleep(0.05)
        pending = contracts.list(ContractStatus.PENDING)
        assert len(pending) == 1
        cid = pending[0].contract.contract_id

        # Trigger EMERGENCY KILL SWITCH via HTTP API
        async with httpx.AsyncClient(base_url=base) as client:
            ks_resp = await client.post("/api/v1/kill-switch", json={"reason": "test emergency"})
            assert ks_resp.status_code == 200
            ks = ks_resp.json()
            assert ks["paused"] is True
            assert cid in ks["revoked_contracts"]
            assert set(pids) <= set(ks["workers"]["terminated"])

        # Both worker OS processes are dead
        for pid in pids:
            assert not is_pid_alive(pid)

        # Pending contract is REVOKED, awaiting call returned PAUSED immediately
        assert contracts.get(cid).status is ContractStatus.REVOKED
        blocked_result = await asyncio.wait_for(pending_task, timeout=3.0)
        assert blocked_result["status"] == ProxyStatus.PAUSED.value

        # New tool calls are paused/blocked until reset
        new_call = await _mcp_call(base, "ks-token", "fs_read_file", {"path": str(readme)})
        assert new_call["status"] == ProxyStatus.PAUSED.value

        # Audit log recorded KILL_SWITCH_TRIGGERED + CONTRACT_REVOKED and chain verifies
        ev_types = [e["event_type"] for e in audit.events()]
        assert AuditEventType.KILL_SWITCH_TRIGGERED.value in ev_types
        assert AuditEventType.CONTRACT_REVOKED.value in ev_types
        assert audit.verify_chain().ok is True

        # Reset kill switch -> new workers spawn with new PIDs -> L0 read works again
        async with httpx.AsyncClient(base_url=base) as client:
            rst = await client.post("/api/v1/kill-switch/reset", json={"restart_workers": True})
            assert rst.status_code == 200
            new_workers = rst.json()["workers"]
            new_pids = [w["pid"] for w in new_workers.values()]
            assert len(new_pids) == 3 and all(pid and is_pid_alive(pid) for pid in new_pids)

        ok_read = await _mcp_call(base, "ks-token", "fs_read_file", {"path": str(readme)})
        assert ok_read["status"] == ProxyStatus.OK.value and "Demo project" in ok_read["result"]["content"]


def test_process_terminate_and_force_kill():
    """Verify terminate_pid / kill_pid cleanly kills a live subprocess."""
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        assert is_pid_alive(proc.pid)
        terminate_pid(proc.pid)
        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline and is_pid_alive(proc.pid):
            time.sleep(0.02)
        if is_pid_alive(proc.pid):
            kill_pid(proc.pid)
            proc.wait(timeout=2)
        else:
            proc.wait(timeout=2)
        assert not is_pid_alive(proc.pid)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=2)
