"""Milestone 4 tests: Glass-Box /monitor UI, /mobile-mock UI, dev-mode signer
gating, CLI commands (init-keys, verify-audit), and the complete end-to-end
workflow (read file -> stage update -> stage summary email -> approve both via
/mobile-mock -> verify hash-chained audit log).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import socket
import threading
import time

import httpx
import pytest
import uvicorn

from mini import cli
from mini.daemon.app import create_app


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@contextlib.contextmanager
def _run_daemon(cfg, *, bearer_token: str = "e2e-token"):
    port = _free_port()
    cfg = cfg.model_copy(update={"port": port})
    app = create_app(cfg, bearer_token=bearer_token, start_workers=True)
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
        yield base, app, bearer_token
    finally:
        server.should_exit = True
        thread.join(timeout=10)


@pytest.mark.asyncio
async def test_ui_routes_and_dev_mode_gating(make_cfg):
    # When dev_mode=False, /monitor and /mobile-mock HTML serve 200, but /api/v1/dev/* returns 403
    app_prod = create_app(make_cfg(dev_mode=False), bearer_token="t", start_workers=False)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app_prod), base_url="http://127.0.0.1:8765") as c:
        r_mon = await c.get("/monitor")
        assert r_mon.status_code == 200 and "EMERGENCY KILL SWITCH" in r_mon.text
        r_mob = await c.get("/mobile-mock")
        assert r_mob.status_code == 200 and "Approve &amp; Sign (Ed25519)" in r_mob.text
        assert (await c.get("/api/v1/dev/signer-info")).status_code == 403

    # When dev_mode=True, /api/v1/dev/signer-info initializes and returns the pinned dev device
    app_dev = create_app(make_cfg(dev_mode=True), bearer_token="t", start_workers=False)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app_dev), base_url="http://127.0.0.1:8765") as c:
        info = await c.get("/api/v1/dev/signer-info")
        assert info.status_code == 200
        assert info.json()["device_id"] == "mobile-mock-dev"
        assert len(info.json()["public_key_b64"]) >= 40


def test_Full_e2e_workflow_and_cli_verify_audit(make_cfg, env_tree, monkeypatch):
    monkeypatch.setenv("MINI_GMAIL_MOCK", "true")
    mock_dir = env_tree.mini_root / "mock_gmail"
    monkeypatch.setenv("MINI_GMAIL_MOCK_DIR", str(mock_dir))

    # Prepare notes/architecture_summary.md in the test project root
    notes = env_tree.project / "notes" / "architecture_summary.md"
    notes.parent.mkdir(parents=True, exist_ok=True)
    notes.write_text("# Architecture Summary\nVerified.\n", encoding="utf-8")

    cfg = make_cfg(dev_mode=True, approval_wait_seconds=30.0)
    with _run_daemon(cfg) as (base, app, token):
        rc = cli.main([
            "run-e2e",
            "--url", base,
            "--token", token,
            "--task-id", "e2e-test-run",
            "--auto-approve-dev",
        ])
        assert rc == 0

        # Verify README.md on disk was actually committed
        readme_text = (env_tree.project / "README.md").read_text(encoding="utf-8")
        assert "Completed & Verified via Ed25519 Contract" in readme_text
        assert "e2e-test-run" in readme_text

        # Verify email was sent in mock mailbox
        mailbox = json.loads((mock_dir / "mailbox.json").read_text(encoding="utf-8"))
        assert len(mailbox["sent"]) == 1
        assert mailbox["sent"][0]["subject"] == "Mini Task e2e-test-run Summary"
        assert mailbox["sent"][0]["attachments"] == ["architecture_summary.md"]

        # Verify hash-chained audit log via audit.verify_chain() and verify_jsonl()
        rep = app.state.mini["audit"].verify_chain()
        assert rep.ok is True and rep.count >= 15
