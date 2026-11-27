"""End-to-end Gmail & MCP Proxy flow over real Streamable HTTP + stdio workers:
L0 search/read -> L1 stage draft -> unsigned L2 block -> forged sig block ->
signed L2 send -> replay block -> attachment TOCTOU abort -> audit chain verify.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import socket
import threading
import time
from pathlib import Path

import httpx
import pytest
import uvicorn
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client

from mini.daemon.app import create_app
from mini.schemas import ContractStatus, SignedApproval, TrustedDevice
from mini.security.contracts import TrustedDeviceStore, generate_keypair, sign_contract


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@contextlib.contextmanager
def _run_daemon(cfg, *, bearer_token: str = "test-secret-token"):
    port = _free_port()
    cfg = cfg.model_copy(update={"port": port})
    app = create_app(cfg, bearer_token=bearer_token, start_workers=True)
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            r = httpx.get(f"{base}/api/v1/health", timeout=0.5)
            if r.status_code == 200:
                break
        except Exception:
            time.sleep(0.1)
    else:
        server.should_exit = True
        thread.join(timeout=5)
        raise RuntimeError("Mini Daemon test server failed to start")
    try:
        yield base, app, bearer_token
    finally:
        server.should_exit = True
        thread.join(timeout=10)


async def _mcp_call(base: str, token: str, tool: str, args: dict) -> dict:
    headers = {"Authorization": f"Bearer {token}"}
    async with httpx.AsyncClient(headers=headers, timeout=30.0) as http_client:
        async with streamable_http_client(f"{base}/mcp", http_client=http_client) as (r, w):
            async with ClientSession(r, w) as session:
                await session.initialize()
                res = await session.call_tool(tool, args)
                return json.loads(res.content[0].text)


async def _mcp_list_tools(base: str, token: str) -> list[str]:
    headers = {"Authorization": f"Bearer {token}"}
    async with httpx.AsyncClient(headers=headers, timeout=30.0) as http_client:
        async with streamable_http_client(f"{base}/mcp", http_client=http_client) as (r, w):
            async with ClientSession(r, w) as session:
                await session.initialize()
                res = await session.list_tools()
                return [t.name for t in res.tools]


@pytest.fixture
def live_gmail_daemon(make_cfg, env_tree, monkeypatch):
    monkeypatch.setenv("MINI_GMAIL_MOCK", "true")
    mock_dir = env_tree.mini_root / "mock_gmail"
    monkeypatch.setenv("MINI_GMAIL_MOCK_DIR", str(mock_dir))

    cfg = make_cfg(approval_wait_seconds=0.0, dev_mode=False)
    priv, pub = generate_keypair()
    TrustedDeviceStore(cfg.trusted_devices).add(
        TrustedDevice(device_id="pixel-1", label="Pixel", public_key_b64=pub)
    )
    with _run_daemon(cfg) as (base, app, token):
        yield base, app, token, priv, mock_dir, env_tree


@pytest.mark.asyncio
async def test_mcp_requires_bearer_token_and_exposes_9_tools(live_gmail_daemon):
    base, _, token, *_ = live_gmail_daemon
    async with httpx.AsyncClient() as client:
        r = await client.post(f"{base}/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        assert r.status_code == 401
        r2 = await client.post(
            f"{base}/mcp",
            headers={"Authorization": "Bearer wrong"},
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
        )
        assert r2.status_code == 401

    tools = await _mcp_list_tools(base, token)
    assert set(tools) == {
        "fs_list_dir", "fs_read_file", "fs_write_staged", "fs_commit_staged", "fs_delete_file",
        "gmail_search", "gmail_read_message", "gmail_stage_draft", "gmail_send_staged",
        "git_status", "git_diff", "git_stage_commit", "git_commit_and_push",
    }


@pytest.mark.asyncio
async def test_gmail_l0_l1_unsigned_l2_block_and_signed_send(live_gmail_daemon):
    base, app, token, priv, mock_dir, env_tree = live_gmail_daemon

    # 1. L0 search + read
    search = await _mcp_call(base, token, "gmail_search", {"query": "Milestone"})
    assert search["status"] == "OK"
    msgs = search["result"]["messages"]
    assert len(msgs) == 1 and msgs[0]["id"] == "msg_welcome_001"

    msg = await _mcp_call(base, token, "gmail_read_message", {"message_id": "msg_welcome_001"})
    assert msg["status"] == "OK" and "summary email" in msg["result"]["body"]

    # 2. L1 stage draft (with real attachment inside approved root)
    report = env_tree.project / "report.pdf"
    staged = await _mcp_call(base, token, "gmail_stage_draft", {
        "task_id": "task-email-1",
        "to": ["advisor@university.edu"],
        "subject": "Project Summary",
        "body": "Attached is the project report.",
        "attachment_paths": [str(report)],
    })
    assert staged["status"] == "OK"
    draft_id = staged["result"]["staged_draft_id"]
    assert staged["result"]["gmail_draft_id"].startswith("gdraft_")

    # 3. L2 gmail_send_staged without approval -> blocked as APPROVAL_PENDING
    pending = await _mcp_call(base, token, "gmail_send_staged", {
        "task_id": "task-email-1",
        "staged_draft_id": draft_id,
    })
    assert pending["status"] == "APPROVAL_PENDING"
    contract_id = pending["contract_id"]
    mailbox = json.loads((mock_dir / "mailbox.json").read_text(encoding="utf-8"))
    assert mailbox["sent"] == []  # NOT sent yet!

    # 4. Inspect approval record + evidence via REST
    async with httpx.AsyncClient(base_url=base) as client:
        detail = (await client.get(f"/api/v1/approvals/{contract_id}")).json()
        rec_json = detail["approval"]
        assert rec_json["evidence"]["kind"] == "email"
        assert rec_json["evidence"]["to"] == ["advisor@university.edu"]
        assert rec_json["evidence"]["attachments"][0]["filename"] == "report.pdf"

        # 5. Forged signature rejected (400) and mailbox still empty
        forged = SignedApproval(
            contract_id=contract_id,
            decision="approve",
            device_id="pixel-1",
            signature_b64=sign_contract(generate_keypair()[0], app.state.mini["contracts"].get(contract_id).contract),
        )
        bad = await client.post(f"/api/v1/approvals/{contract_id}/decide", json=forged.model_dump(mode="json"))
        assert bad.status_code == 400
        assert json.loads((mock_dir / "mailbox.json").read_text(encoding="utf-8"))["sent"] == []

        # 6. Legitimate Ed25519 signature approves & sends via stdio Gmail worker
        contract_obj = app.state.mini["contracts"].get(contract_id).contract
        good = SignedApproval(
            contract_id=contract_id,
            decision="approve",
            device_id="pixel-1",
            signature_b64=sign_contract(priv, contract_obj),
        )
        ok = await client.post(f"/api/v1/approvals/{contract_id}/decide", json=good.model_dump(mode="json"))
        assert ok.status_code == 200
        assert ok.json()["approval"]["status"] == ContractStatus.EXECUTED.value

        mailbox = json.loads((mock_dir / "mailbox.json").read_text(encoding="utf-8"))
        assert len(mailbox["sent"]) == 1
        assert mailbox["sent"][0]["subject"] == "Project Summary"
        assert mailbox["sent"][0]["attachments"] == ["report.pdf"]

        # 7. Replay of same signed approval is blocked
        replay = await client.post(f"/api/v1/approvals/{contract_id}/decide", json=good.model_dump(mode="json"))
        assert replay.status_code == 409

        # 8. Audit chain is valid end-to-end
        rep = (await client.get("/api/v1/audit/verify")).json()
        assert rep["ok"] is True and rep["count"] >= 8


@pytest.mark.asyncio
async def test_gmail_attachment_toctou_aborts_signed_send(live_gmail_daemon):
    base, app, token, priv, mock_dir, env_tree = live_gmail_daemon
    report = env_tree.project / "report.pdf"

    staged = await _mcp_call(base, token, "gmail_stage_draft", {
        "task_id": "task-toctou",
        "to": ["advisor@university.edu"],
        "subject": "TOCTOU check",
        "body": "Body",
        "attachment_paths": [str(report)],
    })
    draft_id = staged["result"]["staged_draft_id"]
    pending = await _mcp_call(base, token, "gmail_send_staged", {
        "task_id": "task-toctou",
        "staged_draft_id": draft_id,
    })
    contract_id = pending["contract_id"]
    contract_obj = app.state.mini["contracts"].get(contract_id).contract

    # Attacker modifies attachment on disk AFTER staging/contract issuance
    report.write_text("%PDF tampered invoice\n", encoding="utf-8")

    good = SignedApproval(
        contract_id=contract_id,
        decision="approve",
        device_id="pixel-1",
        signature_b64=sign_contract(priv, contract_obj),
    )
    async with httpx.AsyncClient(base_url=base) as client:
        res = await client.post(f"/api/v1/approvals/{contract_id}/decide", json=good.model_dump(mode="json"))
        assert res.status_code == 409
        assert res.json()["detail"]["error"] == "ATTACHMENT_DRIFT"
        assert json.loads((mock_dir / "mailbox.json").read_text(encoding="utf-8"))["sent"] == []
        assert app.state.mini["contracts"].get(contract_id).status is ContractStatus.FAILED
