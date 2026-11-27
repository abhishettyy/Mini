"""End-to-end Git MCP worker & Policy Proxy tests:
(a) L0 git_status / git_diff (with denylisted files hidden),
(b) L1 git_stage_commit -> L2 signed git_commit_and_push against a temporary
    local bare remote repo (plus L3 escalation for CI/executable paths),
(c) PathGuard blocking repos outside approved_roots, .git/config access, and
    dangerous flags / unallowlisted remotes,
(d) TOCTOU rejection when staged files drift between approval and commit,
(e) Credential isolation & token scrubbing.
"""

from __future__ import annotations

import contextlib
import json
import socket
import subprocess
import threading
import time
from pathlib import Path

import httpx
import pytest
import uvicorn
import yaml
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client

from mini.config import DEFAULT_PROJECT_ROOT, load_config
from mini.daemon.app import create_app
from mini.daemon.mcp_client_pool import MCPClientPool
from mini.mcp_servers.git_server import GitError, GitRunner, GitWorker
from mini.schemas import ContractStatus, SignedApproval, TrustedDevice
from mini.security.contracts import TrustedDeviceStore, generate_keypair, sign_contract
from mini.security.git_guard import GitPolicyError, assert_safe_git_argv

POLICY_FILE = DEFAULT_PROJECT_ROOT / "config" / "policy.yaml"


def _git(cwd: Path, *args: str) -> str:
    res = subprocess.run(
        ["git", "-c", "commit.gpgSign=false", "-c", "core.autocrlf=false", *args],
        cwd=str(cwd),
        check=True,
        capture_output=True,
        text=True,
    )
    return res.stdout.strip()


def _init_repo_with_bare_remote(work_repo: Path, bare_remote: Path) -> None:
    bare_remote.mkdir(parents=True, exist_ok=True)
    _git(bare_remote, "init", "--bare", "-b", "main")

    work_repo.mkdir(parents=True, exist_ok=True)
    _git(work_repo, "init", "-b", "main")
    _git(work_repo, "config", "user.name", "Test User")
    _git(work_repo, "config", "user.email", "test@example.com")
    _git(work_repo, "config", "core.autocrlf", "false")
    _git(work_repo, "remote", "add", "origin", str(bare_remote))

    (work_repo / "README.md").write_text("# Profile Repo\n\nInitial bio.\n", encoding="utf-8")
    _git(work_repo, "add", "--", "README.md")
    _git(work_repo, "commit", "-m", "initial commit")
    _git(work_repo, "push", "origin", "HEAD:refs/heads/main")


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@contextlib.contextmanager
def _run_daemon(cfg, *, bearer_token: str = "git-test-token"):
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


@pytest.fixture
def git_env(env_tree, monkeypatch):
    """Set up a git repo inside approved_roots paired with a local bare remote."""
    bare = env_tree.tmp / "bare_origin.git"
    repo = env_tree.project
    _init_repo_with_bare_remote(repo, bare)

    # Write a test policy.yaml whose git.allowed_remotes.origin points to bare
    raw_policy = yaml.safe_load(POLICY_FILE.read_text(encoding="utf-8"))
    raw_policy["git"]["allowed_remotes"] = {"origin": str(bare)}
    raw_policy["git"]["allowed_branches"] = ["main"]
    custom_policy = env_tree.mini_root / "config" / "policy.yaml"
    custom_policy.parent.mkdir(parents=True, exist_ok=True)
    custom_policy.write_text(yaml.safe_dump(raw_policy), encoding="utf-8")

    monkeypatch.setenv("MINI_GMAIL_MOCK", "true")
    monkeypatch.setenv("MINI_GIT_MOCK", "true")
    monkeypatch.setenv("MINI_GIT_USER_NAME", "Mini Git Bot")
    monkeypatch.setenv("MINI_GIT_USER_EMAIL", "mini-bot@example.com")

    cfg = load_config(
        custom_policy,
        project_root=env_tree.mini_root,
        home=env_tree.home,
        env={},
        approved_roots=[repo],
        approval_wait_seconds=0.0,
        dev_mode=False,
    )
    priv, pub = generate_keypair()
    TrustedDeviceStore(cfg.trusted_devices).add(
        TrustedDevice(device_id="pixel-git", label="Pixel Git", public_key_b64=pub)
    )
    return cfg, repo, bare, priv, env_tree


@pytest.fixture
def live_git_daemon(git_env):
    cfg, repo, bare, priv, env_tree = git_env
    with _run_daemon(cfg) as (base, app, token):
        yield base, app, token, priv, repo, bare, env_tree


# --------------------------------------------------------------------------- #
# (a) L0 status & diff + denylist filtering
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_git_l0_status_and_diff_hide_denylisted_files(live_git_daemon):
    base, _, token, _, repo, _, _ = live_git_daemon

    # Modify README.md (allowed) and .env (denylisted in fixture)
    (repo / "README.md").write_text("# Profile Repo\n\nUpdated bio line.\n", encoding="utf-8")

    st = await _mcp_call(base, token, "git_status", {"repo_path": str(repo)})
    assert st["status"] == "OK"
    res = st["result"]
    assert res["branch"] == "main"
    assert res["clean"] is False
    visible_paths = [f["path"] for f in res["files"]]
    assert "README.md" in visible_paths
    assert all(".env" not in p and ".pem" not in p and ".key" not in p for p in visible_paths)
    assert res["hidden"] >= 1  # .env / .pem / .key hidden

    df = await _mcp_call(base, token, "git_diff", {"repo_path": str(repo), "staged": False})
    assert df["status"] == "OK"
    assert "README.md" in df["result"]["files"]
    assert "+Updated bio line." in df["result"]["diff"]
    assert "OPENAI_API_KEY" not in df["result"]["diff"]


# --------------------------------------------------------------------------- #
# (b) L1 git_stage_commit -> L2 signed git_commit_and_push to bare remote
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_git_l1_stage_and_l2_signed_commit_and_push(live_git_daemon):
    base, app, token, priv, repo, bare, _ = live_git_daemon

    (repo / "README.md").write_text("# Profile Repo\n\nSigned profile update.\n", encoding="utf-8")
    before_remote_head = _git(bare, "rev-parse", "refs/heads/main")

    # L1 stage commit
    staged = await _mcp_call(base, token, "git_stage_commit", {
        "task_id": "task-git-1",
        "repo_path": str(repo),
        "files": ["README.md"],
        "commit_message": "docs: update profile README",
    })
    assert staged["status"] == "OK"
    assert staged["result"] == {
        "ok": True,
        "staged_commit_id": staged["result"]["staged_commit_id"],
        "files": ["README.md"],
    }
    staged_id = staged["result"]["staged_commit_id"]

    # L2 git_commit_and_push pauses for Ed25519 approval
    pending = await _mcp_call(base, token, "git_commit_and_push", {
        "task_id": "task-git-1",
        "staged_commit_id": staged_id,
    })
    assert pending["status"] == "APPROVAL_PENDING"
    contract_id = pending["contract_id"]
    assert _git(bare, "rev-parse", "refs/heads/main") == before_remote_head

    async with httpx.AsyncClient(base_url=base) as client:
        detail = (await client.get(f"/api/v1/approvals/{contract_id}")).json()
        rec_json = detail["approval"]
        ev = rec_json["evidence"]
        assert ev["kind"] == "git_commit"
        assert ev["branch"] == "main"
        assert ev["commit_message"] == "docs: update profile README"
        assert ev["files"] == ["README.md"]
        assert "+Signed profile update." in ev["unified_diff"]
        assert ev["diff_sha256"].startswith("sha256:")

        # Forged signature must be rejected (400) and remote unchanged
        contract_obj = app.state.mini["contracts"].get(contract_id).contract
        forged = SignedApproval(
            contract_id=contract_id,
            decision="approve",
            device_id="pixel-git",
            signature_b64=sign_contract(generate_keypair()[0], contract_obj),
        )
        bad = await client.post(f"/api/v1/approvals/{contract_id}/decide", json=forged.model_dump(mode="json"))
        assert bad.status_code == 400
        assert _git(bare, "rev-parse", "refs/heads/main") == before_remote_head

        # Valid Ed25519 signature -> commits & pushes to bare remote
        good = SignedApproval(
            contract_id=contract_id,
            decision="approve",
            device_id="pixel-git",
            signature_b64=sign_contract(priv, contract_obj),
        )
        ok = await client.post(f"/api/v1/approvals/{contract_id}/decide", json=good.model_dump(mode="json"))
        assert ok.status_code == 200
        body = ok.json()["approval"]
        assert body["status"] == ContractStatus.EXECUTED.value
        assert body["outcome"]["ok"] is True
        assert body["outcome"]["pushed"] is True
        assert body["outcome"]["branch"] == "main"
        assert len(body["outcome"]["commit"]) == 7

        # Bare remote actually received the commit
        after_remote_head = _git(bare, "rev-parse", "refs/heads/main")
        assert after_remote_head != before_remote_head
        assert after_remote_head.startswith(body["outcome"]["commit"])
        assert _git(bare, "log", "-1", "--pretty=%B", "refs/heads/main") == "docs: update profile README"

        # Nonce replay is blocked (409)
        replay = await client.post(f"/api/v1/approvals/{contract_id}/decide", json=good.model_dump(mode="json"))
        assert replay.status_code == 409


# --------------------------------------------------------------------------- #
# (b2) Monotonic escalation to L3 when commit touches CI workflow / script
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_git_push_touching_workflow_escalates_to_l3(live_git_daemon):
    base, app, token, priv, repo, bare, _ = live_git_daemon

    wf = repo / ".github" / "workflows" / "ci.yml"
    wf.parent.mkdir(parents=True, exist_ok=True)
    wf.write_text("name: CI\non: push\n", encoding="utf-8")

    staged = await _mcp_call(base, token, "git_stage_commit", {
        "task_id": "task-git-l3",
        "repo_path": str(repo),
        "files": [".github/workflows/ci.yml"],
        "commit_message": "ci: add workflow",
    })
    assert staged["status"] == "OK"
    staged_id = staged["result"]["staged_commit_id"]

    pending = await _mcp_call(base, token, "git_commit_and_push", {
        "task_id": "task-git-l3",
        "staged_commit_id": staged_id,
    })
    assert pending["status"] == "APPROVAL_PENDING"
    assert pending["risk_level"] == "L3"
    contract_id = pending["contract_id"]
    contract_obj = app.state.mini["contracts"].get(contract_id).contract
    assert contract_obj.risk_level.value == "L3"

    async with httpx.AsyncClient(base_url=base) as client:
        # Signing with confirm_destructive=False must fail for L3
        no_confirm = SignedApproval(
            contract_id=contract_id,
            decision="approve",
            device_id="pixel-git",
            signature_b64=sign_contract(priv, contract_obj, confirm_destructive=False),
            confirm_destructive=False,
        )
        r_bad = await client.post(f"/api/v1/approvals/{contract_id}/decide", json=no_confirm.model_dump(mode="json"))
        assert r_bad.status_code == 400
        assert r_bad.json()["detail"]["error"] == "CONFIRM_DESTRUCTIVE_REQUIRED"

        # Signing with confirm_destructive=True succeeds
        with_confirm = SignedApproval(
            contract_id=contract_id,
            decision="approve",
            device_id="pixel-git",
            signature_b64=sign_contract(priv, contract_obj, confirm_destructive=True),
            confirm_destructive=True,
        )
        r_ok = await client.post(f"/api/v1/approvals/{contract_id}/decide", json=with_confirm.model_dump(mode="json"))
        assert r_ok.status_code == 200
        assert r_ok.json()["approval"]["status"] == ContractStatus.EXECUTED.value


# --------------------------------------------------------------------------- #
# (c) PathGuard & policy blocking outside repos, .git/config, bad flags/remotes
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_git_pathguard_and_policy_denials(live_git_daemon):
    base, _, token, _, repo, _, env_tree = live_git_daemon

    # 1. Repo outside approved_roots is blocked
    out_res = await _mcp_call(base, token, "git_status", {"repo_path": str(env_tree.outside)})
    assert out_res["status"] == "DENIED"
    assert "OUTSIDE_APPROVED_ROOTS" in out_res["error"]

    # 2. Attempting to stage .git/config or .env is blocked
    dotgit = await _mcp_call(base, token, "git_stage_commit", {
        "task_id": "task-deny-1",
        "repo_path": str(repo),
        "files": [".git/config"],
        "commit_message": "leak config",
    })
    assert dotgit["status"] == "DENIED"
    assert "DENY_PATH_PATTERN" in dotgit["error"]

    dotenv = await _mcp_call(base, token, "git_stage_commit", {
        "task_id": "task-deny-2",
        "repo_path": str(repo),
        "files": [".env"],
        "commit_message": "leak env",
    })
    assert dotenv["status"] == "DENIED"
    assert "DENY_FILENAME" in dotenv["error"]

    # 3. Argument injection via file starting with '-' is blocked
    flag_file = await _mcp_call(base, token, "git_stage_commit", {
        "task_id": "task-deny-3",
        "repo_path": str(repo),
        "files": ["--force"],
        "commit_message": "flag injection",
    })
    assert flag_file["status"] == "DENIED"
    assert "GIT_ARG_INJECTION" in flag_file["error"]

    # 4. Unallowlisted remote URL / name is blocked
    bad_remote = await _mcp_call(base, token, "git_stage_commit", {
        "task_id": "task-deny-4",
        "repo_path": str(repo),
        "files": ["README.md"],
        "commit_message": "exfil",
        "remote": "evil",
    })
    assert bad_remote["status"] == "DENIED"
    assert "REMOTE_NOT_ALLOWED" in bad_remote["error"]


# --------------------------------------------------------------------------- #
# (d) TOCTOU rejection when staged files change between approval and commit
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_git_toctou_aborts_when_staged_index_drifts(live_git_daemon):
    base, app, token, priv, repo, bare, _ = live_git_daemon

    (repo / "README.md").write_text("# Profile Repo\n\nApproved text.\n", encoding="utf-8")
    before_remote_head = _git(bare, "rev-parse", "refs/heads/main")

    staged = await _mcp_call(base, token, "git_stage_commit", {
        "task_id": "task-git-toctou",
        "repo_path": str(repo),
        "files": ["README.md"],
        "commit_message": "docs: approved update",
    })
    assert staged["status"] == "OK"
    staged_id = staged["result"]["staged_commit_id"]

    pending = await _mcp_call(base, token, "git_commit_and_push", {
        "task_id": "task-git-toctou",
        "staged_commit_id": staged_id,
    })
    assert pending["status"] == "APPROVAL_PENDING"
    contract_id = pending["contract_id"]
    contract_obj = app.state.mini["contracts"].get(contract_id).contract

    # Tamper with the staged index AFTER contract issuance (before signing/execution)
    (repo / "README.md").write_text("# Profile Repo\n\nTAMPERED AFTER APPROVAL!\n", encoding="utf-8")
    _git(repo, "add", "--", "README.md")

    good = SignedApproval(
        contract_id=contract_id,
        decision="approve",
        device_id="pixel-git",
        signature_b64=sign_contract(priv, contract_obj),
    )
    async with httpx.AsyncClient(base_url=base) as client:
        res = await client.post(f"/api/v1/approvals/{contract_id}/decide", json=good.model_dump(mode="json"))
        assert res.status_code == 409
        assert res.json()["detail"]["error"] == "GIT_STAGED_DRIFT"
        assert _git(bare, "rev-parse", "refs/heads/main") == before_remote_head
        assert app.state.mini["contracts"].get(contract_id).status is ContractStatus.FAILED


# --------------------------------------------------------------------------- #
# (e) Unit checks: destructive flag blocker, credential isolation & scrubbing
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("bad_argv", [
    ["push", "--force", "origin", "main"],
    ["push", "-f", "origin", "main"],
    ["push", "--force-with-lease", "origin", "main"],
    ["push", "--delete", "origin", "main"],
    ["push", "origin", "+HEAD:refs/heads/main"],
    ["push", "origin", ":refs/heads/main"],
    ["reset", "--hard", "HEAD~1"],
    ["clean", "-fd"],
    ["branch", "-D", "main"],
    ["config", "user.name", "x"],
    ["remote", "set-url", "origin", "https://evil.example/repo.git"],
])
def test_forbidden_git_flags_and_subcommands_blocked(bad_argv):
    with pytest.raises(GitPolicyError):
        assert_safe_git_argv(bad_argv)


def test_credential_isolation_and_token_scrubbing(git_env, monkeypatch):
    cfg, repo, *_ = git_env
    secret_pat = "github_pat_11ABCDEF0123456789_SECRET_TOKEN_VALUE"
    monkeypatch.setenv("MINI_GIT_TOKEN", secret_pat)
    monkeypatch.setenv("MINI_PROXY_TOKEN", "proxy-secret-bearer")

    pool = MCPClientPool(cfg)
    fs_env = pool.worker_env("filesystem", Path("fs.pid"))
    gmail_env = pool.worker_env("gmail", Path("gmail.pid"))
    git_w_env = pool.worker_env("git", Path("git.pid"))

    # Only the git worker receives MINI_GIT_TOKEN; no worker receives MINI_PROXY_TOKEN
    assert "MINI_GIT_TOKEN" not in fs_env
    assert "MINI_GIT_TOKEN" not in gmail_env
    assert git_w_env.get("MINI_GIT_TOKEN") == secret_pat
    for env in (fs_env, gmail_env, git_w_env):
        assert "MINI_PROXY_TOKEN" not in env

    # GitRunner scrubs both raw PAT values and embedded URL credentials
    runner = GitRunner(token=secret_pat, user_name="Bot", user_email="bot@example.com")
    scrubbed = runner.scrub(f"fatal: auth failed for https://user:{secret_pat}@github.com/u/u.git ({secret_pat})")
    assert secret_pat not in scrubbed
    assert "https://***@github.com" in scrubbed

    # Real mode refuses local non-HTTPS remotes
    real_worker = GitWorker(cfg, mock=False, token=secret_pat)
    (repo / "README.md").write_text("# Real mode check\n", encoding="utf-8")
    res = real_worker.handle("git_stage_commit", {
        "task_id": "task-real-check",
        "repo_path": str(repo),
        "files": ["README.md"],
        "commit_message": "test",
    })
    assert res.is_error is True
    assert res.structured_content["error"] == "REMOTE_NOT_HTTPS"
