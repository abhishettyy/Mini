"""Isolated stdio MCP worker for git operations (inspect / stage / commit / push).

Credential isolation
--------------------
* Only this subprocess receives ``MINI_GIT_TOKEN`` (fine-grained GitHub PAT),
  ``MINI_GIT_USER_NAME``, ``MINI_GIT_USER_EMAIL`` and ``MINI_GIT_MOCK``.
* The token is never placed in argv, ``.git/config`` or a remote URL. It is
  handed only to the ``git push`` child via its environment, read back by an
  ephemeral ``GIT_ASKPASS`` helper that is deleted right after the push, and
  scrubbed from any error text before it leaves this process.

Command hygiene
---------------
* ``subprocess.run([...], shell=False)`` only; every invocation passes
  ``assert_safe_git_argv`` (no ``--force``/``-f``/``--hard``/``--delete``/
  ``--mirror``/``+refspec``, no ``reset``/``config``/``remote``/... subcommands).
* Hooks disabled (``core.hooksPath`` -> empty dir, ``--no-verify``), credential
  helpers cleared, system config ignored, literal pathspecs, no external
  diff/textconv drivers, no fsmonitor, no GPG prompts.
* Pushes go to the URL allowlisted in ``policy.yaml`` for the chosen remote —
  never to whatever ``.git/config`` says (which is only cross-checked).

``MINI_GIT_MOCK=true`` (default) = offline: no token needed; local bare-repo
remotes are allowed and HTTPS pushes are simulated. ``false`` = real HTTPS push.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterator

import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from mini.config import MiniConfig, load_config
from mini.schemas import GitArtifactHashes, sha256_tagged
from mini.security.git_guard import (
    BRANCH_RE,
    GitPolicyError,
    assert_safe_git_argv,
    is_local_remote,
    normalize_remote_url,
    remote_url_problem,
    validate_repo_files,
    validate_repo_path,
)
from mini.security.path_guard import PathGuard, PathViolation
from mini.security.staging import StagingEngine, StagingError, TOCTOUError

GIT_TIMEOUT_S = 120

ASKPASS_PY = """\
import os, sys
prompt = " ".join(sys.argv[1:]).strip().lower()
if prompt.startswith("username"):
    sys.stdout.write("x-access-token\\n")
else:
    sys.stdout.write(os.environ.get("MINI_GIT_TOKEN", "") + "\\n")
sys.stdout.flush()
"""

_URL_CRED_RE = re.compile(r"(https?://)[^/\s@]+@")


def _truthy(v: str | None, default: bool) -> bool:
    if v is None or not v.strip():
        return default
    return v.strip().lower() in {"1", "true", "yes", "on"}


class GitError(Exception):
    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}")


@contextlib.contextmanager
def ephemeral_askpass() -> Iterator[str]:
    """Create a throw-away GIT_ASKPASS helper; removed on exit. Holds NO secret."""
    d = Path(tempfile.mkdtemp(prefix="mini-askpass-"))
    try:
        script = d / "askpass.py"
        script.write_text(ASKPASS_PY, encoding="utf-8")
        if os.name == "nt":
            helper = d / "askpass.cmd"
            helper.write_text(f'@echo off\r\n"{sys.executable}" "{script}" %*\r\n', encoding="utf-8")
        else:
            helper = d / "askpass.sh"
            helper.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{script}" "$@"\n', encoding="utf-8")
            os.chmod(helper, stat.S_IRWXU)
        yield str(helper)
    finally:
        shutil.rmtree(d, ignore_errors=True)


class GitRunner:
    """The only place a git process is spawned."""

    def __init__(self, *, token: str | None, user_name: str, user_email: str) -> None:
        git = shutil.which("git")
        if not git:
            raise GitError("GIT_NOT_FOUND", "git executable not found on PATH")
        self.git = git
        self._token = token or None
        self.user_name = user_name
        self.user_email = user_email
        self.hooks_dir = Path(tempfile.mkdtemp(prefix="mini-git-nohooks-"))

    def scrub(self, text: str) -> str:
        if self._token:
            text = text.replace(self._token, "***")
        return _URL_CRED_RE.sub(r"\1***@", text)

    def env(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        env = {k: v for k, v in os.environ.items()
               if not k.upper().startswith(("GIT_", "MINI_GIT_", "SSH_ASKPASS", "GCM_"))}
        env.update({
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_LITERAL_PATHSPECS": "1",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GCM_INTERACTIVE": "never",
            "GIT_AUTHOR_NAME": self.user_name,
            "GIT_AUTHOR_EMAIL": self.user_email,
            "GIT_COMMITTER_NAME": self.user_name,
            "GIT_COMMITTER_EMAIL": self.user_email,
        })
        env.update(extra or {})
        return env

    def run(
        self,
        repo: Path,
        args: list[str],
        *,
        input: bytes | None = None,
        extra_env: dict[str, str] | None = None,
        check: bool = True,
        code: str = "GIT_FAILED",
    ) -> subprocess.CompletedProcess[bytes]:
        assert_safe_git_argv(args)
        argv = [
            self.git, "--no-pager", "-C", str(repo),
            "-c", f"core.hooksPath={self.hooks_dir}",
            "-c", "credential.helper=",
            "-c", "core.fsmonitor=false",
            "-c", "commit.gpgSign=false",
            "-c", "core.quotePath=false",
            "-c", "protocol.ext.allow=never",
            *args,
        ]
        kw: dict[str, Any] = {}
        if os.name == "nt":
            kw["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        try:
            res = subprocess.run(  # noqa: S603 - argv array, shell=False
                argv, shell=False, cwd=str(repo), env=self.env(extra_env), input=input,
                capture_output=True, timeout=GIT_TIMEOUT_S, **kw,
            )
        except subprocess.TimeoutExpired as exc:
            raise GitError("GIT_TIMEOUT", f"git {args[0]} timed out") from exc
        if check and res.returncode != 0:
            err = self.scrub(res.stderr.decode("utf-8", errors="replace").strip())
            raise GitError(code, f"git {args[0]} exited {res.returncode}: {err[:1500]}")
        return res


def _ok(data: Any) -> types.CallToolResult:
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=json.dumps(data, ensure_ascii=False))],
        structured_content=data if isinstance(data, dict) else {"result": data},
        is_error=False,
    )


def _err(code: str, message: str) -> types.CallToolResult:
    payload = {"error": code, "message": message}
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=json.dumps(payload, ensure_ascii=False))],
        structured_content=payload,
        is_error=True,
    )


class GitWorker:
    def __init__(
        self,
        cfg: MiniConfig,
        *,
        mock: bool,
        token: str | None = None,
        user_name: str = "Mini Agent",
        user_email: str = "mini-agent@localhost",
    ) -> None:
        self.cfg = cfg
        self.mock = mock
        self.guard = PathGuard(cfg)
        self.staging = StagingEngine(cfg, self.guard)
        self.git = GitRunner(token=token, user_name=user_name, user_email=user_email)
        self._token = token or None

    # ------------------------------------------------------------------ #
    # helpers
    # ------------------------------------------------------------------ #
    def _repo(self, raw: object) -> Path:
        repo = validate_repo_path(self.guard, raw)
        top = self.git.run(repo, ["rev-parse", "--show-toplevel"]).stdout.decode("utf-8").strip()
        if os.path.normcase(os.path.realpath(top)) != os.path.normcase(str(repo)):
            raise GitError("NOT_REPO_ROOT", f"{repo} is not the work-tree root")
        return repo

    def _branch(self, repo: Path) -> str:
        res = self.git.run(repo, ["symbolic-ref", "--short", "-q", "HEAD"], check=False)
        name = res.stdout.decode("utf-8").strip()
        if res.returncode != 0 or not name:
            raise GitError("DETACHED_HEAD", "HEAD is not on a branch")
        return name

    def _allowed(self, repo: Path, rel: str) -> bool:
        return self.guard.deny_reason(Path(os.path.realpath(repo / rel))) is None and \
            self.guard.deny_reason(repo / rel) is None

    def _names(self, repo: Path, *, cached: bool) -> list[str]:
        args = ["diff", "--name-only", "-z", "--no-renames"]
        if cached:
            args.insert(1, "--cached")
        out = self.git.run(repo, args).stdout.decode("utf-8", errors="surrogateescape")
        return sorted(n for n in out.split("\x00") if n)

    def _cached_diff_bytes(self, repo: Path) -> bytes:
        return self.git.run(repo, ["diff", "--cached", "--binary", "--full-index", "--no-color",
                                   "--no-ext-diff", "--no-textconv", "--no-renames"]).stdout

    def _preview(self, repo: Path, files: list[str], *, cached: bool) -> tuple[str, bool]:
        if not files:
            return "", False
        args = ["diff", "--no-color", "--no-ext-diff", "--no-textconv", "--no-renames", "-U3"]
        if cached:
            args.insert(1, "--cached")
        text = self.git.run(repo, [*args, "--", *files]).stdout.decode("utf-8", errors="replace")
        limit = self.cfg.limits.max_diff_bytes
        raw = text.encode("utf-8")
        if len(raw) > limit:
            return raw[:limit].decode("utf-8", errors="ignore") + "\n... [diff truncated]\n", True
        return text, False

    def _remote(self, repo: Path, remote: str, *, drift_code: str | None = None) -> str:
        url = self.cfg.git.allowed_remotes.get(remote)
        if url is None:
            raise GitError(drift_code or "REMOTE_NOT_ALLOWED", f"remote {remote!r} is not allowlisted")
        problem = remote_url_problem(url, mock=self.mock)
        if problem:
            raise GitError(problem, f"allowlisted URL for {remote!r} is not usable in this mode")
        configured = self.git.run(repo, ["ls-remote", "--get-url", remote]).stdout.decode("utf-8").strip()
        if not configured or configured == remote:
            raise GitError(drift_code or "REMOTE_NOT_CONFIGURED", f"repo has no remote {remote!r}")
        if remote_url_problem(configured, mock=True) == "REMOTE_URL_HAS_CREDENTIALS":
            raise GitError("REMOTE_URL_HAS_CREDENTIALS", "remove credentials embedded in .git/config remote URL")
        if normalize_remote_url(configured) != normalize_remote_url(url):
            raise GitError(drift_code or "REMOTE_URL_MISMATCH",
                           f"repo remote {remote!r} does not match the policy allowlist")
        return url

    # ------------------------------------------------------------------ #
    # tools
    # ------------------------------------------------------------------ #
    def git_status(self, args: dict[str, Any]) -> dict[str, Any]:
        repo = self._repo(args["repo_path"])
        res = self.git.run(repo, ["status", "--porcelain=v1", "-z", "--untracked-files=all", "--no-renames"])
        tokens = [t for t in res.stdout.decode("utf-8", errors="surrogateescape").split("\x00") if t]
        files, hidden = [], 0
        for tok in tokens:
            xy, path = tok[:2], tok[3:]
            if not self._allowed(repo, path):
                hidden += 1
                continue
            files.append({"path": path, "status": xy.strip() or "?"})
        cap = self.cfg.limits.max_list_entries
        res_branch = self.git.run(repo, ["symbolic-ref", "--short", "-q", "HEAD"], check=False)
        return {
            "repo": repo.name,
            "branch": res_branch.stdout.decode("utf-8").strip() or None,
            "clean": not tokens,
            "files": files[:cap],
            "truncated": len(files) > cap,
            "hidden": hidden,
        }

    def git_diff(self, args: dict[str, Any]) -> dict[str, Any]:
        repo = self._repo(args["repo_path"])
        cached = bool(args.get("staged", False))
        names = self._names(repo, cached=cached)
        visible = [n for n in names if self._allowed(repo, n)]
        diff, truncated = self._preview(repo, visible, cached=cached)
        return {"staged": cached, "files": visible, "hidden": len(names) - len(visible),
                "diff": diff, "truncated": truncated}

    def git_stage_commit(self, args: dict[str, Any]) -> dict[str, Any]:
        task_id = args["task_id"]
        self.staging.task_dir(task_id)
        repo = self._repo(args["repo_path"])
        branch = self._branch(repo)
        if not BRANCH_RE.fullmatch(branch) or branch not in self.cfg.git.allowed_branches:
            raise GitError("BRANCH_NOT_ALLOWED", f"branch {branch!r} is not allowlisted")
        remote = args.get("remote") or "origin"
        url = self._remote(repo, remote)
        msg = args["commit_message"]
        if not isinstance(msg, str) or not msg.strip() or "\x00" in msg or \
                len(msg.encode("utf-8")) > self.cfg.git.max_commit_message_bytes:
            raise GitError("INVALID_COMMIT_MESSAGE", "empty, NUL or too long")
        files = validate_repo_files(self.guard, repo, args["files"], max_files=self.cfg.git.max_files)

        self.git.run(repo, ["add", "--", *files], code="GIT_ADD_FAILED")
        staged = self._names(repo, cached=True)
        extra = sorted(set(staged) - set(files))
        if extra:
            raise GitError("STAGED_EXTRA_FILES",
                           f"index already contains other staged changes: {extra[:20]}")
        if not staged:
            raise GitError("NOTHING_STAGED", "no changes in the requested files")
        diff_sha = sha256_tagged(self._cached_diff_bytes(repo))
        tree = self.git.run(repo, ["write-tree"]).stdout.decode("ascii").strip()
        preview, truncated = self._preview(repo, staged, cached=True)
        rec = self.staging.put_git_proposal(task_id, {
            "repo_path": str(repo),
            "repo_name": repo.name,
            "branch": branch,
            "remote": remote,
            "remote_url": url,
            "commit_message": msg,
            "files": staged,
            "diff_sha256": diff_sha,
            "staged_tree": tree,
            "unified_diff": preview,
            "diff_truncated": truncated,
        })
        return {"ok": True, "staged_commit_id": rec["staged_commit_id"], "files": staged}

    def git_commit_and_push(self, args: dict[str, Any]) -> dict[str, Any]:
        task_id = args["task_id"]
        raw_expected = args.get("git_artifacts")
        if not isinstance(raw_expected, dict):
            raise GitError("MISSING_CONTRACT_HASHES", "git_artifacts from the signed contract are required")
        expected = GitArtifactHashes.model_validate(raw_expected)
        rec = self.staging.load_verified_git_proposal(task_id, args["staged_commit_id"], expected)
        p = rec["proposal"]

        # --- TOCTOU re-verification against the signed contract -----------
        repo = self._repo(p["repo_path"])
        branch = self._branch(repo)
        if branch != p["branch"]:
            raise GitError("GIT_BRANCH_DRIFT", f"HEAD moved from {p['branch']!r} to {branch!r}")
        url = self._remote(repo, p["remote"], drift_code="GIT_REMOTE_DRIFT")
        if normalize_remote_url(url) != normalize_remote_url(p["remote_url"]):
            raise GitError("GIT_REMOTE_DRIFT", "allowlisted remote URL changed since approval")
        staged = self._names(repo, cached=True)
        if staged != p["files"]:
            raise GitError("GIT_STAGED_DRIFT", "staged file set changed since approval")
        if sha256_tagged(self._cached_diff_bytes(repo)) != p["diff_sha256"]:
            raise GitError("GIT_STAGED_DRIFT", "staged diff changed since approval")
        tree = self.git.run(repo, ["write-tree"]).stdout.decode("ascii").strip()
        if tree != p["staged_tree"]:
            raise GitError("GIT_STAGED_DRIFT", "staged tree changed since approval")

        # --- commit exactly the approved index ----------------------------
        self.git.run(repo, ["commit", "--no-verify", "--quiet", "--cleanup=verbatim", "-F", "-"],
                     input=p["commit_message"].encode("utf-8"), code="GIT_COMMIT_FAILED")
        head_tree = self.git.run(repo, ["rev-parse", "HEAD^{tree}"]).stdout.decode("ascii").strip()
        if head_tree != p["staged_tree"]:
            raise GitError("POST_COMMIT_MISMATCH", "committed tree differs from approved tree")
        sha = self.git.run(repo, ["rev-parse", "HEAD"]).stdout.decode("ascii").strip()

        pushed = self._push(repo, url, branch, short_sha=sha[:7])
        return {"ok": True, "branch": branch, "commit": sha[:7], "pushed": pushed, "mock": self.mock}

    def _push(self, repo: Path, url: str, branch: str, *, short_sha: str) -> bool:
        refspec = f"HEAD:refs/heads/{branch}"
        args = ["push", "--no-verify", "--porcelain", url, refspec]
        fail = f"commit {short_sha} created locally but push failed"
        if is_local_remote(url):
            if not self.mock:
                raise GitError("REMOTE_NOT_HTTPS", "local remotes are only allowed in mock mode")
            try:
                self.git.run(repo, args, code="PUSH_FAILED")
            except GitError as exc:
                raise GitError("PUSH_FAILED", f"{fail}: {exc.detail}") from exc
            return True
        if self.mock:
            return False  # offline: HTTPS push simulated, nothing leaves the machine
        if not self._token:
            raise GitError("GIT_TOKEN_MISSING", f"{fail}: MINI_GIT_TOKEN not provided to git worker")
        with ephemeral_askpass() as helper:
            try:
                self.git.run(repo, args, code="PUSH_FAILED", extra_env={
                    "GIT_ASKPASS": helper,
                    "MINI_GIT_TOKEN": self._token,
                    "GIT_TERMINAL_PROMPT": "0",
                })
            except GitError as exc:
                raise GitError("PUSH_FAILED", f"{fail}: {exc.detail}") from exc
        return True

    # ------------------------------------------------------------------ #
    def handle(self, name: str, args: dict[str, Any]) -> types.CallToolResult:
        try:
            fn = {
                "git_status": self.git_status,
                "git_diff": self.git_diff,
                "git_stage_commit": self.git_stage_commit,
                "git_commit_and_push": self.git_commit_and_push,
            }.get(name)
            if fn is None:
                return _err("UNKNOWN_TOOL", f"unknown git tool: {name}")
            return _ok(fn(args))
        except PathViolation as exc:
            return _err(exc.code, exc.detail or exc.path)
        except (GitError, GitPolicyError, StagingError, TOCTOUError) as exc:
            return _err(exc.code, self.git.scrub(exc.detail))
        except KeyError as exc:
            return _err("MISSING_ARGUMENT", str(exc))
        except Exception as exc:  # never leak the token through unexpected errors
            return _err("WORKER_ERROR", self.git.scrub(f"{type(exc).__name__}: {exc}"))


def _load_worker_config() -> MiniConfig:
    env = os.environ
    kw: dict[str, Any] = {}
    if env.get("MINI_WORKSPACES_DIR"):
        kw["workspaces_dir"] = env["MINI_WORKSPACES_DIR"]
    return load_config(
        env.get("MINI_CONFIG") or None,
        project_root=env.get("MINI_PROJECT_ROOT") or None,
        home=env.get("MINI_HOME_USER") or None,
        env=env,
        **kw,
    )


def worker_from_env(cfg: MiniConfig) -> GitWorker:
    env = os.environ
    return GitWorker(
        cfg,
        mock=_truthy(env.get("MINI_GIT_MOCK"), True),
        token=env.get("MINI_GIT_TOKEN") or None,
        user_name=env.get("MINI_GIT_USER_NAME") or "Mini Agent",
        user_email=env.get("MINI_GIT_USER_EMAIL") or "mini-agent@localhost",
    )


def build_server(cfg: MiniConfig, worker: GitWorker | None = None) -> Server:
    w = worker or worker_from_env(cfg)

    async def on_list_tools(_ctx: Any, _params: Any) -> types.ListToolsResult:
        return types.ListToolsResult(tools=[
            types.Tool(name="git_status", description="Repo status", inputSchema={"type": "object"}),
            types.Tool(name="git_diff", description="Compact diff", inputSchema={"type": "object"}),
            types.Tool(name="git_stage_commit", description="Stage files + immutable proposal",
                       inputSchema={"type": "object"}),
            types.Tool(name="git_commit_and_push", description="Commit + push verified proposal",
                       inputSchema={"type": "object"}),
        ])

    async def on_call_tool(_ctx: Any, params: types.CallToolRequestParams) -> types.CallToolResult:
        args = dict(params.arguments or {})
        return await asyncio.to_thread(w.handle, params.name, args)

    return Server("mini-git", version="0.1.0", on_list_tools=on_list_tools, on_call_tool=on_call_tool)


def _write_pid_file() -> None:
    pid_file = os.environ.get("MINI_WORKER_PID_FILE")
    if pid_file:
        Path(pid_file).write_text(str(os.getpid()), encoding="utf-8")


async def amain() -> None:
    _write_pid_file()
    cfg = _load_worker_config()
    server = build_server(cfg)
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def main() -> None:
    asyncio.run(amain())


if __name__ == "__main__":
    main()
