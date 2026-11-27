"""Supervises downstream stdio MCP worker processes and enforces the kill switch.

Each worker (``filesystem``, ``gmail``, ``git``) runs as an isolated child process over
private stdio pipes via ``mcp.client.stdio.stdio_client``.
* Only the ``gmail`` worker receives Gmail OAuth environment variables.
* Only the ``git`` worker receives ``MINI_GIT_TOKEN`` / ``MINI_GIT_USER_*`` / ``MINI_GIT_MOCK``.
* No worker receives ``MINI_PROXY_TOKEN``.
* Each worker lives inside its own dedicated asyncio task so ``stdio_client``
  enters and exits its cancel scope in the exact same task.
* ``kill_all()`` immediately terminates all active child processes
  (``terminate()`` -> ``kill_switch_grace_ms`` -> ``kill()``) and sets
  ``paused = True`` until ``reset_kill_switch()`` is called.
"""

from __future__ import annotations

import asyncio
import contextlib
import ctypes
import json
import os
import shutil
import signal
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from mini.config import MiniConfig
from mini.schemas import AuditEventType
from mini.security.audit import AuditLogger


class PoolError(Exception):
    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}")


class PoolPausedError(PoolError):
    pass


class WorkerUnavailableError(PoolError):
    pass


class WorkerToolError(PoolError):
    pass


# --------------------------------------------------------------------------- #
# Cross-platform child process termination (terminate -> grace -> kill)
# --------------------------------------------------------------------------- #
def is_pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        SYNCHRONIZE = 0x00100000
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        WAIT_TIMEOUT = 0x00000102
        STILL_ACTIVE = 259
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return False
        try:
            code = ctypes.c_ulong()
            if kernel32.GetExitCodeProcess(handle, ctypes.byref(code)) and code.value != STILL_ACTIVE:
                return False
            return kernel32.WaitForSingleObject(handle, 0) == WAIT_TIMEOUT
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def terminate_pid(pid: int) -> None:
    if pid <= 0:
        return
    if os.name == "nt":
        # On Windows, GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT) or TerminateProcess;
        # os.kill(pid, signal.SIGTERM) calls TerminateProcess cleanly without affecting
        # the parent's console group.
        with contextlib.suppress(OSError):
            os.kill(pid, signal.SIGTERM)
    else:
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.kill(pid, signal.SIGTERM)


def kill_pid(pid: int) -> None:
    if pid <= 0:
        return
    if os.name == "nt":
        PROCESS_TERMINATE = 0x0001
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
        if handle:
            try:
                kernel32.TerminateProcess(handle, 1)
            finally:
                kernel32.CloseHandle(handle)
    else:
        sig = getattr(signal, "SIGKILL", signal.SIGTERM)
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.kill(pid, sig)


@dataclass
class _WorkerSlot:
    name: str
    module: str
    pid_file: Path
    pid: int | None = None
    session: ClientSession | None = None
    ready: asyncio.Event = field(default_factory=asyncio.Event)
    stop: asyncio.Event = field(default_factory=asyncio.Event)
    task: asyncio.Task[None] | None = None
    error: str | None = None


class MCPClientPool:
    def __init__(
        self,
        cfg: MiniConfig,
        audit: AuditLogger | None = None,
        *,
        extra_env: dict[str, str] | None = None,
    ) -> None:
        self.cfg = cfg
        self.audit = audit
        self._extra_env = dict(extra_env or {})
        self.paused = False
        self._lock = asyncio.Lock()
        self._workers: dict[str, _WorkerSlot] = {}
        self._pid_dir = Path(tempfile.mkdtemp(prefix="mini-pids-"))
        self._call_timeout = 150.0  # git push over HTTPS may be slow; git worker caps at 120s

    # ------------------------------------------------------------------ #
    # Environment construction (credential isolation)
    # ------------------------------------------------------------------ #
    def worker_env(self, server_name: str, pid_file: Path) -> dict[str, str]:
        """Minimal environment for a downstream stdio worker."""
        env: dict[str, str] = {"PYTHONUTF8": "1", "MINI_WORKER_PID_FILE": str(pid_file)}
        for key in ("PATH", "PATHEXT", "SYSTEMROOT", "COMSPEC", "TEMP", "TMP",
                    "HOME", "USERPROFILE", "PYTHONPATH"):
            val = os.environ.get(key)
            if val is not None:
                env[key] = val

        # Ensure src/ is importable even if not installed editable in the caller's PYTHONPATH
        src_dir = str(Path(__file__).resolve().parents[2])
        if env.get("PYTHONPATH"):
            if src_dir not in env["PYTHONPATH"]:
                env["PYTHONPATH"] = src_dir + os.pathsep + env["PYTHONPATH"]
        else:
            env["PYTHONPATH"] = src_dir

        if self.cfg.config_path:
            env["MINI_CONFIG"] = str(self.cfg.config_path)
        env["MINI_PROJECT_ROOT"] = str(self.cfg.project_root)
        env["MINI_HOME_USER"] = str(self.cfg.home)
        env["MINI_HOME"] = str(self.cfg.mini_home)
        env["MINI_WORKSPACES_DIR"] = str(self.cfg.workspaces_dir)
        env["MINI_APPROVED_ROOTS"] = os.pathsep.join(str(r) for r in self.cfg.approved_roots)

        # Credential isolation: ONLY the gmail worker gets Gmail OAuth / mock config.
        if server_name == "gmail":
            for key in ("MINI_GMAIL_MOCK", "MINI_GMAIL_MOCK_DIR",
                        "MINI_GMAIL_CLIENT_SECRETS", "MINI_GMAIL_TOKEN"):
                val = self._extra_env.get(key) or os.environ.get(key)
                if val is not None:
                    env[key] = val
            env.setdefault("MINI_GMAIL_MOCK", "true")
            env.setdefault("MINI_GMAIL_CLIENT_SECRETS", str(self.cfg.secrets_dir / "gmail_client_secret.json"))
            env.setdefault("MINI_GMAIL_TOKEN", str(self.cfg.secrets_dir / "gmail_token.json"))
        # Credential isolation: ONLY the git worker gets the GitHub PAT + identity.
        if server_name == "git":
            for key in ("MINI_GIT_TOKEN", "MINI_GIT_USER_NAME", "MINI_GIT_USER_EMAIL", "MINI_GIT_MOCK"):
                val = self._extra_env.get(key) or os.environ.get(key)
                if val is not None:
                    env[key] = val
            env.setdefault("MINI_GIT_MOCK", "true")
        return env

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #
    async def start(self) -> None:
        async with self._lock:
            if self.paused:
                raise PoolPausedError("KILL_SWITCH_ACTIVE", "reset kill switch before starting workers")
            await self._start_worker("filesystem", "mini.mcp_servers.filesystem_server")
            await self._start_worker("gmail", "mini.mcp_servers.gmail_server")
            await self._start_worker("git", "mini.mcp_servers.git_server")

    async def _start_worker(self, name: str, module: str) -> None:
        if name in self._workers and self._workers[name].task and not self._workers[name].task.done():
            return
        pid_file = self._pid_dir / f"{name}.pid"
        pid_file.unlink(missing_ok=True)
        slot = _WorkerSlot(name=name, module=module, pid_file=pid_file)
        slot.task = asyncio.create_task(self._worker_runner(slot), name=f"mcp-worker-{name}")
        self._workers[name] = slot
        try:
            await asyncio.wait_for(slot.ready.wait(), timeout=15.0)
        except asyncio.TimeoutError as exc:
            slot.stop.set()
            raise WorkerUnavailableError("WORKER_START_TIMEOUT", f"{name} did not start within 15s") from exc
        if slot.error or slot.session is None:
            raise WorkerUnavailableError("WORKER_START_FAILED", f"{name}: {slot.error}")

    async def _worker_runner(self, slot: _WorkerSlot) -> None:
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", slot.module],
            env=self.worker_env(slot.name, slot.pid_file),
            cwd=str(self.cfg.project_root),
        )
        try:
            async with stdio_client(params) as (read_stream, write_stream):
                async with ClientSession(read_stream, write_stream) as session:
                    await session.initialize()
                    if slot.pid_file.exists():
                        with contextlib.suppress(ValueError):
                            slot.pid = int(slot.pid_file.read_text(encoding="utf-8").strip())
                    slot.session = session
                    slot.ready.set()
                    if self.audit:
                        self.audit.append(
                            AuditEventType.WORKER_STARTED,
                            server=slot.name,
                            details={"pid": slot.pid, "module": slot.module},
                        )
                    await slot.stop.wait()
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            slot.error = str(exc)
            slot.ready.set()
        finally:
            slot.session = None
            slot.ready.set()
            if self.audit and slot.pid is not None:
                with contextlib.suppress(Exception):
                    self.audit.append(
                        AuditEventType.WORKER_STOPPED,
                        server=slot.name,
                        details={"pid": slot.pid},
                    )

    async def stop(self) -> None:
        async with self._lock:
            for slot in list(self._workers.values()):
                slot.stop.set()
            tasks = [s.task for s in self._workers.values() if s.task is not None]
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            self._workers.clear()
            shutil.rmtree(self._pid_dir, ignore_errors=True)

    # ------------------------------------------------------------------ #
    # Tool execution
    # ------------------------------------------------------------------ #
    async def call_tool(self, server_name: str, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if self.paused:
            raise PoolPausedError("KILL_SWITCH_ACTIVE", "execution paused by emergency kill switch")
        slot = self._workers.get(server_name)
        if slot is None or slot.session is None:
            raise WorkerUnavailableError("WORKER_UNAVAILABLE", f"worker {server_name!r} is not running")
        try:
            res = await asyncio.wait_for(
                slot.session.call_tool(tool_name, arguments),
                timeout=self._call_timeout,
            )
        except asyncio.TimeoutError as exc:
            raise WorkerUnavailableError("WORKER_TIMEOUT", f"{server_name}.{tool_name} timed out") from exc
        except PoolError:
            raise
        except Exception as exc:
            raise WorkerUnavailableError("WORKER_RPC_ERROR", str(exc)) from exc

        payload: dict[str, Any]
        if isinstance(res.structured_content, dict):
            payload = dict(res.structured_content)
        elif res.content and getattr(res.content[0], "text", None):
            try:
                payload = json.loads(res.content[0].text)
            except ValueError:
                payload = {"text": res.content[0].text}
        else:
            payload = {}

        if res.is_error:
            raise WorkerToolError(
                str(payload.get("error", "WORKER_TOOL_ERROR")),
                str(payload.get("message", payload)),
            )
        return payload

    # ------------------------------------------------------------------ #
    # Emergency Kill Switch: terminate() -> 500 ms -> kill()
    # ------------------------------------------------------------------ #
    async def kill_all(self) -> dict[str, Any]:
        self.paused = True
        terminated: list[int] = []
        force_killed: list[int] = []
        pids: list[tuple[str, int]] = []

        for name, slot in list(self._workers.items()):
            slot.stop.set()
            if slot.pid is None and slot.pid_file.exists():
                with contextlib.suppress(ValueError):
                    slot.pid = int(slot.pid_file.read_text(encoding="utf-8").strip())
            if slot.pid is not None:
                pids.append((name, slot.pid))
                terminate_pid(slot.pid)
                terminated.append(slot.pid)

        # Grace window (default 500 ms) before escalating to hard kill()
        grace_s = max(0.05, self.cfg.kill_switch_grace_ms / 1000.0)
        deadline = time.monotonic() + grace_s
        while time.monotonic() < deadline:
            if not any(is_pid_alive(pid) for _, pid in pids):
                break
            await asyncio.sleep(0.025)

        for _, pid in pids:
            if is_pid_alive(pid):
                kill_pid(pid)
                force_killed.append(pid)

        # Wait briefly for tasks to unwind; cancel if any pipe task lingers
        tasks = [s.task for s in self._workers.values() if s.task is not None]
        if tasks:
            done, pending = await asyncio.wait(tasks, timeout=1.0)
            for t in pending:
                t.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
        self._workers.clear()
        return {"paused": True, "terminated": terminated, "force_killed": force_killed}

    async def reset_kill_switch(self, *, restart_workers: bool = True) -> dict[str, Any]:
        self.paused = False
        if restart_workers:
            await self.start()
        return self.status()

    def status(self) -> dict[str, Any]:
        return {
            "paused": self.paused,
            "workers": {
                name: {
                    "running": slot.session is not None and slot.task is not None and not slot.task.done(),
                    "pid": slot.pid,
                    "alive": is_pid_alive(slot.pid) if slot.pid else False,
                }
                for name, slot in self._workers.items()
            },
        }
