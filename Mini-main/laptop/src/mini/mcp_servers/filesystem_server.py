"""Isolated stdio MCP worker for restricted filesystem operations.

This process is spawned by Mini Daemon over private stdio pipes and receives NO
Gmail OAuth credentials and NO proxy bearer tokens. It enforces ``PathGuard``
and ``StagingEngine`` independently as defence in depth.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any

import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from mini.config import MiniConfig, load_config
from mini.schemas import FileArtifactHashes, DeleteArtifactHashes
from mini.security.path_guard import PathGuard, PathViolation
from mini.security.staging import StagingEngine, StagingError


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


class FilesystemWorker:
    def __init__(self, cfg: MiniConfig) -> None:
        self.cfg = cfg
        self.guard = PathGuard(cfg)
        self.staging = StagingEngine(cfg, self.guard)

    def handle(self, name: str, args: dict[str, Any]) -> types.CallToolResult:
        try:
            if name == "fs_list_dir":
                checked = self.guard.check(args["path"], must_exist=True, kind="dir")
                entries = []
                truncated = False
                for entry in sorted(checked.path.iterdir(), key=lambda p: p.name.lower()):
                    if not self.guard.visible_entry(entry):
                        continue
                    if len(entries) >= self.cfg.limits.max_list_entries:
                        truncated = True
                        break
                    entries.append({
                        "name": entry.name,
                        "path": str(entry),
                        "type": "dir" if entry.is_dir() else "file",
                        "size": entry.stat().st_size if entry.is_file() else None,
                    })
                return _ok({"path": str(checked.path), "entries": entries, "truncated": truncated})

            if name == "fs_read_file":
                checked = self.guard.check(args["path"], must_exist=True, kind="file")
                size = checked.path.stat().st_size
                if size > self.cfg.limits.max_read_bytes:
                    return _err("FILE_TOO_LARGE", f"{size} bytes exceeds limit {self.cfg.limits.max_read_bytes}")
                text = checked.path.read_text(encoding="utf-8")
                return _ok({"path": str(checked.path), "size_bytes": size, "content": text})

            if name == "fs_write_staged":
                res = self.staging.write_staged(args["task_id"], args["target_path"], args["content"])
                return _ok(res)

            if name == "fs_commit_staged":
                hashes = FileArtifactHashes(
                    staged_blob=args["staged_blob"],
                    destination_before=args.get("destination_before"),
                )
                res = self.staging.commit(args["task_id"], args["target_path"], hashes)
                return _ok(res)

            if name == "fs_delete_file":
                hashes = DeleteArtifactHashes(target_before=args["target_before"])
                res = self.staging.delete(args["task_id"], args["path"], hashes)
                return _ok(res)

            return _err("UNKNOWN_TOOL", f"unknown filesystem tool: {name}")
        except PathViolation as exc:
            return _err(exc.code, exc.detail or exc.path)
        except StagingError as exc:
            return _err(exc.code, exc.detail)
        except UnicodeDecodeError:
            return _err("NOT_UTF8", "file is not valid UTF-8 text")
        except Exception as exc:
            return _err("WORKER_ERROR", str(exc))


def build_server(cfg: MiniConfig) -> Server:
    worker = FilesystemWorker(cfg)

    async def on_list_tools(_ctx: Any, _params: Any) -> types.ListToolsResult:
        return types.ListToolsResult(tools=[
            types.Tool(name="fs_list_dir", description="List allowed directory", inputSchema={"type": "object"}),
            types.Tool(name="fs_read_file", description="Read UTF-8 text file", inputSchema={"type": "object"}),
            types.Tool(name="fs_write_staged", description="Stage file write", inputSchema={"type": "object"}),
            types.Tool(name="fs_commit_staged", description="Commit verified blob", inputSchema={"type": "object"}),
            types.Tool(name="fs_delete_file", description="Delete verified file", inputSchema={"type": "object"}),
        ])

    async def on_call_tool(_ctx: Any, params: types.CallToolRequestParams) -> types.CallToolResult:
        return worker.handle(params.name, dict(params.arguments or {}))

    return Server("mini-filesystem", version="0.1.0", on_list_tools=on_list_tools, on_call_tool=on_call_tool)


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
