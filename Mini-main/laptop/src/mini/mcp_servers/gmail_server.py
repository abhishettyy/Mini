"""Isolated stdio MCP worker for Gmail operations.

Credential isolation:
* Only this subprocess receives ``MINI_GMAIL_CLIENT_SECRETS`` and
  ``MINI_GMAIL_TOKEN`` from the daemon.
* OAuth scopes are hard-pinned to ``gmail.readonly`` and ``gmail.compose``.
* Setting ``MINI_GMAIL_MOCK=true`` selects the local file-backed mock adapter for
  offline / CI testing.
"""

from __future__ import annotations

import asyncio
import base64
import json
import mimetypes
import os
import uuid
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Protocol

import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from mini.config import MiniConfig, load_config, resolve_path
from mini.schemas import EmailArtifactHashes, iso_utc
from mini.security.path_guard import PathGuard, PathViolation
from mini.security.staging import StagingEngine, StagingError

SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.compose",
]


class GmailBackend(Protocol):
    def search(self, query: str, max_results: int) -> list[dict[str, Any]]: ...
    def read_message(self, message_id: str) -> dict[str, Any]: ...
    def create_draft(self, msg: EmailMessage) -> str | None: ...
    def send_message(self, msg: EmailMessage, *, payload: dict[str, Any], attachments: list[str]) -> dict[str, Any]: ...


# --------------------------------------------------------------------------- #
# Mock adapter (file-backed so state survives across subprocess invocations)
# --------------------------------------------------------------------------- #
class MockGmailBackend:
    """Offline Gmail adapter stored in ``{mock_dir}/mailbox.json``."""

    DEFAULT_MESSAGES = [
        {
            "id": "msg_welcome_001",
            "threadId": "thr_001",
            "from": "advisor@university.edu",
            "to": ["student@university.edu"],
            "subject": "Mini Project Milestone Update",
            "date": "2026-11-25T10:00:00Z",
            "snippet": "Please review the project README and send a summary draft.",
            "body": "Hi,\n\nPlease review the project README, stage any updates, and send me a summary email.\n\nThanks,\nAdvisor",
            "attachments": [],
        },
        {
            "id": "msg_lab_002",
            "threadId": "thr_002",
            "from": "lab@university.edu",
            "to": ["student@university.edu"],
            "subject": "Lab Rubric & Deadline",
            "date": "2026-11-26T09:00:00Z",
            "snippet": "Submission deadline is Friday 5 PM.",
            "body": "Reminder: include your verification summary before Friday 5 PM.",
            "attachments": [],
        },
    ]

    def __init__(self, mock_dir: Path) -> None:
        self.path = mock_dir / "mailbox.json"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self._save({"inbox": list(self.DEFAULT_MESSAGES), "drafts": [], "sent": []})

    def _load(self) -> dict[str, list[dict[str, Any]]]:
        return json.loads(self.path.read_text(encoding="utf-8"))

    def _save(self, data: dict[str, list[dict[str, Any]]]) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        os.replace(tmp, self.path)

    def search(self, query: str, max_results: int) -> list[dict[str, Any]]:
        q = query.strip().lower()
        data = self._load()
        matches = []
        for m in data["inbox"]:
            hay = " ".join([m.get("subject", ""), m.get("from", ""), m.get("snippet", ""), m.get("body", "")]).lower()
            if not q or q in hay:
                matches.append({
                    "id": m["id"],
                    "threadId": m["threadId"],
                    "from": m["from"],
                    "subject": m["subject"],
                    "date": m["date"],
                    "snippet": m["snippet"],
                })
            if len(matches) >= max_results:
                break
        return matches

    def read_message(self, message_id: str) -> dict[str, Any]:
        data = self._load()
        for m in data["inbox"] + data["sent"]:
            if m["id"] == message_id:
                return m
        raise KeyError(f"message not found: {message_id}")

    def create_draft(self, msg: EmailMessage) -> str:
        data = self._load()
        draft_id = "gdraft_" + uuid.uuid4().hex[:12]
        data["drafts"].append({
            "id": draft_id,
            "to": msg.get("To", ""),
            "subject": msg.get("Subject", ""),
            "created_at": iso_utc(),
        })
        self._save(data)
        return draft_id

    def send_message(self, msg: EmailMessage, *, payload: dict[str, Any], attachments: list[str]) -> dict[str, Any]:
        data = self._load()
        msg_id = "sent_" + uuid.uuid4().hex[:12]
        record = {
            "id": msg_id,
            "threadId": "thr_" + uuid.uuid4().hex[:8],
            "to": payload["to"],
            "cc": payload.get("cc", []),
            "bcc": payload.get("bcc", []),
            "subject": payload["subject"],
            "body": payload["body"],
            "attachments": attachments,
            "sent_at": iso_utc(),
            "mock": True,
        }
        data["sent"].append(record)
        self._save(data)
        return {"sent": True, "message_id": msg_id, "mock": True, "to": payload["to"], "subject": payload["subject"]}


# --------------------------------------------------------------------------- #
# Real Google Gmail API adapter (lazy-imported so offline mode stays clean)
# --------------------------------------------------------------------------- #
class RealGmailBackend:
    def __init__(self, client_secrets: Path, token_path: Path) -> None:
        self.client_secrets = client_secrets
        self.token_path = token_path
        self._service: Any = None

    def _client(self) -> Any:
        if self._service is not None:
            return self._service
        from google.auth.transport.requests import Request
        from google.oauth2.credentials import Credentials
        from google_auth_oauthlib.flow import InstalledAppFlow
        from googleapiclient.discovery import build

        creds = None
        if self.token_path.exists():
            creds = Credentials.from_authorized_user_file(str(self.token_path), SCOPES)
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                if not self.client_secrets.exists():
                    raise RuntimeError(f"Gmail client secrets missing at {self.client_secrets}")
                flow = InstalledAppFlow.from_client_secrets_file(str(self.client_secrets), SCOPES)
                creds = flow.run_local_server(port=0)
            self.token_path.parent.mkdir(parents=True, exist_ok=True)
            self.token_path.write_text(creds.to_json(), encoding="utf-8")
        self._service = build("gmail", "v1", credentials=creds, cache_discovery=False)
        return self._service

    def search(self, query: str, max_results: int) -> list[dict[str, Any]]:
        svc = self._client()
        resp = svc.users().messages().list(userId="me", q=query, maxResults=max_results).execute()
        out = []
        for item in resp.get("messages", []):
            meta = svc.users().messages().get(
                userId="me", id=item["id"], format="metadata",
                metadataHeaders=["Subject", "From", "Date"],
            ).execute()
            hdrs = {h["name"].lower(): h["value"] for h in meta.get("payload", {}).get("headers", [])}
            out.append({
                "id": meta["id"],
                "threadId": meta.get("threadId", ""),
                "from": hdrs.get("from", ""),
                "subject": hdrs.get("subject", ""),
                "date": hdrs.get("date", ""),
                "snippet": meta.get("snippet", ""),
            })
        return out

    def read_message(self, message_id: str) -> dict[str, Any]:
        svc = self._client()
        msg = svc.users().messages().get(userId="me", id=message_id, format="full").execute()
        payload = msg.get("payload", {})
        hdrs = {h["name"].lower(): h["value"] for h in payload.get("headers", [])}
        body = _extract_text_body(payload)
        return {
            "id": msg["id"],
            "threadId": msg.get("threadId", ""),
            "from": hdrs.get("from", ""),
            "to": hdrs.get("to", ""),
            "subject": hdrs.get("subject", ""),
            "date": hdrs.get("date", ""),
            "body": body,
            "snippet": msg.get("snippet", ""),
        }

    def create_draft(self, msg: EmailMessage) -> str | None:
        svc = self._client()
        raw = base64.urlsafe_b64encode(msg.as_bytes()).decode("ascii")
        res = svc.users().drafts().create(userId="me", body={"message": {"raw": raw}}).execute()
        return res.get("id")

    def send_message(self, msg: EmailMessage, *, payload: dict[str, Any], attachments: list[str]) -> dict[str, Any]:
        svc = self._client()
        raw = base64.urlsafe_b64encode(msg.as_bytes()).decode("ascii")
        res = svc.users().messages().send(userId="me", body={"raw": raw}).execute()
        return {"sent": True, "message_id": res.get("id"), "mock": False,
                "to": payload["to"], "subject": payload["subject"]}


def _extract_text_body(payload: dict[str, Any]) -> str:
    if payload.get("mimeType") == "text/plain" and payload.get("body", {}).get("data"):
        return base64.urlsafe_b64decode(payload["body"]["data"]).decode("utf-8", errors="replace")
    for part in payload.get("parts", []) or []:
        text = _extract_text_body(part)
        if text:
            return text
    return ""


def _build_mime(payload: dict[str, Any], blobs: dict[str, bytes]) -> EmailMessage:
    msg = EmailMessage()
    msg["To"] = ", ".join(payload["to"])
    if payload.get("cc"):
        msg["Cc"] = ", ".join(payload["cc"])
    if payload.get("bcc"):
        msg["Bcc"] = ", ".join(payload["bcc"])
    msg["Subject"] = payload["subject"]
    msg.set_content(payload["body"])
    for filename, data in blobs.items():
        ctype, _ = mimetypes.guess_type(filename)
        maintype, subtype = (ctype.split("/", 1) if ctype else ("application", "octet-stream"))
        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=filename)
    return msg


# --------------------------------------------------------------------------- #
# Worker
# --------------------------------------------------------------------------- #
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


class GmailWorker:
    def __init__(self, cfg: MiniConfig, backend: GmailBackend) -> None:
        self.cfg = cfg
        self.guard = PathGuard(cfg)
        self.staging = StagingEngine(cfg, self.guard)
        self.backend = backend

    def handle(self, name: str, args: dict[str, Any]) -> types.CallToolResult:
        try:
            if name == "gmail_search":
                max_r = min(int(args.get("max_results", 10)), self.cfg.limits.max_gmail_results)
                msgs = self.backend.search(args["query"], max_r)
                return _ok({"query": args["query"], "messages": msgs})

            if name == "gmail_read_message":
                msg = self.backend.read_message(args["message_id"])
                return _ok(msg)

            if name == "gmail_stage_draft":
                rec = self.staging.stage_email_draft(
                    args["task_id"],
                    to=args["to"],
                    subject=args["subject"],
                    body=args["body"],
                    cc=args.get("cc") or [],
                    bcc=args.get("bcc") or [],
                    attachment_paths=args.get("attachment_paths") or [],
                )
                _, blobs = self.staging.load_verified_draft(args["task_id"], rec["staged_draft_id"])
                mime = _build_mime(rec["payload"], blobs)
                gmail_draft_id = self.backend.create_draft(mime)
                return _ok({
                    "staged_draft_id": rec["staged_draft_id"],
                    "gmail_draft_id": gmail_draft_id,
                    "payload_hash": rec["payload_hash"],
                    "attachments": rec["attachments"],
                })

            if name == "gmail_send_staged":
                expected = EmailArtifactHashes(
                    email_payload=args["email_payload_sha256"],
                    attachments=dict(args.get("attachment_hashes") or {}),
                )
                rec, blobs = self.staging.load_verified_draft(
                    args["task_id"], args["staged_draft_id"], expected=expected
                )
                mime = _build_mime(rec["payload"], blobs)
                res = self.backend.send_message(
                    mime, payload=rec["payload"], attachments=list(blobs.keys())
                )
                res["staged_draft_id"] = args["staged_draft_id"]
                res["email_payload_sha256"] = rec["payload_hash"]
                return _ok(res)

            return _err("UNKNOWN_TOOL", f"unknown gmail tool: {name}")
        except PathViolation as exc:
            return _err(exc.code, exc.detail or exc.path)
        except StagingError as exc:
            return _err(exc.code, exc.detail)
        except KeyError as exc:
            return _err("NOT_FOUND", str(exc))
        except Exception as exc:
            return _err("WORKER_ERROR", str(exc))


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


def _select_backend(cfg: MiniConfig) -> GmailBackend:
    env = os.environ
    use_mock = env.get("MINI_GMAIL_MOCK", "true").strip().lower() in {"1", "true", "yes", "on"}
    if use_mock:
        mock_dir = Path(env.get("MINI_GMAIL_MOCK_DIR") or (cfg.workspaces_dir / "_mock_gmail"))
        return MockGmailBackend(mock_dir)
    secrets_raw = env.get("MINI_GMAIL_CLIENT_SECRETS") or str(cfg.secrets_dir / "gmail_client_secret.json")
    token_raw = env.get("MINI_GMAIL_TOKEN") or str(cfg.secrets_dir / "gmail_token.json")
    return RealGmailBackend(
        resolve_path(secrets_raw, base=cfg.project_root, home=cfg.home),
        resolve_path(token_raw, base=cfg.project_root, home=cfg.home),
    )


def build_server(cfg: MiniConfig, backend: GmailBackend | None = None) -> Server:
    worker = GmailWorker(cfg, backend or _select_backend(cfg))

    async def on_list_tools(_ctx: Any, _params: Any) -> types.ListToolsResult:
        return types.ListToolsResult(tools=[
            types.Tool(name="gmail_search", description="Search mailbox", inputSchema={"type": "object"}),
            types.Tool(name="gmail_read_message", description="Read message", inputSchema={"type": "object"}),
            types.Tool(name="gmail_stage_draft", description="Stage immutable email draft", inputSchema={"type": "object"}),
            types.Tool(name="gmail_send_staged", description="Send verified staged draft", inputSchema={"type": "object"}),
        ])

    async def on_call_tool(_ctx: Any, params: types.CallToolRequestParams) -> types.CallToolResult:
        return worker.handle(params.name, dict(params.arguments or {}))

    return Server("mini-gmail", version="0.1.0", on_list_tools=on_list_tools, on_call_tool=on_call_tool)


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
