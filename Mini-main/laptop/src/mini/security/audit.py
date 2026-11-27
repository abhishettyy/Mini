"""Tamper-evident audit log: SQLite (WAL) + hash-chained ``logs/audit.jsonl``.

Chain rule (per entry *n*)::

    event_hash[n]      = sha256( rfc8785(entry[n] without "event_hash") )
    prev_event_hash[n] = sha256( rfc8785(entry[n-1]) )        # full previous entry
    prev_event_hash[1] = "0" * 64

Any edit, deletion, insertion or reordering of an entry breaks verification
from that point on. SQLite is the primary store; the JSONL mirror is
independently verifiable (``mini verify-audit``) and both are cross-checked.
"""

from __future__ import annotations

import json
import os
import re
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from mini.schemas import (
    GENESIS_HASH,
    AuditEvent,
    AuditEventType,
    RiskLevel,
    Verdict,
    iso_utc,
    new_id,
    sha256_hex,
    canonical_json,
)
from mini.security._db import SQLiteDB

Listener = Callable[[AuditEvent], None]

_SECRET_PATTERNS = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), "[REDACTED:PRIVATE_KEY]"),
    (re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]{12,}"), r"\1 [REDACTED]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED:AWS_KEY]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"), "[REDACTED:GITHUB_TOKEN]"),
    (re.compile(r"\bya29\.[A-Za-z0-9._-]{20,}"), "[REDACTED:GOOGLE_TOKEN]"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{20,}"), "[REDACTED:API_KEY]"),
    (re.compile(r"(?i)\b(password|passwd|secret|api[_-]?key|token)\s*[:=]\s*\S+"), r"\1=[REDACTED]"),
]


def redact(value: Any) -> Any:
    """Recursively redact obvious secret patterns from strings."""
    if isinstance(value, str):
        for pat, repl in _SECRET_PATTERNS:
            value = pat.sub(repl, value)
        return value
    if isinstance(value, dict):
        return {k: redact(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    if isinstance(value, float) and value != value:  # NaN is not JCS-serializable
        return None
    return value


@dataclass
class ChainReport:
    ok: bool
    count: int
    source: str
    first_bad_seq: int | None = None
    error: str | None = None
    head_hash: str | None = None
    details: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


def verify_events(events: list[dict[str, Any]], source: str) -> ChainReport:
    prev_link = GENESIS_HASH
    for i, raw in enumerate(events, start=1):
        try:
            ev = AuditEvent.model_validate(raw)
        except Exception as exc:  # schema tamper
            return ChainReport(False, i - 1, source, first_bad_seq=i, error=f"malformed entry: {exc}")
        if ev.seq != i:
            return ChainReport(False, i - 1, source, first_bad_seq=i,
                               error=f"sequence gap: expected {i}, found {ev.seq}")
        if ev.prev_event_hash != prev_link:
            return ChainReport(False, i - 1, source, first_bad_seq=i, error="prev_event_hash mismatch")
        # Recompute over the *raw* entry so unknown/extra fields are also caught.
        body = dict(raw)
        claimed = body.pop("event_hash", None)
        if sha256_hex(canonical_json(body)) != claimed or ev.compute_hash() != claimed:
            return ChainReport(False, i - 1, source, first_bad_seq=i, error="event_hash mismatch")
        prev_link = sha256_hex(canonical_json(raw))
    return ChainReport(True, len(events), source, head_hash=prev_link if events else GENESIS_HASH)


def verify_jsonl(path: str | Path) -> ChainReport:
    p = Path(path)
    if not p.exists():
        return ChainReport(True, 0, str(p))
    events = []
    for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            events.append(json.loads(line))
        except ValueError:
            return ChainReport(False, n - 1, str(p), first_bad_seq=n, error="invalid JSON line")
    return verify_events(events, str(p))


class AuditLogger:
    def __init__(self, db: SQLiteDB, jsonl_path: str | Path) -> None:
        self.db = db
        self.jsonl_path = Path(jsonl_path)
        self.jsonl_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._listeners: list[Listener] = []
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS audit_events (
                seq         INTEGER PRIMARY KEY,
                event_id    TEXT NOT NULL UNIQUE,
                ts          TEXT NOT NULL,
                event_type  TEXT NOT NULL,
                task_id     TEXT,
                event_hash  TEXT NOT NULL UNIQUE,
                entry_json  TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_audit_task ON audit_events(task_id);
            """
        )

    # ------------------------------------------------------------------ #
    def add_listener(self, fn: Listener) -> None:
        self._listeners.append(fn)

    def remove_listener(self, fn: Listener) -> None:
        if fn in self._listeners:
            self._listeners.remove(fn)

    def append(
        self,
        event_type: AuditEventType,
        *,
        task_id: str | None = None,
        call_id: str | None = None,
        contract_id: str | None = None,
        server: str | None = None,
        tool: str | None = None,
        risk_level: RiskLevel | None = None,
        verdict: Verdict | None = None,
        details: dict[str, Any] | None = None,
    ) -> AuditEvent:
        with self._lock:
            with self.db.tx() as c:
                row = c.execute("SELECT seq, entry_json FROM audit_events ORDER BY seq DESC LIMIT 1").fetchone()
                if row is None:
                    seq, prev_link = 1, GENESIS_HASH
                else:
                    seq = row["seq"] + 1
                    prev_link = sha256_hex(canonical_json(json.loads(row["entry_json"])))
                body = {
                    "seq": seq,
                    "event_id": new_id(),
                    "ts": iso_utc(),
                    "event_type": AuditEventType(event_type).value,
                    "task_id": task_id,
                    "call_id": call_id,
                    "contract_id": contract_id,
                    "server": server,
                    "tool": tool,
                    "risk_level": RiskLevel(risk_level).value if risk_level else None,
                    "verdict": Verdict(verdict).value if verdict else None,
                    "details": redact(details or {}),
                    "prev_event_hash": prev_link,
                }
                body["event_hash"] = sha256_hex(canonical_json(body))
                event = AuditEvent.model_validate(body)
                entry_json = json.dumps(event.model_dump(mode="json"), ensure_ascii=False,
                                        separators=(",", ":"))
                c.execute(
                    "INSERT INTO audit_events(seq, event_id, ts, event_type, task_id, event_hash, entry_json)"
                    " VALUES (?,?,?,?,?,?,?)",
                    (seq, event.event_id, event.ts, event.event_type.value, task_id, event.event_hash, entry_json),
                )
                # JSONL mirror written inside the DB transaction: if it fails, the row rolls back.
                with open(self.jsonl_path, "a", encoding="utf-8") as fh:
                    fh.write(entry_json + "\n")
                    fh.flush()
                    os.fsync(fh.fileno())
        for fn in list(self._listeners):
            try:
                fn(event)
            except Exception:
                pass
        return event

    # ------------------------------------------------------------------ #
    def events(self, *, since_seq: int = 0, limit: int | None = None,
               task_id: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT entry_json FROM audit_events WHERE seq > ?"
        params: list[Any] = [since_seq]
        if task_id:
            sql += " AND task_id = ?"
            params.append(task_id)
        sql += " ORDER BY seq ASC"
        if limit:
            sql += " LIMIT ?"
            params.append(limit)
        return [json.loads(r["entry_json"]) for r in self.db.query(sql, tuple(params))]

    def tail(self, n: int = 100) -> list[dict[str, Any]]:
        rows = self.db.query("SELECT entry_json FROM audit_events ORDER BY seq DESC LIMIT ?", (n,))
        return [json.loads(r["entry_json"]) for r in reversed(rows)]

    def verify_chain(self) -> ChainReport:
        """Verify SQLite chain, JSONL chain, and that both agree entry-for-entry."""
        db_events = self.events()
        db_rep = verify_events(db_events, "sqlite")
        js_rep = verify_jsonl(self.jsonl_path)
        if not db_rep.ok:
            return db_rep
        if not js_rep.ok:
            return js_rep
        if db_rep.count != js_rep.count or db_rep.head_hash != js_rep.head_hash:
            return ChainReport(False, min(db_rep.count, js_rep.count), "sqlite+jsonl",
                               error=f"stores diverge: sqlite={db_rep.count}/{db_rep.head_hash} "
                                     f"jsonl={js_rep.count}/{js_rep.head_hash}")
        return ChainReport(True, db_rep.count, "sqlite+jsonl", head_hash=db_rep.head_hash)
