"""Hash-chained audit log: append, verify, tamper/deletion/reorder detection, redaction."""

from __future__ import annotations

import json

import pytest

from mini.schemas import GENESIS_HASH, AuditEventType, RiskLevel, Verdict
from mini.security._db import SQLiteDB
from mini.security.audit import AuditLogger, verify_jsonl


@pytest.fixture
def audit(tmp_path):
    db = SQLiteDB(tmp_path / "state" / "mini.db")
    log = AuditLogger(db, tmp_path / "logs" / "audit.jsonl")
    yield log
    db.close()


def _fill(audit, n=5):
    for i in range(n):
        audit.append(AuditEventType.POLICY_DECISION, task_id="t1", tool="fs_read_file",
                     risk_level=RiskLevel.L0, verdict=Verdict.ALLOW, details={"i": i})


def test_chain_links_and_verifies(audit):
    _fill(audit)
    ev = audit.events()
    assert ev[0]["prev_event_hash"] == GENESIS_HASH
    assert [e["seq"] for e in ev] == [1, 2, 3, 4, 5]
    rep = audit.verify_chain()
    assert rep.ok and rep.count == 5


def _rewrite(path, fn):
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join(fn(lines)) + "\n", encoding="utf-8")


def test_jsonl_edit_detected(audit):
    _fill(audit)

    def edit(lines):
        e = json.loads(lines[2])
        e["verdict"] = "DENY"
        lines[2] = json.dumps(e)
        return lines

    _rewrite(audit.jsonl_path, edit)
    rep = verify_jsonl(audit.jsonl_path)
    assert not rep.ok and rep.first_bad_seq == 3
    assert not audit.verify_chain().ok


def test_jsonl_deletion_and_reorder_detected(audit):
    _fill(audit)
    _rewrite(audit.jsonl_path, lambda ls: ls[:1] + ls[2:])
    assert not verify_jsonl(audit.jsonl_path).ok
    _rewrite(audit.jsonl_path, lambda ls: list(reversed(ls)))
    assert not verify_jsonl(audit.jsonl_path).ok


def test_full_rehash_forgery_detected_by_divergence(audit):
    """An attacker recomputing every hash in the JSONL still diverges from SQLite."""
    _fill(audit, 3)
    _rewrite(audit.jsonl_path, lambda ls: ls[:2])  # truncation keeps a valid prefix chain
    assert verify_jsonl(audit.jsonl_path).ok
    rep = audit.verify_chain()
    assert not rep.ok and "diverge" in rep.error


def test_sqlite_tamper_detected(audit):
    _fill(audit, 3)
    row = audit.db.query("SELECT entry_json FROM audit_events WHERE seq=2")[0]
    e = json.loads(row["entry_json"])
    e["details"] = {"i": 999}
    with audit.db.tx() as c:
        c.execute("UPDATE audit_events SET entry_json=? WHERE seq=2", (json.dumps(e),))
    rep = audit.verify_chain()
    assert not rep.ok and rep.source == "sqlite" and rep.first_bad_seq == 2


def test_chain_continues_after_restart(audit, tmp_path):
    _fill(audit, 2)
    db2 = SQLiteDB(tmp_path / "state" / "mini.db")
    try:
        log2 = AuditLogger(db2, audit.jsonl_path)
        log2.append(AuditEventType.DAEMON_STARTED)
        assert log2.verify_chain().ok and log2.verify_chain().count == 3
    finally:
        db2.close()


def test_secrets_redacted_and_listeners_notified(audit):
    seen = []
    audit.add_listener(seen.append)
    audit.append(AuditEventType.TOOL_CALL_RECEIVED,
                 details={"auth": "Bearer abcdefghijklmnopqrstuvwxyz", "body": "password: hunter2",
                          "key": "-----BEGIN PRIVATE KEY-----\nMII\n-----END PRIVATE KEY-----"})
    d = seen[0].details
    assert "abcdefghijklmnop" not in json.dumps(d) and "hunter2" not in d["body"]
    assert d["key"] == "[REDACTED:PRIVATE_KEY]"
