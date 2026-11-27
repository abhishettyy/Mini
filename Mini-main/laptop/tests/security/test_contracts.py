"""Approval contracts: RFC 8785 determinism, Ed25519 verification, TTL,
nonce replay (incl. concurrent), L3 confirmation, persistent queue."""

from __future__ import annotations

import json
import threading
import uuid
from datetime import timedelta

import pytest

from mini.schemas import (
    ActionType,
    ApprovalContract,
    ApprovalRecord,
    ContractStatus,
    FileArtifactHashes,
    FileDiffEvidence,
    RiskLevel,
    SignedApproval,
    TrustedDevice,
    canonical_json,
    parse_iso,
    utcnow,
)
from mini.security._db import SQLiteDB
from mini.security.contracts import (
    ContractError,
    ContractStore,
    ContractVerifier,
    NonceStore,
    ReplayError,
    TrustedDeviceStore,
    b64e,
    generate_keypair,
    sign_contract,
    signing_bytes,
)

H = "sha256:" + "ab" * 32


@pytest.fixture
def env(tmp_path):
    db = SQLiteDB(tmp_path / "state" / "mini.db")
    devices = TrustedDeviceStore(tmp_path / ".mini" / "trusted_devices.json")
    priv, pub = generate_keypair()
    devices.add(TrustedDevice(device_id="phone-1", label="Pixel", public_key_b64=pub))
    nonces = NonceStore(db)
    yield type("Env", (), dict(db=db, devices=devices, priv=priv, nonces=nonces,
                               verifier=ContractVerifier(devices, nonces), store=ContractStore(db)))
    db.close()


def make_contract(risk=RiskLevel.L2, ttl=300, now=None, action=ActionType.FS_COMMIT_STAGED):
    return ApprovalContract.issue(
        task_id="task-1", action_type=action, risk_level=risk, target="/proj/README.md",
        params_hash_sha256="c" * 64,
        artifact_hashes=FileArtifactHashes(staged_blob=H, destination_before=None),
        ttl_seconds=ttl, now=now,
    )


def approve(env, contract, confirm=False, device="phone-1", priv=None):
    return SignedApproval(contract_id=contract.contract_id, decision="approve", device_id=device,
                          signature_b64=sign_contract(priv or env.priv, contract, confirm),
                          confirm_destructive=confirm)


# --------------------------------------------------------------------------- #
# RFC 8785
# --------------------------------------------------------------------------- #
def test_rfc8785_canonical_form():
    obj = {"b": 1, "a": [1.0, "é", {"z": None, "y": True}], "c": 1e21}
    assert canonical_json(obj) == '{"a":[1,"é",{"y":true,"z":null}],"b":1,"c":1e+21}'.encode("utf-8")


def test_rfc8785_key_order_independent():
    assert canonical_json({"x": 1, "y": {"b": 2, "a": 1}}) == canonical_json({"y": {"a": 1, "b": 2}, "x": 1})


def test_contract_bytes_stable_across_roundtrip():
    c = make_contract()
    b = c.canonical_bytes()
    assert ApprovalContract.model_validate(json.loads(b)).canonical_bytes() == b
    shuffled = dict(reversed(list(json.loads(b).items())))
    assert ApprovalContract.model_validate(shuffled).canonical_bytes() == b
    assert c.canonical_bytes() == b  # repeatable


def test_rfc8785_rejects_nan():
    with pytest.raises(Exception):
        canonical_json({"x": float("nan")})


def test_contract_fields_and_ttl():
    c = make_contract()
    assert c.contract_version == "1.0" and uuid.UUID(c.nonce).version == 4
    assert (parse_iso(c.expires_at) - parse_iso(c.issued_at)) == timedelta(seconds=300)


# --------------------------------------------------------------------------- #
# Signature verification
# --------------------------------------------------------------------------- #
def test_valid_signature_verifies_and_consumes_nonce(env):
    c = make_contract()
    v = env.verifier.verify(c, approve(env, c))
    assert v.device_id == "phone-1" and env.nonces.is_consumed(c.nonce)


@pytest.mark.parametrize("field,value", [
    ("target", "/proj/OTHER.md"),
    ("params_hash_sha256", "d" * 64),
    ("risk_level", RiskLevel.L3),
    ("expires_at", "2099-01-01T00:00:00.000Z"),
    ("artifact_hashes", FileArtifactHashes(staged_blob="sha256:" + "ef" * 32)),
])
def test_any_field_tamper_invalidates_signature(env, field, value):
    c = make_contract()
    sa = approve(env, c)
    tampered = c.model_copy(update={field: value})
    with pytest.raises(ContractError) as ei:
        env.verifier.verify(tampered, sa)
    assert ei.value.code in {"INVALID_SIGNATURE", "CONFIRM_DESTRUCTIVE_REQUIRED"}
    assert not env.nonces.is_consumed(c.nonce)


def test_untrusted_device_rejected(env):
    c = make_contract()
    with pytest.raises(ContractError) as ei:
        env.verifier.verify(c, approve(env, c, device="attacker-phone"))
    assert ei.value.code == "UNTRUSTED_DEVICE"


def test_signature_from_unpinned_key_rejected(env):
    attacker, _ = generate_keypair()
    c = make_contract()
    with pytest.raises(ContractError) as ei:
        env.verifier.verify(c, approve(env, c, priv=attacker))
    assert ei.value.code == "INVALID_SIGNATURE"


@pytest.mark.parametrize("sig", ["not-base64!!", b64e(b"\x00" * 10), b64e(b"\x00" * 64)])
def test_malformed_or_zero_signatures(env, sig):
    c = make_contract()
    sa = SignedApproval(contract_id=c.contract_id, decision="approve", device_id="phone-1", signature_b64=sig)
    with pytest.raises(ContractError) as ei:
        env.verifier.verify(c, sa)
    assert ei.value.code in {"MALFORMED_SIGNATURE", "INVALID_SIGNATURE"}


def test_approval_for_other_contract_rejected(env):
    c1, c2 = make_contract(), make_contract()
    sa = approve(env, c1)
    with pytest.raises(ContractError) as ei:
        env.verifier.verify(c2, sa)
    assert ei.value.code == "CONTRACT_MISMATCH"


def test_reject_decision_cannot_execute(env):
    c = make_contract()
    with pytest.raises(ContractError) as ei:
        env.verifier.verify(c, SignedApproval(contract_id=c.contract_id, decision="reject", device_id="phone-1"))
    assert ei.value.code == "NOT_APPROVED"


def test_approve_requires_signature_field():
    with pytest.raises(ValueError):
        SignedApproval(contract_id="x", decision="approve", device_id="phone-1")


# --------------------------------------------------------------------------- #
# TTL
# --------------------------------------------------------------------------- #
def test_expired_contract_rejected(env):
    c = make_contract(ttl=60, now=utcnow() - timedelta(minutes=5))
    with pytest.raises(ContractError) as ei:
        env.verifier.verify(c, approve(env, c))
    assert ei.value.code == "CONTRACT_EXPIRED"
    assert not env.nonces.is_consumed(c.nonce)


def test_expiry_boundary_is_exclusive(env):
    c = make_contract(ttl=60)
    with pytest.raises(ContractError) as ei:
        env.verifier.verify(c, approve(env, c), now=parse_iso(c.expires_at))
    assert ei.value.code == "CONTRACT_EXPIRED"


# --------------------------------------------------------------------------- #
# Replay
# --------------------------------------------------------------------------- #
def test_nonce_replay_blocked(env):
    c = make_contract()
    sa = approve(env, c)
    env.verifier.verify(c, sa)
    with pytest.raises(ReplayError):
        env.verifier.verify(c, sa)


def test_replay_blocked_across_restart(env, tmp_path):
    c = make_contract()
    sa = approve(env, c)
    env.verifier.verify(c, sa)
    db2 = SQLiteDB(tmp_path / "state" / "mini.db")  # fresh connection = daemon restart
    try:
        with pytest.raises(ReplayError):
            ContractVerifier(env.devices, NonceStore(db2)).verify(c, sa)
    finally:
        db2.close()


def test_concurrent_replay_exactly_one_wins(env):
    c = make_contract()
    sa = approve(env, c)
    results: list[str] = []
    barrier = threading.Barrier(12)

    def worker():
        barrier.wait()
        try:
            env.verifier.verify(c, sa)
            results.append("ok")
        except ReplayError:
            results.append("replay")

    threads = [threading.Thread(target=worker) for _ in range(12)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert results.count("ok") == 1 and results.count("replay") == 11


def test_invalid_signature_does_not_burn_nonce(env):
    attacker, _ = generate_keypair()
    c = make_contract()
    with pytest.raises(ContractError):
        env.verifier.verify(c, approve(env, c, priv=attacker))
    env.verifier.verify(c, approve(env, c))  # legitimate approval still works


# --------------------------------------------------------------------------- #
# L3 confirm_destructive
# --------------------------------------------------------------------------- #
def test_l3_requires_confirm_destructive(env):
    c = make_contract(risk=RiskLevel.L3, action=ActionType.FS_DELETE_FILE)
    with pytest.raises(ContractError) as ei:
        env.verifier.verify(c, approve(env, c, confirm=False))
    assert ei.value.code == "CONFIRM_DESTRUCTIVE_REQUIRED"


def test_l3_confirm_flag_must_be_inside_signature(env):
    c = make_contract(risk=RiskLevel.L3, action=ActionType.FS_DELETE_FILE)
    forged = SignedApproval(contract_id=c.contract_id, decision="approve", device_id="phone-1",
                            signature_b64=sign_contract(env.priv, c, False), confirm_destructive=True)
    with pytest.raises(ContractError) as ei:
        env.verifier.verify(c, forged)
    assert ei.value.code == "INVALID_SIGNATURE"


def test_l3_with_signed_confirmation_verifies(env):
    c = make_contract(risk=RiskLevel.L3, action=ActionType.FS_DELETE_FILE)
    v = env.verifier.verify(c, approve(env, c, confirm=True))
    assert v.contract.confirm_destructive is True
    assert signing_bytes(c, True) != c.canonical_bytes()


# --------------------------------------------------------------------------- #
# Persistent queue
# --------------------------------------------------------------------------- #
def _record(c):
    return ApprovalRecord(
        contract=c, call_id="call-1", server="filesystem", tool="fs_commit_staged",
        canonical_args={"task_id": "task-1", "target_path": "/proj/README.md"},
        evidence=FileDiffEvidence(target_path="/proj/README.md", destination_exists=False,
                                  staged_blob_sha256=H, size_after=3, unified_diff="+abc"),
    )


def test_contract_store_cas_and_revoke(env):
    c1, c2, c3 = make_contract(), make_contract(), make_contract()
    for c in (c1, c2, c3):
        env.store.put(_record(c))
    env.store.transition(c1.contract_id, ContractStatus.APPROVED, decided_by="phone-1")
    with pytest.raises(ContractError) as ei:  # cannot approve twice
        env.store.transition(c1.contract_id, ContractStatus.APPROVED)
    assert ei.value.code == "BAD_STATE"
    revoked = env.store.revoke_all_pending()
    assert set(revoked) == {c2.contract_id, c3.contract_id}
    assert env.store.get(c2.contract_id).status is ContractStatus.REVOKED
    assert env.store.get(c1.contract_id).status is ContractStatus.APPROVED
    assert env.store.list(ContractStatus.PENDING) == []


def test_contract_store_expire_stale(env):
    old = make_contract(ttl=1, now=utcnow() - timedelta(minutes=1))
    env.store.put(_record(old))
    assert env.store.expire_stale() == [old.contract_id]
    assert env.store.get(old.contract_id).status is ContractStatus.EXPIRED
