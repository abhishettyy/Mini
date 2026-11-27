"""Approval contracts: RFC 8785 canonicalization, Ed25519 signing/verification,
TTL enforcement, pinned trusted devices, SQLite nonce replay store and the
persistent approval queue.

Verification order (``ContractVerifier.verify``):

1. contract_id / decision sanity;
2. device is pinned in ``trusted_devices.json``;
3. Ed25519 signature over ``rfc8785(contract with confirm_destructive=<signed value>)``;
4. L3 requires ``confirm_destructive=True`` inside the signed bytes;
5. TTL (``now >= expires_at`` is rejected);
6. nonce atomically INSERTed into a UNIQUE column *before* execution.

Signature is checked before the nonce is consumed, so forged approvals cannot
burn a legitimate contract's nonce.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from mini.schemas import (
    ApprovalContract,
    ApprovalRecord,
    ContractStatus,
    RiskLevel,
    SignedApproval,
    TrustedDevice,
    canonical_json,
    iso_utc,
    utcnow,
)
from mini.security._db import SQLiteDB

canonicalize = canonical_json  # public alias: RFC 8785 bytes


class ContractError(Exception):
    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}")


class ReplayError(ContractError):
    pass


# --------------------------------------------------------------------------- #
# Keys
# --------------------------------------------------------------------------- #
def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    try:
        return base64.b64decode(data, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ContractError("MALFORMED_SIGNATURE", "invalid base64") from exc


def generate_keypair() -> tuple[Ed25519PrivateKey, str]:
    priv = Ed25519PrivateKey.generate()
    return priv, public_key_b64(priv.public_key())


def public_key_b64(pub: Ed25519PublicKey) -> str:
    return b64e(pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))


def private_key_to_b64(priv: Ed25519PrivateKey) -> str:
    return b64e(priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                   serialization.NoEncryption()))


def private_key_from_b64(data: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(base64.b64decode(data))


def signing_bytes(contract: ApprovalContract, confirm_destructive: bool | None = None) -> bytes:
    """Exact bytes a device signs. ``confirm_destructive`` overrides the issued value."""
    if confirm_destructive is not None and confirm_destructive != contract.confirm_destructive:
        contract = contract.model_copy(update={"confirm_destructive": confirm_destructive})
    return contract.canonical_bytes()


def sign_contract(priv: Ed25519PrivateKey, contract: ApprovalContract,
                  confirm_destructive: bool = False) -> str:
    return b64e(priv.sign(signing_bytes(contract, confirm_destructive)))


# --------------------------------------------------------------------------- #
# Trusted devices (pinned public keys)
# --------------------------------------------------------------------------- #
class TrustedDeviceStore:
    """``~/.mini/trusted_devices.json`` = ``{"devices": [TrustedDevice, ...]}``"""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def load(self) -> dict[str, TrustedDevice]:
        if not self.path.exists():
            return {}
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        return {d["device_id"]: TrustedDevice(**d) for d in raw.get("devices", [])}

    def add(self, device: TrustedDevice) -> None:
        devices = self.load()
        devices[device.device_id] = device
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"devices": [d.model_dump() for d in devices.values()]}, indent=2),
                       encoding="utf-8")
        os.replace(tmp, self.path)

    def public_key(self, device_id: str) -> Ed25519PublicKey | None:
        dev = self.load().get(device_id)
        if dev is None:
            return None
        raw = base64.b64decode(dev.public_key_b64)
        if len(raw) != 32:
            raise ContractError("BAD_TRUSTED_KEY", device_id)
        return Ed25519PublicKey.from_public_bytes(raw)


# --------------------------------------------------------------------------- #
# Nonce replay store
# --------------------------------------------------------------------------- #
class NonceStore:
    def __init__(self, db: SQLiteDB) -> None:
        self.db = db
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS consumed_nonces (
                nonce        TEXT NOT NULL UNIQUE,
                contract_id  TEXT NOT NULL,
                consumed_at  TEXT NOT NULL
            );
            """
        )

    def consume(self, nonce: str, contract_id: str) -> None:
        """Atomic single-use insert. Raises ``ReplayError`` if already consumed."""
        try:
            with self.db.tx() as c:
                c.execute("INSERT INTO consumed_nonces(nonce, contract_id, consumed_at) VALUES (?,?,?)",
                          (nonce, contract_id, iso_utc()))
        except sqlite3.IntegrityError as exc:
            raise ReplayError("NONCE_REPLAY", f"nonce {nonce} already consumed") from exc

    def is_consumed(self, nonce: str) -> bool:
        return bool(self.db.query("SELECT 1 FROM consumed_nonces WHERE nonce=?", (nonce,)))


# --------------------------------------------------------------------------- #
# Verifier
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class VerifiedApproval:
    contract: ApprovalContract  # with confirm_destructive as signed
    device_id: str
    verified_at: str


class ContractVerifier:
    def __init__(self, devices: TrustedDeviceStore, nonces: NonceStore) -> None:
        self.devices = devices
        self.nonces = nonces

    def verify_signature_only(self, contract: ApprovalContract, approval: SignedApproval) -> ApprovalContract:
        if approval.contract_id != contract.contract_id:
            raise ContractError("CONTRACT_MISMATCH", "approval is for a different contract")
        if approval.decision != "approve":
            raise ContractError("NOT_APPROVED", approval.decision)
        pub = self.devices.public_key(approval.device_id)
        if pub is None:
            raise ContractError("UNTRUSTED_DEVICE", approval.device_id)
        sig = b64d(approval.signature_b64 or "")
        if len(sig) != 64:
            raise ContractError("MALFORMED_SIGNATURE", f"expected 64 bytes, got {len(sig)}")
        signed = contract.model_copy(update={"confirm_destructive": approval.confirm_destructive})
        try:
            pub.verify(sig, signed.canonical_bytes())
        except InvalidSignature as exc:
            raise ContractError("INVALID_SIGNATURE", "Ed25519 verification failed") from exc
        if contract.risk_level is RiskLevel.L3 and not signed.confirm_destructive:
            raise ContractError("CONFIRM_DESTRUCTIVE_REQUIRED",
                                "L3 contracts must be signed with confirm_destructive=true")
        return signed

    def verify(self, contract: ApprovalContract, approval: SignedApproval,
               now: datetime | None = None) -> VerifiedApproval:
        signed = self.verify_signature_only(contract, approval)
        if contract.is_expired(now or utcnow()):
            raise ContractError("CONTRACT_EXPIRED", f"expired at {contract.expires_at}")
        self.nonces.consume(contract.nonce, contract.contract_id)  # BEFORE execution
        return VerifiedApproval(contract=signed, device_id=approval.device_id, verified_at=iso_utc())


# --------------------------------------------------------------------------- #
# Persistent approval queue
# --------------------------------------------------------------------------- #
class ContractStore:
    def __init__(self, db: SQLiteDB) -> None:
        self.db = db
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS contracts (
                contract_id  TEXT PRIMARY KEY,
                task_id      TEXT NOT NULL,
                status       TEXT NOT NULL,
                record_json  TEXT NOT NULL,
                created_at   TEXT NOT NULL,
                updated_at   TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_contracts_status ON contracts(status);
            """
        )

    def put(self, record: ApprovalRecord) -> None:
        now = iso_utc()
        with self.db.tx() as c:
            c.execute(
                "INSERT INTO contracts(contract_id, task_id, status, record_json, created_at, updated_at)"
                " VALUES (?,?,?,?,?,?)",
                (record.contract.contract_id, record.contract.task_id, record.status.value,
                 record.model_dump_json(), now, now),
            )

    def get(self, contract_id: str) -> ApprovalRecord | None:
        rows = self.db.query("SELECT record_json FROM contracts WHERE contract_id=?", (contract_id,))
        return ApprovalRecord.model_validate_json(rows[0]["record_json"]) if rows else None

    def list(self, status: ContractStatus | None = None, limit: int = 200) -> list[ApprovalRecord]:
        if status is None:
            rows = self.db.query("SELECT record_json FROM contracts ORDER BY created_at DESC LIMIT ?", (limit,))
        else:
            rows = self.db.query(
                "SELECT record_json FROM contracts WHERE status=? ORDER BY created_at DESC LIMIT ?",
                (status.value, limit))
        return [ApprovalRecord.model_validate_json(r["record_json"]) for r in rows]

    def transition(self, contract_id: str, new: ContractStatus, *,
                   expected: tuple[ContractStatus, ...] = (ContractStatus.PENDING,),
                   decided_by: str | None = None,
                   outcome: dict[str, Any] | None = None) -> ApprovalRecord:
        """Compare-and-set status change; raises if current status not in ``expected``."""
        with self.db.tx() as c:
            row = c.execute("SELECT record_json FROM contracts WHERE contract_id=?", (contract_id,)).fetchone()
            if row is None:
                raise ContractError("UNKNOWN_CONTRACT", contract_id)
            rec = ApprovalRecord.model_validate_json(row["record_json"])
            if rec.status not in expected:
                raise ContractError("BAD_STATE", f"{contract_id} is {rec.status}, expected {expected}")
            rec.status = new
            if new in (ContractStatus.APPROVED, ContractStatus.REJECTED, ContractStatus.REVOKED,
                       ContractStatus.EXPIRED):
                rec.decided_at = iso_utc()
                rec.decided_by = decided_by or rec.decided_by
            if outcome is not None:
                rec.outcome = outcome
            c.execute("UPDATE contracts SET status=?, record_json=?, updated_at=? WHERE contract_id=?",
                      (new.value, rec.model_dump_json(), iso_utc(), contract_id))
            return rec

    def revoke_all_pending(self, reason: str = "kill switch") -> list[str]:
        revoked: list[str] = []
        with self.db.tx() as c:
            rows = c.execute("SELECT contract_id, record_json FROM contracts WHERE status=?",
                             (ContractStatus.PENDING.value,)).fetchall()
            for r in rows:
                rec = ApprovalRecord.model_validate_json(r["record_json"])
                rec.status = ContractStatus.REVOKED
                rec.decided_at = iso_utc()
                rec.decided_by = "system"
                rec.outcome = {"revoked": reason}
                c.execute("UPDATE contracts SET status=?, record_json=?, updated_at=? WHERE contract_id=?",
                          (ContractStatus.REVOKED.value, rec.model_dump_json(), iso_utc(), r["contract_id"]))
                revoked.append(r["contract_id"])
        return revoked

    def expire_stale(self, now: datetime | None = None) -> list[str]:
        out = []
        for rec in self.list(ContractStatus.PENDING, limit=10_000):
            if rec.contract.is_expired(now):
                try:
                    self.transition(rec.contract.contract_id, ContractStatus.EXPIRED, decided_by="system")
                    out.append(rec.contract.contract_id)
                except ContractError:
                    pass
        return out
