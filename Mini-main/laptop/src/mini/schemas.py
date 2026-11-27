"""Pydantic v2 data models shared by every Mini laptop component.

Design rules
------------
* Every model that participates in hashing or signing is ``frozen`` and
  ``extra="forbid"`` so that no hidden or mutable field can change the bytes
  that were approved.
* All timestamps that are hashed/signed are stored as ISO-8601 UTC *strings*
  (millisecond precision, ``Z`` suffix) rather than ``datetime`` objects, so the
  RFC 8785 canonical form is byte-identical on every platform and in the
  browser.
* Risk levels are produced only by the Policy Engine. ``ToolCall`` deliberately
  has no risk field: the planner cannot supply one.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from typing import Annotated, Any, Literal

import rfc8785
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

__all__ = [
    "CONTRACT_VERSION",
    "GENESIS_HASH",
    "ActionType",
    "ApprovalContract",
    "ApprovalDecision",
    "ApprovalRecord",
    "AttachmentEvidence",
    "AuditEvent",
    "AuditEventType",
    "ContractStatus",
    "DeleteArtifactHashes",
    "EmailArtifactHashes",
    "EmailEvidence",
    "Evidence",
    "FileArtifactHashes",
    "FileDeleteEvidence",
    "FileDiffEvidence",
    "GitArtifactHashes",
    "GitCommitEvidence",
    "PolicyDecision",
    "ProxyResult",
    "ProxyStatus",
    "RiskLevel",
    "SignedApproval",
    "ToolCall",
    "TrustedDevice",
    "Verdict",
    "canonical_json",
    "compute_params_hash",
    "iso_utc",
    "new_id",
    "parse_iso",
    "sha256_hex",
    "sha256_tagged",
    "utcnow",
]

CONTRACT_VERSION: Literal["1.0"] = "1.0"
SHA256_PREFIX = "sha256:"
GENESIS_HASH = "0" * 64

_HEX64 = r"^[0-9a-f]{64}$"
_TAGGED_SHA256 = r"^sha256:[0-9a-f]{64}$"
_GIT_OID = r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$"


# --------------------------------------------------------------------------- #
# Canonicalization / hashing / time helpers
# --------------------------------------------------------------------------- #
def canonical_json(obj: Any) -> bytes:
    """RFC 8785 (JCS) canonical UTF-8 bytes. Raises on NaN/Inf, non-str keys,
    and integers outside the I-JSON safe range."""
    return rfc8785.dumps(obj)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_tagged(data: bytes) -> str:
    """``sha256:<hex>`` form used in artifact hash maps."""
    return SHA256_PREFIX + sha256_hex(data)


def compute_params_hash(server: str, tool: str, canonical_args: dict[str, Any]) -> str:
    """SHA-256 (hex) over the canonicalized ``{server, tool, arguments}`` triple.

    Binding server+tool (not just the arguments) means an approval for one tool
    can never be replayed against another tool with identical arguments.
    """
    return sha256_hex(
        canonical_json({"server": server, "tool": tool, "arguments": canonical_args})
    )


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso_utc(dt: datetime | None = None) -> str:
    """``2026-11-26T17:22:50.123Z`` (always UTC, millisecond precision)."""
    dt = dt or utcnow()
    if dt.tzinfo is None:
        raise ValueError("naive datetime not allowed; use timezone-aware UTC")
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_iso(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError(f"timestamp without timezone: {value!r}")
    return dt.astimezone(timezone.utc)


def new_id() -> str:
    return str(uuid.uuid4())


# --------------------------------------------------------------------------- #
# Enumerations
# --------------------------------------------------------------------------- #
class RiskLevel(StrEnum):
    L0 = "L0"  # read-only: auto-execute after allow/deny validation
    L1 = "L1"  # reversible: auto-execute inside per-task staging / drafts only
    L2 = "L2"  # sensitive/external: Ed25519-signed approval contract required
    L3 = "L3"  # destructive: signed contract with confirm_destructive=true

    @property
    def rank(self) -> int:
        return int(self.value[1])

    @classmethod
    def max(cls, *levels: RiskLevel) -> RiskLevel:
        return max(levels, key=lambda lvl: lvl.rank)

    @property
    def requires_approval(self) -> bool:
        return self.rank >= 2


class Verdict(StrEnum):
    ALLOW = "ALLOW"                        # L0
    STAGE = "STAGE"                        # L1
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"  # L2 / L3
    DENY = "DENY"                          # policy / boundary violation


class ActionType(StrEnum):
    FS_COMMIT_STAGED = "filesystem.commit_staged"
    FS_DELETE_FILE = "filesystem.delete_file"
    GMAIL_SEND_STAGED = "gmail.send_staged"
    GIT_COMMIT_PUSH = "git.commit_and_push"


class ContractStatus(StrEnum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"    # signature verified, nonce consumed, executing
    EXECUTED = "EXECUTED"
    FAILED = "FAILED"        # approved but execution aborted (e.g. TOCTOU)
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"      # kill switch

    @property
    def terminal(self) -> bool:
        return self is not ContractStatus.PENDING


class AuditEventType(StrEnum):
    DAEMON_STARTED = "DAEMON_STARTED"
    WORKER_STARTED = "WORKER_STARTED"
    WORKER_STOPPED = "WORKER_STOPPED"
    TOOL_CALL_RECEIVED = "TOOL_CALL_RECEIVED"
    POLICY_DECISION = "POLICY_DECISION"
    SECURITY_VIOLATION = "SECURITY_VIOLATION"
    STAGED = "STAGED"
    CONTRACT_ISSUED = "CONTRACT_ISSUED"
    SIGNATURE_VERIFIED = "SIGNATURE_VERIFIED"
    SIGNATURE_REJECTED = "SIGNATURE_REJECTED"
    NONCE_REPLAY_BLOCKED = "NONCE_REPLAY_BLOCKED"
    CONTRACT_REJECTED = "CONTRACT_REJECTED"
    CONTRACT_EXPIRED = "CONTRACT_EXPIRED"
    CONTRACT_REVOKED = "CONTRACT_REVOKED"
    APPROVAL_PENDING = "APPROVAL_PENDING"
    TOCTOU_VIOLATION = "TOCTOU_VIOLATION"
    EXECUTION_STARTED = "EXECUTION_STARTED"
    EXECUTION_SUCCEEDED = "EXECUTION_SUCCEEDED"
    EXECUTION_FAILED = "EXECUTION_FAILED"
    KILL_SWITCH_TRIGGERED = "KILL_SWITCH_TRIGGERED"
    KILL_SWITCH_RESET = "KILL_SWITCH_RESET"


class ProxyStatus(StrEnum):
    OK = "OK"
    DENIED = "DENIED"
    APPROVAL_PENDING = "APPROVAL_PENDING"
    REJECTED = "REJECTED"
    FAILED = "FAILED"
    PAUSED = "PAUSED"  # kill switch engaged


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


# --------------------------------------------------------------------------- #
# Tool call & policy decision
# --------------------------------------------------------------------------- #
class ToolCall(_Frozen):
    """A raw, *untrusted* tool invocation received from OpenClaw."""

    call_id: str = Field(default_factory=new_id)
    server: str = Field(min_length=1, max_length=64)
    tool: str = Field(min_length=1, max_length=128, pattern=r"^[a-z][a-z0-9_]*$")
    arguments: dict[str, Any] = Field(default_factory=dict)
    received_at: str = Field(default_factory=iso_utc)
    session_id: str | None = None

    @property
    def task_id(self) -> str | None:
        tid = self.arguments.get("task_id")
        return tid if isinstance(tid, str) else None


class PolicyDecision(_Frozen):
    """Deterministic output of the Policy Engine for one ``ToolCall``."""

    call_id: str
    server: str
    tool: str
    task_id: str | None = None
    verdict: Verdict
    risk_level: RiskLevel
    action_type: ActionType | None = None
    canonical_args: dict[str, Any] = Field(default_factory=dict)
    params_hash_sha256: str = Field(pattern=_HEX64)
    reasons: list[str] = Field(default_factory=list)
    matched_rules: list[str] = Field(default_factory=list)
    violations: list[str] = Field(default_factory=list)  # e.g. "PATH_DENYLIST:.env"

    @property
    def executable_without_approval(self) -> bool:
        return self.verdict in (Verdict.ALLOW, Verdict.STAGE)

    @model_validator(mode="after")
    def _consistency(self) -> PolicyDecision:
        if self.verdict is Verdict.DENY and not (self.violations or self.reasons):
            raise ValueError("DENY decisions must carry a reason or violation")
        if self.verdict is Verdict.REQUIRE_APPROVAL:
            if not self.risk_level.requires_approval:
                raise ValueError("REQUIRE_APPROVAL requires risk L2/L3")
            if self.action_type is None:
                raise ValueError("REQUIRE_APPROVAL requires an action_type")
        return self


# --------------------------------------------------------------------------- #
# Evidence (what the human sees before signing)
# --------------------------------------------------------------------------- #
class FileDiffEvidence(_Frozen):
    kind: Literal["file_diff"] = "file_diff"
    target_path: str
    destination_exists: bool
    destination_before_sha256: str | None = Field(default=None, pattern=_TAGGED_SHA256)
    staged_blob_sha256: str = Field(pattern=_TAGGED_SHA256)
    size_before: int | None = None
    size_after: int
    unified_diff: str
    diff_truncated: bool = False


class FileDeleteEvidence(_Frozen):
    kind: Literal["file_delete"] = "file_delete"
    target_path: str
    target_sha256: str = Field(pattern=_TAGGED_SHA256)
    size_bytes: int
    preview: str = ""


class AttachmentEvidence(_Frozen):
    filename: str
    path: str
    sha256: str = Field(pattern=_TAGGED_SHA256)
    size_bytes: int


class EmailEvidence(_Frozen):
    kind: Literal["email"] = "email"
    staged_draft_id: str
    gmail_draft_id: str | None = None
    to: list[str]
    cc: list[str] = Field(default_factory=list)
    bcc: list[str] = Field(default_factory=list)
    subject: str
    body: str
    attachments: list[AttachmentEvidence] = Field(default_factory=list)
    email_payload_sha256: str = Field(pattern=_TAGGED_SHA256)


class GitCommitEvidence(_Frozen):
    """What the human reviews before signing a git commit + push."""

    kind: Literal["git_commit"] = "git_commit"
    staged_commit_id: str
    repo_name: str
    repo_path: str
    branch: str
    remote: str
    remote_url: str
    commit_message: str
    files: list[str]
    unified_diff: str
    diff_truncated: bool = False
    diff_sha256: str = Field(pattern=_TAGGED_SHA256)
    staged_tree: str = Field(pattern=_GIT_OID)
    escalated_paths: list[str] = Field(default_factory=list)


Evidence = Annotated[
    FileDiffEvidence | FileDeleteEvidence | EmailEvidence | GitCommitEvidence,
    Field(discriminator="kind"),
]


# --------------------------------------------------------------------------- #
# Approval contracts
# --------------------------------------------------------------------------- #
class FileArtifactHashes(_Frozen):
    staged_blob: str = Field(pattern=_TAGGED_SHA256)
    destination_before: str | None = Field(default=None, pattern=_TAGGED_SHA256)


class DeleteArtifactHashes(_Frozen):
    target_before: str = Field(pattern=_TAGGED_SHA256)


class EmailArtifactHashes(_Frozen):
    email_payload: str = Field(pattern=_TAGGED_SHA256)
    attachments: dict[str, str] = Field(default_factory=dict)

    @field_validator("attachments")
    @classmethod
    def _tagged(cls, v: dict[str, str]) -> dict[str, str]:
        for name, digest in v.items():
            if not (digest.startswith(SHA256_PREFIX) and len(digest) == 71):
                raise ValueError(f"attachment {name!r} hash must be sha256:<hex>")
        return v


class GitArtifactHashes(_Frozen):
    """Everything a git commit+push depends on, frozen into the signed bytes.

    ``diff_sha256`` = sha256 of ``git diff --cached --binary --full-index``;
    ``staged_tree`` = ``git write-tree`` of the index; ``proposal_sha256`` =
    sha256 of the RFC 8785 proposal record stored in task staging.
    """

    repo_path: str
    branch: str
    remote: str
    remote_url: str
    commit_message: str
    files: list[str]
    diff_sha256: str = Field(pattern=_TAGGED_SHA256)
    staged_tree: str = Field(pattern=_GIT_OID)
    proposal_sha256: str = Field(pattern=_TAGGED_SHA256)


ArtifactHashes = FileArtifactHashes | DeleteArtifactHashes | EmailArtifactHashes | GitArtifactHashes


class ApprovalContract(_Frozen):
    """The exact payload the mobile device signs (RFC 8785 bytes, Ed25519).

    ``confirm_destructive`` is issued as ``False``. For L3 actions the human
    must explicitly flip it to ``True`` on the device; the signature then
    covers the flipped value and the verifier requires it.
    """

    contract_version: Literal["1.0"] = CONTRACT_VERSION
    contract_id: str = Field(default_factory=new_id)
    task_id: str = Field(min_length=1, max_length=128)
    action_type: ActionType
    risk_level: Literal[RiskLevel.L2, RiskLevel.L3]
    target: str | list[str]
    params_hash_sha256: str = Field(pattern=_HEX64)
    artifact_hashes: ArtifactHashes
    confirm_destructive: bool = False
    nonce: str = Field(default_factory=lambda: str(uuid.uuid4()))
    issued_at: str
    expires_at: str

    @field_validator("issued_at", "expires_at")
    @classmethod
    def _iso(cls, v: str) -> str:
        parse_iso(v)
        return v

    @field_validator("nonce")
    @classmethod
    def _uuid4(cls, v: str) -> str:
        if uuid.UUID(v).version != 4:
            raise ValueError("nonce must be a UUIDv4")
        return v

    @model_validator(mode="after")
    def _window(self) -> ApprovalContract:
        if parse_iso(self.expires_at) <= parse_iso(self.issued_at):
            raise ValueError("expires_at must be after issued_at")
        return self

    @classmethod
    def issue(
        cls,
        *,
        task_id: str,
        action_type: ActionType,
        risk_level: RiskLevel,
        target: str | list[str],
        params_hash_sha256: str,
        artifact_hashes: ArtifactHashes,
        ttl_seconds: int = 300,
        now: datetime | None = None,
    ) -> ApprovalContract:
        now = now or utcnow()
        return cls(
            task_id=task_id,
            action_type=action_type,
            risk_level=risk_level,
            target=target,
            params_hash_sha256=params_hash_sha256,
            artifact_hashes=artifact_hashes,
            issued_at=iso_utc(now),
            expires_at=iso_utc(now + timedelta(seconds=ttl_seconds)),
        )

    def payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    def canonical_bytes(self) -> bytes:
        """The exact bytes that are signed / verified."""
        return canonical_json(self.payload())

    def contract_hash(self) -> str:
        return sha256_tagged(self.canonical_bytes())

    def is_expired(self, now: datetime | None = None) -> bool:
        return (now or utcnow()) >= parse_iso(self.expires_at)


ApprovalDecision = Literal["approve", "reject"]


class SignedApproval(_Frozen):
    """Response from the mobile device (or /mobile-mock)."""

    contract_id: str
    decision: ApprovalDecision
    device_id: str
    signature_b64: str | None = None       # Ed25519 over canonical contract bytes
    confirm_destructive: bool = False      # value the signature was made over
    reason: str | None = None

    @model_validator(mode="after")
    def _sig_required(self) -> SignedApproval:
        if self.decision == "approve" and not self.signature_b64:
            raise ValueError("approve decisions require signature_b64")
        return self


class ApprovalRecord(BaseModel):
    """Mutable queue entry persisted in SQLite and rendered by the UIs."""

    model_config = ConfigDict(extra="forbid")

    contract: ApprovalContract
    evidence: Evidence
    status: ContractStatus = ContractStatus.PENDING
    call_id: str
    server: str
    tool: str
    canonical_args: dict[str, Any]
    created_at: str = Field(default_factory=iso_utc)
    decided_at: str | None = None
    decided_by: str | None = None
    outcome: dict[str, Any] | None = None


class TrustedDevice(_Frozen):
    device_id: str
    label: str = ""
    public_key_b64: str  # raw 32-byte Ed25519 public key, base64
    added_at: str = Field(default_factory=iso_utc)


# --------------------------------------------------------------------------- #
# Audit
# --------------------------------------------------------------------------- #
class AuditEvent(_Frozen):
    """One hash-chained audit entry.

    ``prev_event_hash = sha256(rfc8785(previous full entry))``
    ``event_hash      = sha256(rfc8785(this entry without event_hash))``
    """

    seq: int = Field(ge=1)
    event_id: str = Field(default_factory=new_id)
    ts: str = Field(default_factory=iso_utc)
    event_type: AuditEventType
    task_id: str | None = None
    call_id: str | None = None
    contract_id: str | None = None
    server: str | None = None
    tool: str | None = None
    risk_level: RiskLevel | None = None
    verdict: Verdict | None = None
    details: dict[str, Any] = Field(default_factory=dict)
    prev_event_hash: str = Field(pattern=_HEX64)
    event_hash: str = Field(pattern=_HEX64)

    def body_without_hash(self) -> dict[str, Any]:
        data = self.model_dump(mode="json")
        data.pop("event_hash")
        return data

    def compute_hash(self) -> str:
        return sha256_hex(canonical_json(self.body_without_hash()))

    def chain_link(self) -> str:
        """Value the *next* entry must carry as ``prev_event_hash``."""
        return sha256_hex(canonical_json(self.model_dump(mode="json")))


# --------------------------------------------------------------------------- #
# Proxy → OpenClaw envelope
# --------------------------------------------------------------------------- #
class ProxyResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: ProxyStatus
    call_id: str
    tool: str
    risk_level: RiskLevel | None = None
    verdict: Verdict | None = None
    contract_id: str | None = None
    result: Any = None
    error: str | None = None
    reasons: list[str] = Field(default_factory=list)
