"""Transactional staging, immutable content-addressed blobs, diffs, rollback
and TOCTOU re-verification.

Workspace layout (``workspaces/{task_id}/``)::

    staging/<root-label>/<rel_path>   mutable proposals written by fs_write_staged
    blobs/<sha256-hex>                immutable, read-only, content addressed
    drafts/<staged_draft_id>.json     immutable staged e-mail (RFC 8785 bytes)
    rollback/<stamp>-<name>           pre-commit / pre-delete backups
    rollback/manifest.jsonl           rollback index

Approval binds *hashes*, never paths into ``staging/``: execution always reads
from ``blobs/`` (re-hashed on read), so edits to ``staging/`` after approval
are ignored, and a changed live destination aborts the commit.
"""

from __future__ import annotations

import difflib
import json
import os
import shutil
import stat
import uuid
from pathlib import Path
from typing import Any

from mini.config import MiniConfig
from mini.schemas import (
    AttachmentEvidence,
    DeleteArtifactHashes,
    EmailArtifactHashes,
    EmailEvidence,
    FileArtifactHashes,
    FileDeleteEvidence,
    FileDiffEvidence,
    GitArtifactHashes,
    GitCommitEvidence,
    canonical_json,
    iso_utc,
    sha256_hex,
    sha256_tagged,
)
from mini.security.path_guard import PathGuard, PathViolation, is_within
from mini.security.policy_engine import OPAQUE_ID_RE, TASK_ID_RE


class StagingError(Exception):
    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}")


class TOCTOUError(StagingError):
    """Something changed between approval and execution. Execution aborted."""


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.mini-{uuid.uuid4().hex[:12]}.tmp")
    try:
        with open(tmp, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink(missing_ok=True)


def _make_readonly(path: Path) -> None:
    try:
        os.chmod(path, stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)
    except OSError:
        pass


def _file_hash(path: Path) -> str | None:
    if not path.exists():
        return None
    return sha256_tagged(path.read_bytes())


def _is_binary(data: bytes) -> bool:
    return b"\x00" in data[:8192]


def unified_diff(before: bytes, after: bytes, name: str, max_bytes: int) -> tuple[str, bool]:
    if _is_binary(before) or _is_binary(after):
        return f"Binary content: {len(before)} -> {len(after)} bytes\n", False
    a = before.decode("utf-8", errors="replace").splitlines(keepends=True)
    b = after.decode("utf-8", errors="replace").splitlines(keepends=True)
    text = "".join(difflib.unified_diff(a, b, fromfile=f"a/{name}", tofile=f"b/{name}"))
    if len(text.encode("utf-8")) > max_bytes:
        return text.encode("utf-8")[:max_bytes].decode("utf-8", errors="ignore") + "\n... [diff truncated]\n", True
    return text, False


class StagingEngine:
    def __init__(self, cfg: MiniConfig, guard: PathGuard | None = None) -> None:
        self.cfg = cfg
        self.guard = guard or PathGuard(cfg)
        self.base = Path(os.path.realpath(cfg.workspaces_dir))

    # ------------------------------------------------------------------ #
    # Workspace helpers
    # ------------------------------------------------------------------ #
    def task_dir(self, task_id: str) -> Path:
        if not isinstance(task_id, str) or not TASK_ID_RE.fullmatch(task_id):
            raise StagingError("INVALID_TASK_ID", repr(task_id))
        d = self.base / task_id
        for sub in ("staging", "blobs", "drafts", "rollback", "git"):
            (d / sub).mkdir(parents=True, exist_ok=True)
        return d

    def staged_path(self, task_id: str, target: Path) -> Path:
        root = self.guard.root_for(target)
        if root is None:
            raise StagingError("OUTSIDE_APPROVED_ROOTS", str(target))
        label = f"{root.name or 'root'}-{sha256_hex(os.fspath(root).encode())[:8]}"
        rel = os.path.relpath(target, root)
        staging = self.task_dir(task_id) / "staging"
        p = Path(os.path.realpath(staging / label / rel))
        if not is_within(p, staging):  # paranoia: symlinks planted inside staging
            raise StagingError("STAGING_ESCAPE", str(p))
        return p

    def put_blob(self, task_id: str, data: bytes) -> tuple[str, Path]:
        digest = sha256_hex(data)
        p = self.task_dir(task_id) / "blobs" / digest
        if p.exists():
            if sha256_hex(p.read_bytes()) != digest:
                raise TOCTOUError("BLOB_TAMPERED", digest)
        else:
            _atomic_write(p, data)
            _make_readonly(p)
        return "sha256:" + digest, p

    def read_blob(self, task_id: str, tagged: str) -> bytes:
        if not tagged.startswith("sha256:"):
            raise StagingError("BAD_DIGEST", tagged)
        hexd = tagged.removeprefix("sha256:")
        p = self.task_dir(task_id) / "blobs" / hexd
        if not p.is_file():
            raise TOCTOUError("BLOB_MISSING", tagged)
        data = p.read_bytes()
        if sha256_hex(data) != hexd:
            raise TOCTOUError("BLOB_TAMPERED", tagged)
        return data

    def _checked(self, target: str | Path, **kw: Any) -> Path:
        try:
            return self.guard.check(os.fspath(target), **kw).path
        except PathViolation as exc:
            raise StagingError(exc.code, exc.detail or exc.path) from exc

    def _backup(self, task_id: str, live: Path, reason: str) -> str | None:
        if not live.exists():
            return None
        rb = self.task_dir(task_id) / "rollback"
        stamp = iso_utc().replace(":", "").replace("-", "").replace(".", "")
        dest = rb / f"{stamp}-{uuid.uuid4().hex[:6]}-{live.name}"
        shutil.copy2(live, dest)
        entry = {"ts": iso_utc(), "reason": reason, "original_path": str(live),
                 "backup_path": str(dest), "sha256": _file_hash(dest)}
        with open(rb / "manifest.jsonl", "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
        return str(dest)

    # ------------------------------------------------------------------ #
    # Filesystem: write_staged -> prepare_commit -> commit
    # ------------------------------------------------------------------ #
    def write_staged(self, task_id: str, target: str | Path, content: str) -> dict[str, Any]:
        live = self._checked(target, kind="file")
        data = content.encode("utf-8")
        if len(data) > self.cfg.limits.max_write_bytes:
            raise StagingError("CONTENT_TOO_LARGE", str(len(data)))
        sp = self.staged_path(task_id, live)
        _atomic_write(sp, data)
        before = live.read_bytes() if live.is_file() else b""
        diff, truncated = unified_diff(before, data, live.name, self.cfg.limits.max_diff_bytes)
        return {
            "task_id": task_id,
            "target_path": str(live),
            "staged_path": str(sp),
            "staged_sha256": sha256_tagged(data),
            "destination_exists": live.is_file(),
            "bytes": len(data),
            "unified_diff": diff,
            "diff_truncated": truncated,
        }

    def prepare_commit(self, task_id: str, target: str | Path) -> tuple[FileDiffEvidence, FileArtifactHashes]:
        live = self._checked(target, kind="file")
        sp = self.staged_path(task_id, live)
        if not sp.is_file():
            raise StagingError("NOT_STAGED", f"no staged file for {live}")
        data = sp.read_bytes()
        blob_digest, _ = self.put_blob(task_id, data)  # freeze the exact bytes
        before = live.read_bytes() if live.is_file() else None
        before_digest = sha256_tagged(before) if before is not None else None
        diff, truncated = unified_diff(before or b"", data, live.name, self.cfg.limits.max_diff_bytes)
        evidence = FileDiffEvidence(
            target_path=str(live),
            destination_exists=before is not None,
            destination_before_sha256=before_digest,
            staged_blob_sha256=blob_digest,
            size_before=len(before) if before is not None else None,
            size_after=len(data),
            unified_diff=diff,
            diff_truncated=truncated,
        )
        return evidence, FileArtifactHashes(staged_blob=blob_digest, destination_before=before_digest)

    def commit(self, task_id: str, target: str | Path, hashes: FileArtifactHashes) -> dict[str, Any]:
        live = self._checked(target, kind="file")          # boundary re-check at execution time
        data = self.read_blob(task_id, hashes.staged_blob)  # immutable bytes, re-hashed
        current = _file_hash(live)
        if current != hashes.destination_before:
            raise TOCTOUError(
                "DESTINATION_DRIFT",
                f"expected {hashes.destination_before}, found {current} at {live}",
            )
        rollback = self._backup(task_id, live, "pre-commit")
        _atomic_write(live, data)
        written = _file_hash(live)
        if written != hashes.staged_blob:
            raise TOCTOUError("POST_WRITE_MISMATCH", f"{written} != {hashes.staged_blob}")
        return {"target_path": str(live), "sha256": written, "bytes": len(data),
                "rollback_path": rollback}

    # ------------------------------------------------------------------ #
    # Filesystem: delete (L3)
    # ------------------------------------------------------------------ #
    def prepare_delete(self, task_id: str, target: str | Path) -> tuple[FileDeleteEvidence, DeleteArtifactHashes]:
        live = self._checked(target, must_exist=True, kind="file")
        data = live.read_bytes()
        digest = sha256_tagged(data)
        preview = "" if _is_binary(data) else data[:2000].decode("utf-8", errors="replace")
        self.task_dir(task_id)
        return (
            FileDeleteEvidence(target_path=str(live), target_sha256=digest,
                               size_bytes=len(data), preview=preview),
            DeleteArtifactHashes(target_before=digest),
        )

    def delete(self, task_id: str, target: str | Path, hashes: DeleteArtifactHashes) -> dict[str, Any]:
        live = self._checked(target, must_exist=True, kind="file")
        current = _file_hash(live)
        if current != hashes.target_before:
            raise TOCTOUError("DESTINATION_DRIFT", f"expected {hashes.target_before}, found {current}")
        rollback = self._backup(task_id, live, "pre-delete")
        live.unlink()
        return {"target_path": str(live), "deleted": True, "rollback_path": rollback}

    def list_rollbacks(self, task_id: str) -> list[dict[str, Any]]:
        mf = self.task_dir(task_id) / "rollback" / "manifest.jsonl"
        if not mf.exists():
            return []
        return [json.loads(line) for line in mf.read_text(encoding="utf-8").splitlines() if line]

    # ------------------------------------------------------------------ #
    # E-mail drafts
    # ------------------------------------------------------------------ #
    def stage_email_draft(
        self,
        task_id: str,
        *,
        to: list[str],
        subject: str,
        body: str,
        cc: list[str] | None = None,
        bcc: list[str] | None = None,
        attachment_paths: list[str] | None = None,
    ) -> dict[str, Any]:
        self.task_dir(task_id)
        attachments: list[dict[str, Any]] = []
        for raw in attachment_paths or []:
            live = self._checked(raw, must_exist=True, kind="file")
            size = live.stat().st_size
            if size > self.cfg.limits.max_attachment_bytes:
                raise StagingError("ATTACHMENT_TOO_LARGE", f"{live.name}: {size}B")
            digest, _ = self.put_blob(task_id, live.read_bytes())
            attachments.append({"filename": live.name, "path": str(live),
                                "sha256": digest, "size_bytes": size})
        names = [a["filename"] for a in attachments]
        if len(set(n.lower() for n in names)) != len(names):
            raise StagingError("DUPLICATE_ATTACHMENT_NAME", ",".join(names))
        payload = {
            "to": list(to), "cc": list(cc or []), "bcc": list(bcc or []),
            "subject": subject, "body": body,
            "attachment_hashes": {a["filename"]: a["sha256"] for a in attachments},
        }
        record = {
            "staged_draft_id": uuid.uuid4().hex,
            "task_id": task_id,
            "created_at": iso_utc(),
            "payload": payload,
            "payload_hash": sha256_tagged(canonical_json(payload)),
            "attachments": attachments,
        }
        p = self._draft_path(task_id, record["staged_draft_id"])
        _atomic_write(p, canonical_json(record))
        _make_readonly(p)
        return record

    def _draft_path(self, task_id: str, draft_id: str) -> Path:
        if not OPAQUE_ID_RE.fullmatch(draft_id or ""):
            raise StagingError("INVALID_STAGED_DRAFT_ID", repr(draft_id))
        return self.task_dir(task_id) / "drafts" / f"{draft_id}.json"

    def load_verified_draft(
        self,
        task_id: str,
        draft_id: str,
        expected: EmailArtifactHashes | None = None,
    ) -> tuple[dict[str, Any], dict[str, bytes]]:
        """Re-verify a staged draft end to end. Returns (record, {filename: bytes}).

        Raises ``TOCTOUError`` if the draft file, any attachment blob, or any
        live attachment file differs from what was hashed / approved.
        """
        p = self._draft_path(task_id, draft_id)
        if not p.is_file():
            raise StagingError("DRAFT_NOT_FOUND", draft_id)
        try:
            record = json.loads(p.read_bytes())
        except ValueError as exc:
            raise TOCTOUError("DRAFT_TAMPERED", "unparseable draft") from exc
        payload = record.get("payload", {})
        actual = sha256_tagged(canonical_json(payload))
        if actual != record.get("payload_hash"):
            raise TOCTOUError("DRAFT_TAMPERED", "payload hash mismatch")
        if expected is not None:
            if actual != expected.email_payload:
                raise TOCTOUError("DRAFT_TAMPERED", "payload differs from approved contract")
            if payload.get("attachment_hashes", {}) != expected.attachments:
                raise TOCTOUError("ATTACHMENT_TAMPERED", "attachment set differs from contract")
        blobs: dict[str, bytes] = {}
        for att in record.get("attachments", []):
            want = payload["attachment_hashes"].get(att["filename"])
            if want != att["sha256"]:
                raise TOCTOUError("ATTACHMENT_TAMPERED", att["filename"])
            try:
                blobs[att["filename"]] = self.read_blob(task_id, want)
            except TOCTOUError as exc:
                raise TOCTOUError("ATTACHMENT_TAMPERED", f"{att['filename']}: {exc.code}") from exc
            try:
                live = self._checked(att["path"], must_exist=True, kind="file")
            except StagingError as exc:
                raise TOCTOUError("ATTACHMENT_DRIFT", f"{att['filename']}: {exc.code}") from exc
            if _file_hash(live) != want:
                raise TOCTOUError("ATTACHMENT_DRIFT", f"{att['filename']} changed on disk since staging")
        return record, blobs

    def email_evidence(self, record: dict[str, Any], gmail_draft_id: str | None = None
                       ) -> tuple[EmailEvidence, EmailArtifactHashes]:
        p = record["payload"]
        ev = EmailEvidence(
            staged_draft_id=record["staged_draft_id"],
            gmail_draft_id=gmail_draft_id,
            to=p["to"], cc=p["cc"], bcc=p["bcc"], subject=p["subject"], body=p["body"],
            attachments=[AttachmentEvidence(**a) for a in record["attachments"]],
            email_payload_sha256=record["payload_hash"],
        )
        return ev, EmailArtifactHashes(email_payload=record["payload_hash"],
                                       attachments=dict(p["attachment_hashes"]))

    # ------------------------------------------------------------------ #
    # Git commit proposals (git_stage_commit -> git_commit_and_push)
    # ------------------------------------------------------------------ #
    GIT_FROZEN_FIELDS = ("repo_path", "branch", "remote", "remote_url", "commit_message",
                         "files", "diff_sha256", "staged_tree")

    def _git_proposal_path(self, task_id: str, staged_commit_id: str) -> Path:
        if not OPAQUE_ID_RE.fullmatch(staged_commit_id or ""):
            raise StagingError("INVALID_STAGED_COMMIT_ID", repr(staged_commit_id))
        return self.task_dir(task_id) / "git" / f"{staged_commit_id}.json"

    def put_git_proposal(self, task_id: str, proposal: dict[str, Any]) -> dict[str, Any]:
        """Persist an immutable, self-hashing commit proposal (RFC 8785 bytes, read-only)."""
        record = {
            "staged_commit_id": uuid.uuid4().hex,
            "task_id": task_id,
            "created_at": iso_utc(),
            "proposal": proposal,
            "proposal_sha256": sha256_tagged(canonical_json(proposal)),
        }
        p = self._git_proposal_path(task_id, record["staged_commit_id"])
        _atomic_write(p, canonical_json(record))
        _make_readonly(p)
        return record

    def load_verified_git_proposal(
        self,
        task_id: str,
        staged_commit_id: str,
        expected: GitArtifactHashes | None = None,
    ) -> dict[str, Any]:
        """Load + re-hash a proposal; optionally compare against the signed contract."""
        p = self._git_proposal_path(task_id, staged_commit_id)
        if not p.is_file():
            raise StagingError("STAGED_COMMIT_NOT_FOUND", staged_commit_id)
        try:
            record = json.loads(p.read_bytes())
        except ValueError as exc:
            raise TOCTOUError("PROPOSAL_TAMPERED", "unparseable proposal") from exc
        proposal = record.get("proposal") or {}
        actual = sha256_tagged(canonical_json(proposal))
        if actual != record.get("proposal_sha256"):
            raise TOCTOUError("PROPOSAL_TAMPERED", "proposal hash mismatch")
        if record.get("task_id") != task_id or record.get("staged_commit_id") != staged_commit_id:
            raise TOCTOUError("PROPOSAL_TAMPERED", "proposal identity mismatch")
        if expected is not None:
            if actual != expected.proposal_sha256:
                raise TOCTOUError("PROPOSAL_TAMPERED", "proposal differs from approved contract")
            for f in self.GIT_FROZEN_FIELDS:
                if proposal.get(f) != getattr(expected, f):
                    raise TOCTOUError("PROPOSAL_TAMPERED", f"{f} differs from approved contract")
        return record

    def git_evidence(self, record: dict[str, Any], escalated_paths: list[str] | None = None
                     ) -> tuple[GitCommitEvidence, GitArtifactHashes]:
        p = record["proposal"]
        ev = GitCommitEvidence(
            staged_commit_id=record["staged_commit_id"],
            repo_name=p["repo_name"],
            repo_path=p["repo_path"],
            branch=p["branch"],
            remote=p["remote"],
            remote_url=p["remote_url"],
            commit_message=p["commit_message"],
            files=list(p["files"]),
            unified_diff=p.get("unified_diff", ""),
            diff_truncated=bool(p.get("diff_truncated", False)),
            diff_sha256=p["diff_sha256"],
            staged_tree=p["staged_tree"],
            escalated_paths=list(escalated_paths or []),
        )
        hashes = GitArtifactHashes(
            **{f: (list(p[f]) if f == "files" else p[f]) for f in self.GIT_FROZEN_FIELDS},
            proposal_sha256=record["proposal_sha256"],
        )
        return ev, hashes
