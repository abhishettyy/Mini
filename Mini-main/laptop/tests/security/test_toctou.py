"""TOCTOU prevention: live-file drift, staging/blob tamper after approval,
attachment & draft tamper, and the full approve -> drift -> abort flow."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from mini.schemas import (
    ActionType,
    ApprovalContract,
    EmailArtifactHashes,
    RiskLevel,
    SignedApproval,
    TrustedDevice,
    ToolCall,
)
from mini.security._db import SQLiteDB
from mini.security.contracts import (
    ContractVerifier,
    NonceStore,
    ReplayError,
    TrustedDeviceStore,
    generate_keypair,
    sign_contract,
)
from mini.security.policy_engine import PolicyEngine
from mini.security.staging import StagingEngine, StagingError, TOCTOUError


def _writable(p: Path) -> None:
    os.chmod(p, stat.S_IREAD | stat.S_IWRITE)


@pytest.fixture
def st(cfg):
    return StagingEngine(cfg)


@pytest.fixture
def readme(env_tree) -> Path:
    return env_tree.project / "README.md"


# --------------------------------------------------------------------------- #
# Filesystem commit
# --------------------------------------------------------------------------- #
def test_write_staged_never_touches_live_file(st, readme):
    before = readme.read_bytes()
    res = st.write_staged("t1", str(readme), "# Demo project\n\nStatus: final\n")
    assert readme.read_bytes() == before
    assert Path(res["staged_path"]).is_file()
    assert "-Status: draft" in res["unified_diff"] and "+Status: final" in res["unified_diff"]


def test_happy_commit_with_rollback(st, readme):
    original = readme.read_bytes()
    st.write_staged("t1", str(readme), "new content\n")
    ev, hashes = st.prepare_commit("t1", str(readme))
    assert ev.destination_before_sha256 == hashes.destination_before
    out = st.commit("t1", str(readme), hashes)
    assert readme.read_text() == "new content\n"
    assert Path(out["rollback_path"]).read_bytes() == original
    assert st.list_rollbacks("t1")[0]["original_path"] == str(readme.resolve())


def test_live_file_drift_before_commit_aborts(st, readme):
    st.write_staged("t1", str(readme), "agent version\n")
    _, hashes = st.prepare_commit("t1", str(readme))
    readme.write_text("user edited meanwhile\n")  # drift after evidence was shown
    with pytest.raises(TOCTOUError) as ei:
        st.commit("t1", str(readme), hashes)
    assert ei.value.code == "DESTINATION_DRIFT"
    assert readme.read_text() == "user edited meanwhile\n"  # user's edit preserved


def test_destination_created_after_approval_aborts(st, env_tree):
    target = env_tree.project / "new.md"
    st.write_staged("t1", str(target), "fresh\n")
    _, hashes = st.prepare_commit("t1", str(target))
    assert hashes.destination_before is None
    target.write_text("someone else created this\n")
    with pytest.raises(TOCTOUError):
        st.commit("t1", str(target), hashes)
    assert target.read_text() == "someone else created this\n"


def test_staging_tamper_after_approval_is_ignored(st, readme):
    res = st.write_staged("t1", str(readme), "approved text\n")
    _, hashes = st.prepare_commit("t1", str(readme))
    Path(res["staged_path"]).write_text("MALICIOUS swap after approval\n")
    st.commit("t1", str(readme), hashes)
    assert readme.read_text() == "approved text\n"  # committed from immutable blob


def test_blob_tamper_aborts(st, readme, cfg):
    st.write_staged("t1", str(readme), "approved text\n")
    _, hashes = st.prepare_commit("t1", str(readme))
    blob = Path(cfg.workspaces_dir) / "t1" / "blobs" / hashes.staged_blob.removeprefix("sha256:")
    assert not os.access(blob, os.W_OK)  # blobs are read-only
    _writable(blob)
    blob.write_text("evil\n")
    original = readme.read_bytes()
    with pytest.raises(TOCTOUError) as ei:
        st.commit("t1", str(readme), hashes)
    assert ei.value.code == "BLOB_TAMPERED"
    assert readme.read_bytes() == original


def test_commit_without_staging_fails(st, readme):
    with pytest.raises(StagingError) as ei:
        st.prepare_commit("t1", str(readme))
    assert ei.value.code == "NOT_STAGED"


def test_commit_rechecks_boundary_at_execution(st, env_tree):
    with pytest.raises(StagingError) as ei:
        st.write_staged("t1", str(env_tree.project / ".env"), "X=1")
    assert ei.value.code == "DENY_FILENAME"


def test_delete_drift_aborts(st, readme):
    _, hashes = st.prepare_delete("t1", str(readme))
    readme.write_text("changed\n")
    with pytest.raises(TOCTOUError):
        st.delete("t1", str(readme), hashes)
    assert readme.exists()


# --------------------------------------------------------------------------- #
# E-mail drafts & attachments
# --------------------------------------------------------------------------- #
def _stage(st, env_tree, **kw):
    return st.stage_email_draft("t1", to=["alice@example.com"], subject="Weekly summary",
                                body="Hi Alice,\nSee attached.\n",
                                attachment_paths=[str(env_tree.project / "report.pdf")], **kw)


def test_draft_roundtrip_verifies(st, env_tree):
    rec = _stage(st, env_tree)
    ev, hashes = st.email_evidence(rec)
    loaded, blobs = st.load_verified_draft("t1", rec["staged_draft_id"], hashes)
    assert blobs["report.pdf"] == (env_tree.project / "report.pdf").read_bytes()
    assert ev.attachments[0].sha256 == hashes.attachments["report.pdf"]


def test_attachment_live_tamper_aborts(st, env_tree):
    rec = _stage(st, env_tree)
    _, hashes = st.email_evidence(rec)
    (env_tree.project / "report.pdf").write_text("%PDF swapped invoice\n")
    with pytest.raises(TOCTOUError) as ei:
        st.load_verified_draft("t1", rec["staged_draft_id"], hashes)
    assert ei.value.code == "ATTACHMENT_DRIFT"


def test_attachment_blob_tamper_aborts(st, env_tree, cfg):
    rec = _stage(st, env_tree)
    _, hashes = st.email_evidence(rec)
    blob = Path(cfg.workspaces_dir) / "t1" / "blobs" / hashes.attachments["report.pdf"].removeprefix("sha256:")
    _writable(blob)
    blob.write_text("evil")
    with pytest.raises(TOCTOUError) as ei:
        st.load_verified_draft("t1", rec["staged_draft_id"], hashes)
    assert ei.value.code == "ATTACHMENT_TAMPERED"


def test_draft_file_tamper_aborts(st, env_tree, cfg):
    rec = _stage(st, env_tree)
    _, hashes = st.email_evidence(rec)
    p = Path(cfg.workspaces_dir) / "t1" / "drafts" / f"{rec['staged_draft_id']}.json"
    _writable(p)
    p.write_bytes(p.read_bytes().replace(b"alice@example.com", b"mallory@evil.com"))
    with pytest.raises(TOCTOUError) as ei:
        st.load_verified_draft("t1", rec["staged_draft_id"], hashes)
    assert ei.value.code == "DRAFT_TAMPERED"


def test_draft_swapped_for_different_approved_contract_aborts(st, env_tree):
    rec_a = _stage(st, env_tree)
    rec_b = st.stage_email_draft("t1", to=["mallory@evil.com"], subject="x", body="y")
    _, hashes_a = st.email_evidence(rec_a)
    with pytest.raises(TOCTOUError):
        st.load_verified_draft("t1", rec_b["staged_draft_id"], hashes_a)


def test_attachment_from_secret_dir_rejected_at_staging(make_cfg, env_tree):
    st = StagingEngine(make_cfg(approved_roots=[env_tree.home]))
    with pytest.raises(StagingError) as ei:
        st.stage_email_draft("t1", to=["a@example.com"], subject="s", body="b",
                             attachment_paths=[str(env_tree.home / ".ssh" / "id_rsa")])
    assert ei.value.code == "DENY_PROTECTED_DIR"


# --------------------------------------------------------------------------- #
# Full flow: policy -> evidence -> contract -> signature -> drift -> abort
# --------------------------------------------------------------------------- #
def test_signed_approval_still_aborts_on_drift_and_cannot_be_replayed(cfg, st, readme, tmp_path):
    engine = PolicyEngine(cfg)
    db = SQLiteDB(tmp_path / "flow.db")
    devices = TrustedDeviceStore(tmp_path / "trusted.json")
    priv, pub = generate_keypair()
    devices.add(TrustedDevice(device_id="phone", public_key_b64=pub))
    verifier = ContractVerifier(devices, NonceStore(db))
    try:
        st.write_staged("t1", str(readme), "approved\n")
        d = engine.evaluate(ToolCall(server="filesystem", tool="fs_commit_staged",
                                     arguments={"task_id": "t1", "target_path": "README.md"}))
        _, hashes = st.prepare_commit("t1", d.canonical_args["target_path"])
        contract = ApprovalContract.issue(task_id="t1", action_type=ActionType.FS_COMMIT_STAGED,
                                          risk_level=RiskLevel.L2, target=d.canonical_args["target_path"],
                                          params_hash_sha256=d.params_hash_sha256, artifact_hashes=hashes)
        sa = SignedApproval(contract_id=contract.contract_id, decision="approve", device_id="phone",
                            signature_b64=sign_contract(priv, contract))
        verified = verifier.verify(contract, sa)
        readme.write_text("drifted\n")
        with pytest.raises(TOCTOUError):
            st.commit("t1", d.canonical_args["target_path"], verified.contract.artifact_hashes)
        with pytest.raises(ReplayError):  # the consumed approval can't be reused after fixing drift
            verifier.verify(contract, sa)
        assert readme.read_text() == "drifted\n"
        assert isinstance(contract.artifact_hashes, type(hashes)) and not isinstance(hashes, EmailArtifactHashes)
    finally:
        db.close()
