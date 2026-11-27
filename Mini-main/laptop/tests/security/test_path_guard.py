"""Filesystem boundary: denylist, traversal, symlink/junction escape, secrets,
Windows path aliases, and policy-engine integration (risk cannot be supplied)."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from mini.schemas import RiskLevel, ToolCall, Verdict
from mini.security.path_guard import PathGuard, PathViolation
from mini.security.policy_engine import PolicyEngine

WIN = os.name == "nt"


def _code(guard: PathGuard, raw: str) -> str:
    with pytest.raises(PathViolation) as ei:
        guard.check(raw)
    return ei.value.code


# --------------------------------------------------------------------------- #
# Allowed paths
# --------------------------------------------------------------------------- #
def test_allows_regular_file_inside_root(cfg, env_tree):
    g = PathGuard(cfg)
    res = g.check(str(env_tree.project / "README.md"), must_exist=True, kind="file")
    assert res.path == Path(os.path.realpath(env_tree.project / "README.md"))
    assert res.root == Path(os.path.realpath(env_tree.project))


def test_relative_path_resolves_against_first_root(cfg, env_tree):
    g = PathGuard(cfg)
    assert g.check("notes/todo.md").path == Path(os.path.realpath(env_tree.project / "notes" / "todo.md"))


def test_nonexistent_file_inside_root_is_allowed_for_staging(cfg, env_tree):
    assert PathGuard(cfg).check(str(env_tree.project / "new" / "summary.md")).path.name == "summary.md"


# --------------------------------------------------------------------------- #
# Hard denylist (even inside approved roots)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("name", [".env", ".env.local", "server.pem", "deploy.key",
                                  "gcp-credentials.json", "oauth_token.json"])
def test_denylisted_filenames_blocked(cfg, env_tree, name):
    assert _code(PathGuard(cfg), str(env_tree.project / name)) == "DENY_FILENAME"


def test_denylist_is_case_insensitive(cfg, env_tree):
    assert _code(PathGuard(cfg), str(env_tree.project / ".ENV")) == "DENY_FILENAME"
    assert _code(PathGuard(cfg), str(env_tree.project / "Server.PEM")) == "DENY_FILENAME"


def test_git_config_blocked(cfg, env_tree):
    assert _code(PathGuard(cfg), str(env_tree.project / ".git" / "config")) == "DENY_PATH_PATTERN"


def test_ssh_and_aws_blocked_even_when_home_is_approved(make_cfg, env_tree):
    g = PathGuard(make_cfg(approved_roots=[env_tree.home]))
    assert _code(g, str(env_tree.home / ".ssh" / "id_rsa")) == "DENY_PROTECTED_DIR"
    assert _code(g, "~/.ssh/id_rsa") == "DENY_PROTECTED_DIR"
    assert _code(g, str(env_tree.home / ".aws" / "credentials")) == "DENY_PROTECTED_DIR"


def test_gmail_secrets_and_trusted_devices_blocked(make_cfg, env_tree):
    g = PathGuard(make_cfg(approved_roots=[env_tree.home]))
    assert _code(g, str(env_tree.home / ".mini" / "secrets" / "gmail_token.json")) == "DENY_PROTECTED_DIR"
    # Replacing the pinned mobile key would defeat the whole approval system.
    assert _code(g, str(env_tree.home / ".mini" / "trusted_devices.json")) == "DENY_PROTECTED_DIR"


def test_mini_state_dirs_blocked_when_project_root_approved(make_cfg, env_tree):
    g = PathGuard(make_cfg(approved_roots=[env_tree.mini_root]))
    for sub in ("workspaces/t1/blobs/x", "logs/audit.jsonl", "state/mini.db"):
        assert _code(g, str(env_tree.mini_root / sub)) == "DENY_PROTECTED_DIR"


def test_system_dirs_blocked(make_cfg, env_tree):
    sysdir = Path("C:/Windows") if WIN else Path("/etc")
    g = PathGuard(make_cfg(approved_roots=[sysdir.parent]))
    target = sysdir / ("win.ini" if WIN else "passwd")
    assert _code(g, str(target)) == "DENY_SYSTEM_DIR"


# --------------------------------------------------------------------------- #
# Traversal & escapes
# --------------------------------------------------------------------------- #
def test_dotdot_traversal_out_of_root(cfg, env_tree):
    g = PathGuard(cfg)
    raw = str(env_tree.project / ".." / ".." / ".." / "outside" / "secret.txt")
    assert _code(g, raw) == "OUTSIDE_APPROVED_ROOTS"
    assert _code(g, "../../../outside/secret.txt") == "OUTSIDE_APPROVED_ROOTS"


def test_absolute_path_outside_root(cfg, env_tree):
    assert _code(PathGuard(cfg), str(env_tree.outside / "secret.txt")) == "OUTSIDE_APPROVED_ROOTS"


def test_sibling_prefix_is_not_containment(make_cfg, env_tree):
    """/home/projects/demo must not contain /home/projects/demo-evil."""
    evil = env_tree.project.parent / (env_tree.project.name + "-evil")
    evil.mkdir()
    (evil / "x.txt").write_text("x")
    assert _code(PathGuard(make_cfg()), str(evil / "x.txt")) == "OUTSIDE_APPROVED_ROOTS"


def _make_dir_link(link: Path, target: Path) -> None:
    try:
        os.symlink(target, link, target_is_directory=True)
        return
    except (OSError, NotImplementedError):
        if not WIN:
            pytest.skip("symlinks not supported")
    import _winapi  # junctions need no privilege on Windows

    _winapi.CreateJunction(str(target), str(link))


def test_symlink_or_junction_escape_blocked(cfg, env_tree):
    link = env_tree.project / "escape"
    _make_dir_link(link, env_tree.outside)
    assert _code(PathGuard(cfg), str(link / "secret.txt")) == "OUTSIDE_APPROVED_ROOTS"


def test_symlink_into_ssh_blocked(make_cfg, env_tree):
    link = env_tree.project / "keys"
    _make_dir_link(link, env_tree.home / ".ssh")
    g = PathGuard(make_cfg(approved_roots=[env_tree.home]))
    assert _code(g, str(link / "id_rsa")) == "DENY_PROTECTED_DIR"


def test_file_symlink_to_env_blocked(cfg, env_tree):
    link = env_tree.project / "innocent.txt"
    try:
        os.symlink(env_tree.project / ".env", link)
    except (OSError, NotImplementedError):
        pytest.skip("file symlinks need privilege on this platform")
    assert _code(PathGuard(cfg), str(link)) == "DENY_FILENAME"


def test_listing_filter_hides_secrets_and_escapes(cfg, env_tree):
    g = PathGuard(cfg)
    _make_dir_link(env_tree.project / "escape", env_tree.outside)
    visible = {p.name for p in env_tree.project.iterdir() if g.visible_entry(p)}
    assert {"README.md", "notes", "report.pdf"} <= visible
    assert not visible & {".env", ".env.local", "server.pem", "deploy.key", "gcp-credentials.json",
                          "oauth_token.json", "escape"}


# --------------------------------------------------------------------------- #
# Syntactic screening
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("raw,code", [("", "PATH_EMPTY"), ("   ", "PATH_EMPTY"),
                                      ("README.md\x00.txt", "PATH_NUL_BYTE")])
def test_garbage_paths(cfg, raw, code):
    assert _code(PathGuard(cfg), raw) == code


def test_non_string_path(cfg):
    with pytest.raises(PathViolation) as ei:
        PathGuard(cfg).check(["README.md"])  # type: ignore[arg-type]
    assert ei.value.code == "PATH_INVALID_TYPE"


@pytest.mark.skipif(not WIN, reason="Windows path aliasing")
@pytest.mark.parametrize("suffix,code", [
    (".env.", "PATH_WIN_ALIAS"),
    (".env ", "PATH_WIN_ALIAS"),
    (".env::$DATA", "PATH_ADS"),
    ("README.md:hidden", "PATH_ADS"),
    ("NUL", "PATH_RESERVED_NAME"),
    ("con.txt", "PATH_RESERVED_NAME"),
])
def test_windows_aliases_blocked(cfg, env_tree, suffix, code):
    assert _code(PathGuard(cfg), str(env_tree.project) + "\\" + suffix) == code


@pytest.mark.skipif(not WIN, reason="Windows only")
def test_windows_device_and_unc_paths_blocked(cfg, env_tree):
    g = PathGuard(cfg)
    assert _code(g, "\\\\?\\" + str(env_tree.project / "README.md")) == "PATH_DEVICE_NAMESPACE"
    assert _code(g, "\\\\attacker\\share\\x.txt") == "PATH_UNC"


# --------------------------------------------------------------------------- #
# Policy engine integration
# --------------------------------------------------------------------------- #
def _call(tool, server="filesystem", **args):
    return ToolCall(server=server, tool=tool, arguments=args)


def test_policy_l0_read_allowed_and_canonicalized(cfg, env_tree):
    d = PolicyEngine(cfg).evaluate(_call("fs_read_file", path="notes/../README.md"))
    assert d.verdict is Verdict.ALLOW and d.risk_level is RiskLevel.L0
    assert d.canonical_args["path"] == os.path.realpath(env_tree.project / "README.md")


def test_policy_denies_env_read(cfg, env_tree):
    d = PolicyEngine(cfg).evaluate(_call("fs_read_file", path=str(env_tree.project / ".env")))
    assert d.verdict is Verdict.DENY
    assert d.violations[0].startswith("DENY_FILENAME")


def test_policy_l1_and_l2_classification(cfg, env_tree):
    e = PolicyEngine(cfg)
    w = e.evaluate(_call("fs_write_staged", task_id="t1", target_path="README.md", content="x"))
    c = e.evaluate(_call("fs_commit_staged", task_id="t1", target_path="README.md"))
    assert (w.verdict, w.risk_level) == (Verdict.STAGE, RiskLevel.L1)
    assert (c.verdict, c.risk_level, c.action_type.value) == (Verdict.REQUIRE_APPROVAL, RiskLevel.L2,
                                                              "filesystem.commit_staged")


def test_policy_l3_delete(cfg):
    d = PolicyEngine(cfg).evaluate(_call("fs_delete_file", task_id="t1", path="README.md"))
    assert d.risk_level is RiskLevel.L3 and d.verdict is Verdict.REQUIRE_APPROVAL


def test_planner_cannot_supply_or_downgrade_risk(cfg):
    e = PolicyEngine(cfg)
    d = e.evaluate(_call("fs_commit_staged", task_id="t1", target_path="README.md", risk_level="L0"))
    assert d.verdict is Verdict.DENY and "UNEXPECTED_ARGUMENT:risk_level" in d.violations
    d = e.evaluate(_call("fs_delete_file", task_id="t1", path="README.md", confirm_destructive=True))
    assert d.verdict is Verdict.DENY


def test_escalation_is_monotonic(cfg):
    d = PolicyEngine(cfg).evaluate(_call("fs_commit_staged", task_id="t1", target_path="scripts/run.ps1"))
    assert d.risk_level is RiskLevel.L3
    assert "escalation:commit-executable-or-ci" in d.matched_rules


def test_unknown_tool_and_server_mismatch_denied(cfg):
    e = PolicyEngine(cfg)
    assert e.evaluate(_call("shell_exec", cmd="rm -rf /")).verdict is Verdict.DENY
    assert e.evaluate(_call("fs_read_file", server="gmail", path="README.md")).verdict is Verdict.DENY


@pytest.mark.parametrize("task_id", ["../evil", "a/b", "", "x" * 65, ".."])
def test_task_id_traversal_denied(cfg, task_id):
    d = PolicyEngine(cfg).evaluate(_call("fs_write_staged", task_id=task_id, target_path="a.md", content="x"))
    assert d.verdict is Verdict.DENY and d.violations == ["INVALID_TASK_ID"]


def test_gmail_attachment_secret_blocked(make_cfg, env_tree):
    e = PolicyEngine(make_cfg(approved_roots=[env_tree.home]))
    d = e.evaluate(_call("gmail_stage_draft", server="gmail", task_id="t1", to=["a@example.com"],
                         subject="s", body="b",
                         attachment_paths=[str(env_tree.home / ".mini" / "secrets" / "gmail_token.json")]))
    assert d.verdict is Verdict.DENY
    assert d.violations[0].startswith("DENY_PROTECTED_DIR")


def test_gmail_header_injection_and_bad_recipients(cfg):
    e = PolicyEngine(cfg)
    d = e.evaluate(_call("gmail_stage_draft", server="gmail", task_id="t1",
                         to=["a@example.com\r\nBcc: spy@evil.com"], subject="hi\r\nBcc: x@y.z", body="b"))
    assert d.verdict is Verdict.DENY
    assert any(v.startswith("INVALID_RECIPIENT") for v in d.violations)
    assert "HEADER_INJECTION:subject" in d.violations


def test_params_hash_is_deterministic_and_tool_bound(cfg):
    e = PolicyEngine(cfg)
    a = e.evaluate(_call("fs_commit_staged", task_id="t1", target_path="README.md"))
    b = e.evaluate(_call("fs_commit_staged", target_path="./README.md", task_id="t1"))
    c = e.evaluate(_call("fs_write_staged", task_id="t1", target_path="README.md", content=""))
    assert a.params_hash_sha256 == b.params_hash_sha256 != c.params_hash_sha256
