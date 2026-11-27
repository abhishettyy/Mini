"""Git-specific boundary checks shared by the Policy Engine (proxy side) and
the isolated git worker (defence in depth).

* ``validate_repo_path``  — PathGuard + "is a real, non-redirected work tree".
* ``validate_repo_files`` — every file canonicalized by PathGuard, contained in
  the repo, outside ``.git`` and not denylisted; returned repo-relative POSIX.
* ``assert_safe_git_argv`` — hard block on destructive / unsafe git flags.
* ``normalize_remote_url`` / ``remote_url_problem`` — remote allowlist helpers.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from urllib.parse import urlsplit

from mini.security.path_guard import PathGuard, PathViolation, is_within

# Flags that can rewrite/destroy history or refs, or bypass Mini's controls.
FORBIDDEN_GIT_FLAGS = frozenset({
    "-f", "--force", "--force-with-lease", "--force-if-includes",
    "--hard", "--delete", "-d", "-D", "--mirror", "--prune", "--prune-tags",
    "--all", "--tags", "--follow-tags", "--exec", "--receive-pack", "--upload-pack",
    "--set-upstream", "-u", "--amend", "--allow-empty", "--no-literal-pathspecs",
})
_FORBIDDEN_PREFIXES = ("--force", "--exec=", "--receive-pack=", "--upload-pack=", "--delete")

BRANCH_RE = re.compile(r"^(?!-)(?!.*\.\.)(?!.*//)(?!.*@\{)[A-Za-z0-9._/-]{1,200}(?<![./])$")
REMOTE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class GitPolicyError(Exception):
    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}")


def assert_safe_git_argv(subcommand_args: list[str]) -> None:
    """Reject destructive flags anywhere before ``--`` and unsafe refspecs.

    Applied to the arguments after ``git <global -c options>`` — i.e. the
    subcommand and its options. Pathspecs after ``--`` are user data and are
    validated separately by ``validate_repo_files``.
    """
    if not subcommand_args:
        raise GitPolicyError("GIT_EMPTY_COMMAND")
    sub = subcommand_args[0]
    before_dd = []
    for tok in subcommand_args[1:]:
        if tok == "--":
            break
        before_dd.append(tok)
    for tok in before_dd:
        low = tok.lower()
        if tok in FORBIDDEN_GIT_FLAGS or low.startswith(_FORBIDDEN_PREFIXES):
            raise GitPolicyError("GIT_FORBIDDEN_FLAG", f"{sub} {tok}")
        # short-option clusters such as -fq / -df
        if (re.fullmatch(r"-[A-Za-z]{2,}", tok) and sub in {"push", "reset", "clean", "branch", "checkout"}
                and any(c in tok[1:] for c in "fdD")):
            raise GitPolicyError("GIT_FORBIDDEN_FLAG", f"{sub} {tok}")
    if sub == "push":
        for tok in before_dd:
            if tok.startswith("-"):
                continue
            if tok.startswith("+") or tok.startswith(":") or ":+" in tok:
                raise GitPolicyError("GIT_FORBIDDEN_REFSPEC", tok)
    if sub in {"reset", "clean", "rebase", "filter-branch", "update-ref", "gc", "reflog",
               "config", "remote", "submodule", "worktree"}:
        raise GitPolicyError("GIT_FORBIDDEN_SUBCOMMAND", sub)


def validate_repo_path(guard: PathGuard, raw: object) -> Path:
    """Canonical repo root inside an approved root with a real ``.git`` dir.

    ``.git`` files (``gitdir:`` redirects used by worktrees/submodules) and
    symlinked ``.git`` directories are rejected: they could point git at a
    repository outside the approved roots.
    """
    checked = guard.check(raw, must_exist=True, kind="dir")
    repo = checked.path
    gitdir = repo / ".git"
    if gitdir.is_symlink() or not gitdir.is_dir():
        raise PathViolation("NOT_A_GIT_REPO", str(repo), f"{repo} has no regular .git directory")
    real_gitdir = Path(os.path.realpath(gitdir))
    if not is_within(real_gitdir, checked.root):
        raise PathViolation("GITDIR_OUTSIDE_ROOT", str(real_gitdir), "git dir escapes approved root")
    return repo


def validate_repo_files(guard: PathGuard, repo: Path, files: object, *, max_files: int) -> list[str]:
    """Return sorted, de-duplicated repo-relative POSIX paths or raise ``PathViolation``."""
    if not isinstance(files, list) or not files:
        raise PathViolation("NO_FILES", str(files), "files must be a non-empty list")
    if len(files) > max_files:
        raise PathViolation("TOO_MANY_FILES", str(len(files)), f"more than {max_files} files")
    out: set[str] = set()
    for raw in files:
        if not isinstance(raw, str) or not raw.strip():
            raise PathViolation("PATH_INVALID_TYPE", repr(raw), "file must be a non-empty string")
        if raw.startswith("-"):
            raise PathViolation("GIT_ARG_INJECTION", raw, "file paths may not start with '-'")
        if any(c in raw for c in "\r\n\t"):
            raise PathViolation("PATH_CONTROL_CHAR", raw.encode("unicode_escape").decode(), "control char")
        p = Path(raw)
        if not p.is_absolute():
            p = repo / p
        canon = guard.check(str(p)).path  # realpath + approved root + denylist
        if not is_within(canon, repo) or os.path.normcase(str(canon)) == os.path.normcase(str(repo)):
            raise PathViolation("OUTSIDE_REPO", str(canon), f"{raw} is not inside {repo}")
        rel = os.path.relpath(canon, repo).replace("\\", "/")
        if any(part.lower() == ".git" for part in rel.split("/")):
            raise PathViolation("DENY_GIT_INTERNAL", str(canon), f"{rel} is inside .git")
        out.add(rel)
    return sorted(out)


def is_local_remote(url: str) -> bool:
    parts = urlsplit(url)
    if parts.scheme in ("http", "https", "ssh", "git"):
        return False
    if parts.scheme == "file":
        return True
    # Windows drive letters parse as a 1-char scheme.
    return parts.scheme == "" or len(parts.scheme) == 1


def normalize_remote_url(url: str) -> str:
    url = url.strip()
    if is_local_remote(url):
        if url.startswith("file://"):
            url = url[7:]
            if re.match(r"^/[A-Za-z]:", url):
                url = url[1:]
        return os.path.normcase(os.path.realpath(url))
    parts = urlsplit(url)
    path = parts.path.rstrip("/")
    return f"{parts.scheme.lower()}://{parts.netloc.lower()}{path}"


def remote_url_problem(url: str, *, mock: bool) -> str | None:
    """Return an error code if ``url`` may not be pushed to in this mode."""
    if not isinstance(url, str) or not url.strip():
        return "REMOTE_URL_EMPTY"
    if any(c in url for c in "\r\n\t\x00 ") and not is_local_remote(url):
        return "REMOTE_URL_INVALID"
    if url.startswith("-"):
        return "GIT_ARG_INJECTION"
    if is_local_remote(url):
        return None if mock else "REMOTE_NOT_HTTPS"
    parts = urlsplit(url)
    if parts.scheme != "https":
        return "REMOTE_NOT_HTTPS"
    if "@" in parts.netloc or parts.username or parts.password:
        return "REMOTE_URL_HAS_CREDENTIALS"
    if parts.query or parts.fragment:
        return "REMOTE_URL_INVALID"
    return None
