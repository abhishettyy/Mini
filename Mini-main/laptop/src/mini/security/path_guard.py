"""Filesystem boundary enforcement.

Every path argument coming from the planner is:

1. syntactically screened (NUL bytes, Windows ADS ``file:stream``, device
   namespaces ``\\\\?\\``/``\\\\.\\``, reserved DOS names, trailing dot/space
   aliases such as ``.env.`` which Win32 silently maps to ``.env``);
2. canonicalized with ``os.path.realpath`` (resolves ``..`` and *all* symlinks
   / junctions);
3. required to be contained in an approved root via ``os.path.commonpath``;
4. checked against the hard denylist (filename globs, path globs, protected
   directory trees, OS system directories) — the denylist wins even inside an
   approved root.

The same guard runs in the proxy *and* again inside the filesystem worker just
before each I/O operation (defence in depth against symlink swaps).
"""

from __future__ import annotations

import fnmatch
import ntpath
import os
import re
from dataclasses import dataclass
from pathlib import Path

from mini.config import MiniConfig

IS_WINDOWS = os.name == "nt"

_WIN_RESERVED = re.compile(r"^(con|prn|aux|nul|com[0-9¹²³]|lpt[0-9¹²³]|conin\$|conout\$)(\..*)?$", re.I)


class PathViolation(Exception):
    """Raised when a path breaks the filesystem boundary."""

    def __init__(self, code: str, path: str, detail: str = "") -> None:
        self.code = code
        self.path = path
        self.detail = detail
        super().__init__(f"{code}: {detail or path}")

    @property
    def violation(self) -> str:
        return f"{self.code}:{self.detail or self.path}"


@dataclass(frozen=True)
class CheckedPath:
    path: Path  # canonical, absolute
    root: Path  # approved root that contains it


def _norm(p: str | os.PathLike[str]) -> str:
    return os.path.normcase(os.path.normpath(os.fspath(p)))


def _posix_lower(p: str | os.PathLike[str]) -> str:
    return os.fspath(p).replace("\\", "/").lower()


def is_within(path: str | os.PathLike[str], root: str | os.PathLike[str]) -> bool:
    """True if ``path`` == ``root`` or lies beneath it (both must be canonical)."""
    a, b = _norm(path), _norm(root)
    try:
        return os.path.commonpath([a, b]) == b
    except ValueError:  # different drives / mix of absolute & relative
        return False


class PathGuard:
    def __init__(self, cfg: MiniConfig) -> None:
        self.cfg = cfg
        self.roots: tuple[Path, ...] = tuple(Path(os.path.realpath(r)) for r in cfg.approved_roots)
        self._filename_globs = tuple(g.lower() for g in cfg.filename_globs)
        self._path_globs = tuple(g.lower() for g in cfg.path_globs)
        self._protected = tuple(Path(os.path.realpath(p)) for p in cfg.protected_dirs)
        self._system = tuple(Path(os.path.realpath(p)) for p in cfg.system_dirs)

    # ------------------------------------------------------------------ #
    def _screen(self, raw: object) -> str:
        if not isinstance(raw, str):
            raise PathViolation("PATH_INVALID_TYPE", repr(raw), "path must be a string")
        if not raw.strip():
            raise PathViolation("PATH_EMPTY", raw, "empty path")
        if "\x00" in raw:
            raise PathViolation("PATH_NUL_BYTE", raw.replace("\x00", "\\0"), "NUL byte in path")
        if len(raw) > 4096:
            raise PathViolation("PATH_TOO_LONG", raw[:64] + "...", "path too long")
        if IS_WINDOWS:
            if raw.startswith(("\\\\?\\", "\\\\.\\", "//?/", "//./")):
                raise PathViolation("PATH_DEVICE_NAMESPACE", raw, "device namespace path")
            drive, rest = ntpath.splitdrive(raw)
            if ":" in rest:
                raise PathViolation("PATH_ADS", raw, "alternate data stream / colon in path")
            if drive.startswith(("\\\\", "//")):
                raise PathViolation("PATH_UNC", raw, "UNC/network paths are not allowed")
            for comp in re.split(r"[\\/]+", rest):
                if comp in ("", ".", ".."):
                    continue
                if comp.endswith((".", " ")):
                    raise PathViolation("PATH_WIN_ALIAS", raw, f"trailing dot/space in {comp!r}")
                if _WIN_RESERVED.match(comp):
                    raise PathViolation("PATH_RESERVED_NAME", raw, f"reserved device name {comp!r}")
        return raw

    def canonicalize(self, raw: object) -> Path:
        """Screen + realpath. Relative paths resolve against the first approved root."""
        s = self._screen(raw)
        if s == "~" or s.startswith(("~/", "~\\")):
            s = os.path.join(os.fspath(self.cfg.home), s[2:])
        p = Path(s)
        if not p.is_absolute():
            p = self.roots[0] / p
        try:
            return Path(os.path.realpath(p, strict=False))
        except (OSError, ValueError) as exc:
            raise PathViolation("PATH_UNRESOLVABLE", s, str(exc)) from exc

    def deny_reason(self, canon: Path) -> str | None:
        """Return a violation code if ``canon`` hits the hard denylist."""
        for sysdir in self._system:
            if is_within(canon, sysdir):
                return "DENY_SYSTEM_DIR"
        for prot in self._protected:
            if is_within(canon, prot):
                return "DENY_PROTECTED_DIR"
        name = canon.name.lower()
        for g in self._filename_globs:
            if fnmatch.fnmatchcase(name, g):
                return "DENY_FILENAME"
        full = _posix_lower(canon)
        for g in self._path_globs:
            if fnmatch.fnmatchcase(full, g):
                return "DENY_PATH_PATTERN"
        return None

    def root_for(self, canon: Path) -> Path | None:
        # Longest matching root wins (nested roots).
        best: Path | None = None
        for r in self.roots:
            if is_within(canon, r) and (best is None or len(str(r)) > len(str(best))):
                best = r
        return best

    def check(self, raw: object, *, must_exist: bool = False, kind: str = "any") -> CheckedPath:
        """Full boundary check. Raises ``PathViolation``; returns canonical path."""
        canon = self.canonicalize(raw)
        root = self.root_for(canon)
        if root is None:
            raise PathViolation("OUTSIDE_APPROVED_ROOTS", str(canon), f"{raw!s} -> {canon}")
        reason = self.deny_reason(canon)
        if reason:
            raise PathViolation(reason, str(canon), f"{canon.name} ({reason})")
        if must_exist and not canon.exists():
            raise PathViolation("PATH_NOT_FOUND", str(canon), str(canon))
        if kind == "file" and canon.exists() and not canon.is_file():
            raise PathViolation("PATH_NOT_A_FILE", str(canon), str(canon))
        if kind == "dir" and canon.exists() and not canon.is_dir():
            raise PathViolation("PATH_NOT_A_DIR", str(canon), str(canon))
        return CheckedPath(path=canon, root=root)

    def is_allowed(self, raw: object) -> bool:
        try:
            self.check(raw)
            return True
        except PathViolation:
            return False

    def visible_entry(self, entry: Path) -> bool:
        """Listing filter: hide denylisted entries and symlinks escaping the roots."""
        try:
            canon = Path(os.path.realpath(entry))
        except OSError:
            return False
        if self.root_for(canon) is None:
            return False
        return self.deny_reason(canon) is None and self.deny_reason(Path(os.path.abspath(entry))) is None
