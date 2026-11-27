"""Policy/config loader.

Loads ``config/policy.yaml`` into an immutable, fully-resolved ``MiniConfig``:
every path is expanded (``~``), made absolute against the *project root*
(never the CWD) and canonicalized with ``os.path.realpath`` once, at load time.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Mapping

import yaml
from pydantic import BaseModel, ConfigDict, Field

from mini.schemas import ActionType, RiskLevel

DEFAULT_PROJECT_ROOT = Path(__file__).resolve().parents[2]  # .../laptop


class ToolRule(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    server: str
    risk: RiskLevel
    path_args: tuple[str, ...] = ()
    path_list_args: tuple[str, ...] = ()
    task_scoped: bool = False
    action_type: ActionType | None = None


class Escalation(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    id: str
    tools: tuple[str, ...]
    path_globs: tuple[str, ...]
    risk: RiskLevel


class Limits(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    max_read_bytes: int = 1_048_576
    max_write_bytes: int = 1_048_576
    max_list_entries: int = 500
    max_diff_bytes: int = 200_000
    max_attachment_bytes: int = 10_485_760
    max_recipients: int = 20
    max_gmail_results: int = 50


class GmailPolicy(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    scopes: tuple[str, ...] = ()
    allowed_recipient_domains: tuple[str, ...] = ()
    blocked_recipient_domains: tuple[str, ...] = ()


class GitPolicy(BaseModel):
    """Allowlists for the isolated git worker.

    ``allowed_remotes`` maps a remote name to the ONLY URL Mini will ever push
    to for that name. In real mode the URL must be ``https://`` without
    embedded credentials; in mock mode (``MINI_GIT_MOCK=true``) a local bare
    repository path is also accepted (offline tests).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")
    allowed_remotes: dict[str, str] = Field(default_factory=dict)
    allowed_branches: tuple[str, ...] = ("main",)
    max_files: int = 50
    max_commit_message_bytes: int = 4096


class MiniConfig(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    project_root: Path
    config_path: Path | None = None
    home: Path

    host: str = "127.0.0.1"
    port: int = 8765
    mcp_path: str = "/mcp"
    require_bearer_token: bool = True
    dev_mode: bool = False
    approval_wait_seconds: float = 120
    contract_ttl_seconds: int = 300
    kill_switch_grace_ms: int = 500

    mini_home: Path
    secrets_dir: Path
    trusted_devices: Path
    workspaces_dir: Path
    logs_dir: Path
    state_db: Path

    approved_roots: tuple[Path, ...]
    filename_globs: tuple[str, ...]
    path_globs: tuple[str, ...]
    protected_dirs: tuple[Path, ...]
    system_dirs: tuple[Path, ...]

    limits: Limits = Field(default_factory=Limits)
    gmail: GmailPolicy = Field(default_factory=GmailPolicy)
    git: GitPolicy = Field(default_factory=GitPolicy)
    tools: dict[str, ToolRule]
    escalations: tuple[Escalation, ...] = ()

    @property
    def audit_jsonl(self) -> Path:
        return self.logs_dir / "audit.jsonl"


def _truthy(v: str | None) -> bool | None:
    if v is None:
        return None
    return v.strip().lower() in {"1", "true", "yes", "on"}


def resolve_path(raw: str | os.PathLike[str], *, base: Path, home: Path) -> Path:
    s = os.fspath(raw)
    if s == "~" or s.startswith(("~/", "~\\")):
        s = os.path.join(os.fspath(home), s[2:])
    p = Path(s)
    if not p.is_absolute():
        p = base / p
    return Path(os.path.realpath(p))


def load_config(
    path: str | os.PathLike[str] | None = None,
    *,
    project_root: str | os.PathLike[str] | None = None,
    home: str | os.PathLike[str] | None = None,
    env: Mapping[str, str] | None = None,
    **overrides: Any,
) -> MiniConfig:
    """Load and resolve the policy.

    ``overrides`` may replace any top-level ``MiniConfig`` field *after*
    resolution (paths given as overrides are resolved the same way).
    """
    env = os.environ if env is None else env
    root = Path(os.path.realpath(project_root or DEFAULT_PROJECT_ROOT))
    home_p = Path(os.path.realpath(home or Path.home()))
    cfg_path = Path(path or env.get("MINI_CONFIG") or root / "config" / "policy.yaml")
    if not cfg_path.is_absolute():
        cfg_path = root / cfg_path
    raw: dict[str, Any] = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}

    def rp(x: str | os.PathLike[str]) -> Path:
        return resolve_path(x, base=root, home=home_p)

    daemon = raw.get("daemon", {}) or {}
    paths = raw.get("paths", {}) or {}
    deny = raw.get("denylist", {}) or {}

    mini_home = rp(env.get("MINI_HOME") or paths.get("mini_home", "~/.mini"))
    if env.get("MINI_HOME"):
        secrets_dir = mini_home / "secrets"
        trusted = mini_home / "trusted_devices.json"
    else:
        secrets_dir = rp(paths.get("secrets_dir", "~/.mini/secrets"))
        trusted = rp(paths.get("trusted_devices", "~/.mini/trusted_devices.json"))

    roots_src: list[str] = list(raw.get("approved_roots", []) or [])
    if env.get("MINI_APPROVED_ROOTS"):
        roots_src = [r for r in env["MINI_APPROVED_ROOTS"].split(os.pathsep) if r.strip()]

    sys_key = "windows" if os.name == "nt" else "posix"
    system_dirs = [rp(p) for p in (deny.get("system_dirs", {}) or {}).get(sys_key, [])]
    if os.name == "nt" and env.get("SystemRoot"):
        system_dirs.append(rp(env["SystemRoot"]))

    values: dict[str, Any] = dict(
        project_root=root,
        config_path=cfg_path,
        home=home_p,
        host=daemon.get("host", "127.0.0.1"),
        port=int(daemon.get("port", 8765)),
        mcp_path=daemon.get("mcp_path", "/mcp"),
        require_bearer_token=bool(daemon.get("require_bearer_token", True)),
        dev_mode=bool(daemon.get("dev_mode", False)),
        approval_wait_seconds=float(daemon.get("approval_wait_seconds", 120)),
        contract_ttl_seconds=int(daemon.get("contract_ttl_seconds", 300)),
        kill_switch_grace_ms=int(daemon.get("kill_switch_grace_ms", 500)),
        mini_home=mini_home,
        secrets_dir=secrets_dir,
        trusted_devices=trusted,
        workspaces_dir=rp(paths.get("workspaces_dir", "./workspaces")),
        logs_dir=rp(paths.get("logs_dir", "./logs")),
        state_db=rp(paths.get("state_db", "./state/mini.db")),
        approved_roots=[rp(r) for r in roots_src],
        filename_globs=list(deny.get("filename_globs", []) or []),
        path_globs=list(deny.get("path_globs", []) or []),
        protected_dirs=[rp(p) for p in deny.get("protected_dirs", []) or []],
        system_dirs=system_dirs,
        limits=Limits(**(raw.get("limits", {}) or {})),
        gmail=GmailPolicy(**(raw.get("gmail", {}) or {})),
        git=GitPolicy(**(raw.get("git", {}) or {})),
        tools={name: ToolRule(**rule) for name, rule in (raw.get("tools", {}) or {}).items()},
        escalations=[Escalation(**e) for e in raw.get("escalations", []) or []],
    )

    if (v := _truthy(env.get("MINI_DEV_MODE"))) is not None:
        values["dev_mode"] = v
    if env.get("MINI_APPROVAL_WAIT_SECONDS"):
        values["approval_wait_seconds"] = float(env["MINI_APPROVAL_WAIT_SECONDS"])

    path_fields = {"mini_home", "secrets_dir", "trusted_devices", "workspaces_dir", "logs_dir", "state_db"}
    for key, val in overrides.items():
        if key in path_fields:
            val = rp(val)
        elif key in {"approved_roots", "protected_dirs", "system_dirs"}:
            val = [rp(v) for v in val]
        values[key] = val

    # Mini's own secret/state locations are ALWAYS protected, whatever the YAML says.
    forced = [values["mini_home"], values["secrets_dir"], values["workspaces_dir"],
              values["logs_dir"], Path(values["state_db"]).parent, cfg_path.parent]
    prot = list(values["protected_dirs"])
    for p in forced:
        p = Path(os.path.realpath(p))
        if p not in prot:
            prot.append(p)
    values["protected_dirs"] = prot

    if not values["approved_roots"]:
        raise ValueError("policy must define at least one approved root")
    return MiniConfig(**values)
