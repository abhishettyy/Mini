"""Deterministic L0–L3 classifier and rule evaluator.

``evaluate(ToolCall) -> PolicyDecision`` is a pure function of
``(policy.yaml, server, tool, arguments, filesystem realpath state)``. The
planner cannot pass a risk level: unexpected arguments (including
``risk_level`` / ``confirm_destructive``) are rejected outright.
"""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path
from typing import Any

from mini.config import MiniConfig
from mini.schemas import (
    PolicyDecision,
    RiskLevel,
    ToolCall,
    Verdict,
    compute_params_hash,
)
from mini.security.git_guard import REMOTE_NAME_RE, validate_repo_files
from mini.security.path_guard import PathGuard, PathViolation

TASK_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
OPAQUE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$")

# tool -> (required args, optional args with defaults)
TOOL_SIGNATURES: dict[str, tuple[frozenset[str], dict[str, Any]]] = {
    "fs_list_dir": (frozenset({"path"}), {}),
    "fs_read_file": (frozenset({"path"}), {}),
    "fs_write_staged": (frozenset({"task_id", "target_path", "content"}), {}),
    "fs_commit_staged": (frozenset({"task_id", "target_path"}), {}),
    "fs_delete_file": (frozenset({"task_id", "path"}), {}),
    "gmail_search": (frozenset({"query"}), {"max_results": 10}),
    "gmail_read_message": (frozenset({"message_id"}), {}),
    "gmail_stage_draft": (
        frozenset({"task_id", "to", "subject", "body"}),
        {"cc": [], "bcc": [], "attachment_paths": []},
    ),
    "gmail_send_staged": (frozenset({"task_id", "staged_draft_id"}), {}),
    "git_status": (frozenset({"repo_path"}), {}),
    "git_diff": (frozenset({"repo_path"}), {"staged": False}),
    "git_stage_commit": (
        frozenset({"task_id", "repo_path", "files", "commit_message"}),
        {"remote": "origin"},
    ),
    "git_commit_and_push": (frozenset({"task_id", "staged_commit_id"}), {}),
}

_STR_ARGS = {"path", "target_path", "content", "task_id", "query", "message_id",
             "subject", "body", "staged_draft_id", "repo_path", "commit_message",
             "staged_commit_id", "remote"}
_LIST_STR_ARGS = {"to", "cc", "bcc", "attachment_paths", "files"}
_BOOL_ARGS = {"staged"}

_VERDICT_FOR_RISK = {
    RiskLevel.L0: Verdict.ALLOW,
    RiskLevel.L1: Verdict.STAGE,
    RiskLevel.L2: Verdict.REQUIRE_APPROVAL,
    RiskLevel.L3: Verdict.REQUIRE_APPROVAL,
}


class PolicyEngine:
    def __init__(self, cfg: MiniConfig, guard: PathGuard | None = None) -> None:
        self.cfg = cfg
        self.guard = guard or PathGuard(cfg)

    # ------------------------------------------------------------------ #
    def evaluate(self, call: ToolCall) -> PolicyDecision:
        violations: list[str] = []
        reasons: list[str] = []
        matched: list[str] = []
        args: dict[str, Any] = dict(call.arguments)

        rule = self.cfg.tools.get(call.tool)
        sig = TOOL_SIGNATURES.get(call.tool)
        if rule is None or sig is None:
            return self._deny(call, args, RiskLevel.L3, ["UNKNOWN_TOOL:" + call.tool],
                              ["tool is not in the policy allowlist"])
        risk = rule.risk
        matched.append(f"tool:{call.tool}:{rule.risk}")

        if call.server != rule.server:
            return self._deny(call, args, risk, [f"SERVER_MISMATCH:{call.server}!={rule.server}"],
                              ["tool is not served by the requested server"])

        # --- argument schema --------------------------------------------
        required, optional = sig
        allowed = required | set(optional)
        extra = sorted(set(args) - allowed)
        missing = sorted(required - set(args))
        if extra:
            violations.append("UNEXPECTED_ARGUMENT:" + ",".join(extra))
        if missing:
            violations.append("MISSING_ARGUMENT:" + ",".join(missing))
        if violations:
            return self._deny(call, args, risk, violations, ["argument schema violation"])
        for k, default in optional.items():
            args.setdefault(k, list(default) if isinstance(default, list) else default)

        for k, v in args.items():
            if k in _STR_ARGS and not isinstance(v, str):
                violations.append(f"BAD_TYPE:{k}:expected str")
            elif k in _LIST_STR_ARGS and not (isinstance(v, list) and all(isinstance(i, str) for i in v)):
                violations.append(f"BAD_TYPE:{k}:expected list[str]")
            elif k in _BOOL_ARGS and not isinstance(v, bool):
                violations.append(f"BAD_TYPE:{k}:expected bool")
            elif k == "max_results" and (isinstance(v, bool) or not isinstance(v, int) or v < 1):
                violations.append("BAD_TYPE:max_results:expected positive int")
        if violations:
            return self._deny(call, args, risk, violations, ["argument type violation"])

        # --- task scoping --------------------------------------------------
        if rule.task_scoped and not TASK_ID_RE.fullmatch(args.get("task_id", "")):
            return self._deny(call, args, risk, ["INVALID_TASK_ID"],
                              ["task_id must match ^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$"])

        # --- filesystem boundary --------------------------------------------
        for name in rule.path_args:
            try:
                args[name] = str(self.guard.check(args[name]).path)
            except PathViolation as exc:
                violations.append(exc.violation)
        for name in rule.path_list_args:
            canon_list = []
            for item in args.get(name, []):
                try:
                    canon_list.append(str(self.guard.check(item, must_exist=True, kind="file").path))
                except PathViolation as exc:
                    violations.append(exc.violation)
            args[name] = canon_list
        if violations:
            return self._deny(call, args, risk, violations, ["filesystem boundary violation"])

        # --- tool-specific content rules --------------------------------------
        violations += self._content_rules(call.tool, args, reasons)
        if violations:
            return self._deny(call, args, risk, violations, reasons or ["content policy violation"])

        # --- monotonic escalation --------------------------------------------
        paths = [args[n] for n in rule.path_args if n in args]
        paths += [p for n in rule.path_list_args for p in args.get(n, [])]
        risk, esc_reasons, esc_rules, _ = self.escalate_for_paths(call.tool, risk, paths)
        reasons += esc_reasons
        matched += esc_rules

        verdict = _VERDICT_FOR_RISK[risk]
        action_type = rule.action_type
        if verdict is Verdict.REQUIRE_APPROVAL and action_type is None:
            return self._deny(call, args, risk, ["NO_ACTION_TYPE"],
                              ["approval-gated tool lacks an action_type in policy"])
        reasons.append({Verdict.ALLOW: "read-only; auto-execute",
                        Verdict.STAGE: "reversible; confined to task staging",
                        Verdict.REQUIRE_APPROVAL: "requires signed approval contract"}[verdict])
        return PolicyDecision(
            call_id=call.call_id,
            server=call.server,
            tool=call.tool,
            task_id=args.get("task_id") if isinstance(args.get("task_id"), str) else None,
            verdict=verdict,
            risk_level=risk,
            action_type=action_type if risk.requires_approval else None,
            canonical_args=args,
            params_hash_sha256=compute_params_hash(call.server, call.tool, args),
            reasons=reasons,
            matched_rules=matched,
        )

    # ------------------------------------------------------------------ #
    def escalate_for_paths(
        self, tool: str, risk: RiskLevel, paths: list[str]
    ) -> tuple[RiskLevel, list[str], list[str], list[str]]:
        """Apply monotonic escalation rules for ``tool`` to ``paths``.

        Returns ``(risk, reasons, matched_rules, matched_paths)``. Never lowers risk.
        """
        reasons: list[str] = []
        matched: list[str] = []
        hit_paths: list[str] = []
        for esc in self.cfg.escalations:
            if tool not in esc.tools:
                continue
            hits = [p for p in paths
                    if any(fnmatch.fnmatchcase(p.replace("\\", "/").lower(), g.lower()) for g in esc.path_globs)]
            if hits:
                hit_paths += [h for h in hits if h not in hit_paths]
                new = RiskLevel.max(risk, esc.risk)
                if new is not risk:
                    reasons.append(f"escalated {risk}->{new} by rule {esc.id}")
                    matched.append(f"escalation:{esc.id}")
                    risk = new
        return risk, reasons, matched, hit_paths

    # ------------------------------------------------------------------ #
    def _git_rules(self, tool: str, args: dict[str, Any]) -> list[str]:
        gp = self.cfg.git
        v: list[str] = []
        if tool == "git_stage_commit":
            msg = args["commit_message"]
            if not msg.strip():
                v.append("EMPTY_COMMIT_MESSAGE")
            if "\x00" in msg:
                v.append("COMMIT_MESSAGE_NUL_BYTE")
            if len(msg.encode("utf-8")) > gp.max_commit_message_bytes:
                v.append(f"COMMIT_MESSAGE_TOO_LONG:>{gp.max_commit_message_bytes}B")
            remote = args["remote"]
            if not REMOTE_NAME_RE.fullmatch(remote) or remote not in gp.allowed_remotes:
                v.append(f"REMOTE_NOT_ALLOWED:{remote[:64]}")
            try:
                args["files"] = validate_repo_files(
                    self.guard, Path(args["repo_path"]), args["files"], max_files=gp.max_files
                )
            except PathViolation as exc:
                v.append(exc.violation)
        if tool == "git_commit_and_push" and not OPAQUE_ID_RE.fullmatch(args["staged_commit_id"]):
            v.append("INVALID_STAGED_COMMIT_ID")
        return v

    def _content_rules(self, tool: str, args: dict[str, Any], reasons: list[str]) -> list[str]:
        lim = self.cfg.limits
        v: list[str] = []
        if tool.startswith("git_"):
            v += self._git_rules(tool, args)
        if tool == "fs_write_staged" and len(args["content"].encode("utf-8")) > lim.max_write_bytes:
            v.append(f"CONTENT_TOO_LARGE:>{lim.max_write_bytes}B")
        if tool == "gmail_search":
            if args["max_results"] > lim.max_gmail_results:
                reasons.append(f"max_results clamped to {lim.max_gmail_results}")
                args["max_results"] = lim.max_gmail_results
            if len(args["query"]) > 1024:
                v.append("QUERY_TOO_LONG")
        if tool == "gmail_read_message" and not OPAQUE_ID_RE.fullmatch(args["message_id"]):
            v.append("INVALID_MESSAGE_ID")
        if tool == "gmail_send_staged" and not OPAQUE_ID_RE.fullmatch(args["staged_draft_id"]):
            v.append("INVALID_STAGED_DRAFT_ID")
        if tool == "gmail_stage_draft":
            recips = [r.strip() for k in ("to", "cc", "bcc") for r in args[k]]
            for k in ("to", "cc", "bcc"):
                args[k] = [r.strip() for r in args[k]]
            if not args["to"]:
                v.append("NO_RECIPIENTS")
            if len(recips) > lim.max_recipients:
                v.append(f"TOO_MANY_RECIPIENTS:>{lim.max_recipients}")
            allowed = {d.lower() for d in self.cfg.gmail.allowed_recipient_domains}
            blocked = {d.lower() for d in self.cfg.gmail.blocked_recipient_domains}
            for r in recips:
                if not EMAIL_RE.fullmatch(r):
                    v.append(f"INVALID_RECIPIENT:{r[:80]}")
                    continue
                domain = r.rsplit("@", 1)[1].lower()
                if domain in blocked or (allowed and domain not in allowed):
                    v.append(f"RECIPIENT_DOMAIN_BLOCKED:{domain}")
            if any(c in args["subject"] for c in "\r\n"):
                v.append("HEADER_INJECTION:subject")
            if len(args["subject"]) > 998:
                v.append("SUBJECT_TOO_LONG")
            if len(args["body"].encode("utf-8")) > lim.max_write_bytes:
                v.append("BODY_TOO_LARGE")
            names = [p.replace("\\", "/").rsplit("/", 1)[-1].lower() for p in args["attachment_paths"]]
            if len(set(names)) != len(names):
                v.append("DUPLICATE_ATTACHMENT_NAME")
        return v

    def _deny(self, call: ToolCall, args: dict[str, Any], risk: RiskLevel,
              violations: list[str], reasons: list[str]) -> PolicyDecision:
        try:
            phash = compute_params_hash(call.server, call.tool, args)
        except Exception:  # un-canonicalizable garbage from the planner
            phash = compute_params_hash(call.server, call.tool, {"_unhashable": True})
        return PolicyDecision(
            call_id=call.call_id,
            server=call.server,
            tool=call.tool,
            task_id=call.task_id,
            verdict=Verdict.DENY,
            risk_level=risk,
            canonical_args={},
            params_hash_sha256=phash,
            reasons=reasons,
            violations=violations,
        )
