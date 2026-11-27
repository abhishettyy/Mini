"""MCP Policy Proxy: intercepts every OpenClaw tool call before any worker runs.

* Exposes the exact 13-tool surface over MCP Streamable HTTP (``/mcp``):
  5 filesystem, 4 gmail, 4 git.
* Evaluates ``PolicyEngine`` deterministically (OpenClaw cannot supply risk).
* L0 (ALLOW) and L1 (STAGE) execute via ``MCPClientPool``.
* L2/L3 (REQUIRE_APPROVAL) freeze immutable evidence + artifact hashes, issue an
  RFC 8785 ``ApprovalContract``, wait up to ``approval_wait_seconds`` for an
  Ed25519-signed decision, verify signature + TTL + SQLite nonce, and execute
  from the immutable blob/draft after TOCTOU checks.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import mcp.types as types
from mcp.server.lowlevel import Server

from mini.config import MiniConfig
from mini.schemas import (
    ApprovalContract,
    ApprovalRecord,
    ArtifactHashes,
    AuditEventType,
    ContractStatus,
    DeleteArtifactHashes,
    EmailArtifactHashes,
    Evidence,
    FileArtifactHashes,
    GitArtifactHashes,
    PolicyDecision,
    ProxyResult,
    ProxyStatus,
    SignedApproval,
    ToolCall,
    Verdict,
)
from mini.security.audit import AuditLogger
from mini.security.contracts import (
    ContractError,
    ContractStore,
    ContractVerifier,
    ReplayError,
)
from mini.security.path_guard import PathGuard
from mini.security.policy_engine import PolicyEngine
from mini.security.staging import StagingEngine, StagingError, TOCTOUError
from mini.daemon.mcp_client_pool import MCPClientPool, PoolError, PoolPausedError, WorkerToolError

TOCTOU_CODES = {
    "DESTINATION_DRIFT",
    "BLOB_TAMPERED",
    "BLOB_MISSING",
    "POST_WRITE_MISMATCH",
    "ATTACHMENT_DRIFT",
    "ATTACHMENT_TAMPERED",
    "DRAFT_TAMPERED",
    "PROPOSAL_TAMPERED",
    "GIT_STAGED_DRIFT",
    "GIT_BRANCH_DRIFT",
    "GIT_REMOTE_DRIFT",
    "POST_COMMIT_MISMATCH",
}


def _git_tools() -> list[types.Tool]:
    repo = {"type": "string", "description": "Path to a git work-tree root inside an approved root"}
    return [
        types.Tool(
            name="git_status",
            description="[L0 Read-Only] Current branch, clean/dirty state and changed files (denylisted files hidden).",
            inputSchema={
                "type": "object",
                "properties": {"repo_path": repo},
                "required": ["repo_path"],
                "additionalProperties": False,
            },
        ),
        types.Tool(
            name="git_diff",
            description="[L0 Read-Only] Compact unified diff of unstaged (default) or staged changes.",
            inputSchema={
                "type": "object",
                "properties": {"repo_path": repo, "staged": {"type": "boolean", "default": False}},
                "required": ["repo_path"],
                "additionalProperties": False,
            },
        ),
        types.Tool(
            name="git_stage_commit",
            description=("[L1 Staged] `git add` the given files and freeze an immutable commit proposal "
                         "(diff SHA-256 + staged tree + message). Returns staged_commit_id."),
            inputSchema={
                "type": "object",
                "properties": {
                    "task_id": {"type": "string"},
                    "repo_path": repo,
                    "files": {"type": "array", "items": {"type": "string"}, "minItems": 1},
                    "commit_message": {"type": "string"},
                    "remote": {"type": "string", "default": "origin"},
                },
                "required": ["task_id", "repo_path", "files", "commit_message"],
                "additionalProperties": False,
            },
        ),
        types.Tool(
            name="git_commit_and_push",
            description=("[L2 Approval-Gated; L3 for CI/executable files] Request human Ed25519 approval to "
                         "commit the staged proposal and push it to the allowlisted remote/branch."),
            inputSchema={
                "type": "object",
                "properties": {"task_id": {"type": "string"}, "staged_commit_id": {"type": "string"}},
                "required": ["task_id", "staged_commit_id"],
                "additionalProperties": False,
            },
        ),
    ]


def _public_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="fs_list_dir",
            description="[L0 Read-Only] List contents of an approved directory (denylisted entries hidden).",
            inputSchema={
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
                "additionalProperties": False,
            },
        ),
        types.Tool(
            name="fs_read_file",
            description="[L0 Read-Only] Read UTF-8 text from an approved, non-denylisted file.",
            inputSchema={
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
                "additionalProperties": False,
            },
        ),
        types.Tool(
            name="fs_write_staged",
            description="[L1 Staged] Write proposed file content into isolated per-task staging and return unified diff.",
            inputSchema={
                "type": "object",
                "properties": {
                    "task_id": {"type": "string"},
                    "target_path": {"type": "string"},
                    "content": {"type": "string"},
                },
                "required": ["task_id", "target_path", "content"],
                "additionalProperties": False,
            },
        ),
        types.Tool(
            name="fs_commit_staged",
            description="[L2 Approval-Gated] Request human Ed25519 approval to commit staged file to target_path.",
            inputSchema={
                "type": "object",
                "properties": {
                    "task_id": {"type": "string"},
                    "target_path": {"type": "string"},
                },
                "required": ["task_id", "target_path"],
                "additionalProperties": False,
            },
        ),
        types.Tool(
            name="fs_delete_file",
            description="[L3 Destructive] Request explicit destructive human Ed25519 approval to delete a file.",
            inputSchema={
                "type": "object",
                "properties": {
                    "task_id": {"type": "string"},
                    "path": {"type": "string"},
                },
                "required": ["task_id", "path"],
                "additionalProperties": False,
            },
        ),
        types.Tool(
            name="gmail_search",
            description="[L0 Read-Only] Search mailbox metadata and snippets.",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "max_results": {"type": "integer", "minimum": 1, "default": 10},
                },
                "required": ["query"],
                "additionalProperties": False,
            },
        ),
        types.Tool(
            name="gmail_read_message",
            description="[L0 Read-Only] Read message headers and body by message_id.",
            inputSchema={
                "type": "object",
                "properties": {"message_id": {"type": "string"}},
                "required": ["message_id"],
                "additionalProperties": False,
            },
        ),
        types.Tool(
            name="gmail_stage_draft",
            description="[L1 Staged] Validate attachments and create an immutable staged email draft.",
            inputSchema={
                "type": "object",
                "properties": {
                    "task_id": {"type": "string"},
                    "to": {"type": "array", "items": {"type": "string"}},
                    "subject": {"type": "string"},
                    "body": {"type": "string"},
                    "cc": {"type": "array", "items": {"type": "string"}, "default": []},
                    "bcc": {"type": "array", "items": {"type": "string"}, "default": []},
                    "attachment_paths": {"type": "array", "items": {"type": "string"}, "default": []},
                },
                "required": ["task_id", "to", "subject", "body"],
                "additionalProperties": False,
            },
        ),
        types.Tool(
            name="gmail_send_staged",
            description="[L2 Approval-Gated] Request human Ed25519 approval to send a staged email draft.",
            inputSchema={
                "type": "object",
                "properties": {
                    "task_id": {"type": "string"},
                    "staged_draft_id": {"type": "string"},
                },
                "required": ["task_id", "staged_draft_id"],
                "additionalProperties": False,
            },
        ),
        *_git_tools(),
    ]


class MCPPolicyProxy:
    def __init__(
        self,
        *,
        cfg: MiniConfig,
        guard: PathGuard,
        engine: PolicyEngine,
        staging: StagingEngine,
        verifier: ContractVerifier,
        contracts: ContractStore,
        audit: AuditLogger,
        pool: MCPClientPool,
    ) -> None:
        self.cfg = cfg
        self.guard = guard
        self.engine = engine
        self.staging = staging
        self.verifier = verifier
        self.contracts = contracts
        self.audit = audit
        self.pool = pool
        self._waiters: dict[str, asyncio.Event] = {}
        self.mcp_server = self._build_mcp_server()

    # ------------------------------------------------------------------ #
    # MCP Server (Streamable HTTP facing OpenClaw)
    # ------------------------------------------------------------------ #
    def _build_mcp_server(self) -> Server:
        async def on_list_tools(_ctx: Any, _params: Any) -> types.ListToolsResult:
            return types.ListToolsResult(tools=_public_tools())

        async def on_call_tool(ctx: Any, params: types.CallToolRequestParams) -> types.CallToolResult:
            session_id = getattr(ctx, "session_id", None)
            res = await self.handle_tool_call(
                params.name, dict(params.arguments or {}), session_id=session_id
            )
            payload = res.model_dump(mode="json")
            is_err = res.status in (
                ProxyStatus.DENIED,
                ProxyStatus.REJECTED,
                ProxyStatus.FAILED,
                ProxyStatus.PAUSED,
            )
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=json.dumps(payload, ensure_ascii=False))],
                structured_content=payload,
                is_error=is_err,
            )

        return Server(
            "mini-policy-proxy",
            version="0.1.0",
            instructions=(
                "Mini Independent MCP Policy Proxy. All operations are policy-checked. "
                "L2/L3 operations require out-of-band human Ed25519 approval."
            ),
            on_list_tools=on_list_tools,
            on_call_tool=on_call_tool,
        )

    # ------------------------------------------------------------------ #
    # Tool call interception pipeline
    # ------------------------------------------------------------------ #
    async def handle_tool_call(
        self,
        tool: str,
        arguments: dict[str, Any],
        *,
        session_id: str | None = None,
    ) -> ProxyResult:
        rule = self.cfg.tools.get(tool)
        server = rule.server if rule else "unknown"
        call = ToolCall(server=server, tool=tool, arguments=arguments, session_id=session_id)

        self.audit.append(
            AuditEventType.TOOL_CALL_RECEIVED,
            task_id=call.task_id,
            call_id=call.call_id,
            server=server,
            tool=tool,
            details={"arguments": arguments, "session_id": session_id},
        )

        if self.pool.paused:
            self.audit.append(
                AuditEventType.SECURITY_VIOLATION,
                task_id=call.task_id,
                call_id=call.call_id,
                server=server,
                tool=tool,
                verdict=Verdict.DENY,
                details={"reason": "KILL_SWITCH_ACTIVE"},
            )
            return ProxyResult(
                status=ProxyStatus.PAUSED,
                call_id=call.call_id,
                tool=tool,
                verdict=Verdict.DENY,
                error="KILL_SWITCH_ACTIVE: execution paused until reset",
                reasons=["kill switch engaged"],
            )

        decision = self.engine.evaluate(call)
        self.audit.append(
            AuditEventType.POLICY_DECISION,
            task_id=decision.task_id,
            call_id=call.call_id,
            server=decision.server,
            tool=decision.tool,
            risk_level=decision.risk_level,
            verdict=decision.verdict,
            details={
                "params_hash_sha256": decision.params_hash_sha256,
                "matched_rules": decision.matched_rules,
                "reasons": decision.reasons,
                "violations": decision.violations,
            },
        )

        if decision.verdict is Verdict.DENY:
            self.audit.append(
                AuditEventType.SECURITY_VIOLATION,
                task_id=decision.task_id,
                call_id=call.call_id,
                server=decision.server,
                tool=decision.tool,
                risk_level=decision.risk_level,
                verdict=Verdict.DENY,
                details={"violations": decision.violations, "reasons": decision.reasons},
            )
            return ProxyResult(
                status=ProxyStatus.DENIED,
                call_id=call.call_id,
                tool=tool,
                risk_level=decision.risk_level,
                verdict=decision.verdict,
                error="; ".join(decision.violations or decision.reasons),
                reasons=decision.reasons,
            )

        if decision.verdict in (Verdict.ALLOW, Verdict.STAGE):
            return await self._execute_direct(decision)

        # L2 / L3 -> Evidence + Approval Contract
        return await self._handle_approval_required(decision)

    async def _execute_direct(self, decision: PolicyDecision) -> ProxyResult:
        self.audit.append(
            AuditEventType.EXECUTION_STARTED,
            task_id=decision.task_id,
            call_id=decision.call_id,
            server=decision.server,
            tool=decision.tool,
            risk_level=decision.risk_level,
            verdict=decision.verdict,
        )
        try:
            result = await self.pool.call_tool(
                decision.server, decision.tool, decision.canonical_args
            )
        except PoolPausedError as exc:
            return ProxyResult(
                status=ProxyStatus.PAUSED,
                call_id=decision.call_id,
                tool=decision.tool,
                risk_level=decision.risk_level,
                verdict=decision.verdict,
                error=str(exc),
            )
        except PoolError as exc:
            self.audit.append(
                AuditEventType.EXECUTION_FAILED,
                task_id=decision.task_id,
                call_id=decision.call_id,
                server=decision.server,
                tool=decision.tool,
                risk_level=decision.risk_level,
                details={"code": exc.code, "error": exc.detail},
            )
            return ProxyResult(
                status=ProxyStatus.FAILED,
                call_id=decision.call_id,
                tool=decision.tool,
                risk_level=decision.risk_level,
                verdict=decision.verdict,
                error=f"{exc.code}: {exc.detail}",
            )

        if decision.verdict is Verdict.STAGE:
            self.audit.append(
                AuditEventType.STAGED,
                task_id=decision.task_id,
                call_id=decision.call_id,
                server=decision.server,
                tool=decision.tool,
                risk_level=decision.risk_level,
                verdict=decision.verdict,
                details={k: v for k, v in result.items() if k != "content"},
            )
        self.audit.append(
            AuditEventType.EXECUTION_SUCCEEDED,
            task_id=decision.task_id,
            call_id=decision.call_id,
            server=decision.server,
            tool=decision.tool,
            risk_level=decision.risk_level,
            verdict=decision.verdict,
        )
        return ProxyResult(
            status=ProxyStatus.OK,
            call_id=decision.call_id,
            tool=decision.tool,
            risk_level=decision.risk_level,
            verdict=decision.verdict,
            result=result,
            reasons=decision.reasons,
        )

    async def _handle_approval_required(self, decision: PolicyDecision) -> ProxyResult:
        try:
            evidence, artifact_hashes, target, decision = self._prepare_evidence(decision)
        except StagingError as exc:
            self.audit.append(
                AuditEventType.EXECUTION_FAILED,
                task_id=decision.task_id,
                call_id=decision.call_id,
                server=decision.server,
                tool=decision.tool,
                risk_level=decision.risk_level,
                details={"code": exc.code, "error": exc.detail},
            )
            return ProxyResult(
                status=ProxyStatus.FAILED,
                call_id=decision.call_id,
                tool=decision.tool,
                risk_level=decision.risk_level,
                verdict=decision.verdict,
                error=f"{exc.code}: {exc.detail}",
            )

        contract = ApprovalContract.issue(
            task_id=decision.task_id or "default",
            action_type=decision.action_type,  # type: ignore[arg-type]
            risk_level=decision.risk_level,
            target=target,
            params_hash_sha256=decision.params_hash_sha256,
            artifact_hashes=artifact_hashes,
            ttl_seconds=self.cfg.contract_ttl_seconds,
        )
        rec = ApprovalRecord(
            contract=contract,
            evidence=evidence,
            call_id=decision.call_id,
            server=decision.server,
            tool=decision.tool,
            canonical_args=decision.canonical_args,
        )
        self.contracts.put(rec)
        ev = asyncio.Event()
        self._waiters[contract.contract_id] = ev

        self.audit.append(
            AuditEventType.CONTRACT_ISSUED,
            task_id=contract.task_id,
            call_id=decision.call_id,
            contract_id=contract.contract_id,
            server=decision.server,
            tool=decision.tool,
            risk_level=decision.risk_level,
            verdict=decision.verdict,
            details={
                "action_type": contract.action_type.value,
                "target": contract.target,
                "expires_at": contract.expires_at,
                "contract_hash": contract.contract_hash(),
            },
        )

        wait_s = max(0.0, float(self.cfg.approval_wait_seconds))
        try:
            if wait_s > 0:
                await asyncio.wait_for(ev.wait(), timeout=wait_s)
            else:
                raise asyncio.TimeoutError
        except asyncio.TimeoutError:
            self.audit.append(
                AuditEventType.APPROVAL_PENDING,
                task_id=contract.task_id,
                call_id=decision.call_id,
                contract_id=contract.contract_id,
                server=decision.server,
                tool=decision.tool,
                risk_level=decision.risk_level,
                details={"wait_seconds": wait_s},
            )
            return ProxyResult(
                status=ProxyStatus.APPROVAL_PENDING,
                call_id=decision.call_id,
                tool=decision.tool,
                risk_level=decision.risk_level,
                verdict=decision.verdict,
                contract_id=contract.contract_id,
                result={"approval_pending": True, "contract_id": contract.contract_id,
                        "expires_at": contract.expires_at},
                reasons=["awaiting signed approval contract"],
            )
        finally:
            self._waiters.pop(contract.contract_id, None)

        latest = self.contracts.get(contract.contract_id)
        if latest is None:
            return ProxyResult(status=ProxyStatus.FAILED, call_id=decision.call_id,
                               tool=decision.tool, contract_id=contract.contract_id, error="contract vanished")
        if latest.status is ContractStatus.EXECUTED:
            return ProxyResult(
                status=ProxyStatus.OK,
                call_id=decision.call_id,
                tool=decision.tool,
                risk_level=decision.risk_level,
                verdict=decision.verdict,
                contract_id=contract.contract_id,
                result=latest.outcome,
            )
        if latest.status is ContractStatus.REVOKED:
            return ProxyResult(
                status=ProxyStatus.PAUSED,
                call_id=decision.call_id,
                tool=decision.tool,
                risk_level=decision.risk_level,
                verdict=decision.verdict,
                contract_id=contract.contract_id,
                error="contract revoked by emergency kill switch",
            )
        if latest.status in (ContractStatus.REJECTED, ContractStatus.EXPIRED):
            return ProxyResult(
                status=ProxyStatus.REJECTED,
                call_id=decision.call_id,
                tool=decision.tool,
                risk_level=decision.risk_level,
                verdict=decision.verdict,
                contract_id=contract.contract_id,
                error=f"contract {latest.status.value.lower()}",
            )
        return ProxyResult(
            status=ProxyStatus.FAILED,
            call_id=decision.call_id,
            tool=decision.tool,
            risk_level=decision.risk_level,
            verdict=decision.verdict,
            contract_id=contract.contract_id,
            error=str((latest.outcome or {}).get("error", "execution failed")),
        )

    def _prepare_evidence(
        self, decision: PolicyDecision
    ) -> tuple[Evidence, ArtifactHashes, str | list[str], PolicyDecision]:
        """Freeze evidence + artifact hashes. May escalate risk (never lowers it)."""
        args = decision.canonical_args
        if decision.tool == "fs_commit_staged":
            ev, hashes = self.staging.prepare_commit(args["task_id"], args["target_path"])
            return ev, hashes, ev.target_path, decision
        if decision.tool == "fs_delete_file":
            ev, hashes = self.staging.prepare_delete(args["task_id"], args["path"])
            return ev, hashes, ev.target_path, decision
        if decision.tool == "gmail_send_staged":
            rec, _ = self.staging.load_verified_draft(args["task_id"], args["staged_draft_id"])
            ev, hashes = self.staging.email_evidence(rec)
            return ev, hashes, list(ev.to), decision
        if decision.tool == "git_commit_and_push":
            rec = self.staging.load_verified_git_proposal(args["task_id"], args["staged_commit_id"])
            prop = rec["proposal"]
            repo_posix = prop["repo_path"].replace("\\", "/").rstrip("/")
            paths = [f"{repo_posix}/{f}" for f in prop["files"]]
            risk, reasons, matched, hits = self.engine.escalate_for_paths(
                decision.tool, decision.risk_level, paths
            )
            escalated = [h[len(repo_posix) + 1:] for h in hits]
            if risk is not decision.risk_level:
                decision = decision.model_copy(update={
                    "risk_level": risk,
                    "reasons": [*decision.reasons, *reasons],
                    "matched_rules": [*decision.matched_rules, *matched],
                })
                self.audit.append(
                    AuditEventType.POLICY_DECISION,
                    task_id=decision.task_id,
                    call_id=decision.call_id,
                    server=decision.server,
                    tool=decision.tool,
                    risk_level=risk,
                    verdict=decision.verdict,
                    details={"escalation": reasons, "escalated_paths": escalated},
                )
            ev, hashes = self.staging.git_evidence(rec, escalated_paths=escalated)
            target = f"{prop['repo_name']}:{prop['branch']} -> {prop['remote']} ({prop['remote_url']})"
            return ev, hashes, target, decision
        raise StagingError("UNSUPPORTED_APPROVAL_TOOL", decision.tool)

    # ------------------------------------------------------------------ #
    # Out-of-band approval decision (called by /api/v1/approvals/{id}/decide)
    # ------------------------------------------------------------------ #
    async def submit_decision(self, contract_id: str, approval: SignedApproval) -> ApprovalRecord:
        rec = self.contracts.get(contract_id)
        if rec is None:
            raise ContractError("UNKNOWN_CONTRACT", contract_id)
        if rec.status is not ContractStatus.PENDING:
            raise ContractError("BAD_STATE", f"{contract_id} is {rec.status}")

        if approval.decision == "reject":
            updated = self.contracts.transition(
                contract_id,
                ContractStatus.REJECTED,
                decided_by=approval.device_id,
                outcome={"rejected": True, "reason": approval.reason},
            )
            self.audit.append(
                AuditEventType.CONTRACT_REJECTED,
                task_id=rec.contract.task_id,
                call_id=rec.call_id,
                contract_id=contract_id,
                server=rec.server,
                tool=rec.tool,
                risk_level=rec.contract.risk_level,
                details={"device_id": approval.device_id, "reason": approval.reason},
            )
            self._wake(contract_id)
            return updated

        if self.pool.paused:
            raise PoolPausedError("KILL_SWITCH_ACTIVE", "cannot execute while kill switch is active")

        try:
            verified = self.verifier.verify(rec.contract, approval)
        except ReplayError as exc:
            self.audit.append(
                AuditEventType.NONCE_REPLAY_BLOCKED,
                task_id=rec.contract.task_id,
                call_id=rec.call_id,
                contract_id=contract_id,
                server=rec.server,
                tool=rec.tool,
                risk_level=rec.contract.risk_level,
                details={"device_id": approval.device_id, "error": exc.detail},
            )
            raise
        except ContractError as exc:
            if exc.code == "CONTRACT_EXPIRED":
                self.contracts.transition(contract_id, ContractStatus.EXPIRED, decided_by="system")
                self.audit.append(
                    AuditEventType.CONTRACT_EXPIRED,
                    task_id=rec.contract.task_id,
                    call_id=rec.call_id,
                    contract_id=contract_id,
                    server=rec.server,
                    tool=rec.tool,
                    risk_level=rec.contract.risk_level,
                )
                self._wake(contract_id)
            else:
                self.audit.append(
                    AuditEventType.SIGNATURE_REJECTED,
                    task_id=rec.contract.task_id,
                    call_id=rec.call_id,
                    contract_id=contract_id,
                    server=rec.server,
                    tool=rec.tool,
                    risk_level=rec.contract.risk_level,
                    details={"code": exc.code, "error": exc.detail, "device_id": approval.device_id},
                )
            raise

        self.audit.append(
            AuditEventType.SIGNATURE_VERIFIED,
            task_id=rec.contract.task_id,
            call_id=rec.call_id,
            contract_id=contract_id,
            server=rec.server,
            tool=rec.tool,
            risk_level=rec.contract.risk_level,
            details={"device_id": verified.device_id, "confirm_destructive": verified.contract.confirm_destructive},
        )
        self.contracts.transition(contract_id, ContractStatus.APPROVED, decided_by=verified.device_id)

        worker_args = dict(rec.canonical_args)
        ah = verified.contract.artifact_hashes
        if isinstance(ah, FileArtifactHashes):
            worker_args["staged_blob"] = ah.staged_blob
            worker_args["destination_before"] = ah.destination_before
        elif isinstance(ah, DeleteArtifactHashes):
            worker_args["target_before"] = ah.target_before
        elif isinstance(ah, EmailArtifactHashes):
            worker_args["email_payload_sha256"] = ah.email_payload
            worker_args["attachment_hashes"] = dict(ah.attachments)
        elif isinstance(ah, GitArtifactHashes):
            worker_args["git_artifacts"] = ah.model_dump(mode="json")

        self.audit.append(
            AuditEventType.EXECUTION_STARTED,
            task_id=rec.contract.task_id,
            call_id=rec.call_id,
            contract_id=contract_id,
            server=rec.server,
            tool=rec.tool,
            risk_level=rec.contract.risk_level,
        )
        try:
            outcome = await self.pool.call_tool(rec.server, rec.tool, worker_args)
        except WorkerToolError as exc:
            ev_type = AuditEventType.TOCTOU_VIOLATION if exc.code in TOCTOU_CODES else AuditEventType.EXECUTION_FAILED
            self.audit.append(
                ev_type,
                task_id=rec.contract.task_id,
                call_id=rec.call_id,
                contract_id=contract_id,
                server=rec.server,
                tool=rec.tool,
                risk_level=rec.contract.risk_level,
                details={"code": exc.code, "error": exc.detail},
            )
            updated = self.contracts.transition(
                contract_id,
                ContractStatus.FAILED,
                expected=(ContractStatus.APPROVED,),
                outcome={"error": exc.code, "message": exc.detail},
            )
            self._wake(contract_id)
            if exc.code in TOCTOU_CODES:
                raise TOCTOUError(exc.code, exc.detail) from exc
            return updated
        except PoolError as exc:
            self.audit.append(
                AuditEventType.EXECUTION_FAILED,
                task_id=rec.contract.task_id,
                call_id=rec.call_id,
                contract_id=contract_id,
                server=rec.server,
                tool=rec.tool,
                risk_level=rec.contract.risk_level,
                details={"code": exc.code, "error": exc.detail},
            )
            updated = self.contracts.transition(
                contract_id,
                ContractStatus.FAILED,
                expected=(ContractStatus.APPROVED,),
                outcome={"error": exc.code, "message": exc.detail},
            )
            self._wake(contract_id)
            return updated

        updated = self.contracts.transition(
            contract_id,
            ContractStatus.EXECUTED,
            expected=(ContractStatus.APPROVED,),
            outcome=outcome,
        )
        self.audit.append(
            AuditEventType.EXECUTION_SUCCEEDED,
            task_id=rec.contract.task_id,
            call_id=rec.call_id,
            contract_id=contract_id,
            server=rec.server,
            tool=rec.tool,
            risk_level=rec.contract.risk_level,
            details={"outcome": outcome},
        )
        self._wake(contract_id)
        return updated

    def _wake(self, contract_id: str) -> None:
        ev = self._waiters.get(contract_id)
        if ev is not None:
            ev.set()

    # ------------------------------------------------------------------ #
    # Kill switch
    # ------------------------------------------------------------------ #
    async def trigger_kill_switch(self, reason: str = "manual") -> dict[str, Any]:
        worker_report = await self.pool.kill_all()
        revoked = self.contracts.revoke_all_pending(reason)
        for cid in revoked:
            self.audit.append(
                AuditEventType.CONTRACT_REVOKED,
                contract_id=cid,
                details={"reason": reason},
            )
            self._wake(cid)
        for cid in list(self._waiters):
            self._wake(cid)
        self.audit.append(
            AuditEventType.KILL_SWITCH_TRIGGERED,
            details={"reason": reason, "revoked_contracts": revoked, "workers": worker_report},
        )
        return {"paused": True, "revoked_contracts": revoked, "workers": worker_report}

    async def reset_kill_switch(self, *, restart_workers: bool = True) -> dict[str, Any]:
        status = await self.pool.reset_kill_switch(restart_workers=restart_workers)
        self.audit.append(
            AuditEventType.KILL_SWITCH_RESET,
            details={"restart_workers": restart_workers, "workers": status},
        )
        return status
