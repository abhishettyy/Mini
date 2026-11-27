You are a Principal Systems & Security Architect helping me build the **Laptop Execution Environment** for **Mini**, a secure dual-device AI agent orchestration platform.

### Mission
Build a production-structured, runnable laptop execution runtime connecting **OpenClaw** (untrusted AI planner) → **Mini Daemon & MCP Policy Proxy** (independent security boundary) → **Restricted Filesystem MCP** and **Gmail MCP** workers, complete with **Transactional Staging**, **Cryptographically Bound Approval Contracts (RFC 8785 + Ed25519)**, **TOCTOU Prevention**, a **Glass-Box Monitor (SSE)**, and a **Local Mock Mobile Approval UI** (for testing out-of-band signing before the Android app is connected).

---

### Core Security Architecture (Non-Negotiable Invariants)

1. **Untrusted Planner Isolation (OpenClaw Lockdown)**
   - Generate a hardened `openclaw/openclaw.mini.json` configuration snippet that:
     - Denies OpenClaw's built-in tools via `tools.deny`: `["group:runtime", "group:fs", "group:ui", "group:web", "group:automation", "group:nodes"]`.
     - Configures a single MCP server under `mcp.servers.mini_proxy` pointing to `http://127.0.0.1:8765/mcp` with `transport: "streamable-http"`, `enabled: true`, `connectionTimeoutMs: 5000`, and `requestTimeoutMs: 180000`.
   - OpenClaw NEVER receives direct access to the host shell, filesystem, Gmail OAuth tokens, or downstream MCP server processes.

2. **Independent MCP Policy Proxy (Interception Layer)**
   - Mini Daemon runs a FastAPI ASGI app exposing the MCP Streamable HTTP endpoint at `/mcp` (using MCP Python SDK v2: `from mcp.server import MCPServer` or low-level `Server` + `streamable_http_app()`).
   - Downstream MCP servers (`filesystem` and `gmail`) are spawned exclusively as unprivileged child processes by Mini Daemon over private `stdio` pipes (`StdioServerParameters`).
   - Every `tools/call` from OpenClaw is intercepted by the Policy Engine **before** forwarding to any downstream MCP worker.
   - Deterministic Risk Classification (`L0`–`L3`) is computed exclusively by the Policy Engine from `(server, tool, canonical_args)`. The AI agent cannot supply, modify, or downgrade risk levels.

3. **Risk-Based Permission Model**
   - **L0 (Read-Only):** Auto-execute after allowlist/denylist validation (e.g., `fs_list_dir`, `fs_read_file`, `gmail_search`, `gmail_read_message`).
   - **L1 (Reversible / Staged):** Auto-execute strictly inside an isolated per-task staging workspace (`workspaces/{task_id}/staging/`) or Gmail Drafts (e.g., `fs_write_staged`, `gmail_stage_draft`). Never mutates live user files or sends external messages.
   - **L2 (Sensitive / External):** Hard-blocked by default. Proxy generates structured **Evidence** + an **Approval Contract**, pushes it to the Approval Queue (Mock Mobile UI / future NectarLink), and requires a valid **Ed25519 signature** before executing (`fs_commit_staged`, `gmail_send_staged`).
   - **L3 (Highly Destructive):** Hard-blocked; requires explicit strong confirmation flag (`confirm_destructive: true`) inside the signed contract (e.g., `fs_delete_file`).

4. **Filesystem & Secret Boundary Enforcement**
   - **Path Canonicalization:** Resolve every path argument with `os.path.realpath()` (resolving all symlinks and `../` traversal) and enforce strict containment under `config.approved_roots` using `os.path.commonpath()`.
   - **Hard Denylist (Always Blocked, Even Inside Approved Roots):** `.env`, `.env.*`, `*.pem`, `*.key`, `*.p12`, `*credentials*.json`, `*token*.json`, `.git/config`, `~/.ssh/**`, `~/.aws/**`, `~/.mini/secrets/**`, and OS system directories.
   - **Credential Isolation:** Gmail OAuth files live strictly in `~/.mini/secrets/` (outside `approved_roots` and on the hard denylist). Only the Gmail MCP subprocess reads them via explicit env vars.

5. **Cryptographic Approval Contracts (RFC 8785 + Ed25519)**
   - **Canonical Serialization:** Use the `rfc8785` Python library (`rfc8785.dumps(...)`) to produce deterministic UTF-8 JSON bytes prior to hashing and Ed25519 signing/verification.
   - **Contract Payload Fields:**
     - `contract_version`: `"1.0"`
     - `contract_id`: UUID/ULID
     - `task_id`: Active task session ID
     - `action_type`: e.g., `"filesystem.commit_staged"` or `"gmail.send_staged"`
     - `risk_level`: `"L2"` | `"L3"`
     - `target`: Canonical file path or recipient list
     - `params_hash_sha256`: SHA-256 of canonicalized tool arguments
     - `artifact_hashes`: Map of `{ "staged_blob": "sha256:...", "destination_before": "sha256:... | null" }` (or `{ "email_payload": "sha256:...", "attachments": { filename: "sha256:..." } }`)
     - `nonce`: Single-use UUIDv4
     - `issued_at` / `expires_at`: ISO-8601 UTC timestamps (default 300s TTL)
   - **Verification & Replay Protection:**
     - Verify Ed25519 signature against the pinned trusted mobile public key (`~/.mini/trusted_devices.json`).
     - Reject expired contracts (`now >= expires_at`).
     - Persist consumed nonces in SQLite (WAL mode) with a `UNIQUE` constraint; atomically insert the nonce **before** executing the L2 action to prevent replay and race conditions.

6. **Transactional Staging & TOCTOU Prevention**
   - **Filesystem (`fs_write_staged` → `fs_commit_staged`):**
     - `fs_write_staged` writes only to `workspaces/{task_id}/staging/<rel_path>`.
     - When `fs_commit_staged` is proposed, the proxy copies the staged file into an immutable content-addressed store (`workspaces/{task_id}/blobs/<sha256>`), computes `destination_before` SHA-256 (if target exists), and attaches a unified `before/after` diff as Evidence.
     - After signature verification, the commit engine re-checks that the live destination file's current SHA-256 still equals `destination_before`, copies directly from the immutable blob (ignoring any later edits to `staging/`), and saves a rollback backup in `workspaces/{task_id}/rollback/`.
   - **Gmail (`gmail_stage_draft` → `gmail_send_staged`):**
     - `gmail_stage_draft` validates attachment paths against `approved_roots` + denylist, hashes the canonical email payload (`to`, `cc`, `bcc`, `subject`, `body`, `attachment_hashes`), stores an immutable staged draft blob locally (and optionally creates a Gmail Draft), and returns `staged_draft_id`.
     - `gmail_send_staged(staged_draft_id)` generates Evidence showing exact `To/CC/BCC`, `Subject`, full `Body`, and attachment filenames + hashes.
     - Upon Ed25519 approval, the Gmail MCP sends directly from the verified immutable staged draft blob after re-verifying attachment hashes. Any parameter or attachment tampering aborts execution.

7. **Glass-Box Monitor, Tamper-Evident Audit Log & Kill Switch**
   - **Hash-Chained Audit Log:** Every intercepted tool call, policy decision (`ALLOW`, `STAGE`, `REQUIRE_APPROVAL`, `DENY`), signature check, and execution outcome is written to SQLite (WAL mode) and appended to `logs/audit.jsonl` where each entry includes `prev_event_hash = sha256(rfc8785.dumps(prev_entry))` and `event_hash`.
   - **Real-Time SSE Stream:** FastAPI exposes `GET /api/v1/events/stream` pushing live audit events to the Glass-Box Web UI.
   - **Emergency Kill Switch:** `POST /api/v1/kill-switch` immediately terminates all active MCP child processes (`terminate()` → 500 ms → `kill()`), revokes all `PENDING` Approval Contracts in SQLite, pauses new tool calls until explicitly reset, and logs a `KILL_SWITCH_TRIGGERED` audit event.

---

### Locked Technology Stack
- **Language & Runtime:** Python 3.12+ (Windows & POSIX compatible; use `pathlib` and cross-platform process termination)
- **Web / Daemon:** FastAPI, Uvicorn, Pydantic v2, `asyncio`, `sse-starlette`
- **MCP Protocol:** Official `mcp` Python SDK v2 (`mcp>=2.0`, using `MCPServer` / low-level `Server`, `streamable_http_app()`, and `stdio_client`)
- **Security & Crypto:** `cryptography` (Ed25519), `rfc8785` (JCS canonicalization), `hashlib` (SHA-256)
- **Persistence:** SQLite (`sqlite3` / `aiosqlite`) in WAL mode
- **Gmail Integration:** `google-api-python-client`, `google-auth-oauthlib`, `google-auth-httplib2` (scoped strictly to `gmail.readonly` and `gmail.compose`, plus a `MINI_GMAIL_MOCK=true` adapter for offline/CI testing)
- **Testing:** `pytest`, `pytest-asyncio`, `httpx`

---

### Exact MCP Tool Surface Exposed to OpenClaw (via Proxy)

#### Filesystem Tools
1. `fs_list_dir(path: str)` — **L0**: Lists allowed directory contents (filtering out denylisted entries).
2. `fs_read_file(path: str)` — **L0**: Reads UTF-8 text from an allowed, non-denylisted file.
3. `fs_write_staged(task_id: str, target_path: str, content: str)` — **L1**: Writes proposed content into `workspaces/{task_id}/staging/` and returns staged path + unified diff preview.
4. `fs_commit_staged(task_id: str, target_path: str)` — **L2**: Triggers Approval Contract + diff evidence; commits immutable blob to `target_path` only after valid Ed25519 signature + TOCTOU recheck.

#### Gmail Tools
5. `gmail_search(query: str, max_results: int = 10)` — **L0**: Searches mailbox metadata/snippets.
6. `gmail_read_message(message_id: str)` — **L0**: Reads message headers and body (redacting obvious secret patterns in logs).
7. `gmail_stage_draft(task_id: str, to: list[str], subject: str, body: str, cc: list[str] = [], bcc: list[str] = [], attachment_paths: list[str] = [])` — **L1**: Validates attachment paths against security policy, saves immutable staged draft + hashes, returns `staged_draft_id`.
8. `gmail_send_staged(task_id: str, staged_draft_id: str)` — **L2**: Triggers Approval Contract + full email evidence; sends only after valid Ed25519 signature + attachment TOCTOU check.

#### Approval Helper (Optional Non-Blocking Mode)
- Configure proxy L2 handling to await approval asynchronously up to `APPROVAL_WAIT_SECONDS` (default `120s`, matching OpenClaw's `requestTimeoutMs`). If the user approves/rejects within the window, return the execution result directly to OpenClaw; if it times out, return `APPROVAL_PENDING` with `contract_id`.

---

### UI Requirements (Served by Mini Daemon on `127.0.0.1:8765`)
1. **Glass-Box Monitor (`/monitor`):** Clean single-page HTML/JS dashboard showing live SSE tool traces, risk badges (`L0`–`L3`), policy verdicts, blocked security violations, audit chain verification status button, and a prominent red **EMERGENCY KILL SWITCH** button.
2. **Mock Mobile Companion (`/mobile-mock`):** Simulates the paired smartphone over LAN/localhost. Generates/loads a local test Ed25519 keypair (or uses WebCrypto / local signer endpoint restricted to dev mode), displays pending L2 Approval Contracts with rendered before/after file diffs and Gmail recipient/body/attachment previews, and signs canonical RFC 8785 bytes with **Approve** / **Reject** buttons.

---

### Repository Structure to Create
```text
mini/
├── pyproject.toml
├── .env.example
├── openclaw/
│   └── openclaw.mini.json          # Hardened OpenClaw config (proxy-only, built-in tools denied)
├── config/
│   └── policy.yaml                 # Approved roots, denylist globs, L0-L3 tool risk map
├── src/
│   └── mini/
│       ├── schemas.py              # Pydantic v2 models (ToolCall, PolicyDecision, ApprovalContract, Evidence, AuditEvent)
│       ├── security/
│       │   ├── path_guard.py       # realpath canonicalization, allowlist, hard denylist
│       │   ├── policy_engine.py    # Deterministic L0-L3 classifier & rule evaluator
│       │   ├── staging.py          # Per-task workspace, immutable blobs, unified diffs, rollback, TOCTOU check
│       │   ├── contracts.py        # RFC 8785 canonicalizer, Ed25519 verifier, TTL & SQLite nonce replay store
│       │   └── audit.py            # SQLite WAL + hash-chained JSONL logger & chain verifier
│       ├── mcp_servers/
│       │   ├── filesystem_server.py # Isolated stdio MCP worker for filesystem ops
│       │   └── gmail_server.py      # Isolated stdio MCP worker (real Gmail API + MINI_GMAIL_MOCK adapter)
│       ├── daemon/
│       │   ├── mcp_client_pool.py  # Spawns/supervises downstream stdio MCP workers + hard kill switch
│       │   ├── mcp_proxy.py        # Streamable HTTP MCP server intercepting OpenClaw tool calls
│       │   ├── app.py              # FastAPI app mounting /mcp, SSE /api/v1/events/stream, approval API, kill switch
│       │   └── static/
│       │       ├── monitor.html    # Glass-Box Monitor UI
│       │       └── mobile_mock.html # Mock Mobile Approval & Evidence Viewer UI
│       └── cli.py                  # Dev commands: init-keys, run-daemon, verify-audit
└── tests/
    └── security/
        ├── test_path_guard.py      # .env, ~/.ssh, ../ traversal, symlink escape, Gmail secrets block
        ├── test_contracts.py       # RFC 8785 determinism, invalid signature, expired TTL, nonce replay
        ├── test_toctou.py          # Live file drift before commit, staging tamper after approval, attachment tamper
        ├── test_gmail_flow.py      # L0 search -> L1 stage draft -> unsigned L2 block -> signed L2 send
        └── test_kill_switch.py     # Terminates workers & revokes pending contracts