# Mini — Laptop Execution Environment

Production-structured laptop runtime connecting **OpenClaw** (untrusted AI planner) → **Mini Daemon & MCP Policy Proxy** (independent security boundary) → **Restricted Filesystem MCP** and **Gmail MCP** stdio child workers, with **Transactional Staging**, **RFC 8785 + Ed25519 Approval Contracts**, **TOCTOU Prevention**, **Glass-Box Monitor (SSE)**, and **Mock Mobile Companion UI**.

```text
OpenClaw (untrusted planner; all built-in tool groups denied)
   │  MCP Streamable HTTP  (http://127.0.0.1:8765/mcp, Bearer token)
   ▼
Mini Daemon + MCP Policy Proxy  ──► Glass-Box Monitor (/monitor, live SSE)
   │                            ──► Mock Mobile Approval UI (/mobile-mock)
   │  PolicyEngine (L0–L3) → PathGuard → StagingEngine → ContractVerifier → AuditLogger
   │  private stdio pipes (StdioServerParameters)
   ├──► filesystem_server (stdio child; no Gmail credentials, no proxy token)
   └──► gmail_server      (stdio child; only holder of Gmail OAuth credentials)
```

---

## Directory Layout (`laptop/`)

```text
laptop/
├── pyproject.toml
├── .env.example
├── openclaw/
│   └── openclaw.mini.json          # Hardened OpenClaw config (proxy-only, built-in tools denied)
├── config/
│   └── policy.yaml                 # Approved roots, denylist globs, L0–L3 tool risk map
├── demo_project/                   # Default approved root for local E2E testing
│   ├── README.md
│   └── notes/architecture_summary.md
├── src/
│   └── mini/
│       ├── config.py               # Immutable policy loader & realpath resolver
│       ├── schemas.py              # Pydantic v2 models + RFC 8785 helpers
│       ├── security/
│       │   ├── _db.py              # Thread-safe SQLite WAL helper
│       │   ├── path_guard.py       # realpath canonicalization, allowlist, hard denylist
│       │   ├── policy_engine.py    # Deterministic L0–L3 classifier & rule evaluator
│       │   ├── staging.py          # Per-task workspace, immutable blobs, diffs, rollback, TOCTOU check
│       │   ├── contracts.py        # RFC 8785 canonicalizer, Ed25519 verifier, TTL & SQLite nonce store
│       │   └── audit.py            # SQLite WAL + hash-chained JSONL logger & chain verifier
│       ├── mcp_servers/
│       │   ├── filesystem_server.py # Isolated stdio MCP worker for filesystem ops
│       │   └── gmail_server.py      # Isolated stdio MCP worker (real Gmail API + MINI_GMAIL_MOCK adapter)
│       ├── daemon/
│       │   ├── mcp_client_pool.py  # Spawns/supervises downstream stdio MCP workers + hard kill switch
│       │   ├── mcp_proxy.py        # Streamable HTTP MCP server intercepting OpenClaw tool calls
│       │   ├── app.py              # FastAPI app mounting /mcp, SSE, approval API, kill switch
│       │   └── static/
│       │       ├── monitor.html    # Glass-Box Monitor UI (/monitor)
│       │       └── mobile_mock.html # Mock Mobile Approval & Evidence Viewer UI (/mobile-mock)
│       └── cli.py                  # CLI: init-keys, run-daemon, verify-audit, run-e2e
└── tests/
    ├── conftest.py
    └── security/
        ├── test_path_guard.py
        ├── test_contracts.py
        ├── test_toctou.py
        ├── test_audit.py
        ├── test_gmail_flow.py
        ├── test_kill_switch.py
        └── test_e2e_and_ui.py
```

---

## Step-by-Step Runbook (Windows PowerShell & POSIX)

### 1. Install & Initialize Keys / Environment

```powershell
cd d:\OneDrive\Desktop\Mini-main\Mini-main\laptop
uv venv .venv --python 3.13
uv pip install --python .venv\Scripts\python.exe -e ".[dev]"

# Generates ~/.mini/trusted_devices.json, ~/.mini/dev_mobile_key.json, .env (with MINI_PROXY_TOKEN), and ./demo_project
.venv\Scripts\mini.exe init-keys
```

### 2. Launch Mini Daemon (Terminal 1)

```powershell
cd d:\OneDrive\Desktop\Mini-main\Mini-main\laptop
.venv\Scripts\mini.exe run-daemon --dev
```

Open the two local web UIs in your browser:
- **Glass-Box Monitor:** `http://127.0.0.1:8765/monitor`
- **Mock Mobile Approval UI:** `http://127.0.0.1:8765/mobile-mock`

### 3. Attach OpenClaw (or Run the Built-In E2E Test Task)

#### Option A — Attach OpenClaw with Hardened Config

1. Export the bearer token generated in `laptop/.env` so OpenClaw interpolates `${MINI_PROXY_TOKEN}` in `openclaw/openclaw.mini.json`:
   ```powershell
   # Load MINI_PROXY_TOKEN from laptop/.env into your shell
   Get-Content .\laptop\.env | ForEach-Object {
     if ($_ -match '^MINI_PROXY_TOKEN=(.+)$') { $env:MINI_PROXY_TOKEN = $matches[1] }
   }
   ```
2. Merge or copy `laptop/openclaw/openclaw.mini.json` into `~/.openclaw/openclaw.json` (which denies `group:runtime`, `group:fs`, `group:ui`, `group:web`, `group:automation`, `group:nodes` and exposes **only** `mcp.servers.mini_proxy` at `http://127.0.0.1:8765/mcp`):
   ```powershell
   New-Item -ItemType Directory -Force "$HOME\.openclaw" | Out-Null
   Copy-Item .\laptop\openclaw\openclaw.mini.json "$HOME\.openclaw\openclaw.json" -Force
   ```
3. Prompt OpenClaw with the end-to-end test task:
   > *"Using task_id `e2e-demo-01`: (1) read `README.md`, (2) stage an updated `README.md` marking status as completed, (3) stage a summary email draft to `advisor@university.edu` attaching `notes/architecture_summary.md`, and (4) commit the staged file and send the staged email."*

#### Option B — Run the Automated End-to-End Task via `mini run-e2e` (Terminal 2)

With `mini run-daemon --dev` running in Terminal 1:

```powershell
cd d:\OneDrive\Desktop\Mini-main\Mini-main\laptop

# Interactive mode — click "Approve & Sign (Ed25519)" in http://127.0.0.1:8765/mobile-mock when prompted:
.venv\Scripts\mini.exe run-e2e

# Non-interactive mode — automatically signs & approves both L2 contracts via the dev signer endpoint:
.venv\Scripts\mini.exe run-e2e --auto-approve-dev
```

### 4. Verify the Tamper-Evident Audit Log

```powershell
cd d:\OneDrive\Desktop\Mini-main\Mini-main\laptop
.venv\Scripts\mini.exe verify-audit
```

Or click **Verify Audit Chain** inside `http://127.0.0.1:8765/monitor`.
