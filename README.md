# Mini — Secure Dual-Device AI Agent Orchestration Platform

<p align="center">

**Bridging Mobile Context with Local AI Execution.**

An AI-powered, cross-device automation platform that enables autonomous multi-step workflows while maintaining security, transparency and human control.

</p>

---

## Overview

**Mini** is a secure, dual-device AI orchestration platform that connects a smartphone companion with a local laptop agent to automate complex workflows across devices and applications.

The smartphone acts as the context and human-interaction layer, enabling AI agents to discover mobile documents, capture physical documents, transfer files and request human input when necessary.

The laptop serves as the primary AI execution environment, where OpenClaw orchestrates specialized Model Context Protocol (MCP) servers to interact with local files, generate documents, automate browsers, manage emails and perform Git operations.

Unlike conventional AI agents that may receive broad access to system resources, Mini introduces an independent **Policy Enforcement Layer** that validates every tool invocation, restricts permissions, isolates tasks and prevents unauthorized operations.

For sensitive or irreversible actions, Mini implements a cryptographically bound **Approval Contract** mechanism that requires explicit human authorization for the exact proposed operation.

The entire execution process is observable through a **Glass-Box Monitor**, providing real-time visibility into agent activity, file operations, staged artifacts, security violations and execution traces.

### Core Principle

> Let AI autonomously prepare and coordinate complex workflows while keeping permissions restricted, execution transparent and final authority with the human.

---

## Problem Statement

Existing AI agents lack secure, seamless cross-device access and controlled execution, limiting their ability to automate complex workflows while maintaining user privacy, transparency and control.

### Key Challenges

- **Device Fragmentation:** Mobile documents, OTPs and laptop resources exist in separate environments.
- **Limited Integration:** AI agents struggle to coordinate complex workflows across devices and applications.
- **Security Risks:** Unrestricted filesystem and tool access can expose sensitive information.
- **Lack of Transparency:** Users have limited visibility into what AI agents access, modify or execute.
- **Uncontrolled Execution:** Sensitive operations such as sending emails, submitting forms and modifying files require reliable human authorization.

---

## Proposed Solution

Mini addresses these challenges through a dual-device architecture combining AI orchestration, secure device connectivity, independent policy enforcement and human-controlled authorization.

The platform consists of two primary environments:

1. **Smartphone Companion:** Provides mobile context, document discovery, human input and approval interfaces.
2. **Laptop Agent:** Performs AI orchestration, tool execution, local file operations and browser automation.

The two environments communicate through **NectarLink**, which serves as the device connectivity foundation.

On the laptop, OpenClaw coordinates specialized MCP servers through Mini's security architecture. Every operation passes through the independent Policy Enforcement Layer before execution.

Sensitive actions generate Approval Contracts that are transmitted to the smartphone for review and authorization.

---

## System Architecture

### High-Level Architecture

```text
                 USER
                   |
                   v
       +-----------------------+
       |   MINI SMARTPHONE     |
       |                       |
       |  Mobile Companion     |
       |  File Discovery       |
       |  Document Capture     |
       |  Human Input Handler  |
       |  Approval UI          |
       |  Evidence Viewer      |
       +-----------------------+
                   |
                   v
       +-----------------------+
       |      NECTARLINK       |
       |                       |
       | Device Pairing        |
       | Encrypted Transport   |
       | File Transfer         |
       +-----------------------+
                   |
                   v
       +-----------------------+
       |     MINI DAEMON       |
       |                       |
       | Task Coordination     |
       | Session Management    |
       | Communication Bridge  |
       +-----------------------+
                   |
                   v
       +-----------------------+
       |   OPENCLAW AGENT      |
       |    ORCHESTRATOR       |
       |                       |
       | Task Planning         |
       | Workflow Execution    |
       | MCP Coordination      |
       +-----------------------+
                   |
                   v
       +-----------------------+
       |    MCP ECOSYSTEM      |
       |                       |
       | Filesystem MCP        |
       | Search MCP            |
       | Document MCP          |
       | Browser MCP           |
       | Gmail MCP             |
       | Git MCP               |
       +-----------------------+
                   |
                   v
       +-----------------------+
       | POLICY ENFORCEMENT    |
       |       LAYER           |
       |                       |
       | Permission Validation |
       | Risk Classification   |
       | Task Isolation        |
       | Transactional Staging |
       +-----------------------+
                   |
                   v
       +-----------------------+
       |  APPROVAL CONTRACT    |
       |       MANAGER         |
       |                       |
       | Action Validation     |
       | Approval Requests     |
       | Signature Validation  |
       | Replay Protection     |
       +-----------------------+
                   |
                   v
       +-----------------------+
       |   LOCAL EXECUTION     |
       |                       |
       | Files / Documents     |
       | Browser / Gmail       |
       | Git / Applications    |
       +-----------------------+

       +-----------------------+
       |   GLASS-BOX MONITOR   |
       |                       |
       | Live Tool Calls       |
       | Execution Traces      |
       | Security Events       |
       | Audit Logs            |
       | Pause / Cancel        |
       +-----------------------+
```

*Conceptual architecture: the diagram represents the intended system design, not a claim that all components have been implemented.*

### 1. Smartphone Companion

The smartphone acts as the context and human-interaction layer.

**Components:**

- **Mobile Companion Agent:** Understands user requests and coordinates with the laptop agent.
- **Mobile File Discovery:** Locates PDFs, images, scanned documents and other relevant mobile files.
- **Document Capture:** Captures physical documents using the smartphone camera.
- **Human Input Handler:** Handles OTP verification, CAPTCHA assistance and other user-dependent interactions.
- **Control & Approval UI:** Receives approval requests and allows users to approve or reject proposed actions.
- **Evidence Viewer:** Displays document previews, screenshots, file diffs and execution summaries.

### 2. NectarLink — Device Connectivity

NectarLink provides the smartphone-to-laptop connectivity foundation.

Its intended responsibilities include:

- Device discovery and pairing.
- Authenticated device connectivity.
- Encrypted communication.
- Cross-device file transfer.
- Transfer of generated artifacts and execution evidence.
- Integration with the laptop-side Mini Daemon.

NectarLink handles connectivity, while Mini implements its own application-level authorization and task security.

### 3. Mini Daemon

The Mini Daemon is the primary laptop-side coordination service.

Responsibilities:

- Receives requests from the smartphone.
- Creates and manages task sessions.
- Communicates with OpenClaw.
- Coordinates execution and MCP interactions.
- Routes approval requests and responses.
- Maintains task state.
- Reports execution progress to the smartphone.

### 4. OpenClaw — AI Orchestration

OpenClaw acts as the AI agent orchestration engine.

Responsibilities:

- Understands natural-language instructions.
- Breaks complex tasks into smaller operations.
- Plans multi-step workflows.
- Selects appropriate MCP tools.
- Coordinates tool execution.
- Requests human intervention when required.
- Reports proposed sensitive actions to the security layer.

OpenClaw does not receive unrestricted access to the laptop's resources. Tool invocations are subject to Mini's independent security controls.

### 5. MCP Server Ecosystem

Mini uses specialized MCP servers to provide controlled access to different capabilities.

| MCP Server | Responsibilities |
|---|---|
| Filesystem MCP | Restricted file reading, writing and management |
| Search MCP | Project and document discovery |
| Document MCP | DOCX/PDF generation and template population |
| Browser MCP | Playwright-based browser automation |
| Gmail MCP | Email discovery, drafting and sending |
| Git MCP | Repository inspection, diffs, commits and pushes |

All tool invocations must pass through the Policy Enforcement Layer.

---

## Security Architecture

Security is a foundational part of Mini rather than an additional feature.

### 1. Independent Policy Enforcement Layer

The Policy Enforcement Layer operates independently of the AI agent and validates every tool invocation.

**Key responsibilities:**

- Least-privilege access control.
- Approved-directory restrictions.
- Sensitive path protection.
- Tool-level permission validation.
- Command and operation restrictions.
- Task-specific workspace isolation.
- Transactional file staging.
- Risk classification.
- Prevention of unauthorized execution.

Sensitive locations such as `.env` files, SSH credentials, private keys and system directories are blocked from unauthorized access.

### 2. Risk-Based Permission Model

Mini classifies operations into four risk levels.

| Level | Risk Category | Execution Policy |
|---|---|---|
| L0 | Read-only | Automatic execution |
| L1 | Reversible | Execute within isolated staging |
| L2 | Sensitive / External | Explicit human approval |
| L3 | Highly Destructive | Strong confirmation and explicit authorization |

**Examples:**

- L0: Searching project files and reading documents.
- L1: Generating reports and creating temporary artifacts.
- L2: Sending emails, submitting forms and pushing Git changes.
- L3: Deleting important directories and destructive bulk modifications.

The AI agent cannot independently lower the risk level assigned by the policy layer.

### 3. Transactional Staging

Mini avoids directly overwriting important files during agent execution.

Instead:

1. Create an isolated task workspace.
2. Perform modifications within the workspace.
3. Generate staged artifacts.
4. Compare changes with existing files.
5. Request authorization when required.
6. Apply approved changes.
7. Preserve rollback information where supported.

This reduces the risk of accidental data loss and unintended modifications.

### 4. Approval Contract System

The Approval Contract Manager ensures that sensitive actions require authorization for the exact operation being performed.

An approval request contains:

- Unique Task ID.
- Action type.
- Exact operation parameters.
- Destination or target.
- Artifact ID and cryptographic hash.
- Risk level.
- Expiration timestamp.
- One-time nonce.

**Approval Workflow:**

1. AI proposes a sensitive action.
2. Policy Enforcement Layer validates the request.
3. Approval Contract Manager creates a structured approval contract.
4. Smartphone receives the approval request.
5. User reviews the action and supporting evidence.
6. User explicitly approves or rejects it.
7. Laptop verifies approval authenticity and validity.
8. Policy Enforcement Layer revalidates permissions and execution conditions.
9. Only then is the operation executed.

Any change to the action parameters, destination or artifact version invalidates the existing approval.

Approvals are single-use and time-limited to prevent replay and stale authorization.

### 5. Evidence-Based Approval

Mini does not rely exclusively on screenshots.

Different actions require different evidence:

| Operation | Evidence |
|---|---|
| Document Generation | DOCX/PDF preview |
| File Modification | Before/after diff |
| File Deletion | Exact paths and impact |
| Email Sending | Recipient, subject, body and attachments |
| Web Submission | Destination URL, field values and screenshot |
| Git Commit | Branch, commit message and staged diff |
| Git Push | Remote, branch and commits |

Screenshots provide visual context, while the Approval Contract provides the actual authorization mechanism.

---

## Glass-Box Monitor

The Glass-Box Monitor provides real-time observability into Mini's execution environment.

Instead of operating as a black-box AI agent, Mini exposes its execution activity to the user.

**Key Features:**

- Live MCP tool invocation tracking.
- Agent execution traces.
- File access and modification activity.
- Current task status.
- Staged artifacts and pending changes.
- Approval request status.
- Blocked operations and security violations.
- Execution logs.
- Pause and cancel controls.
- Emergency kill switch.

The monitor connects to the Mini Daemon, Policy Enforcement Layer and execution environment.

---

## End-to-End Workflow

### Example: Automated Lab Report Submission

Mini demonstrates its capabilities through a complete cross-device workflow.

**User Request:**

"Find my lab rubric on my phone, generate a report using my laptop project, fill the university submission portal and submit it."

### Workflow

| Step | Operation | Component |
|---|---|---|
| 1 | User submits task | Mini Mobile App |
| 2 | Locate lab rubric | Mobile File Discovery |
| 3 | Transfer document | NectarLink |
| 4 | Create execution plan | OpenClaw |
| 5 | Validate permissions | Policy Enforcement Layer |
| 6 | Find relevant project files | Search MCP |
| 7 | Generate lab report | Document Generation MCP |
| 8 | Populate submission portal | Playwright MCP |
| 9 | Request OTP/human input | Human Input Handler |
| 10 | Generate previews and evidence | Evidence Generator |
| 11 | Create approval contract | Approval Contract Manager |
| 12 | Review and authorize | Smartphone Approval UI |
| 13 | Revalidate exact action | Policy Enforcement Layer |
| 14 | Submit report | Browser Automation MCP |
| 15 | Record execution outcome | Audit Logger |

**Important:** The browser may prepare the submission form autonomously, but the final submission must remain blocked until the user explicitly authorizes the exact operation.

---

## Technology Stack

The following technologies form the proposed implementation stack.

| Layer | Technologies |
|---|---|
| Mobile Application | Android, Kotlin |
| Device Connectivity | NectarLink |
| Laptop Daemon | Python / Node.js |
| AI Orchestration | OpenClaw |
| Tool Integration | Model Context Protocol (MCP) |
| Browser Automation | Playwright |
| Document Generation | Python, python-docx, docxtpl |
| Communication | REST APIs, JSON-RPC |
| Security | TLS, Cryptographic Signatures, RBAC |
| Monitoring | Glass-Box Monitor, Audit Logging |
| Version Control | Git, GitHub |

*Specific implementation choices may evolve during development based on integration requirements.*

---

## Novelty and Innovation

Mini combines existing AI orchestration and device connectivity technologies with an independent security and authorization architecture.

Its key innovations include:

**1. Dual-Device AI Architecture**

Bridges smartphone context and local laptop execution, allowing workflows to span multiple devices.

**2. Independent Policy Enforcement**

Introduces a security boundary between AI-generated tool requests and actual system execution.

**3. Cryptographically Bound Approval Contracts**

Binds human authorization to exact actions, destinations, task identifiers and artifact versions.

**4. Risk-Based Execution**

Differentiates safe, reversible, sensitive and destructive operations through configurable permission levels.

**5. Glass-Box Monitoring**

Provides real-time visibility into agent actions, tool invocations and security violations.

**6. Transactional Execution**

Uses isolated workspaces and staged modifications to reduce unintended changes and preserve original files.

### Key Innovation

Combining autonomous cross-device AI orchestration with independent security enforcement, transparent execution and exact-action human authorization.

---

## Impact

- **Productivity:** Automates repetitive, multi-step workflows across devices.
- **Security:** Prevents unrestricted AI access to sensitive files and resources.
- **User Control:** Ensures explicit authorization for sensitive operations.
- **Transparency:** Provides real-time execution visibility and audit trails.
- **Accessibility:** Connects mobile documents, laptop applications and online services through a unified workflow.
- **Extensibility:** Supports additional MCP tools and workflows through a modular architecture.

## Feasibility

Mini builds on existing technologies rather than requiring an entirely new AI or device communication infrastructure.

- NectarLink provides an existing device connectivity foundation.
- OpenClaw provides AI agent orchestration.
- MCP enables modular tool integration.
- Playwright supports browser automation.
- Python libraries support document generation.
- Local laptop resources provide the execution environment.

The architecture supports incremental implementation, beginning with a functional cross-device workflow and progressively introducing advanced security and monitoring capabilities.

**Feasibility Assessment:** A functional prototype is achievable using existing technologies. Advanced policy enforcement, approval cryptography and seamless device integration require custom development and testing.

---

## Business Model

Mini can adopt a freemium and enterprise-oriented business model.

| Model | Description |
|---|---|
| Freemium | Basic automation and local execution |
| Premium Subscription | Advanced workflows and integrations |
| Enterprise Licensing | Policy-controlled AI automation for organizations |
| On-Premise Deployment | Private deployments for sensitive environments |
| Custom Integrations | Organization-specific MCP tools and workflows |

**Target Customers:** Students, developers, professionals, startups and enterprises.

**Potential Revenue Streams:** Subscriptions, enterprise licensing and custom integrations.

---

## Development Roadmap

Mini will be developed incrementally, prioritizing a functional end-to-end workflow before introducing advanced capabilities.

### Phase 1 — Foundation

- [ ] Set up the project architecture.
- [ ] Integrate NectarLink device connectivity.
- [ ] Develop the laptop-side Mini Daemon.
- [ ] Establish smartphone-to-laptop communication.
- [ ] Integrate OpenClaw.

### Phase 2 — AI Orchestration

- [ ] Configure MCP server ecosystem.
- [ ] Implement filesystem access.
- [ ] Implement project and document search.
- [ ] Integrate document generation.
- [ ] Integrate Playwright browser automation.

### Phase 3 — Security Architecture

- [ ] Develop independent Policy Enforcement Layer.
- [ ] Implement approved-directory restrictions.
- [ ] Introduce task-specific workspaces.
- [ ] Implement transactional staging.
- [ ] Introduce risk-based permissions.

### Phase 4 — Human Authorization

- [ ] Develop Approval Contract Manager.
- [ ] Implement cryptographic approval binding.
- [ ] Implement expiration and replay protection.
- [ ] Develop smartphone approval interface.
- [ ] Implement independent approval revalidation.

### Phase 5 — Monitoring and Integration

- [ ] Develop Glass-Box Monitor.
- [ ] Implement live execution traces.
- [ ] Implement audit logging.
- [ ] Add pause, cancel and emergency controls.
- [ ] Complete the end-to-end lab submission demonstration.

---

## Future Scope

Potential future enhancements include:

- Multi-device orchestration.
- Additional MCP integrations.
- Support for multiple AI models and agents.
- Advanced policy configuration.
- Enterprise permission management.
- Workflow templates and reusable automations.
- Tamper-evident audit storage.
- Advanced artifact versioning and rollback.
- Remote task monitoring.
- Organization-specific deployment configurations.

---

## Project Structure

The following is a proposed logical repository structure. Actual directories may change as implementation progresses.

```text
mini/
│
├── mobile/
│   ├── app/
│   ├── companion-agent/
│   ├── file-discovery/
│   ├── approval-ui/
│   └── evidence-viewer/
│
├── laptop/
│   ├── mini-daemon/
│   ├── task-manager/
│   ├── communication/
│   └── configuration/
│
├── orchestration/
│   ├── openclaw/
│   ├── agent-workflows/
│   └── task-planner/
│
├── mcp-servers/
│   ├── filesystem/
│   ├── search/
│   ├── document-generation/
│   ├── browser/
│   ├── gmail/
│   └── git/
│
├── security/
│   ├── policy-engine/
│   ├── permission-manager/
│   ├── workspace-isolation/
│   ├── transactional-staging/
│   └── approval-contracts/
│
├── monitoring/
│   ├── glass-box/
│   ├── execution-traces/
│   └── audit-logger/
│
├── docs/
│   ├── architecture.md
│   ├── security-model.md
│   ├── approval-protocol.md
│   └── workflows.md
│
└── README.md
```

---

## Security Considerations

Mini is designed around the principle of least privilege.

The following security requirements guide implementation:

- No unrestricted remote shell access.
- No publicly exposed laptop services as part of the intended communication architecture.
- No unrestricted filesystem access for AI agents.
- No direct execution of sensitive tool operations without policy validation.
- No execution of approval-required actions without valid human authorization.
- No reuse of expired or previously consumed approvals.
- No direct overwriting of protected files without the required authorization.
- No exposure of credentials, private keys or sensitive environment variables.
- All critical operations should be traceable through audit records.

Security mechanisms must be validated through testing rather than assumed to be secure merely because encrypted communication or AI-agent permissions are enabled.

---

## Project Status

**Development Stage:** Architecture and design / initial implementation planning.

Mini is currently being designed around a modular dual-device architecture. Its components and workflows are intended to be implemented and validated incrementally.

The end-to-end lab report submission workflow will serve as the primary functional demonstration.

---

## Contributing

Contributions are welcome as the project develops.

Potential contribution areas include:

- Android application development.
- NectarLink integration.
- AI agent orchestration.
- MCP server development.
- Browser automation.
- Security and permission enforcement.
- Approval protocol implementation.
- Monitoring and observability.

For major architectural changes, discuss the proposed approach before implementation.

---

## License

License to be determined.

---

## Final Vision

**Mini aims to make AI agents capable of performing real-world, multi-step workflows across devices without sacrificing security or user control.**

Rather than giving AI unrestricted access to personal devices, Mini creates a controlled execution environment where agents can plan and prepare autonomously, permissions are independently enforced, every sensitive action is explicitly authorized, and execution remains observable.

**Autonomous Intelligence. Restricted Execution. Human Authority.**
