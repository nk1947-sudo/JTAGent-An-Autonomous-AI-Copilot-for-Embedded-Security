# Repository Audit & Implementation Plan Review: JTAGent (SiliconSentinel)

> **Scope correction (2026-10-25):** The inference and target rows below have been corrected against
> the dated `dashboard-manual-test` record, which documents paid Nebius runs using derived evidence
> from physical 64-byte captures. The hosted synthetic audit and physical-evidence runs are separate
> historical results. Neither authorizes a new hosted request or live-data transmission; no such call
> was made in this update.

**Review Date:** 2026-10-23
**Target Repository:** `JTAGent-An-Autonomous-AI-Copilot-for-Embedded-Security`
**Current Branch / HEAD:** `dev` (`e45f56e`) / tracked against `origin/dev`
**Working Tree State:** Dirty (pre-existing uncommitted modifications preserved in `edge/backends.py`, `orchestrator/app.py`, `tests/test_adapters.py`, `tests/test_status.py`, `README.md`; untracked `scripts/run_hardware.py`, `docs/hardware-run.md`)
**Scope:** Architecture and implementation plan audit; claim validation; gap analysis. **Application code was not modified.**

---

## 1. Document Reconciliation & Baseline Ground Truth

### 1.1 `AGENTS.md`
* **Claimed Document:** `AGENTS.md`
* **Repository Ground Truth:** **Absent.** `AGENTS.md` does not exist in the working tree, git index, or any commit history.
* **Supporting Evidence:**
  * Git ignore rule added in commit `6390665` (`Keep local planning and agent files untracked`): `/.gitignore` explicitly ignores `/AGENTS.md` and `/.agents/`.
  * `.dockerignore` line 10 explicitly lists `AGENTS.md`.
  * `docs/milestones.md:5` notes: *"No applicable AGENTS.md found."*
  * `docs/JTAGent-live-application-evaluation-2026-09-29.md:31` confirms: *"no `AGENTS.md` found in the repository."*
  * `SYSTEM_AUDIT.md:4` confirms: *"No applicable AGENTS.md found during baseline traversal."*
* **Finding:** External handoffs or instructions referencing `AGENTS.md` are out of date or rely on an untracked local file convention that was deliberately excluded from version control.

### 1.2 `docs/implementation-plan.md` vs `IMPLEMENTATION_PLAN.md`
* **Claimed Document:** `docs/implementation-plan.md`
* **Repository Ground Truth:** **Path mismatch.** The implementation plan exists as `./IMPLEMENTATION_PLAN.md` in the project root, not inside `docs/`.
* **Supporting Evidence:**
  * Root file `IMPLEMENTATION_PLAN.md` (1,872 bytes) was created 2026-09-21 and updated 2026-09-22.
  * Git ignore rule in `.gitignore:4` explicitly ignores `/IMPLEMENTATION_PLAN.md` alongside `PRD.md`, `BUG_TRACKER.md`, `DAILY_MANAGER.md`, `SYSTEM_AUDIT.md`, and `TESTING_STRATEGY.md`.
  * `docs/milestones.md:42-44` notes: *"Existing local management equivalents are PRD.md, IMPLEMENTATION_PLAN.md, DAILY_MANAGER.md, BUG_TRACKER.md, TESTING_STRATEGY.md and SYSTEM_AUDIT.md. They remain ignored under the operator's policy; there are no duplicate lower-case copies."*
* **Finding:** Referring to `docs/implementation-plan.md` causes automated tools and engineers to report missing plan files (as recorded in `docs/handoff.md`).

### 1.3 `docs/handoff.md`
* **Claimed Document:** `docs/handoff.md`
* **Repository Ground Truth:** Present. Contains 24 lines dated post-evaluation.
* **Claims Analyzed:**
  1. *"No code or plan changes. `docs/review.md` is absent, so no finding could be verified or selected for implementation."* -> **Verified true.** `docs/review.md` was absent prior to this review, stalling subsequent implementation work.
  2. *"Checked the `docs` directory, tracked files, and all local branch history for `docs/review.md`; none contains it."* -> **Verified true.**
  3. *"Inspected the existing implementation plan and working tree. There are pre-existing edits to the hardware launcher path and related tests; they were left untouched."* -> **Verified true.** Pre-existing modifications in `scripts/run_hardware.py`, `docs/hardware-run.md`, `edge/backends.py`, `orchestrator/app.py`, `tests/test_adapters.py`, and `tests/test_status.py` were present and untouched.
  4. *"No tests were run because no review task could be identified."* -> **Verified.**
* **Finding:** The handoff stalled because `docs/review.md` was missing. This review unblocks the workflow by establishing verified findings.

---

## 2. Verification of Claims Against Actual Repository

| Document Claim | Source Document | Ground Truth in Code / Environment | Status | Evidence / Analysis |
|---|---|---|---|---|
| **Phase 1 Offline: 54 pytest tests overall** | `IMPLEMENTATION_PLAN.md:10` | **118 pytest tests pass** | **Stale / Exceeded** | `uv run pytest -q` executed: 118 passed, 1 deprecation warning (Starlette `BlockingPortal`). Test suite expanded from 54 -> 70 -> 118 tests. |
| **Browser mock audit/export & TS build pass** | `IMPLEMENTATION_PLAN.md:10` | **12 Playwright tests pass; Vite builds** | **Verified** | `npm --prefix web test` passed all 12 tests in 22.5s; `npm --prefix web run build` succeeded (41 modules, 1.59s). |
| **Generated-contract drift check clean** | `IMPLEMENTATION_PLAN.md:17` | **Drift check fails when `TARGET_BACKEND=openocd` is configured in `.env`** | **Fragile / Environment Coupled** | `uv run python scripts/generate_contracts.py --check` crashes with `FileNotFoundError: /absolute/path/to/operator-profile.json` because `edge.app:create_app()` initializes backends during OpenAPI export. Passes only when forced to `TARGET_BACKEND=mock`. |
| **Phase 2 Inference: Nebius Nemotron tool calling & synthetic audit pass** | `IMPLEMENTATION_PLAN.md:11` | Synthetic provider audit and separate physical-evidence dashboard runs are both recorded in 2026-09-25 docs | **Historically verified; current authorization not implied** | `docs/milestones.md` records the synthetic audit and provider usage; `docs/dashboard-manual-test-2026-09-25.md` records paid Nebius analysis of derived evidence from physical 64-byte captures. Retention remains unknown. |
| **Phase 3 Target: Complete for 64-byte live profile** | `IMPLEMENTATION_PLAN.md:12` | Historical docs record both a 16-byte live snapshot and a 64-byte physical-target audit | **Physical reads recorded; recovery/manual comparison pending** | `docs/live-snapshot-report-2026-09-29.md`, `docs/security-assessment-2026-09-25.md` and `docs/dashboard-manual-test-2026-09-25.md` document the separate bounded captures and restoration. Disconnect recovery and independent same-state comparison remain pending. |
| **Phase 4 Delivery: Assets prepared, Compose check recorded** | `IMPLEMENTATION_PLAN.md:13` | Dockerfile, `deploy/compose.yaml`, `deploy/Caddyfile.example` exist. Docker daemon is **unavailable** | **Syntax Only** | Docker CLI is installed, but the daemon is not running on the Windows workstation (`SYSTEM_AUDIT.md:20`). Compose validation is purely syntactic (`docker compose config --quiet`). Containers cannot be run locally. |
| **Status schema v2 & build identity loaded in live runtime** | `docs/status-and-evidence.md:7` | Present in source code, but **live running edge process on port 8001 runs legacy code** | **Runtime Gap** | `docs/JTAGent-P0-P1-post-implementation-verification-2026-09-30.md:18` verifies the active live edge process was started before schema v2 edits. `/api/readiness` returns 404 on the active PID 29820 stack. |
| **Ruff linting & formatting** | `docs/milestones.md:20`, `BUG_TRACKER.md:38` | `ruff check` passes across source targets; repo-wide `ruff format` crashes | **Verified with Known Tooling Bug** | `uv run ruff check analysis config contracts edge orchestrator scripts tests` passed. Repo-wide `ruff format --check .` crashes on permission-denied directories (`.test-results/pytest-temp`). Source-scoped format passes (47 files). |

---

## 3. Missing Requirements

### [M-01] Attack Plan Memory Leak and Permanent Allocation Deadlock
* **File Reference:** `orchestrator/app.py:523-539`
* **Evidence:**
  ```python
  if len(attack_plans) >= 20:
      raise HTTPException(429, "Attack plan capacity reached")
  ```
* **Gap Description:** While `orchestrator/app.py:429` implements `DELETE /api/runs/{rid}` with a 20-run cap, **no endpoint or UI action exists to delete an Attack Plan** (`DELETE /api/attack-lab/plans/{id}`). Once 20 attack plans are generated, any subsequent request to `POST /api/attack-lab/plans` fails permanently with HTTP 429 until the orchestrator process is killed and restarted.
* **Requirement Needed:** Add `DELETE /api/attack-lab/plans/{plan_id}` to `orchestrator/app.py`, update `contracts/openapi.json`, and expose a deletion control in `web/src/AttackLab.tsx`.

### [M-02] Operation Ledger Hard Limit Causes Permanent Edge Refusal
* **File Reference:** `edge/service.py:313-314`
* **Evidence:**
  ```python
  if len(self.ledger) >= 1024:
      raise PolicyError("operation_ledger_full_restart_required")
  ```
* **Gap Description:** `self.ledger` stores idempotent operation results keyed by `(session_id, request_id)`. The ledger has no sliding window, no time-to-live eviction, and no prune API. In continuous automated testing or extended interactive sessions, hitting 1,024 operations irreversibly raises `operation_ledger_full_restart_required`, locking out all target reads and snapshots.
* **Requirement Needed:** Implement an LRU or TTL-based eviction policy for completed ledger transactions older than session expiry, retaining only unexpired session transactions.

### [M-03] Automated Transport Disconnect and Watchdog Recovery Missing
* **File Reference:** `edge/backends.py:164-180`, `docs/live-validation-procedure.md:48-52`
* **Evidence:** The working tree modification in `edge/backends.py` sets `self.ready = False` if `self.rpc.writer is None`. However, if the physical USB JTAG adapter (FTDI C232HM) disconnects or OpenOCD restarts under a different PID:
  1. The edge does not automatically re-probe or re-negotiate target attachment.
  2. The AM335x hardware watchdog (WDT1) triggers an unhandled board reset if the core remains halted beyond the watchdog interval.
  3. No automated recovery sequence exists to handle target reset detection (`state == "reset"`).
* **Requirement Needed:** The plan must specify an explicit state-machine transition for `state == "reset"`, timeout thresholds for core halting relative to SoC watchdog periods, and an automated reconnection policy.

### [M-04] In-Memory Volatility of Investigation Audit Trails
* **File Reference:** `orchestrator/app.py:114`
* **Evidence:**
  ```python
  runs, tasks, cancellations, login_sessions, attack_plans = {}, {}, {}, {}, {}
  ```
* **Gap Description:** `runs` and `attack_plans` reside solely in process memory. If the orchestrator process is restarted (which is explicitly required to clear source drift or upgrade status schema), all prior audit results, observations, and findings disappear unless the operator manually clicked "Export evidence bundle" before shutdown.
* **Requirement Needed:** An opt-in local SQLite or append-only JSONL event journal on disk (`./data/audit.journal`) to persist run headers, status, and linked bundle paths across process restarts.

### [M-05] Missing Invalidation Cascade for Edge Sessions on Operator Logout
* **File Reference:** `orchestrator/app.py:230-235`, `edge/service.py:73-85`
* **Evidence:** When an operator logs out (`POST /api/logout`), the orchestrator deletes the HTTP-only `operator` session cookie. However, no cancellation or session termination request is dispatched to `DELETE /api/v1/sessions/{id}` on the edge service. Active edge leases and sessions remain valid on the edge until their standalone TTL expires (up to 120 seconds).
* **Requirement Needed:** Orchestrator logout must issue a revocation call to the edge service to terminate active inspection sessions and release held leases immediately.

### [M-06] Incomplete Acquisition Record on Snapshot Abort / Read Failure
* **File Reference:** `edge/service.py:240-275`
* **Evidence:** If `self.read(req)` raises a `BackendError` (e.g. read timeout), the `finally` block attempts to restore target execution state, but `result["acquisition"]` is constructed *after* the `finally` block. Because the exception terminates the method, no `AcquisitionRecord` is generated or saved for failed or aborted hardware operations.
* **Requirement Needed:** Construct and retain the `AcquisitionRecord` in both success and failure branches, recording `initial_state`, `final_state`, and error diagnostics for post-mortem forensic review.

---

## 4. Incorrect Assumptions

### [A-01] Path and Tracking Conventions for Plan Files
* **Assumption:** Documentation and handoff procedures assume `docs/implementation-plan.md` and `AGENTS.md` are tracked files in standard directories.
* **Repository Reality:** The plan lives at `./IMPLEMENTATION_PLAN.md` (root) and is explicitly git-ignored. `AGENTS.md` does not exist.
* **Impact:** Engineers and automated subagents stall looking for missing files, resulting in handoff blocks (e.g., `docs/handoff.md`).

### [A-02] Contract Generation Decoupled from Hardware Environment
* **File Reference:** `scripts/generate_contracts.py:14`, `edge/app.py:35, 64`
* **Assumption:** Static API contract generation (`scripts/generate_contracts.py --check`) is a pure metadata task that can run in any environment.
* **Repository Reality:** `scripts/generate_contracts.py` invokes `edge_app().openapi()`. In `edge/app.py`, `create_app()` calls `configured_service()`, which parses environment variables. If `.env` contains `TARGET_BACKEND=openocd` and `TARGET_PROFILE=/absolute/path/to/operator-profile.json`, the script attempts to read the file from disk and crashes with `FileNotFoundError`, breaking CI/CD contract validation.
* **Impact:** Contract drift verification cannot run on developer machines that have a live hardware `.env` configured without manually overriding environment variables.

### [A-03] CPU Halt State Assumed to Freeze System State
* **File Reference:** `edge/service.py:206`, `docs/live-integration.md:44-48`
* **Assumption:** Halting the Cortex-A8 core via OpenOCD (`halt 1000`) creates a frozen system snapshot.
* **Repository Reality:** On the AM335x SoC, halting the ARM core halts CPU execution, but DMA engines, timers (WDT1, DMTimer), and bus peripherals continue operating unless specifically configured in OpenOCD target stop scripts. Memory and registers are read in sequential round-trips over Tcl RPC, not as an atomic hardware snapshot.
* **Impact:** Memory can mutate between the memory read and register capture. The plan must treat sequential reads as loosely coupled observations rather than atomic freeze-frames.

### [A-04] Region Profile Mode Assumed to Dictate Instruction Encoding
* **File Reference:** `web/src/Workbench.tsx:100`, `orchestrator/workbench.py:11-25`, `analysis/evidence.py:36-60`
* **Assumption:** Bytes captured within an ARM-configured region represent valid ARM instructions.
* **Repository Reality:** In bare-metal bootloaders and SRAM vector tables, data words (vector table branch offsets, literal pools, zero-padding) reside alongside code. Capstone mechanically disassembles data words (e.g. `0x00000000`) as `andeq r0, r0, r0`. Non-expert operators can mistake disassembled data for malicious code or shellcode.
* **Impact:** The plan lacks a requirement to distinguish code vs data/literal pools via symbol maps or cross-reference analysis (e.g., via Ghidra).

### [A-05] Phase 4 Delivery Readiness under Windows Environment
* **File Reference:** `IMPLEMENTATION_PLAN.md:13`, `deploy/compose.yaml`
* **Assumption:** Docker Compose deployment can be delivered and validated as part of Phase 4.
* **Repository Reality:** The Docker daemon is unavailable on the workstation. OpenOCD requires direct WinUSB / libusb access to the FTDI C232HM adapter, which is non-trivial to pass into Docker containers on Windows without native WSL2 USBIP forwarding.
* **Impact:** Delivery must be framed around native process orchestration (`scripts/run_hardware.py`) rather than Docker Compose.

---

## 5. Unnecessary Complexity

### [C-01] Redundant Client-Side Runtime Schema Validation (Ajv)
* **File Reference:** `web/src/contract.ts`, `web/src/Workbench.tsx:18`, `web/scripts/gen-validators.mjs`
* **Description:** The build pipeline generates standalone Ajv validation functions from `openapi.json` (`web/src/generated/validators.js`) and runs runtime validation on internal API responses in React. The frontend is already strictly typed using TypeScript types generated from the same OpenAPI schema (`api.d.ts`).
* **Critique:** Running full Ajv schema compilation and validation in the browser for trusted localhost API endpoints adds 405 kB to the JS bundle, increases Vite build time, and creates fragile failure points where minor schema extensions (e.g., adding an optional field) cause the UI to blank out or display contract error banners.

### [C-02] Heavyweight Source Fingerprinting in `BuildIdentity`
* **File Reference:** `contracts/build.py:26-36`
* **Description:** Every time `create_app` is called, `source_fingerprint()` walks five directory trees (`analysis`, `contracts`, `edge`, `fixtures`, `orchestrator`) and computes a SHA-256 hash over every `.py` file to detect source drift.
* **Critique:** Calculating SHA-256 over dozens of files on every application instantiation introduces unnecessary filesystem overhead on Windows and breaks if files are packaged or zipped. Git commit hash + dirty flag is sufficient for build provenance in development.

### [C-03] Triple-Tier Target Locking Architecture
* **File Reference:** `orchestrator/app.py:115` (`target_start_lock`), `edge/service.py:65` (`self.lock`), `edge/service.py:68` (`self.lease`)
* **Description:** The system enforces single-target ownership using:
  1. An `asyncio.Lock()` in the orchestrator (`target_start_lock`).
  2. A run state check in the orchestrator (`if any(r.status in ('running', 'queued'))`).
  3. An `asyncio.Lock()` in the edge (`self.lock`).
  4. An explicit lease tuple in the edge (`self.lease = (session_id, generation)`).
* **Critique:** Having three separate locking abstractions across two processes increases the risk of desynchronization, deadlock, or lease recovery failures when requests timeout.

---

## 6. Security Gaps

### [S-01] Unauthenticated OpenOCD Loopback Ports (Local Policy Bypass)
* **Severity:** **High (CVSS 7.8 - Local Privilege Escalation / Policy Bypass)**
* **File Reference:** `deploy/compose.yaml`, `scripts/run_hardware.py:100-115`, `edge/backends.py:120-140`
* **Vulnerability:** OpenOCD binds to `127.0.0.1:6666` (Tcl), `127.0.0.1:4444` (Telnet), and `127.0.0.1:3333` (GDB) without authentication.
* **Threat Model:** Any unprivileged process or malware executing locally on the operator's workstation can connect directly to port 6666 or 4444. This allows an attacker to issue arbitrary OpenOCD commands (e.g., `mww` to write memory, `flash write_image`, `halt`, `resume`), completely bypassing JTAGent's region allowlists, read-only policies, and audit logging.
* **Mitigation:**
  1. Pass `-c "tcl_port disabled"` and `-c "telnet_port disabled"` to OpenOCD if Telnet/GDB are unused, or use a Unix domain socket / named pipe where access control can be enforced.
  2. Require OpenOCD configuration scripts to bind exclusively to a random local loopback port dynamically assigned per session.

### [S-02] Plaintext Secrets Stored in Working Directory `.env`
* **Severity:** **Medium**
* **File Reference:** `.env:1-35`
* **Vulnerability:** Active API keys (`TAVILY_API_KEY`, `LANGSMITH_API_KEY`, `NEBIUS_API_KEY`) and hardware credentials (`UART_AUDIT_PASSWORD=temppwd`) are stored in cleartext on disk in the root `.env` file.
* **Threat Model:** While `.env` is git-ignored, local processes, IDE extensions, or diagnostic bundles can expose these credentials.
* **Mitigation:** Support loading secrets from the OS credential store (Windows Credential Manager) or interactive terminal prompts rather than relying on persistent plaintext `.env` files.

### [S-03] Information Disclosure via Unauthenticated `/healthz`
* **Severity:** **Low**
* **File Reference:** `contracts/models.py:348-358`, `edge/app.py:84`, `orchestrator/app.py:246`
* **Vulnerability:** `GET /healthz` returns full `BuildIdentity` without authentication:
  ```json
  {
    "status": "ok",
    "build": {
      "component": "orchestrator",
      "version": "0.1.0",
      "commit": "e45f56e",
      "dirty": true,
      "source_fingerprint": "...",
      "build_id": "e45f56e+dirty:...",
      "process_started_at": "2026-10-23T06:27:00Z",
      "pid": 29820,
      "python": "3.12.14"
    }
  }
  ```
* **Threat Model:** An unauthorized local process or network observer probing port 8000/8001 gains exact internal process IDs, Python versions, commit hashes, and source drift status before presenting credentials.
* **Mitigation:** Restrict `/healthz` to returning `{"status": "ok"}` only. Require authentication for detailed build identity inspection via `/api/readiness`.

### [S-04] Cross-Origin Loopback Requests (DNS Rebinding / CSRF)
* **Severity:** **Medium**
* **File Reference:** `orchestrator/app.py:120-130`, `edge/app.py:70-80`
* **Vulnerability:** The edge API relies on `Authorization: Bearer <key>`, but the orchestrator uses session cookies with `SameSite=Lax`. Neither service validates the HTTP `Host` or `Origin` header against `PUBLIC_ORIGIN`.
* **Threat Model:** If an operator visits an untrusted website while running JTAGent locally, a malicious script on the web page could trigger cross-origin POST requests or DNS rebinding against `127.0.0.1:8000` to trigger runs or state transitions.
* **Mitigation:** Implement strict `Host` header and `Origin` validation middleware verifying requests originate strictly from `127.0.0.1` or `localhost`.

---

## 7. Weak Acceptance Criteria

### [W-01] Count-Based Test Criteria (`54 pytest tests`)
* **Plan Text:** `IMPLEMENTATION_PLAN.md:10` (*"54 pytest tests overall; browser mock audit/export passed; TS build passed"*).
* **Deficiency:** A static test count (54) is a poor proxy for quality. The repository now has 118 tests, yet critical failure modes (such as physical JTAG adapter disconnection, Tcl socket crash, or attack plan memory leak) were not covered until recent targeted additions.
* **Replacement Criterion:** Acceptance must require 100% pass rate on a tagged functional test matrix including:
  * Adapter disconnect/reconnect recovery.
  * Policy rejection of unapproved memory ranges (`address_overflow`, `range_not_approved`).
  * Invariant restoration of CPU state (`running` -> `halted` -> `running`).
  * Zero memory leaks after 50 consecutive runs/plans.

### [W-02] Unquantified "Fault/Manual Comparison Pending"
* **Plan Text:** `IMPLEMENTATION_PLAN.md:12` (*"Complete for 64-byte live profile; fault/manual comparison pending"*).
* **Deficiency:** "Pending" provides no measurable pass/fail threshold.
* **Replacement Criterion:** Bounded live validation passes if and only if:
  1. An independent manual read (`mdw phys 0x402F0400 4`) via Telnet produces identical bytes to JTAGent's captured memory (`scripts/compare_manual_read.py` returns exit code 0).
  2. CPU core execution state is restored to `running` within 1,000 ms.
  3. `scripts/verify_bundle.py` reports `VERIFIED: 22 checks passed, 0 failed, 0 unverifiable` on the resulting export.

### [W-03] Schema-Only Validation for AI Model Outputs
* **Plan Text:** `IMPLEMENTATION_PLAN.md:11` (*"Real model visibility, native tool call and full synthetic evidence audit pass"*).
* **Deficiency:** Validating that the model returned schema-valid JSON does not evaluate semantic safety or prompt injection vulnerability. A compromised or hallucinating model could return valid JSON suggesting invalid actions or misclassifying data strings as critical vulnerabilities.
* **Replacement Criterion:** The verifier node (`orchestrator/workflow.py:verify`) must deterministically validate all model findings:
  1. Every cited register must match the exact snapshot value.
  2. String observations must match exact extracted strings from approved regions.
  3. Hypotheses must never be upgraded to confirmed vulnerabilities without physical proof.

### [W-04] Superficial Deployment Acceptance Criteria
* **Plan Text:** `IMPLEMENTATION_PLAN.md:13` (*"Assets prepared; final Compose check recorded in docs/milestones.md"*).
* **Deficiency:** Relying on `docker compose config` verifies only YAML syntax, not functional deployment, container networking, or USB device pass-through.
* **Replacement Criterion:** Deployment acceptance must require:
  1. Successful launch of native services via `scripts/run_hardware.py` or containerized stack.
  2. Successful health and readiness check via `/api/readiness`.
  3. Passing all Playwright end-to-end tests against the deployed stack on isolated ports.

---

## 8. Prioritized Implementation Recommendations

To transition from the current evaluation state to a clean, production-grade release, `IMPLEMENTATION_PLAN.md` should be updated with the following prioritized work packages:

### Priority 0 (P0): Path Normalization & Contract Independence
1. **Reconcile Plan File Paths:** Relocate `./IMPLEMENTATION_PLAN.md` to `docs/implementation-plan.md` (or add a symlink/redirect pointer) and update documentation references to prevent broken handoffs.
2. **Decouple Contract Generation from Hardware Environment:** Refactor `scripts/generate_contracts.py` and `edge/app.py` so that `edge_app().openapi()` can be evaluated with mock defaults without reading `.env` or failing on missing target profiles.

### Priority 1 (P1): Memory Management & Operational Stability
1. **Add Attack Plan Deletion Endpoint:** Implement `DELETE /api/attack-lab/plans/{plan_id}` in `orchestrator/app.py` to prevent the 20-plan hard allocation deadlock ([M-01]).
2. **Implement Sliding Window for Edge Ledger:** Replace the 1,024-entry hard failure limit in `edge/service.py` with an LRU cache or TTL pruner ([M-02]).
3. **Persist Acquisition Records on Failure:** Ensure `AcquisitionRecord` is constructed and preserved even when memory read or snapshot operations fail ([M-06]).

### Priority 2 (P2): Security Hardening & Isolation
1. **Sanitize `/healthz`:** Strip internal PID, file paths, and Python versions from unauthenticated `/healthz` responses; move detailed build telemetry to authenticated `/api/readiness` ([S-03]).
2. **Add Host/Origin Validation:** Introduce middleware in `orchestrator/app.py` and `edge/app.py` verifying that incoming requests originate strictly from authorized loopback origins ([S-04]).
3. **Session Revocation Cascade:** Dispatch an edge session termination call when an operator signs out of the dashboard ([M-05]).

### Priority 3 (P3): Target Recovery & Verification Execution
1. **Formalize Hardware Reconnection Logic:** Integrate the OpenOCD reconnect check from `edge/backends.py` with automated backoff and state recovery in `scripts/run_hardware.py` ([M-03]).
2. **Execute Bounded Live Validation:** Execute the prepared 16-byte live validation procedure (`docs/live-validation-procedure.md`) under operator supervision with the independent manual `mdw` comparison.
