# JTAGent — Live Application Evaluation and Embedded Engineer Review

**Evaluation date:** 2026-09-29 (America/New_York)  
**Repository:** `JTAGent-An-Autonomous-AI-Copilot-for-Embedded-Security`  
**Branch / baseline:** `codex/uboot-security-audit` / `1208a1b88fccae95d2cebee082227b3c1d9427a4`  
**Working tree:** materially dirty before this evaluation; existing changes were preserved  
**Reviewer change:** one narrow UI null-handling correction in `web/src/Workbench.tsx`

## 1. Overall assessment and readiness verdict

**Verdict: useful evidence-review prototype; not yet ready for unattended live investigations or independent forensic reproduction.**

JTAGent currently helps an embedded engineer confirm local service readiness, see the configured AM335x SRAM boundary, review retained JTAG memory/register evidence, obtain bounded scripted debugger guidance, preview equal-length patches offline, and export an Attack Lab plan. The application correctly keeps live writes disabled and makes the physical snapshot path subject to HITL approval.

The strongest verified qualities are policy-bounded target access, clear backend labeling, retained evidence provenance, deterministic Capstone output, explicit uncertainty, and a working local analysis path. The most important limitations are:

1. the active edge service is older than the latest source and does not expose the source tree's layered debugger status fields;
2. the current investigation store contains no dashboard audit runs, so a dashboard-driven live investigation was not completed during this evaluation;
3. the retained live capture withholds raw bytes, preventing independent recomputation of its SHA-256 hash or disassembly;
4. Attack Lab Markdown omits the detailed capture, registers, timestamps, instruction list, and hash that exist in JSON;
5. the AI Workbench initially crashed on a schema-valid `null` action address; this was corrected and verified in the running browser.

No new JTAG snapshot, halt, read, resume, reset, flash, write, register modification, breakpoint, UART audit, or cloud inference was performed. Therefore this report does **not** claim a newly performed physical attack or vulnerability validation.

## 2. Repository version, running configuration, and access

### Newly verified access

| Capability | Result | Evidence |
| --- | --- | --- |
| Repository | Available | Branch and HEAD above; no `AGENTS.md` found in the repository. |
| Terminal | Available | Python, Ruff, npm, port, process, and authenticated loopback API checks executed. |
| Browser | Available | Dashboard opened in the Codex in-app browser and exercised at mobile/default and 1440×1000 desktop viewports. |
| Authentication | Available | Documented password login succeeded; secret is intentionally omitted. |
| Dashboard | Listening on `127.0.0.1:8000` | PID 29820, Python/Uvicorn, started 21:10:11 local. |
| Edge API | Listening on `127.0.0.1:8001` | PID 3800, Python/Uvicorn, started 21:09:50 local. |
| OpenOCD | Listening on loopback ports 3333, 3334, 4444, and 6666 | PID 11076, xPack OpenOCD, started 21:12:56 local. Command line uses `interface/ftdi/c232hm.cfg`, `target/am335x.cfg`, 100 kHz, and `bindto 127.0.0.1`. |
| Saved/in-memory evidence | Available | Saved 16-byte report and one process-retained 64-byte Attack Lab capture. |
| Docker | Not established | Docker client could not access its daemon/config in this environment. Native services were reused. |

### Active application configuration

Authenticated `/api/config` returned:

- target `beaglebone-black-am335x`, ARM, little-endian, 32-bit physical address space;
- approved region `am335x-internal-sram-smoke-window`, `[0x402F0400, 0x402F0440)`, 64 bytes, executable, profile mode ARM;
- approved registers `pc`, `lr`, `sp`, `cpsr`;
- edge backend `openocd`, target state `running`, generation 2, `recovery_required=false`;
- UART enabled on COM12 at 115200 baud;
- inference backend `scripted`, model `scripted-demo-v1`;
- live JTAG Attack Lab option armed.

This verifies the configured target and the application's current view of target state. It does not independently prove board identity beyond the active OpenOCD configuration and previously recorded scan-chain result.

### Important running-code distinction

The active edge process started at 21:09:50. `edge/service.py` was modified at 21:44:07. The live edge response still has the older flat shape (`state`, `target_backend`, `generation`, `capabilities`, `recovery_required`) and lacks the source tree's `application`, nested `debugger`, nested `target`, `snapshots_armed`, and `read_prerequisite` fields implemented at `edge/service.py:89-129`. The latest layered-status code is therefore **present and unit-tested but not loaded by the active edge process**.

The frontend static bundle was rebuilt during evaluation. Uvicorn serves the updated static files without restarting the Python process, which allowed the Workbench UI correction to be verified while preserving the edge and OpenOCD sessions.

## 3. Test scope and hardware authorization

The evaluation began with non-mutating checks: process/listener inventory, `/healthz`, authenticated configuration/status, browser inspection, retained evidence review, exports, and local analysis. No new physical operation was authorized.

The only physical artifacts reviewed were pre-existing:

- **Previously reported:** a 16-byte snapshot at `0x402F0400` plus PC/LR/SP/CPSR in `docs/live-snapshot-report-2026-09-29.md`. This evaluation verified the file exists and is internally coherent, but did not reproduce the capture or recompute its hash.
- **Currently retained in the running Attack Lab:** a 64-byte physical capture at `0x402F0400`, evidence `80c5dffb-da01-4f0f-86d0-d5c07252a898`, plus a register snapshot. This evaluation read the retained application data; it did not execute that step.

No live evidence was sent to Nebius. The active inference backend is scripted.

## 4. Workflow test matrix

| Workflow | Objective and actions performed | Expected | Actual | Status | Practical effect |
| --- | --- | --- | --- | --- | --- |
| A. Connection readiness | Opened dashboard; compared readiness tiles with authenticated config, raw edge status, listener/process metadata, and OpenOCD command line; reloaded at two viewports. | Distinguish app, edge, debugger, target, CPU state, authorization, and inference. | App/edge/target/UART/inference and CPU `running` are visible. Attack Lab shows `REAL JTAG ARMED`. OpenOCD version and debugger layer are not separately visible because the active edge is stale. Readiness is loaded on login/reconnect, not periodically refreshed. | **Partial** | Good first glance, but an engineer can mistake stale or aggregate status for current debugger proof. |
| B. Memory and registers | Reviewed allowed region, retained 64-byte capture, register list, provenance, partial flag, target state, generation, hash, and raw-byte policy. No new read. | Validated inputs, clear failure semantics, provenance, partial labeling. | Scope is fixed to the approved 64-byte region; no arbitrary live address field exists in Investigation. Retained capture is full length and labeled `halted` at capture. Error classification is covered by tests, but the active edge has not loaded the latest explanatory fields. | **Partial** | Safe bounded inspection works; live failure guidance is not fully represented in the running UI. |
| C. Instruction and CPU interpretation | Reviewed Workbench disassembly/registers and saved report CPSR decode. | Separate configured memory mode from current CPU state; show sources and uncertainty. | Workbench says ARM/little from the region profile and shows raw CPSR `0x600000b3`; the saved audit report decodes Supervisor/Thumb and states captures are non-atomic. The UI does not decode CPSR or strongly explain that current Thumb state does not override region ARM mode. Zero/data words are mechanically decoded after the vector entries. | **Partial** | Useful low-level view, but code/data boundaries and mode provenance require expert judgment. |
| D. Interface investigation | Inspected current dashboard state, run history, controls, progress surfaces, and exports. Exercised Workbench local analysis; did not click Start audit because it would request a new live snapshot. | UI/API/evidence/analyst/report operate together. | No retained dashboard runs exist. Python integration tests cover mock/scripted orchestration. The existing Playwright test could not run because its configuration refuses to reuse occupied ports 8000/8001. | **Blocked live / passed in automated mock tests** | Current physical workflow cannot be certified end-to-end without bounded authorization or an isolated browser-test port configuration. |
| E. Analysis quality | Invoked the local scripted debugger agent on the retained capture and inspected its response. | Evidence citations, hypotheses, uncertainty, useful typed follow-ups, no unsupported vulnerability. | Response cited address, length, hash, instruction count, and PC; separated a hypothesis; proposed only typed read-only actions; disclosed missing symbols/Ghidra and no breakpoint/write. Initial rendering crash was fixed. | **Pass after fix, scripted only** | Useful triage guidance; not evidence of paid model quality. |
| F. Export and reproduce | Requested existing Attack Lab JSON and Markdown; compared plan ID, status, evidence ID, physical flag, results, capture, and registers. | UI/JSON/Markdown/capture consistent and independently reviewable. | Shared fields agree. JSON contains capture/register detail. Markdown contains only plan metadata, steps, one evidence ID, and safety boundary. Raw bytes are withheld, so the hash and disassembly cannot be independently recomputed. | **Partial** | Another engineer can audit the decision trail, but cannot fully verify the physical evidence from the Markdown export alone. |

## 5. Detailed findings and evidence

### F-01 — Active edge does not run the latest layered-status implementation

**Severity:** P0 safety/accuracy concern  
**Newly verified:** yes

The source implements a non-raising layered report with debugger reachability, version compatibility, target communication, execution state, snapshot arming, and a running-target read prerequisite (`edge/service.py:89-129`). Unit tests cover these fields. The active `/api/v1/target/status` response omits them, and its process predates the source modification.

This matters because the dashboard currently reports `READY running` without separately proving OpenOCD version compatibility or presenting the read prerequisite. Attack Lab does show that live JTAG is armed, but Investigation does not expose the source tree's `snapshots_armed` signal.

### F-02 — AI Workbench crashed on a valid nullable action field

**Severity:** P1 workflow blocker  
**Newly verified and corrected:** yes

Clicking **Ask debugger agent** on the retained physical capture produced a blank page. Browser console evidence:

```text
TypeError: Cannot read properties of null (reading 'toString')
```

The API correctly returned an `inspect_registers` action with `address: null`. `Workbench.tsx` checked only `address !== undefined`, then passed `null` to the hex formatter. The correction models `address`, `length`, and `count` as nullable and renders the address only when `item.address != null` (`web/src/Workbench.tsx:8,32`).

After rebuilding, the same live browser flow rendered both actions and no new page failure occurred. The response showed:

- capture `0x402F0400`, 64 bytes, hash `27826a...a499`;
- 16 profile-mode instructions;
- PC `0xC0017006`;
- typed `disassemble` and `inspect registers` actions;
- explicit limitations: no source symbols/Ghidra, and no breakpoint, step, write, or persistent modification.

### F-03 — Attack Lab Markdown is materially less complete than JSON

**Severity:** P1 reproducibility gap  
**Newly verified:** yes

The JSON export contains one 64-byte capture, one register snapshot, the full capture hash, timestamp, source mode, target state, decoded instructions, PC/LR/SP/CPSR, and step results. The Markdown export contains the plan metadata, steps, a single evidence UUID, and the safety boundary, but none of the detailed capture or register data.

The export truthfully says physical execution occurred and the target was restored to running. However, the Markdown alone cannot support that statement with the available detailed evidence.

### F-04 — Raw evidence policy prevents independent validation

**Severity:** P1 reproducibility gap  
**Newly verified:** yes

The retained capture exposes `approved_hex: null` and `withheld_reason: Raw bytes withheld by edge data policy`. This is a defensible data-minimization boundary, but it means the reported SHA-256 and Capstone instructions cannot be independently recomputed from the export. The offline patch preview reinforces the limitation: it can compare user-supplied equal-length bytes and disassemble before/after, but warns that the supplied original bytes are not read-back verified.

The banner **OFFLINE PREVIEW VERIFIED** therefore means schema/length/disassembly validation, not verification that the proposed original bytes match target memory.

### F-05 — Readiness does not refresh automatically

**Severity:** P2 usability/accuracy issue  
**Newly verified from UI and source:** yes

Configuration/readiness loads on mount/login and on explicit reconnect. There is no periodic refresh; the only interval is the UART countdown (`web/src/main.tsx:56`). During a debugging session, OpenOCD or the target can change state while old green tiles remain visible until reload.

### F-06 — Mode and code/data interpretation remain expert-facing

**Severity:** P2 clarity issue  
**Newly verified:** yes

The Workbench correctly labels the captured region `ARM · little` and separately shows the capture state `halted`. PC/CPSR are shown, while the saved audit Markdown describes CPSR `0x600000b3` as Supervisor mode, Thumb state, IRQ masked. This separation is technically important: the current CPSR Thumb bit does not prove the SRAM vector-table bytes should be decoded as Thumb.

The first word decodes to `b #0x402f0444` followed by vector-like `ldr pc, [pc, #0x14]` entries. Later zero/data words decode mechanically as conditional instructions. The UI exposes the profile assumption and uncertainty but does not mark likely data/vector literals versus reachable code.

### F-07 — Existing evidence is process-local and fragmented across artifacts

**Severity:** P2 evidence lifecycle issue  
**Newly verified:** yes

The Investigation run list is empty while Attack Lab retains a 64-byte capture in process memory. A separate 16-byte audit report exists on disk. The two artifacts have different evidence IDs, lengths, hashes, and capture times. This is not necessarily inconsistent—they are different prior captures—but the product lacks a durable, unified evidence store tying runs, plans, reports, and provenance together after restart.

### UI reference images

The following repository images are from the earlier scripted demonstration, not screenshots of this evaluation's live session. They are included only as visual references and are not evidence of current hardware state.

![Scripted dashboard demonstration](../artifacts/SiliconSentinel-demo-preview.png)

![Local start-command demonstration](../artifacts/SiliconSentinel-start-command-preview.png)

Current-session visual verification was performed directly in the in-app browser. Secrets were not displayed or copied into this report.

## 6. Previous Claude claims versus current verification

| Previous claim | Current disposition |
| --- | --- |
| Edge 8001, dashboard 8000, OpenOCD Tcl 6666 | **Verified now.** All listeners are active on loopback. |
| Temporary edge 8011 stopped | **Verified now.** No listener on 8011 was observed. |
| Improved layered status and debugger classification | **Source/tests verified; active edge not updated.** The running API returns the old flat status shape. |
| Improved audit Markdown with instructions, registers, CPU state, CPSR | **Verified in source, tests, and saved 16-byte report.** This does not apply to the separate Attack Lab Markdown exporter. |
| 70 pytest tests pass | **Verified now:** 70 passed, one upstream Starlette/AnyIO deprecation warning, 3.56 s. |
| Ruff clean | **Verified now:** `ruff check .` passed. Repository-wide `ruff format --check .` crashed while traversing an inaccessible generated result directory; a targeted check reports all 31 Python source files formatted. |
| One 16-byte physical snapshot and restored running | **Report exists; not re-executed.** Current status is running, but this evaluation cannot prove historical restoration causality. |
| Report assembled from saved live evidence using scripted analyst | **File and scripted label verified.** Hash not independently recomputed because bytes are withheld. |
| No dashboard-driven live investigation/browser status-tile verification | **Partially changed.** Browser status tiles were verified now; no new dashboard live investigation was authorized or performed. |
| No independent byte comparison, disconnect recovery, web build, or Playwright | **Web build now verified.** Independent bytes and disconnect remain untested. Playwright test is discovered but full execution remains blocked by occupied ports in its current configuration. |

## 7. Software validation

| Check | Command | Result |
| --- | --- | --- |
| Python tests | `uv run pytest -q` | **Pass:** 70 passed, one deprecation warning, 3.56 s. |
| Ruff lint | `uv run ruff check .` | **Pass:** all checks passed; access warnings were emitted for out-of-scope paths. |
| Ruff format, repository-wide | `uv run ruff format --check .` | **Tooling failure:** Ruff panicked with `Expected a ruff source file` while traversing an inaccessible generated test-results path. Not classified as a source formatting defect. |
| Ruff format, source targets | `uv run ruff format --check analysis config contracts edge orchestrator scripts tests` | **Pass:** 31 files already formatted. |
| Frontend build | `npm run build` | **Pass:** TypeScript and Vite; 33 modules; 1.11 s after the Workbench fix. |
| Playwright discovery | `npx playwright test --list` | **Pass:** one test discovered. |
| Playwright execution | `npx playwright test ...` | **Blocked by environment/config:** test webServer refuses to start because 8000 is already occupied and `reuseExistingServer=false`. The active live stack was preserved. |
| Manual browser verification | In-app browser | **Pass/partial:** login, readiness, desktop/mobile layout, Investigation, Attack Lab boundary text, retained Workbench evidence, local debugger guidance, and offline patch preview verified. |

The 70-test suite validates policy gates, API contracts, evidence verification, report content, mock/replay paths, status classification, UART behavior, and Attack Lab semantics. It is not a substitute for a new physical capture or disconnect test.

## 8. Engineering usefulness

### What it helps accomplish today

- Confirm that the local dashboard, edge bridge, OpenOCD-backed target, UART configuration, and inference adapter are available.
- Enforce a small reviewed physical memory window and register allowlist.
- Review historical JTAG bytes through deterministic ARM disassembly and provenance metadata.
- Keep observation, hypothesis, and typed follow-up actions separate.
- Require HITL approval before the one implemented physical Attack Lab operation.
- Preview equal-length byte substitutions offline without writing the target.
- Produce machine-readable plan evidence and an operator-readable decision trail.

### Where an engineer still needs other tools

- **OpenOCD/GDB:** breakpoints, stepping, stack inspection, symbols, dynamic control flow, fault recovery, and independent reads.
- **UART terminal/logic capture:** complete boot logs, timing-sensitive autoboot interaction, and independent transcript retention.
- **ELF and symbols:** mapping PC/LR and SRAM vectors to functions and source.
- **Ghidra/IDA/Binary Ninja:** functions, xrefs, CFG, data/code boundaries, decompilation, and patch context.
- **Independent acquisition/export:** raw bytes or a signed local evidence bundle to verify hashes and decoding.
- **Fault-injection/side-channel hardware:** dedicated trigger, power/glitch, capture, and safety adapters; the current app only plans these workflows.

The single largest practical limitation is the lack of a durable, independently verifiable evidence bundle connecting raw acquisition, registers, target state before/after, analysis, and reports.

## 9. Evidence integrity and target-state handling

Positive controls include an approved 64-byte physical range, explicit capabilities, operation/byte budgets, generation checks, recovery flags, a single-target lease, restore-on-exit snapshot design, raw-byte withholding, local scripted analysis, and disabled live writes.

The retained plan states `restoration=running` and the current edge reports `running` with `recovery_required=false`. Those are two consistent application observations. They are not an independent hardware trace of the historical transition. Memory and registers were captured separately, and the report correctly warns they are not atomic; DMA/peripherals may continue while the CPU is halted.

No vulnerability is established by the vector-like instructions, the ability to attach JTAG, or current register values alone. Debug exposure is a finding only when compared with the intended production security policy and device lifecycle.

## 10. Performance observations and limits

- Two observed `/api/config` readiness refreshes reported edge/target latency of approximately **52.1 ms** and **66.8 ms**. These include local edge/status work under the current live setup; sample count is two and this is not a benchmark.
- The frontend production build completed in **1.11 s** on the second build.
- Python tests completed in **3.56 s**.
- The saved prior report states a 696 ms 16-byte snapshot; this evaluation did not reproduce it.
- The retained 64-byte plan has event timestamps around the physical step but no dedicated operation latency field, so no snapshot-performance claim is made from it.

## 11. Prioritized recommendations

### P0 — Make loaded status capability explicit and fail closed on schema downgrade

- **Observed problem:** current edge serves an older flat schema while the UI appears ready; source changes are not running proof.
- **Engineering example:** an operator sees `CPU target READY running` but cannot tell whether OpenOCD version validation or snapshot arming was evaluated by this process.
- **Proposed change:** version the edge status schema; have the orchestrator require and display `application`, `debugger.reachable`, `debugger.version_ok`, `target.communication`, `target.execution_state`, `snapshots_armed`, and `read_prerequisite`. Show `STALE/INCOMPATIBLE` when fields are absent. Add build/commit identifiers to `/healthz`.
- **Components:** `edge/service.py`, `edge/app.py`, `orchestrator/app.py`, `web/src/main.tsx`.
- **Acceptance criteria:** a deliberately old edge produces an amber incompatible-state tile and disables live Start/Execute controls; a current edge displays all layers and the exact build ID.

### P1 — Export one complete evidence bundle

- **Observed problem:** Attack Lab JSON is detailed, Markdown is sparse, raw bytes are withheld, and saved/current evidence is fragmented.
- **Engineering example:** a peer cannot recompute hash `27826a...a499` or reproduce the disassembly from the Markdown report.
- **Proposed change:** create a local-only, operator-approved evidence bundle containing manifest, raw or encrypted bytes, exact hash scope, profile, OpenOCD/build versions, before/after target states, registers, decoder settings, findings, and linked Markdown/JSON. Keep cloud payload separately sanitized.
- **Components:** edge evidence store, `orchestrator/attack_lab.py`, `orchestrator/report.py`.
- **Acceptance criteria:** an offline verifier recomputes every hash and identical Capstone instructions from an exported bundle; Markdown links each evidence ID to bundle content.

### P1 — Add Workbench contract and rendering regression coverage

- **Observed problem:** a valid nullable address blanked the entire Workbench.
- **Engineering example:** `inspect_registers` needs no address, so the API returned `null` and React called `toString()` on it.
- **Proposed change:** generate frontend types from the actual advice schema, add an error boundary, and add a browser/component fixture containing nullable action fields.
- **Components:** `web/src/Workbench.tsx`, OpenAPI contract generation, frontend tests.
- **Acceptance criteria:** null address/length/count renders without an address row, a malformed response shows an inline error rather than a blank page, and CI covers both.

### P1 — Make browser tests coexist with a preserved live stack

- **Observed problem:** the sole Playwright test hardcodes ports and refuses reuse, so it cannot run while live services are preserved.
- **Engineering example:** evaluation correctly avoided stopping the live stack but therefore could not execute the test.
- **Proposed change:** parameterize base/edge ports; allocate ephemeral test ports; keep mock/scripted fixtures; never reuse a live OpenOCD backend in CI.
- **Components:** `web/playwright.config.ts`, `scripts/demo.py`.
- **Acceptance criteria:** `npm test` passes while 8000/8001 are occupied and proves it used mock/scripted services on separate ports.

### P2 — Refresh and age readiness data

- **Observed problem:** readiness refreshes only on login/reconnect/page load.
- **Engineering example:** unplugged or restarted debugger state can remain green during an investigation.
- **Proposed change:** poll non-mutating status at a bounded interval or use SSE; display age and mark stale after a threshold; pause polling while a target operation owns the lease.
- **Components:** `web/src/main.tsx`, orchestrator config/status endpoint.
- **Acceptance criteria:** a controlled mock transition appears within five seconds; data older than ten seconds is visibly stale; no overlapping status calls occur during snapshot execution.

### P2 — Explain mode provenance and code/data boundaries

- **Observed problem:** profile ARM mode and current CPSR Thumb state are visible but not explained together; data words are disassembled as code.
- **Engineering example:** zero vector literals appear as `eormi`, which a non-expert may interpret as reachable instructions.
- **Proposed change:** label `decode mode: region profile`, `CPU state: CPSR at separate register capture`, decode CPSR in UI, and allow instruction/data annotations without asserting reachability.
- **Components:** Workbench, evidence model, future Ghidra adapter.
- **Acceptance criteria:** UI explicitly states the two mode sources, renders CPSR fields deterministically, and marks unclassified words as uncertain until xrefs/CFG support them.

### P2 — Clarify offline patch terminology

- **Observed problem:** `OFFLINE PREVIEW VERIFIED` can overstate confidence when original bytes were user-entered and not compared with retained raw data.
- **Engineering example:** default `00000000` was accepted even though the original capture bytes were withheld.
- **Proposed change:** use `OFFLINE PATCH SYNTAX VALIDATED`; add separate `original bytes verified` status that requires a local evidence match.
- **Components:** Workbench UI/API.
- **Acceptance criteria:** preview cannot say original bytes verified without matching an evidence hash/range; warnings remain visible in exports.

### P3 — Integrate symbols, Ghidra, and typed GDB/MI

- **Observed problem:** no functions, xrefs, source mapping, stack unwind, or controlled dynamic debugger flow.
- **Proposed change:** import ELF/map files locally, add Ghidra headless analysis with versioned project provenance, then introduce typed GDB/MI operations with separate HITL and restore/recovery policies.
- **Components:** new local adapters and evidence schema.
- **Acceptance criteria:** a known fixture resolves PC/LR to symbols, produces reproducible xrefs/CFG, and every dynamic action is typed, bounded, approved, logged, and recoverable.

## 12. Reproduction steps

### Read-only current-state checks

1. Confirm listeners for 8000, 8001, and 6666 without starting duplicates.
2. Open `http://127.0.0.1:8000/` and sign in with the password printed by the launcher.
3. Verify the header labels `OPENOCD TARGET` and `SCRIPTED ANALYSIS`.
4. Compare the dashboard readiness tiles with authenticated `/api/config` and edge `/api/v1/target/status`.
5. Open **AI Workbench** and select the retained `jtag-debug-lock-audit` plan.
6. Verify the address range, 64-byte count, hash, ARM/little labels, capture state, instructions, and PC/LR/SP/CPSR.
7. Click **Ask debugger agent**. After the correction, the page must render both `disassemble` and addressless `inspect registers` actions without a browser exception.
8. Click **Validate offline patch** only as an offline preview. Confirm `Hardware unchanged` and the warning that original live bytes were not read-back verified.
9. Fetch Attack Lab Markdown and JSON for the retained plan and compare shared fields.

### Software checks

```powershell
uv run pytest -q
uv run ruff check .
uv run ruff format --check analysis config contracts edge orchestrator scripts tests
cd web
npm run build
npx playwright test --list
```

Do not run the existing Playwright webServer configuration against the active live ports. Parameterize isolated mock ports first.

## 13. Remaining checks requiring access or authorization

### Bounded snapshot proposal — authorization required before execution

If a new live validation is desired, the minimum concrete operation is:

- address space: physical;
- region: `am335x-internal-sram-smoke-window` only;
- address: `0x402F0400`;
- length: 16 bytes (or 64 only if explicitly authorized);
- registers: PC, LR, SP, CPSR;
- expected state change: briefly halt, acquire memory/registers, resume;
- recovery: restore the observed initial execution state in a `finally` path; set `recovery_required` and stop further operations if restoration cannot be verified;
- success criteria: full requested length, non-partial result, hash/evidence IDs, initial and final `running`, `recovery_required=false`, and an independently obtained byte comparison using a separately authorized debugger read;
- inference: scripted/local only; no cloud transmission.

This report does not grant that authorization.

Other blocked checks:

- independent raw-byte/hash comparison;
- controlled OpenOCD disconnect/reconnect recovery using an isolated fixture or scheduled hardware window;
- positive UART boot/U-Boot-interrupt flow requiring a physical power cycle;
- paid Nebius analysis of hardware-derived evidence and provider-retention verification;
- Docker runtime validation;
- GDB/MI, symbols, Ghidra, stepping, breakpoints, live patching, fault injection, and side-channel acquisition.

## Concise outcome

**Works:** authenticated dashboard, current OpenOCD-backed readiness, bounded profile display, retained physical evidence review, Capstone decoding, HITL boundaries, scripted evidence-backed guidance, offline patch preview, JSON export, 70 Python tests, Ruff lint/source formatting, and frontend build.

**Failed during evaluation:** Workbench guidance rendering on nullable address; corrected and verified. Repository-wide Ruff format traversal still crashes on an inaccessible generated-results path.

**Blocked:** new live capture, dashboard-driven physical audit, independent bytes, disconnect recovery, UART power-cycle tests, paid Nebius on hardware evidence, Docker, and full Playwright execution while preserving the active ports.

**Next concrete milestone:** restart only the edge and orchestrator under the reviewed configuration (leaving user-owned OpenOCD running), verify build/schema IDs and the full layered status in the UI, then run an isolated-port mock Playwright suite. After separate operator approval, perform one bounded 16-byte snapshot with an independent byte comparison and export a complete local evidence bundle.
