# Delivery status and measured evidence
Updated 2026-09-25; branch codex/uboot-security-audit. Baseline 1208a1b.
The live JTAG and Nebius milestone is committed at 1208a1b; the bounded UART audit is implemented and
verified in the working tree but is not yet committed.

## Implemented and exercised
- Authenticated mock edge, strict Pydantic contracts, local session policy, read/register/snapshot APIs.
- Capstone ARM/Thumb decoding, exact strings, original-byte hashing and explicit raw-byte withholding.
- Real LangGraph stages, finite policy-gated follow-ups, cancellation/deadline/budget termination.
- React dashboard with source badges, selected scope, live SSE, memory/instruction/register evidence,
  findings, Markdown/JSON download and in-memory run deletion.
- Read-only replay with attributed original timestamps, profile and hash validation.
- Nebius adapter and OpenOCD transport exercised against fake HTTP/socket servers; no fixture fallback.
- Physical C232HM-to-AM335x JTAG scan chain verified. A live, authenticated, policy-bounded snapshot
  captured 16 SRAM bytes plus `pc/lr/sp/cpsr` and restored running state in 816.45 ms.
- A complete physical-target LangGraph audit traversed planner, policy gate, collector, decoder,
  analyst, verifier and reporter; it captured 64 bytes plus registers with no errors in 1293.26 ms.
- The configured Nebius account exposed `nvidia/nemotron-3-super-120b-a12b`. A real native tool-call
  smoke used 1230 tokens, followed by a complete synthetic-evidence LangGraph audit with two provider
  calls (1199 and 3212 tokens), one capture, verified references and no errors.
- A bounded UART audit is available through the authenticated edge and dashboard APIs. Its fixed modes
  passively observe boot, send one autoboot-interrupt character, or run the reviewed credential check
  (`id`, `uname -r`, and non-interactive `sudo id`) before logging out. It does not accept arbitrary
  commands, keeps credentials on the edge, bounds capture size and time, and redacts returned evidence.
- The credential-check mode was exercised through the project API against the physical BeagleBone on
  COM12. It authenticated with the locally configured account, detected passwordless root access,
  returned a redacted transcript and SHA-256 evidence hash, and logged out without changing the target.

## Verification
Python: 58 tests passed. Browser: one smoke test passed against two real loopback HTTP services.
TypeScript/Vite production build passed. Ruff source checks passed. One upstream Starlette/AnyIO
deprecation warning remains. The latest Python/ruff rerun completed in 3.79 s.
Generated OpenAPI/TypeScript had no drift. Compose configuration passed validation using placeholders;
no containers were started.

Environment: Windows 11 build 26200, Python 3.12.14, Node 22.14.0, npm 11.19.1, uv 0.12.5.
Locked dependencies: uv.lock and web/package-lock.json. Generated schemas/types are checked in.

20 in-process ASGI mock/scripted runs:
| Measurement | Samples | p50 ms | p95 ms |
| --- | ---: | ---: | ---: |
| Edge operation | 40 | 0.505 | 1.205 |
| Scripted analysis | 20 | 0.048 | 0.075 |
| Graph end to end | 20 | 12.919 | 16.149 |

This measures local synthetic code paths, not physical JTAG, TCP/network latency, or model inference.
No manual baseline or real-world success percentage is claimed.

## Remaining gates and limits
OpenOCD and the physical board are verified for the narrow read-only SRAM audit above; ARM GDB,
disconnect recovery, broader memory ranges and independent byte comparison remain unverified.
Nebius credentials, model visibility, native tool calling and synthetic analysis are verified. Provider
retention settings and sending derived live-target evidence remain unverified and unauthorized.
Docker CLI exists but its daemon is unavailable. No paid resources or public deployment created.
The .env.example, Dockerfile, Compose and reverse-proxy example are integration assets, not deployment evidence.

Live independent halt/step and live writes are disabled. Full control-flow reconstruction, automated
stack unwinding, U-Boot environment storage validation, raw live-export and durable graph resume remain deferred.
The UART interrupt mode is implemented but has not yet been exercised against the physical board.
UART guidance is mode-specific, empty captures report `no_uart_data_received`, contradictory quoted
register values are rejected by the verifier, and the dashboard exposes authenticated sign-out.
The dashboard also presents dependency readiness and latency, retained run history, approved-range
visualization, separate rejected claims, provider token/cost estimates, guided UART progress, contextual
failure recovery, a mobile run-status strip, and confirmation before deleting in-memory evidence.
An initial Attack Lab is implemented with model-backed selection from five typed modules, evidence-linked
plans, authorization acknowledgement, step-level HITL approval/rejection, pause/resume, emergency abort,
and an explicit opt-in physical JTAG snapshot probe with target restoration. Firmware mutation, pulse
generation, and measurement-hardware control remain blocked pending dedicated adapters and recovery validation.
The dashboard's verified references do not constitute independently validated vulnerabilities.
See architecture.md and docs/live-integration.md for boundaries, retention, recovery and official references.

Existing local management equivalents are PRD.md, IMPLEMENTATION_PLAN.md, DAILY_MANAGER.md,
BUG_TRACKER.md, TESTING_STRATEGY.md and SYSTEM_AUDIT.md. They remain ignored under the operator's
policy; there are no duplicate lower-case copies. This tracked summary survives a fresh clone.

## 2026-09-29 read-only live session
Reused the existing xPack OpenOCD 0.12.0 (C232HM, am335x.cfg, 100 kHz, Tcl 6666/telnet 4444/GDB 3333 on loopback).
A separate, unarmed edge instance (port 8011, no halt/resume/write, UART off) confirmed through the app API:
OpenOCD version match and target state `running`. Direct reads of the approved 16-byte SRAM window and of `pc`
failed while running, with OpenOCD text that the adapter misclassified; fixed and re-verified live (see BUG_TRACKER
LIVE-001..003). The target stayed `running`; no recovery flag. Offline: 68 pytest tests pass, ruff clean.
After operator authorization, one snapshot (edge port 8011, ARM_SNAPSHOTS=1) halted, read 16 bytes at physical
0x402F0400 plus pc/lr/sp/cpsr, and resumed in 696.07 ms; app status and OpenOCD `curstate` both reported running after.
Bytes decode as an ARM vector table (`b 0x402f0444`, then three `ldr pc,[pc,#0x14]`); cpsr 0x600000b3 = Supervisor, Thumb,
IRQ masked. See docs/live-snapshot-report-2026-09-29.md (assembled offline from that response; scripted analyst).
Not done: independent byte comparison, disconnect recovery, a dashboard-driven run against the live edge, UI check of the new tile.

## 2026-09-30 status contract, evidence bundles, resilience, isolated browser tests
Implemented (see docs/status-and-evidence.md): edge status schema v2 with build identity and fail-closed readiness enforced
server-side; local evidence bundles + offline verifier; Workbench generated types/validation/error boundaries; isolated
Playwright stack; prepared live procedure with fixture rehearsal.
Verification (offline, automated fixtures): pytest 115 passed; ruff check and ruff format --check clean on
`analysis config contracts edge orchestrator scripts tests`; `npm run build` passes; `npm test` 12 passed twice with
8000/8001 occupied by the live stack (left untouched, same pids before and after).
Not yet done: running edge/orchestrator still on the old code until restarted (restart needs the operator's secrets);
no new physical operation performed; independent byte comparison pending authorization.
