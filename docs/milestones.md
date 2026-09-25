# Delivery status and measured evidence
Updated 2026-09-25; branch dev. Baseline ad823ab842526fd8ee10acc57a15c8ca39327350.
Local milestone commits: 50e2597 (bounded edge and evidence), 48de175 (working offline audit/dashboard).

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

## Verification
Python: 54 tests passed. Browser: one smoke test passed against two real loopback HTTP services.
TypeScript/Vite production build passed. Ruff source checks passed. One upstream Starlette/AnyIO
deprecation warning remains. Final reruns passed: pytest 3.18 s; browser 2.4 s (12.4 s total).
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
The dashboard's verified references do not constitute independently validated vulnerabilities.
See architecture.md and docs/live-integration.md for boundaries, retention, recovery and official references.

Existing local management equivalents are PRD.md, IMPLEMENTATION_PLAN.md, DAILY_MANAGER.md,
BUG_TRACKER.md, TESTING_STRATEGY.md and SYSTEM_AUDIT.md. They remain ignored under the operator's
policy; there are no duplicate lower-case copies. This tracked summary survives a fresh clone.
