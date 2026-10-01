# SiliconSentinel

Evidence-first embedded CPU and memory inspection. SiliconSentinel is an autonomous
AI copilot for hardware security research: it bridges a JTAG-attached ARM target
(edge) with an LLM-driven audit orchestrator (cloud/local), so a researcher can ask
for a bootloader/memory audit and get back a report built only from addressable,
attributable evidence. Reference verification does not prove semantic correctness:
unestablished conclusions remain hypotheses, and invalid references are rejected.

See [architecture.md](architecture.md) for the full system design, [PRD.md](PRD.md)
for product scope and requirements, and [docs/milestones.md](docs/milestones.md) for
delivery status.

## How it works

1. **Edge service** (`edge/`) — a FastAPI bridge that talks to the physical target
   through OpenOCD/Tcl RPC, or to a mock/replay backend for development. It enforces
   an approved-region policy, bounds every read, and turns raw bytes into attributed
   evidence (disassembly, ASCII strings, hashes) via `analysis/evidence.py`.
2. **Orchestrator** (`orchestrator/`) — a LangGraph workflow that plans reads,
   calls the edge service over authenticated HTTP, and asks an inference backend
   (scripted, or a Nebius/NVIDIA model) to reason over the returned evidence. Every
   finding is checked against evidence IDs and addresses. Rejected findings remain
   labeled rejected for auditability (`orchestrator/workflow.py`, `orchestrator/report.py`).
3. **Dashboard** (`web/`) — a React/Vite UI for dependency readiness, launching
   audits, watching the agent loop live, reviewing retained run history and rejected
   model claims, guiding UART capture, and exporting markdown/JSON reports.
4. **Attack Lab** (`orchestrator/attack_lab.py`, `web/src/AttackLab.tsx`) — converts
   operator objectives and retained evidence into catalogued JTAG, debug-interface,
   firmware, fault-injection, and side-channel plans with step-level HITL decisions.
   Its executor supports one explicit opt-in real operation: a restore-on-exit OpenOCD
   snapshot probe over an approved region. Other attack steps remain evidence-review/dry-run;
   it never forwards writes, firmware bytes, glitch pulses, or arbitrary commands to the edge.

Both services are single Python 3.12 processes (FastAPI + uvicorn); no database is
used. In-memory state, operator exports and provider retention are separate concerns.

## Project layout

| Path | Purpose |
| --- | --- |
| `edge/` | Hardware bridge: FastAPI app, backends (mock/replay/OpenOCD), session/policy service |
| `orchestrator/` | LangGraph agent loop, inference adapters (scripted/Nebius), report generation |
| `analysis/` | Evidence derivation: ELF/disassembly parsing, string extraction, redaction |
| `contracts/` | Shared Pydantic models and the generated OpenAPI schema |
| `fixtures/` | Synthetic memory segments and the reproducible replay manifest |
| `web/` | React dashboard (Vite, TypeScript, Playwright smoke tests) |
| `scripts/` | Local tooling: one-command demo, benchmark, ELF inspection, replay generation, provider smoke test |
| `tests/` | Pytest suite covering edge policy, workflow verification, and inference adapters |
| `config/demo.json` | Synthetic target profile used by the mock/demo backend |
| `docs/`, `architecture.md`, `PRD.md` | Design and product documentation |

## Requirements

- Python 3.12 or 3.13 (`>=3.12,<3.14`)
- [uv](https://docs.astral.sh/uv/) for dependency management
- Node.js 22+ and npm, for the dashboard
- A physical JTAG-attached target and OpenOCD are only required for live hardware
  mode — everything else runs against the mock or replay backend

## Quickstart (mock demo)

The fastest way to see the full loop end-to-end, with no hardware and no external
API calls, is the bundled demo script. It builds the dashboard, starts both
services against the mock backend and scripted inference, and prints a per-process
operator password:

```powershell
uv sync --frozen --python 3.12
uv run python scripts/demo.py
```

Then open `http://127.0.0.1:8000` and sign in with the printed password. Pass
`--skip-build` to reuse a previously built `web/dist`.

The launcher defaults to mock + scripted but honors explicitly set backend variables.
It does not automatically load `.env`; use `uv run --env-file .env python scripts/demo.py`
when deliberately supplying that configuration. Preserve an existing `.env` and never commit it.

### One-command live Windows stack

Connect and power the BeagleBone, then start OpenOCD, the native hardware bridge, and the
Dockerized dashboard/orchestrator together:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\start_live_stack.ps1
```

To explicitly arm the real, restore-on-exit Attack Lab JTAG snapshot probe, use:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\start_live_stack.ps1 -EnableLiveJtagAttack
```

The switch does not execute an attack by itself; the operator must still approve the physical
step in the Attack Lab. It does not enable writes or persistent firmware modification.

Press `Ctrl+C` to stop everything started by the launcher. Add `-SkipBuild` after the first
successful image build. If OpenOCD is already listening on port 6666, the launcher reuses it
and leaves it running when the rest of the stack stops.
The edge stays native because Docker Desktop does not directly expose Windows COM/USB devices;
the authenticated edge API is reachable only as required by Docker's host gateway and OpenOCD
remains bound to the host loopback interface.

## Running the services manually

The dashboard also includes an **AI Workbench**. After a real JTAG snapshot, it displays retained
memory/register evidence, requests typed debugger guidance from the configured model, and validates
equal-length ARM/Thumb patches offline. See [the merged workbench and live-debugger plan](docs/ai-firmware-workbench.md).

Patch preview does not write hardware. Volatile JTAG patch execution remains locked until snapshot,
read-back, bounded execution, and automatic rollback are implemented.

```powershell
uv sync --frozen --python 3.12

# Terminal 1 — edge bridge (mock backend)
$env:TARGET_BACKEND="mock"
$env:EDGE_API_KEY="replace-with-a-unique-secret-at-least-16-characters"
uv run uvicorn edge.app:create_app --factory --host 127.0.0.1 --port 8001 --workers 1 --no-access-log

# Terminal 2 — orchestrator
$env:INFERENCE_BACKEND="scripted"
$env:EDGE_API_URL="http://127.0.0.1:8001"
$env:EDGE_API_KEY="same-unique-secret-as-terminal-1"
$env:DASHBOARD_PASSWORD="replace-with-a-unique-password-at-least-12-characters"
uv run uvicorn orchestrator.app:create_app --factory --host 127.0.0.1 --port 8000 --workers 1 --no-access-log
```

On macOS/Linux use `export NAME=value`. For a built dashboard first run
`npm --prefix web ci` and `npm --prefix web run build`. The one-command launcher handles this.

### Dashboard (development mode)

```bash
cd web
npm ci
npm run dev
```

For Vite's default port, set `PUBLIC_ORIGIN=http://127.0.0.1:5173` on the orchestrator
before starting it. Use the same hostname in the browser so origin checks match.

## Backend modes

**`TARGET_BACKEND`** (edge service)

| Mode | Description |
| --- | --- |
| `mock` (default) | Synthetic in-memory target driven by `fixtures/synthetic.py`; select a variant with `MOCK_VARIANT` |
| `replay` | Deterministic replay of a captured manifest, set via `REPLAY_MANIFEST` (see `fixtures/replay.json`, regenerated by `scripts/make_replay.py`) |
| `openocd` | Live hardware over OpenOCD's Tcl RPC (`OPENOCD_TARGET`, `OPENOCD_PORT`, `OPENOCD_VERSION_PREFIX`); requires a `TARGET_PROFILE` explicitly marked `verified_for_live` |

**`INFERENCE_BACKEND`** (orchestrator)

| Mode | Description |
| --- | --- |
| `scripted` (default) | Deterministic, offline rule-based planner/analyzer — no external calls, used for demos and tests |
| `nebius` | NVIDIA model inference through Nebius Token Factory; this does not imply compute deployment (`NEBIUS_BASE_URL`, `NEBIUS_MODEL`, `NEBIUS_API_KEY`, `NEBIUS_VERIFIED_CONTEXT_TOKENS`, `NEBIUS_MAX_OUTPUT_TOKENS`) |

Other notable environment variables: `MAX_READ_BYTES`, `ARM_SNAPSHOTS`,
`REDACT_VALUES`, `PUBLIC_ORIGIN`, `COOKIE_SECURE`. Set `UART_AUDIT_ENABLED=1`,
`UART_PORT`, and optional local `UART_AUDIT_USERNAME`/`UART_AUDIT_PASSWORD` to expose
the dashboard's bounded UART assessment. LangSmith/LangChain tracing is
force-disabled by the orchestrator entrypoint. Live raw bytes are withheld at the edge;
approved derived evidence is sent to the provider only when Nebius mode is explicitly selected.
Set optional `NEBIUS_INPUT_USD_PER_MILLION` and `NEBIUS_OUTPUT_USD_PER_MILLION`
display rates to show a run-cost estimate from provider token usage. These rates are
operator-supplied display metadata, not billing records.

## Testing

```bash
uv run pytest -q
uv run ruff check .
uv run ruff format --check .
```

Covers edge policy enforcement, evidence sanitization, workflow finding
verification, and both inference adapters (scripted and a faked Nebius provider).

Browser smoke tests for the dashboard live in `web/demo.spec.ts` and run via
`npm test` (Playwright) from `web/`. First run `npm ci`, `npm run build` and
`npx playwright install chromium` there. Keep ports 8000/8001 free for the smoke test.

Regenerate shared types after contract changes:

```powershell
uv run python scripts/generate_contracts.py
npm --prefix web run types
```

## Utility scripts

| Script | Purpose |
| --- | --- |
| `scripts/demo.py` | One-command local demo (mock backend + scripted inference); builds and serves the dashboard |
| `scripts/benchmark.py` | Offline in-process ASGI benchmark; no provider or physical target |
| `scripts/inspect_elf.py` | Local ELF metadata inspection (never loads or executes the file) |
| `scripts/make_replay.py` | Regenerates the attributed synthetic replay manifest |
| `scripts/nebius_smoke.py` | Opt-in gate that sends one synthetic bounded task to a configured Nebius endpoint |
| `scripts/nebius_audit.py` | Opt-in full LangGraph audit using synthetic target evidence and real Nebius inference |
| `scripts/generate_contracts.py` | Regenerates `contracts/openapi.json` from both FastAPI apps |
| `scripts/record_dashboard_demo.mjs` | Records a captioned, credential-safe dashboard walkthrough to `artifacts/SiliconSentinel-comprehensive-demo.webm` using isolated mock services on ports 8100/8101 |

## Security notes

- The edge bridge is a trust boundary. Use HTTPS/private routing outside loopback;
  target routes require the bearer `EDGE_API_KEY`. `/healthz` is process liveness only.
  A tunnel does not replace application authentication. Never tunnel debugger ports.
- Reads are bounded (`MAX_READ_BYTES`, default 4096) and restricted to explicitly
  approved regions in the target profile — see `edge/service.py::containing`.
- The verifier checks cited addresses and source modes, and labels unsupported claims
  as suspected/inconclusive or rejected. It does not establish real-world vulnerabilities.
- Credential patterns and configured sensitive values are redacted at the edge;
  pattern matching cannot identify every secret (`analysis/evidence.py`).
- UART audits run only three fixed modes: passive capture, one Space to interrupt U-Boot, or a
  configured-account check limited to identity/kernel/passwordless-sudo detection followed by logout.
  Credentials remain in the local edge environment and are not accepted in API requests.
- Attack Lab recommendations are restricted to a typed module catalog. Authorization acknowledgement,
  per-step approval, pause/resume, emergency abort, and an event log are enforced server-side. Set
  `ATTACK_LAB_LIVE_JTAG=1` to arm the real JTAG snapshot probe after reviewing recovery; it temporarily
  halts through the edge snapshot primitive, reads at most 64 approved bytes and registers, restores the
  target, and records evidence. Fault injection, side-channel capture, live writes, and firmware
  modification remain unavailable until separate hardware adapters and recovery controls are validated.
- Orchestrator runs expire after one hour or can be deleted. The bounded edge operation
  ledger keeps sanitized results until restart. Exports are operator-managed; provider
  retention is unverified. No database does not establish zero retention.

## Current status

This project is under active development. See
[docs/milestones.md](docs/milestones.md) for what's implemented versus planned,
and [BUG_TRACKER.md](BUG_TRACKER.md) / [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md)
for in-progress work. Live hardware (OpenOCD) and hosted inference (Nebius) modes
require separately verified credentials/hardware and are not exercised by the
default test suite.

See [live integration gates](docs/live-integration.md) and the [three-minute demo](docs/demo.md).
Management files such as PRD.md and BUG_TRACKER.md remain locally ignored under the operator's policy;
the tracked architecture and milestone summary provide the status in a fresh clone.

## Status, evidence bundles and live validation (2026-09-30)
- Status contract, build identity and fail-closed readiness: [docs/status-and-evidence.md](docs/status-and-evidence.md).
- Export a local evidence bundle from the dashboard, then verify it offline with
  `uv run python scripts/verify_bundle.py exports/<bundle>` (exit 0 verified, 2 incomplete/no raw bytes, 1 failed).
- Before restarting services, checkpoint in-memory evidence: `uv run python scripts/export_retained_evidence.py`;
  restart natively with `scripts/restart_native_services.ps1` (OpenOCD is never touched; arming is opt-in).
- Browser tests are isolated from the live stack: `npm --prefix web test` (mock + scripted, own ports).
- Prepared, not yet executed on hardware: [docs/live-validation-procedure.md](docs/live-validation-procedure.md).
