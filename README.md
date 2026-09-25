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
3. **Dashboard** (`web/`) — a React/Vite UI for launching audits, watching the
   agent loop live, and exporting the resulting markdown/JSON report.

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

## Running the services manually

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
`REDACT_VALUES`, `PUBLIC_ORIGIN`, `COOKIE_SECURE`. LangSmith/LangChain tracing is
force-disabled by the orchestrator entrypoint. Live raw bytes are withheld at the edge;
approved derived evidence is sent to the provider only when Nebius mode is explicitly selected.

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
