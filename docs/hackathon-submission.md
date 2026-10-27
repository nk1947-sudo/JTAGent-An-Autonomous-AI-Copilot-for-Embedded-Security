# JTAGent Hackathon Submission and Demo

## Submission summary

JTAGent is an evidence-first copilot for bounded embedded CPU and memory inspection. It connects an authenticated operator dashboard to a policy-enforcing edge service, derives attributed evidence locally, and can use a typed NVIDIA model through Nebius Token Factory to propose scoped reads and analyze evidence. A deterministic verifier checks finding evidence IDs and addresses; unsupported claims stay suspected, inconclusive, or rejected. The system does not establish a vulnerability from a printable string alone.

The repeatable demonstration uses the synthetic `mock` target and `scripted` inference. The Nebius adapter is separately exercised with fake HTTP tests in the current suite. Historical real hosted results and physical hardware measurements are listed separately below; neither is presented as the current automated demo.

## Reproduce the dashboard demo

From the repository root in PowerShell, with Python 3.12, Node 22, npm, and `uv` installed:

```powershell
uv sync --frozen --python 3.12
$env:TARGET_BACKEND = "mock"
$env:INFERENCE_BACKEND = "scripted"
$env:ATTACK_LAB_LIVE_JTAG = "0"
$env:LANGSMITH_TRACING = "false"
$env:LANGCHAIN_TRACING_V2 = "false"
uv run --frozen python scripts/demo.py
```

The launcher installs/builds the dashboard, starts edge/orchestrator on loopback ports 8001/8000, and prints the local URL and fresh operator password. It forces mock/scripted mode and removes inherited edge, target, UART, replay, provider, and hardware settings before starting child processes. Sign in and confirm **MOCK TARGET**, **SCRIPTED ANALYSIS**, and the **READY · NON-LIVE BACKEND** status. The browser suite isolates its services on other loopback ports; the manual demo uses the launcher's documented ports. Press Ctrl+C in the launcher terminal to stop the services.

### Four-minute narration

1. **Start and readiness (0:00–0:40):** Run the command above, sign in with the printed password, and show the mock target, scripted inference, edge status, and non-live readiness. State that this path contacts neither a board nor a paid model.
2. **Scope (0:40–1:15):** Select bootloader inspection and the two approved synthetic regions. Show excluded ranges and the byte, action, iteration, and time budgets.
3. **Investigation (1:15–2:10):** Start the run. Follow planner, policy gate, capture, decoder, analyst, and verifier events. Point out progress, the selected model ID, captured bytes/instructions/registers, and evidence-linked findings.
4. **Evidence limits (2:10–2:45):** Open a finding's cited evidence. Explain that the synthetic bootloader/shell string proves bytes were present, not that a shell was reachable or a vulnerability was established. Show rejected claims and limitations if present.
5. **Exports (2:45–3:30):** Download Markdown and JSON reports; show source mode, requested model ID, budgets, evidence IDs, hashes, and acquisition records. Export and locally verify the synthetic evidence bundle. Raw bytes in an exported bundle are operator-managed files.
6. **Close (3:30–4:00):** Reopen the retained run and delete it from process memory. Explain that export files are separate and the default path makes no hardware or paid-provider calls.

## Nebius-hosted verification commands

The smoke script performs two model-catalog GETs and one typed planner request on the synthetic demo profile. The audit script uses `MockBackend("demo")`, one typed planning request, up to two typed analysis requests, a 1,024-byte collection budget, at most four capture actions, two analysis iterations, and a 120-second workflow deadline. The adapter's output limit defaults to 2,048 tokens and is bounded to 128–4,096; the configured conservative context limit must exceed the output limit. Requests have a 30-second total timeout and streamed responses are capped at 1 MB. One retry for selected transient HTTP statuses remains and can duplicate billing if a request completed before a gateway error.

Configure a protected local `.env` only after verifying the current account, model entitlement, context limit, output limit, pricing/spending cap, and retention terms:

```dotenv
INFERENCE_BACKEND=nebius
NEBIUS_BASE_URL=https://api.tokenfactory.nebius.com/v1
NEBIUS_MODEL=nvidia/nemotron-3-super-120b-a12b
NEBIUS_API_KEY=<operator-managed secret>
NEBIUS_VERIFIED_CONTEXT_TOKENS=<verified account limit>
NEBIUS_MAX_OUTPUT_TOKENS=2048
```

Potentially billable commands (each requires `--allow-paid-inference`):

```powershell
uv run --frozen --env-file .env python scripts/nebius_smoke.py --allow-paid-inference
uv run --frozen --env-file .env python scripts/nebius_audit.py --allow-paid-inference
```

The two scripts can issue at most 4 logical chat completions total (one smoke and up to three audit),
or 8 POST attempts if each completion is retried. With the default 2,048-token output cap, the maximum
requested output across retries is 16,384 tokens; input is bounded by the verified context setting.
The precise dollar ceiling still depends on the currently entitled model, account rates, and context
limit. See [the demo runbook](demo.md) for per-script timeouts and workflow limits.

The user funded and authorized one bounded synthetic smoke plus one synthetic audit on 2026-10-27. Both completed through these supported scripts: three logical completions/POST attempts, zero retries, 6,043 provider-reported tokens. All three responses reported the configured NVIDIA model ID. The public-rate usage estimate is $0.00249570, with actual account billing and retention unknown. The conservative eight-attempt full-limit estimate was $0.172032 before account terms or tax, below the user's $1 estimate ceiling; it was not an enforced billing cap. Redacted results are in `tmp/acceptance-live/nebius-cycle-20261027.json`. Live-target Nebius requests remain denied in code by default; `NEBIUS_LIVE_EVIDENCE_ENABLED=1` still requires separate authorization and account-retention review and remains unset.

## Evidence categories and supported claims

| Category | What is recorded | What it supports |
| --- | --- | --- |
| Current offline tests | 209 Python tests and 25 isolated Playwright tests passed on the current worktree; OpenAPI drift, Ruff, TypeScript contract and production build checks passed | Repeatable mock/replay application behavior, run-linked Workbench evidence, deterministic policy checks, and fake-provider adapter behavior; not a fresh hosted inference result |
| Current hosted synthetic inference | On 2026-10-27, an authorized typed smoke and MockBackend audit completed: three matching returned model IDs, three POST attempts, zero retries, 6,043 reported tokens, one verifier-accepted low-confidence suspected observation | Current synthetic provider workflow and typed/evidence-reference checks; no proof of physical finding, account charge, or retention setting |
| Historical hosted inference | On 2026-09-25, `nvidia/nemotron-3-super-120b-a12b` was visible and completed a typed tool-call smoke (1,230 reported tokens) and a synthetic evidence audit (1,199 + 3,212 reported tokens) | Prior account/model/tool-call operation at that time; not current retention |
| Historical hosted live-derived evidence | A separate same-day dashboard record documents paid Nebius runs using derived evidence from physical 64-byte captures | Historical transmission occurred; this does not authorize another live-data request |
| Replay | `fixtures/replay.json` is an attributed, hash-checked read-only fixture | Deterministic replay workflow; not a new target acquisition |
| Physical hardware | Historical records plus one release-aligned 64-byte BeagleBone audit on 2026-10-27 UTC: run `7694635d-823d-4fea-8fcc-c73334093d02`, running-to-running restoration, zero findings/errors, rendered run-linked Workbench capture and acquisition-linked registers | The bounded current-session read, restoration, and Workbench evidence display were observed; old-launcher restoration, disconnect recovery and independent byte comparison remain unverified |
| Local Qwen | Adapter and fake-provider tests remain; real Qwen generation was not run | Local-model quality is unevaluated and explicitly deferred, outside this hackathon milestone |

For OpenOCD targets or retained OpenOCD evidence, audit, recommendation, and debugger-advice provider calls return 403 by default. They require `NEBIUS_LIVE_EVIDENCE_ENABLED=1`; do not set it without separate authorization and retention review. A cached recommendation can be returned without a provider call. Provider retention remains unknown. The configured/requested model ID is not proof of the served ID when the provider omits its response identity field. Local Qwen evaluation remains deferred and outside this release scope.

## Release record

The release-aligned source revision was `27fe20f60a3bda4f2ba26c93af6567c3ef7f003d`; its served frontend bytes and physical Workbench path were checked on 2026-10-27 UTC. The run and plan bundles are raw-free and independently `INCOMPLETE`, so they do not prove the captured bytes or disassembly. The funded synthetic hosted gate completed separately from the physical scripted run. The remaining UART console gate is one locally confirmed wiring and power-cycle action during app-owned receive-only observation. See `docs/handoff.md` and `docs/operator-acceptance-20261026.md` for the verification record.
