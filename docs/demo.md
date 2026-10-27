# Hackathon demonstration

## Repeatable dashboard demo (mock target + scripted inference)

From the repository root in PowerShell, with Python 3.12, `uv`, Node 22 and npm installed:

```powershell
uv sync --frozen --python 3.12
$env:TARGET_BACKEND = "mock"
$env:INFERENCE_BACKEND = "scripted"
$env:ATTACK_LAB_LIVE_JTAG = "0"
$env:LANGSMITH_TRACING = "false"
$env:LANGCHAIN_TRACING_V2 = "false"
uv run --frozen python scripts/demo.py
```

The launcher installs/builds the dashboard if needed, forces mock + scripted mode, disables UART
and real Attack Lab access, strips inherited hardware/provider credentials, and starts both services
on loopback. It creates fresh local edge/dashboard credentials and prints the temporary password.
Harmless local settings such as `REDACT_VALUES` remain available. No board, cloud provider, or
external service is used by the app. Keep the printed password local; press Ctrl+C in the launcher
terminal to stop the services.

### Three-minute narration

1. **Startup and sign-in (0:00–0:30):** Open the printed URL and sign in with the printed temporary
   password. Point out `MOCK TARGET`, `SCRIPTED ANALYSIS`, and the readiness panel showing a ready,
   non-live backend.
2. **Scope (0:30–1:00):** Choose *Bootloader inspection*. Select the approved `demo-code` and
   `demo-log` regions. Point to the excluded ranges and displayed action, byte, iteration, and time
   budgets.
3. **Investigation and progress (1:00–1:45):** Start the audit. Follow planner, policy gate,
   collection, decoder, analyst, and verifier entries in the timeline. Show the model label
   `scripted-demo-v1`, the captures, Capstone instructions, and timestamped register snapshot.
4. **Cited findings (1:45–2:15):** Open a finding's evidence link. The demo U-Boot/shell strings are
   observations of synthetic bytes; they do not establish authentication, reachability, or a
   vulnerability. Show the verifier's evidence IDs and limitations.
5. **Exports and cleanup (2:15–3:00):** Download Markdown and JSON reports. Export and locally verify
   the evidence bundle; raw bytes are included only if the operator checks the explicit option.
   Reopen the retained run from history and sign out. The run may then be deleted from memory; an
   exported bundle remains a separate operator-managed file.

The browser suite runs this workflow against isolated loopback services. The target is mock and the
inference mode is scripted, so these results are repeatable and are not hosted-model or hardware
measurements.

## Optional Nebius smoke and synthetic audit

These commands contact the real Nebius provider and may incur charges. Run them only after current
spending authorization for these specific synthetic requests, credentials, model entitlement, and
the account's context limit are confirmed. The CLI's `--allow-paid-inference` flag is a safety gate,
not spending authorization. Do not switch the target to `openocd`; both scripts construct synthetic
`config/demo.json` evidence locally.

Put the authorized values in a local, untracked `.env` file. Do not paste or commit the API key. Set
`NEBIUS_BASE_URL`, `NEBIUS_MODEL` (an entitled NVIDIA model ID), `NEBIUS_API_KEY`, and
`NEBIUS_VERIFIED_CONTEXT_TOKENS` to the verified account configuration. `NEBIUS_MAX_OUTPUT_TOKENS`
defaults to 2048 and is limited to 128–4096; the verified context limit must exceed it. No model is
downloaded and no provider fallback is used.

After the authorization gate is satisfied, run from the repository root:

```powershell
uv run --frozen --env-file .env python scripts/nebius_smoke.py --allow-paid-inference
uv run --frozen --env-file .env python scripts/nebius_audit.py --allow-paid-inference
```

The smoke performs two model-catalog GETs and one typed planner request against the synthetic
`demo-code` scope. The audit uses `MockBackend("demo")`, `demo-code` and `demo-log`, a 1,024-byte
collection budget, at most 4 acquisitions, 2 analysis iterations, and a 120-second workflow deadline.
It makes one typed planning request and at most two typed analysis requests (up to 3 chat completions
total). The smoke makes exactly one chat completion when successful. Each provider HTTP
attempt has a 5-second connect timeout and a 30-second total timeout, a 1 MB streamed-response cap,
and a conservative input-size check against the configured context budget. Output defaults to at
most 2,048 tokens. The adapter permits one retry for selected transient HTTP statuses; a retry may
duplicate billable work if the service completed the first request before returning an error. Check
provider-reported token usage and the final status before presenting a result. The smoke has three
fixed sequential HTTP operations (two catalog lookups and one completion). With one retry per
operation, its per-request limits imply a worst-case duration of about 181 seconds; it has no
separate whole-script deadline. The audit's 120-second workflow deadline bounds the whole
investigation. Across both commands, there are at most 4 logical chat completions, or 8 chat POST
attempts if every one is retried. At the default output cap this is at most 16,384 generated tokens;
input is separately bounded by the configured verified context limit. A dollar cap cannot be stated
until the currently entitled model's account price and the context limit are confirmed.

The current checkout has no current spending authorization for a new hosted run, and provider
retention/pricing settings are not verified. Therefore only `--help` and the no-opt-in guards were
run locally; neither paid command above was executed for this release preparation. Historical
2026-09-25 hosted results are in `docs/live-integration.md` and `docs/milestones.md` and do not grant
current authorization.
