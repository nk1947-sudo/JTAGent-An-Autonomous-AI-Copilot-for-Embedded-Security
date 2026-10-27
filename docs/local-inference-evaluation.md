# Local inference evaluation — deferred for the Nebius × NVIDIA hackathon milestone

Updated 2026-10-25. Local Qwen/Ollama implementation and fake-provider tests are preserved, but
real local-model evaluation is outside the current milestone and is not a hackathon readiness gate.
The resource measurements below are historical context only; available RAM/VRAM does not block
Nebius integration, synthetic demos, offline checks, or delivery.

## Reproduce

From the repository root, with the project virtual environment installed:

```powershell
.venv\Scripts\python.exe -B -m pytest -q -p no:cacheprovider tests/test_model_safety.py tests/test_operator_failures.py
.venv\Scripts\python.exe -B scripts/evaluate_local_inference.py
# After confirming free RAM and VRAM, opt in to the installed local model:
.venv\Scripts\python.exe -B scripts/evaluate_local_inference.py --local --model qwen3.5:4b
```

The evaluator uses only the `demo` and `clean` synthetic `MockBackend` fixtures, two approved 256-byte regions, a 512-byte collection budget, two actions, one analysis iteration, and a 120-second run deadline. It prints status, model identity, total workflow elapsed time, analyst-call latency, adapter request latencies (including model-tag checks), provider-reported usage, schema and evidence-reference outcomes, and finding status counts. `--local` calls loopback Ollama only; it does not pull models or invoke paid inference. The script does not touch physical hardware.

## Fixed fixture results

| Provider | Fixture | Completion | Captures | Schema valid | Evidence references | Findings | Elapsed |
| --- | --- | --- | ---: | --- | --- | --- | ---: |
| `scripted-demo-v1` | `demo` | completed | 2 | yes | yes | 2 observed; 0 rejected or validated | 108.9 ms |
| `scripted-demo-v1` | `clean` | completed | 2 | yes | yes | 1 observed; 0 rejected or validated | 21.4 ms |
| Fake Ollama HTTP responses | `demo`, `clean` | completed in regression tests | 1 each | yes | yes | 1 observed each | test only |
| Real `qwen3.5:4b` | `demo`, `clean` | deferred; outside hackathon milestone | — | — | — | — | — |

These scripted and fake-Ollama rows are offline regression evidence; they are not real hosted-model
results. The specific Nebius audit in `docs/milestones.md` used the configured NVIDIA Nemotron model
with synthetic evidence. A separate same-day dashboard test used paid Nebius inference over derived
evidence from physical 64-byte captures; this historical use does not authorize a new call. No new
paid hosted request was made for this handoff.

The scripted timings are one local run, not benchmark estimates. The fake Ollama tests use the actual adapter, typed planner/analyst paths, mock snapshot, and deterministic verifier. They include the `demo` prompt-injection string as untrusted target data. No out-of-scope capture or validated vulnerability resulted. Separate regressions reject malformed and truncated model responses, HTTP failure, invented evidence IDs, unsupported vulnerability claims, and out-of-scope follow-up reads; cancellation is propagated.

## Deferred local model details

Ollama 0.24.0 is installed. `qwen3.5:4b` is downloaded, visible through `/api/tags`, and has digest `2a654d98e6fba55d452b7043684e9b57a947e393bbffa62485a7aac05ee4eefd`; preflight reports `inference_verified: false` until generation completes. Adapter defaults are loopback `http://127.0.0.1:11434`, `num_ctx=8192`, `num_predict=1536`, temperature 0, nonstreaming structured JSON, and a 60-second request timeout. No paid fallback is configured.

At the time of the prior check, Windows reported 14.88 GB total RAM with about 2.1–2.3 GB available; the RTX 3050 Laptop GPU reported 4,096 MiB VRAM with about 3,485 MiB free. The 4b quantized model occupies 3.4 GB on disk. Real 4b and 9b generations were not run. This is recorded solely as deferred evaluation context; it is not a blocker for the current Nebius × NVIDIA hackathon milestone.

The verifier checks evidence IDs, addresses, source modes, exact cited register values, and exact printable string observations. Other semantic claims stay suspected or inconclusive. The evaluator reports schema validity as `null` when a full typed planner/analyst result was not obtained. A completed run with no findings reports evidence-reference validity as `null` because there are no citations to check.
