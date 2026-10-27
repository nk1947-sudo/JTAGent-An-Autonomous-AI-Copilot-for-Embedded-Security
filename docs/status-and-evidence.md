# Status contract, build identity and evidence bundles

Updated 2026-09-30. Describes behavior implemented in the working tree on branch `codex/uboot-security-audit`.
Whether a *running* process has this behavior is a separate question: compare its reported `build_id` with
this tree (see "Build identity").

## 1. Edge status schema v2 (`GET /api/v1/target/status`)

The old unversioned flat response (`state`, `target_backend`, `generation`, `capabilities`,
`recovery_required`) is schema **v1**. v2 carries `schema_name: "jtagent.edge.status"`, `schema_version: 2`
and separate layers. Models: `EdgeStatus` in `contracts/models.py` (types in `web/src/api.d.ts` are generated
from it).

| Layer | Field | Meaning |
| --- | --- | --- |
| Freshness | `observed_at` | UTC time the edge produced the status |
| Application | `application` | `ok` = the edge process answered; says nothing about hardware |
| Build | `build`, `source_drift` | identity of the loaded code (below) |
| Debugger | `debugger.applicable / reachable / version_ok / version / expected_version_prefix / error_code` | OpenOCD Tcl endpoint. `applicable=false` for mock/replay |
| Target | `target.communication` (`ok/failed/unknown`), `target.execution_state` | valid target reply vs. running/halted |
| Policy | `snapshots_armed`, `retains_raw_locally`, `recovery_required` | local arming and recovery state |
| Guidance | `read_prerequisite` | e.g. a running CPU may need a snapshot (brief halt) before reads succeed |
| Summary | `live_operations.allowed / blockers` | the edge's own view; **never trusted by the orchestrator** |

`GET /healthz` is liveness plus build identity only. It is intentionally not a readiness signal.

### Fail-closed readiness (orchestrator)
`contracts/status.py::assess` validates the raw edge payload and produces `Readiness`
(`GET /api/readiness`, also `readiness` inside `/api/config`). Rules:

* Not an object, no `schema_version` but flat fields -> `incompatible: legacy_flat_schema`.
* Wrong/unsupported version, wrong `schema_name`, missing or wrongly-typed fields (booleans are strict, so
  `"no"` is not `false`), unparseable `observed_at` -> `incompatible`.
* Status older (or further in the future) than 15 s -> `status_stale`.
* Edge unreachable -> `edge_unreachable`. `/api/config` still answers 200 with `profile: null` so the UI can
  show a degraded state instead of a blank page.
* Live readiness is recomputed from the validated fields (`live_blockers`): debugger unknown/unreachable/
  version-incompatible, target communication not `ok`, execution state not running/halted/captured,
  `recovery_required`, or a running CPU with snapshots not armed. Anything absent stays a blocker.
* `run_ready` (may an investigation start) ignores only `not_live_backend`; `live_ready` additionally needs the
  OpenOCD backend.

**Enforcement is server-side and uses a fresh status, never a cache:** `POST /api/runs` returns 409 unless
`run_ready`; `POST /api/attack-lab/plans/{id}/execute-next` returns 409 for the live JTAG step unless
`live_ready`, before any session or snapshot request and without changing the step, so a retry is possible.
The edge independently enforces session policy, arming and the single-target lock/lease for every operation.
The dashboard disables the same controls, but that is a convenience, not the boundary. Evidence review,
Workbench (retained plans) and offline verification stay available when readiness is blocked.

## 2. Build identity (`contracts/build.py`)
`BuildIdentity` = `{component, version, commit, dirty, source_fingerprint, build_id, process_started_at, pid, python}`.

* `source_fingerprint`: SHA-256 over path + SHA-256 of every `*.py` in `analysis contracts edge fixtures
  orchestrator`, **computed once** when the process builds its identity (in `create_app`) and cached.
* `commit`/`dirty`: `git` at that same moment (`dirty` ignores untracked files). On a dirty tree the commit alone
  does not describe the loaded code; the fingerprint does.
* `build_id` = `<commit7>[+dirty]:<fingerprint12>`.
* `source_drift` = a freshly computed fingerprint differs from the loaded one, i.e. the files changed after this
  process started (it is **not** part of the identity). The dashboard shows it; restart to load new code.
* Limitation: modules are imported before the fingerprint is taken; a file edited in that short window could be
  loaded from old content but fingerprinted from new content. Restart to be certain.

Shown in `/healthz`, edge status, `/api/readiness`, the dashboard, each acquisition record and bundle manifests.

## 3. Evidence bundles

Three data classes stay separate:
1. **Acquisition evidence retained locally.** The edge keeps raw bytes only when started with
   `RETAIN_RAW_LOCAL=1` (off by default; the launcher does not enable it unless `-RetainRawLocal` is passed).
   Bounded (64 captures), in memory, authenticated route `GET /api/v1/evidence/{id}/raw`. Lost on edge restart.
2. **Operator-approved local export.** A bundle contains raw bytes only when the operator ticks *Include raw
   bytes* (`include_raw`) **and** the edge still holds them. Files are written under `EXPORT_DIR`
   (default `./exports`, git-ignored). Nothing is sent to a provider.
3. **Sanitized data for inference.** Unchanged: the edge still withholds raw bytes from run/plan state, reports,
   and model prompts. The bytes exist only at the edge and in the local bundle file.

Export: `POST /api/runs/{id}/bundle` and `POST /api/attack-lab/plans/{id}/bundle` (`{"include_raw": bool}`);
`GET /api/exports` lists bundles from disk (so they survive restarts); `GET /api/exports/{id}/{manifest.json|report.json|report.md}`.
The dashboard has *Export evidence bundle* on both pages.

Layout (`format: "jtagent-evidence-bundle"`, `format_version: 1`):
```
<kind>-<subject8>-<UTC stamp>-<bundle8>/
  manifest.json      captures, registers, profile, hash policy, acquisition records, artifact digests
  report.json        run or Attack Lab plan data (same source as the JSON export)
  report.md          the Markdown report plus an "Evidence bundle" section linking every evidence id to its artifact
  captures/<evidence_id>.bin   raw returned bytes (only if included)
```
Written to `<name>.partial` and renamed, so a failed export leaves no half bundle.

**Hash scope:** SHA-256 over the exact returned bytes (`returned_length` bytes from `base_address` in the stated
address space, in the byte order the debugger returned), computed at the edge before redaction. **A matching hash
proves integrity relative to the bytes supplied. It does not prove they came from genuine hardware.**

**Unknown is recorded as unknown.** Captures made before acquisition metadata existed get
`acquisition: {"status": "unknown"}`; register-to-capture pairing is `index_order_assumed` or `unknown`. Current
decoder/build versions are never attached to historical captures; the decoder version is the one recorded in the
capture's own evidence. Memory and registers are separate reads (`atomic_with_memory: false`); DMA and peripherals
may change memory even while the CPU is halted.

**A bundle without raw bytes says so** (`verification_claim: unavailable`, "NO raw bytes ... no verification is
claimed") and is reported `INCOMPLETE` by the verifier.

### Offline verifier
```powershell
uv run python scripts/verify_bundle.py exports\<bundle-directory> [--json]
```
Needs only the directory. Exit codes: `0` VERIFIED, `1` FAILED, `2` INCOMPLETE (raw bytes missing for at least one
capture; not verification), `3` UNSUPPORTED (unknown format/version, missing or unreadable manifest).
It checks: manifest format/version/required fields; artifact presence, size and SHA-256 and path safety (no
absolute paths or `..`); per capture the recomputed SHA-256, byte count, `partial` flag, that the range lies in an
approved region of the recorded profile, and that Capstone output and extracted strings recomputed from the raw
bytes with the recorded mode/endianness equal the exported ones; register pairing; that `report.json` and
`report.md` agree with the manifest (subject id, every evidence id and hash). Installed-vs-recorded Capstone
version differences are noted in the failure detail if instructions differ.

## 4. Generated contracts and frontend validation
`contracts/models.py` (Pydantic) -> `contracts/openapi.json` -> `web/src/api.d.ts`. Regenerate and check:
```powershell
uv run python scripts/generate_contracts.py          # rewrite openapi.json
npm --prefix web run types                            # rewrite api.d.ts
uv run python scripts/generate_contracts.py --check   # fail on OpenAPI drift
npm --prefix web run types:check                      # fail on TypeScript drift
```
`web/src/contract.ts` validates responses at runtime with Ajv **against the same `openapi.json`**; there is no
hand-maintained frontend schema. The Workbench validates plans, advice and patch previews before rendering,
preserves `null` for `address/length/count` (a valid `0` is kept), tolerates only an unknown action *type*
(shown as `UNRECOGNIZED · not executable`), shows a contract error inline otherwise, and wraps evidence, advice,
patch preview and the whole page in error boundaries.
