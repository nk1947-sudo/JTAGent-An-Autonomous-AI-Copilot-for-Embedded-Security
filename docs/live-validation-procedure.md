# Bounded live validation: one 16-byte snapshot with an independent comparison

Prepared 2026-09-30. **Nothing in this document has been executed on hardware.** The earlier authorization
covered one historical snapshot; this procedure needs new, explicit authorization (section 8).
Rehearsed against a scripted fake debugger only: `tests/test_live_rehearsal.py` (13 tests). That proves the
software's gates, restoration and recovery logic, not the behavior of the real board.

## 1. Scope (fixed)
| Item | Value |
| --- | --- |
| Address space / address / length | physical `0x402F0400`, 16 bytes |
| Region | `am335x-internal-sram-smoke-window` only, `[0x402F0400, 0x402F0440)`, approved, ARM profile mode |
| Registers | `pc`, `lr`, `sp`, `cpsr` |
| State change | one halt, then resume (only if the edge halted the CPU) |
| Inference | scripted / local. No cloud transmission |
| Excluded | writes, flash, reset, breakpoints, single-step, UART boot interruption, any other address |

Profile re-verified offline on 2026-09-30 with the same `containing()` policy the edge uses:
`0x402F0400+16` and `+64` physical are allowed; `+65`, `0x402F0440+1`, `0x402F03FF+2` and a `virtual` request are refused.

## 2. Preconditions (all must hold; the script re-checks the software ones and stops with no state change)
1. **User-owned OpenOCD untouched**: same process as observed (pid recorded in the run log), Tcl `127.0.0.1:6666`
   (also 3333/4444) on loopback. Do not restart it.
2. **Application current**: the edge to be used reports build `<id>` with `source_drift=false` at
   `GET /healthz` and in the dashboard *Readiness* panel (Edge build). A stale edge (old flat status) is refused
   automatically. See `docs/status-and-evidence.md`.
3. **Raw bytes retained**: that edge was started with `RETAIN_RAW_LOCAL=1` (status field `retains_raw_locally`).
   Without it the bundle is metadata-only and the script refuses (override `--allow-metadata-only`, result then
   cannot be `PASS`).
4. **Snapshots armed on that edge** (`ARM_SNAPSHOTS=1`) because the CPU is running, and that arming was a deliberate
   part of the authorization in section 8, not an inherited default.
5. **Current target state observed** non-mutatingly: `GET /api/v1/target/status` -> `target.execution_state`
   (`running` expected), `recovery_required=false`, `debugger.version_ok=true`, `live_operations.allowed=true`.
6. No other debugger client attached; no UART audit or Attack Lab step running; operator physically present
   (Linux on the board pauses for about a second).
7. Retained-evidence checkpoint taken if the dashboard will be restarted (`scripts/export_retained_evidence.py`).

## 3. Exact action
```powershell
# run on the workstation, from the repository root; EDGE_API_KEY is the running edge's key, never printed
$env:EDGE_API_KEY = '<the running edge key>'
uv run python scripts/live_snapshot.py --i-authorize-one-halt-resume
```
Defaults: `--edge-url http://127.0.0.1:8001 --address 0x402f0400 --length 16`. The flag is mandatory. The Attack Lab
executor (dashboard) is *not* used for the 16-byte step because it reads up to 64 bytes.

## 4. Expected behavior (fixture-proven order; real timing to be measured)
Preflight (no state change): status v2 fresh and compatible; `live_ready`; initial state; range inside the approved
region; raw retention; arming. Then the single operation, all under the edge's target lock:
`version` -> `curstate` (running) -> `targets am335x.cpu; halt 1000` -> `curstate` -> `read_memory 1076823040 8 16 phys`
-> `get_reg -force {pc lr sp cpsr}` -> `curstate` -> `targets am335x.cpu; resume` -> `curstate`.
No other verb is sent (asserted by the rehearsal). The previous physical snapshot took ~0.7 s end to end (696 ms) at 100 kHz;
treat that as an expectation, not a guarantee.

## 5. Timeouts and cancellation
* Per-command Tcl timeout 2 s; whole edge operation 8 s; restoration has its own 3 s local timeout, independent of the caller.
* A timeout during `halt` is *uncertain*: the edge sets `recovery_required`, does not retry, and blocks further operations.
* There is no cancel inside a snapshot: it is one bounded request that either completes or restores in its `finally`.
  Ctrl+C on the script abandons the response only; the edge still finishes/restores. Afterwards **check status**
  (section 7). Attack Lab pause/abort act between steps, not inside one.

## 6. Restoration
The edge resumes only a CPU it halted itself, and only if it is halted when checked. A CPU that was already halted stays
halted (rehearsed). Pass requires `execution_state` after == observed initial state, `recovery_required=false`, and the
acquisition record `final_state == initial_state`.

## 7. Failure recovery
| Symptom | Meaning | Do |
| --- | --- | --- |
| script exit `2` | a precondition failed; the target was not touched | fix the named blocker; re-run |
| `restoration_failed_operator_required`, `outcome_uncertain`, or `recovery_required=true` | the CPU may still be halted | via OpenOCD telnet `127.0.0.1 4444`: `targets` ; `am335x.cpu curstate` ; if `halted`: `resume`; confirm `running`; then restart the **edge only** to clear the flag. Never restart the edge before confirming the CPU state |
| debugger unreachable mid-operation | edge cannot tell if it resumed | same as above, then check the OpenOCD process |
| script exit `1` with `partial`/hash/verification failure | data or evidence problem, state restored | keep the bundle; do not proceed to comparison |
Every later operation is refused server-side until the flag is cleared (`operator_reconciliation_required`).

## 8. Evidence bundle and offline verification
The script writes `exports/run-<id>-<time>-<id>/` and verifies it. Repeat any time, offline:
```powershell
uv run python scripts/verify_bundle.py exports\<bundle>        # expect VERIFIED, exit 0
```
Pass criteria for acquisition: script `RESULT: PASS` (all criteria `PASS`), bundle `VERIFIED`, `content_hash` present,
`returned_length == requested_length == 16`, `partial=false`, initial/capture/final states `running/halted/running`,
`recovery_required=false`, registers pc/lr/sp/cpsr present. Observations are not findings: a vector-table-shaped
result is an observation, not a vulnerability.

## 9. Independent byte comparison (separate step, separate authorization)
**Method:** the operator reads the same 16 bytes through the *already running* OpenOCD's telnet console, not through JTAGent:
```
telnet 127.0.0.1 4444
> am335x.cpu curstate
> halt
> mdw phys 0x402f0400 4
> resume
> am335x.cpu curstate
```
Save the printed `mdw` line to a file, then:
```powershell
uv run python scripts/compare_manual_read.py exports\<bundle> manual-mdw.txt     # MATCH exit 0, MISMATCH exit 1
```
**What it is independent of:** JTAGent's policy layer, `read_memory` adapter/parser, hashing and Capstone; it uses a
different client and command (`mdw`, 32-bit accesses vs 8-bit `read_memory`) and a separate parser (the comparison script).
**What it is not independent of:** the same OpenOCD process, adapter, DAP/AHB path and target. It cannot detect a fault
common to those. It needs **another halt** (`halt`/`resume` on the console), of about a second.
**Temporal consistency:** two reads at different times need not match. A match strongly suggests the region is stable and
both methods agree. On a mismatch do not conclude the app is wrong: bracket it, i.e. app snapshot A1, manual read M, app
snapshot A2. If A1 == A2 != M the methods disagree (investigate); if A1 != A2 the memory changed and the comparison is
inconclusive. The bracket costs up to two more halts and needs its own authorization.

## 10. Precise authorization requested
*Acquisition (A):* one halt/read/resume of the running BeagleBone CPU through JTAGent, physical `0x402F0400`, 16 bytes,
registers pc/lr/sp/cpsr, using `scripts/live_snapshot.py`, against an edge restarted by the operator with `RETAIN_RAW_LOCAL=1`
and `ARM_SNAPSHOTS=1` (this arms snapshots; halts ~1 s; no writes/reset/breakpoints/UART/cloud).
*Independent read (B), separate:* one operator-run `halt` + `mdw phys 0x402f0400 4` + `resume` on the OpenOCD telnet console.
*Bracket (C), only if B mismatches:* up to two further app snapshots as in (A).
None of A, B, C is authorized by this document.

## 11. Checklist (tick during the live window)
- [ ] OpenOCD pid/ports unchanged  - [ ] edge build id recorded, drift false  - [ ] `live_operations.allowed` true
- [ ] state `running`, recovery false  - [ ] script `RESULT: PASS`  - [ ] state `running` after, recovery false
- [ ] `verify_bundle` VERIFIED  - [ ] (B) telnet read done, state `running` after  - [ ] compare MATCH/MISMATCH recorded
- [ ] results appended to `docs/milestones.md` with the date, build id and hashes
