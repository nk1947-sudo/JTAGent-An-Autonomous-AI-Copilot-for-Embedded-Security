# Dashboard manual test — 2026-09-25

Environment: physical BeagleBone Black, C232HM JTAG through OpenOCD, UART on COM12, and paid
Nebius inference. Testing used the authenticated dashboard at `http://127.0.0.1:8000`.

## Results

| Area | Result | Evidence |
| --- | --- | --- |
| Operator login | Pass | Correct password opened the authenticated workspace. |
| Live configuration | Pass | Dashboard reported OpenOCD target, Nebius analysis, AM335x profile, COM12 at 115200 8N1, and the approved SRAM window. |
| Scope controls | Pass | Investigation, memory-budget and UART-mode selectors changed correctly. Clearing the only region disabled Start audit; restoring it re-enabled the action. |
| Bootloader inspection | Partial by policy | Physical 64-byte snapshot and registers succeeded. Nebius returned a referenced low-confidence finding, then proposed 192 bytes beyond the approved 64-byte live window. The policy gate rejected it with `invalid_proposal`. |
| Firmware triage | Pass | Paid run completed in 17.495 seconds with one 64-byte physical capture, restored target state, local decoding, verified references and a low-confidence informational finding. |
| Crash investigation | Historical semantic defect; verifier fixed | Paid run completed in 10.604 seconds with one physical capture. Its explanation cited PC `0xC000000E`, while the captured PC was `0xC0017006`; the verifier now rejects this contradiction, with regression coverage. |
| Cancellation | Pass | A live paid run was cancelled before collection and terminated as `operator_cancelled` in 3.370 seconds. |
| Evidence navigation | Pass | Finding evidence action focused its referenced capture. |
| Markdown export | Pass | Browser received the report download event. |
| JSON export | Pass | Browser received the report download event. |
| UART credential check | Pass | Fixed check authenticated the configured account, detected non-interactive root, logged out, redacted the password and returned a transcript hash. |
| UART interrupt | Inconclusive | Listener remained armed for the full window, but no reboot bytes arrived; it correctly returned failed with zero bytes. A physical power cycle is required for the positive path. |
| UART observe | Not yet exercised | A physical power cycle is required while the listener is armed. |
| Browser runtime | Pass | No browser console warnings or errors after the runs. |
| Logout UI | Fixed after test | The dashboard now exposes Sign out and clears local evidence state after invalidating the authenticated cookie. |
| Delete run | Confirmation implemented | Deletion now requires an explicit confirmation dialog and recommends exporting evidence first. Browser regression coverage exercises the confirmed path. |

## Defects and follow-ups

1. Semantic register verification now rejects numeric register claims that contradict cited snapshots.
2. UART instructions now reserve physical power-cycle guidance for observe and interrupt modes;
   credential mode explicitly states that no reboot is required.
3. A visible Sign out control now invalidates the session and clears dashboard evidence state.
4. Repeat UART observe and interrupt with an operator-performed power cycle during the armed window;
   software cannot switch physical power without separately authorized reset-relay hardware.
5. Keep the 64-byte live range until a larger JTAG read can meet the two-second hardware-call limit;
   do not widen the policy merely to satisfy model follow-up proposals.
