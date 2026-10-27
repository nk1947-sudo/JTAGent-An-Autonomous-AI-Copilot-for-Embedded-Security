> Exported from one live snapshot (2026-09-29). Analysis is the deterministic scripted analyst, not an LLM. Report assembled offline from the edge response; not produced by a dashboard run.

# SiliconSentinel audit

Run: fac4f31b-cb19-4c04-9ce1-bf8d68049222
Target mode: openocd | Inference: scripted
Model: scripted-demo-v1
Target: beaglebone-black-am335x
Created: 2026-09-30T01:49:45.107648+00:00
Purpose: bootloader inspection
Result: completed / completed
Scope: am335x-internal-sram-smoke-window

## Inspected evidence

- f65b2d01-5847-459b-a770-dbd67f254094: physical 0x402f0400, 16/16 bytes, captured 2026-09-30T01:48:26.863968+00:00, generation 1, Capstone 5.0.7; SHA256 d2dacb1bd1e8faac150afc088b321da1bbac68d8413cc9e5e287ffe94e56e10a
  Settings: arm/little/arm; Operator profile: am335x-internal-sram-smoke-window
  CPU state at capture: halted; Bounded sequential capture; DMA/peripherals may change even while CPU halted
  Raw bytes: not exported (Raw bytes withheld by edge data policy); verify against the hash.
  - 0x402f0400  b #0x402f0444
  - 0x402f0404  ldr pc, [pc, #0x14]
  - 0x402f0408  ldr pc, [pc, #0x14]
  - 0x402f040c  ldr pc, [pc, #0x14]
  - uncertainty: Profile mode/code boundaries are assumptions; decoding does not prove reachability.
  - uncertainty: Pattern redaction cannot identify all secrets; review ranges before cloud use.

## Register snapshots

- fdb8c8ef-1d39-417c-8821-f73bca82693f: openocd, CPU halted at capture, 2026-09-30T01:48:26.918647+00:00, generation 1 (captured separately from memory, not an atomic snapshot)
  - pc = 0xc0017006
  - lr = 0xc000d263
  - sp = 0xc084dfa8
  - cpsr = 0x600000b3  (Supervisor mode, Thumb state, flags -ZC-, interrupt masks I-)

## Findings

## Exclusions and limits

- CPU/memory inspection, not boundary-scan testing or a complete control-flow graph.
- Configured ranges are not discovered memory; MMIO and unknown ranges excluded.
- No confirmed vulnerability follows from a shell string or isolated symbol.
- Capture consistency is bounded; DMA/peripheral writes may continue.
- Live hardware, hosted inference and deployment require separate verification gates.

Excluded/unselected regions: 
Errors: none
Budgets used: 1 captures, 16 bytes, 1 iterations.
Elapsed: 0.0 ms. Tool and inference samples are separate in JSON.
Retention: {"application": "In-memory; delete run or restart; automatic expiry after one hour", "provider": "Unknown until account configuration is verified", "exports": "User-managed files; delete separately", "tracing": "Disabled; no LangGraph checkpoints"}

No findings were independently validated on physical hardware by this report.