# AI Firmware Workbench and Live Debugger Plan

## Objective

Turn physical JTAG and UART evidence into inspectable code, typed model guidance, reversible patch
experiments, and evidence-backed reports without giving the model an unrestricted debugger or shell.

## Delivered MVP

- Successful JTAG snapshot plans retain memory and register evidence instead of only an evidence ID.
- The AI Workbench displays capture metadata, Capstone ARM/Thumb disassembly, strings, registers, and
  raw-byte withholding status.
- The Nebius/NVIDIA model acts through a `DebuggerAdvice` schema containing observations,
  hypotheses, limitations, and catalogued debugger proposals.
- The model cannot submit raw shell, GDB, OpenOCD, payload, or write commands.
- The immutable patch-draft panel validates an equal-length change inside the captured, approved RAM
  range and shows hashes plus before/after disassembly.
- Patch preview is offline-only. The API always reports `live_execution_enabled: false`.

## Next milestones

### 1. Ghidra headless worker

Run analysis in an isolated container with read-only inputs, file and CPU limits, analysis timeouts,
and structured JSON exports for functions, symbols, strings, xrefs, control-flow graphs, and
pseudocode. Preserve the original artifact by content hash.

### 2. GDB/MI debugger adapter

Implement typed register, memory, breakpoint, halt, bounded-step, and bounded-resume operations. The
adapter, not the model, renders protocol syntax. Each state-changing operation enters the HITL queue.

### 3. Emulation gate

Execute patch working copies under QEMU or Unicorn first. Capture exit state, changed control flow,
UART expectations, and regression assertions before offering hardware execution.

### 4. Volatile JTAG patch executor

Require a separate arming flag and exact-byte approval. Snapshot original bytes and registers, halt,
verify expected bytes, write only an approved RAM range, read back, run for a bounded interval, halt,
restore, read back again, and verify the final target state. Any uncertain outcome sets
`recovery_required`.

### 5. Persistent firmware workflow

Keep disabled until the product supports complete backup, verified recovery media, image-format
checksums, signature policy, rollback testing, and two-person approval.

## Safety and evidence rules

- Physical, simulated, emulated, and offline results use different terminal states and banners.
- Model text never becomes an executable command.
- Original firmware and captures are immutable and content-addressed.
- Every proposal cites exact evidence IDs and addresses.
- Every hardware mutation records before/after bytes, operator approval, read-back verification, and
  rollback status.
- Persistent rootkits, arbitrary payload generation, and unrestricted command consoles are not
  supported.
