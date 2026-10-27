# Run an agent audit on connected hardware

The first supported hardware path is a BeagleBone Black (AM335x) with a C232HM JTAG adapter on a Windows workstation. The reviewed profile permits only the first 64 bytes of internal SRAM and `pc`, `lr`, `sp`, and `cpsr`. The agent can inspect and report on that evidence; it does not write memory or firmware.

## Prepare

1. Confirm the board revision, CTI header pinout, adapter voltage and ground against the manuals for **your** hardware. Connect and power the board. This project does not supply a universal wiring recipe.
2. Install Python 3.12, `uv`, Node.js 22+, and the reviewed xPack OpenOCD 0.12.0 build. Set `OPENOCD_EXE` to its `openocd.exe` path if it is not on `PATH`.
3. From the repository root, run `uv sync --frozen --python 3.12` and copy `.env.example` to `.env`. For model-backed analysis, configure `NEBIUS_BASE_URL`, `NEBIUS_MODEL`, `NEBIUS_API_KEY`, and `NEBIUS_VERIFIED_CONTEXT_TOKENS` in `.env`. Keep this file private. The launcher generates an edge key and dashboard password if they are absent.

## Connect and run

```powershell
uv run --env-file .env python scripts/run_hardware.py --arm-snapshots
```

The launcher builds the dashboard, starts OpenOCD on loopback, then starts the edge and agent services. Open the printed local URL and sign in with the printed password. Check **Readiness** for the debugger version, target communication, CPU state and recovery flag. Select the approved SRAM region and start an audit. The agent plans bounded reads, collects a snapshot, analyzes evidence through the configured model, verifies references and produces a report. Export an evidence bundle before stopping if you need to retain the result.

`--arm-snapshots` allows a brief halt and restore when the CPU is running. Without it, readiness blocks a running target. `--retain-raw-local` also keeps up to 64 raw captures in edge memory for an explicit local bundle export. Raw bytes are not sent to the model. `--inference scripted` skips the model call but still accesses the connected hardware when you start an audit. If you already run a reviewed OpenOCD process on local Tcl port 6666, pass `--use-running-openocd`; the launcher leaves that process alone.

Press Ctrl+C to stop only the processes started by the launcher. It stops the orchestrator first, lets the edge finish an in-flight snapshot, then checks the CPU state. It leaves the edge and OpenOCD running if the target is halted, unknown, or needs recovery. If a snapshot reports an uncertain outcome or restoration failure, inspect the target state locally and follow the [recovery procedure](live-validation-procedure.md#7-failure-recovery) before another operation.

## Current limits

This is a supervised first hardware release, not an unattended production deployment. The supported profile and OpenOCD startup configuration are specific to the BeagleBone/C232HM setup. Broader target support needs separately reviewed profiles and adapter configurations. The remaining physical gates include independent byte comparison and disconnect recovery on the target hardware. Runs and plans are kept in process memory; export bundles for durable evidence. Provider retention depends on the configured account.
