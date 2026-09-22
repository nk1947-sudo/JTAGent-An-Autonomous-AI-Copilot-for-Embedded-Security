# Live integration gates
Updated 2026-09-22 UTC. These are operator gates, not completed hardware or deployment claims.

## BeagleBone/OpenOCD
The adapter implements documented Tcl RPC framing and fixed read/get_reg/control templates.
It never starts OpenOCD, resets a board, flashes firmware or accepts arbitrary commands.
CPU/memory debugging is not boundary-scan testing.

Before connecting, supply board revision, connector population, adapter model, reference voltage,
ground and exact CTI pinout checked against the matching board/adapter manuals. The Black's optional
20-pin CTI header is not evidence of an onboard USB JTAG probe. No wiring recipe is supplied here
because these specific inputs are unknown.

Install a compatible OpenOCD on the workstation that owns the adapter. Review all included startup
scripts and target events for reset, initialization and memory-write side effects. Pin the installed
version in OPENOCD_VERSION_PREFIX after reviewing its commands. Keep Tcl/GDB/telnet on loopback;
disable unused listeners. The bridge is the only permitted external interface.
Only one edge process and no competing debugger may own this target. External resets or debugger
access invalidate the process-local generation model; stop the run and re-establish the session.

Create TARGET_PROFILE from verified RAM/ROM ranges, architecture, endian and execution mode. Set
verified_for_live=true only after review. Demo addresses are arbitrary. MMIO/unknown regions are
unrepresentable by the MVP Region contract. Virtual and physical access must be deliberately selected;
neither identifies relocated U-Boot without independent evidence. Capabilities must reflect actual
policy: read/registers/snapshot, and halt/resume only if locally authorized.
Set ARM_SNAPSHOTS=1 to arm snapshot halt/restoration. A session still needs both permissions.
Independent live halt/step remains disabled, and all live writes remain dry-run only.

Start one edge worker using:
```sh
uv run uvicorn edge.app:create_app --factory --host 127.0.0.1 --port 8001 --workers 1 --no-access-log
```
Use a locally set EDGE_API_KEY (16+ characters); keep it on the orchestrator server.
An HTTPS tunnel may route to port 8001, but application bearer authentication remains mandatory.
Never tunnel the OpenOCD ports.

A snapshot owns one lock: inspect initial state, optionally halt, read bounded memory/registers,
then reconcile and restore if this operation halted it. Restoration gets its own local timeout.
The edge blocks further operations after an uncertain change or failed restoration. Reconcile
with a local debugger, establish whether the CPU is halted/running and only then restart the bridge.
A lost connection cannot prove exactly-once execution. Never blindly replay a failed step/write.
A host crash or power loss cannot be recovered by an in-process watchdog; the operator must reconcile.
Independent mock controls have a maximum ten-second lease and restore only a CPU they halted.

Physical exit gate: read known memory/registers in an authorized session, demonstrate restoration,
unplug/failure handling and compare bytes with an independent manual debugger read from a compatible
snapshot. Pending: no installed OpenOCD, ARM GDB or physical board verified in this environment.

## Nebius
Token Factory inference and Nebius compute hosting are separate. The code requires explicit
NEBIUS_BASE_URL, NVIDIA-prefixed NEBIUS_MODEL, key, hosted context limit and bounded output limit.
The prompt's candidate nvidia/nemotron-3-super-120b-a12b is not a guaranteed account entitlement.
The vendor announcement confirms Super availability and optional zero-retention, but does not
verify this account, exact hosted limits or its enabled retention settings.

The adapter checks model visibility and requires a native schema-valid tool call. Unsupported
responses stop the run. It never executes free-form generated commands. Requests have a five-second
connect timeout and 30-second response timeout within the total run deadline. Only 429/502/503/504
receive one bounded retry. Usage is recorded only when supplied by the provider; costs are not invented.
Plain JSON-mode compatibility is not assumed or used as an unverified fallback.

With credentials and verified configuration, explicitly opt into a minimal potentially billable check:
```sh
uv run --env-file .env python scripts/nebius_smoke.py --allow-paid-inference
```
Then run the dashboard with INFERENCE_BACKEND=nebius and TARGET_BACKEND=mock first. A successful
full audit must show the model's bounded request, collected synthetic evidence, validated schema and
verified references. The smoke script alone does not pass the full analysis gate.
Provider retention remains unknown until the account settings/contract are checked.

## Deployment
The Dockerfile combines built React assets with the orchestrator. deploy/compose.yaml deliberately
does not run OpenOCD or an edge container. Configure the authenticated HTTPS bridge URL, secrets,
PUBLIC_ORIGIN and TLS reverse proxy. COOKIE_SECURE=1 is required for HTTPS deployment.
Use separate process secrets and one worker. Healthz is only process liveness, not target readiness.
No public deployment or paid resources were created. Docker daemon verification is pending.

## Official references checked
- [OpenOCD Tcl RPC](https://openocd.org/doc/html/Tcl-Scripting-API.html): 0x1a framing and disabled notifications.
- [OpenOCD target commands](https://openocd.org/doc/html/CPU-Configuration.html): target-qualified read_memory/get_reg/curstate.
- [OpenOCD general commands](https://openocd.org/doc/html/General-Commands.html): halt/resume/step require selected target.
- [BeagleBone Black specifications](https://docs.beagleboard.org/boards/beaglebone/black/ch05.html): optional CTI header.
- [pyOCD target support](https://pyocd.io/docs/target_support.html): Cortex-M focus; not the default Cortex-A8 driver.
- [Capstone Python](https://www.capstone-engine.org/lang_python.html): explicit ARM/Thumb and endian modes.
- [LangGraph graph API](https://docs.langchain.com/oss/python/langgraph/graph-api): state graph and bounded transitions.
- [Nebius Super announcement](https://nebius.com/blog/posts/nemotron3-super-now-available): product availability, not this account's gate.
- [Token Factory API example](https://docs.tokenfactory.nebius.com/api-reference/examples/batches): current API base URL.
