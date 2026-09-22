# Delivery milestones

Baseline inspected 2026-09-22 UTC: dev at ad823ab842526fd8ee10acc57a15c8ca39327350.
Documentation only; no application, manifests or tests. Existing records claiming boilerplate,
LangSmith or observed hardware defects are unsupported. No applicable AGENTS.md found.

1. Contracts, reproducible fixtures, decoding and authenticated single-owner edge.
   Exit: policy, evidence and snapshot lifecycle tests pass.
2. Bounded LangGraph, scripted inference, React UI, authenticated events and exports.
   Exit: real HTTP audit, cancellation and browser smoke pass.
3. Replay, Nebius adapter and OpenOCD Tcl transport.
   Exit: protocol and provider fake-server tests. Physical/provider gates separately documented.
4. Reconcile management records, deployment assets, commands and measured results.

Environment: Python 3.13.1, Node 22.14.0, npm 11.19.1, uv 0.12.5.
OpenOCD and ARM GDB are absent from PATH; no board connection attempted. Python 3.12 selected.
Missing: adapter model, board revision, populated connector, verified pinout/voltage/ground,
reviewed target configuration, trusted ranges, provider credentials/entitlement/limits,
provider retention settings and deployment host/TLS/identity configuration.
Proceed using explicit mock + scripted modes. Preserve ignored management records as local files.
