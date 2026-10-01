import json

from analysis.evidence import sanitize, sanitize_data


def report_data(run):
    data = run.model_dump()
    # UI may show approved synthetic hex, exports default to compact evidence only.
    for capture in data["captures"]:
        capture["evidence"].pop("approved_hex", None)
    data["retention"] = {
        "application": "In-memory; delete run or restart; automatic expiry after one hour",
        "provider": "Unknown until account configuration is verified",
        "exports": "User-managed files; delete separately",
        "tracing": "Disabled; no LangGraph checkpoints",
    }
    data["limitations"] = [
        "CPU/memory inspection, not boundary-scan testing or a complete control-flow graph.",
        "Configured ranges are not discovered memory; MMIO and unknown ranges excluded.",
        "No confirmed vulnerability follows from a shell string or isolated symbol.",
        "Capture consistency is bounded; DMA/peripheral writes may continue.",
        "Live hardware, hosted inference and deployment require separate verification gates.",
    ]
    return sanitize_data(data)


ARM_MODES = {
    0x10: "User",
    0x11: "FIQ",
    0x12: "IRQ",
    0x13: "Supervisor",
    0x16: "Monitor",
    0x17: "Abort",
    0x1A: "Hyp",
    0x1B: "Undefined",
    0x1F: "System",
}


def describe_cpsr(value):
    """Deterministic ARMv7-A CPSR decode; a description of the bits, not of program behavior."""
    flags = "".join(n if value >> b & 1 else "-" for n, b in (("N", 31), ("Z", 30), ("C", 29), ("V", 28)))
    masks = "".join(n if value >> b & 1 else "-" for n, b in (("I", 7), ("F", 6)))
    state = "Thumb" if value >> 5 & 1 else "ARM"
    mode = ARM_MODES.get(value & 0x1F, f"reserved 0b{value & 0x1F:05b}")
    return f"{mode} mode, {state} state, flags {flags}, interrupt masks {masks}"


def acquisition_lines(a):
    if a is None:
        return ["  Acquisition: unknown (captured before acquisition metadata was recorded)"]
    return [
        (
            f"  Acquisition: {a.method}; edge halted the CPU: {a.halted_by_edge}; states initial="
            f"{a.initial_state}, at capture={a.capture_state}, final={a.final_state or 'unknown'}; "
            f"restoration={a.restoration}; recovery required: {a.recovery_required}; "
            f"generation {a.generation_before}->{a.generation_after}"
        ),
        (
            f"  Recorded builds: edge {a.edge_build_id or 'unknown'}, orchestrator "
            f"{a.orchestrator_build_id or 'unknown'}; debugger {a.debugger_version or 'unknown'}"
        ),
    ]


def evidence_lines(captures, registers, acquisitions):
    """Capture and register detail shared by the investigation and Attack Lab Markdown exports."""
    by_evidence = {a.evidence_id: a for a in acquisitions}
    lines = []
    for c in captures:
        lines += [
            (
                f"- {c.evidence_id}: {c.address_space} 0x{c.base_address:08x}, "
                f"{c.returned_length}/{c.requested_length} bytes, captured {c.timestamp}, "
                f"generation {c.generation}, {c.evidence.decoder}; SHA256 {c.content_hash}"
            ),
            (
                f"  Settings: {c.evidence.architecture}/{c.evidence.endianness}/"
                f"{c.evidence.instruction_mode}; {c.evidence.settings_source}"
            ),
            f"  CPU state at capture: {c.target_state}; {c.consistency}",
            *acquisition_lines(by_evidence.get(c.evidence_id)),
        ]
        if c.evidence.withheld_reason:
            lines.append(
                f"  Raw bytes: not exported ({c.evidence.withheld_reason}); verify against the hash."
            )
        for i in c.evidence.instructions[:64]:
            lines.append(f"  - 0x{i.address:08x}  {i.mnemonic} {i.operands}".rstrip())
        lines += [f"  - string 0x{s.address:08x} (+{s.offset}): {s.text}" for s in c.evidence.strings[:64]]
        lines += ["  - uncertainty: " + u for u in c.evidence.uncertainties]
    lines += ["", "## Register snapshots", ""]
    lines += ["No register snapshots captured."] if not registers else []
    for r in registers:
        lines.append(
            f"- {r.evidence_id}: {r.source_mode}, CPU {r.target_state} at capture, {r.timestamp}, "
            f"generation {r.generation} (captured separately from memory, not an atomic snapshot)"
        )
        for name, value in r.values.items():
            note = f"  ({describe_cpsr(value)})" if name == "cpsr" else ""
            lines.append(f"  - {name} = 0x{value:08x}{note}")
    return lines


def markdown(run):
    d = report_data(run)
    lines = [
        "# SiliconSentinel audit",
        "",
        f"Run: {run.run_id}",
        f"Target mode: {run.target_backend} | Inference: {run.inference_backend}",
        f"Model: {run.model_id}",
        f"Target: {run.profile.target_id}",
        f"Created: {run.created_at}",
        f"Purpose: {run.request.purpose}",
        f"Result: {run.status} / {run.termination_reason}",
        f"Scope: {', '.join(run.request.region_names)}",
        "",
        "## Inspected evidence",
        "",
    ]
    lines += evidence_lines(run.captures, run.registers, run.acquisitions)
    lines += ["", "## Findings", ""]
    for f in run.findings:
        lines += [
            f"### {f.title}",
            "",
            f"{f.status} | severity {f.severity} | confidence {f.confidence}",
            f.explanation,
            "Evidence: " + ", ".join(f.evidence_ids),
            "Addresses: " + ", ".join(hex(a) for a in f.addresses),
            "Limitations: " + "; ".join(f.limitations),
            "Next: " + f.suggested_verification,
            "",
        ]
    lines += ["## Exclusions and limits", ""] + ["- " + s for s in d["limitations"]]
    lines += [
        "",
        "Excluded/unselected regions: "
        + ", ".join(
            r.name for r in run.profile.regions if not r.approved or r.name not in run.request.region_names
        ),
        "Errors: " + ("; ".join(run.errors) or "none"),
        f"Budgets used: {run.collection_actions} captures, {run.bytes_requested} bytes, {run.analysis_iterations} iterations.",
        f"Elapsed: {run.elapsed_ms:.1f} ms. Tool and inference samples are separate in JSON.",
        "Retention: " + json.dumps(d["retention"]),
        "",
        "No findings were independently validated on physical hardware by this report.",
    ]
    return sanitize("\n".join(lines))
