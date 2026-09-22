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
    for c in run.captures:
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
        ]
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
