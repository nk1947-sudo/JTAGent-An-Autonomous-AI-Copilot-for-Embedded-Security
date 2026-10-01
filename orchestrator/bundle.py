"""Durable local evidence bundles (format documented in docs/status-and-evidence.md).

Three data classes stay separate:
  1. acquisition evidence the edge retained locally (only when RETAIN_RAW_LOCAL=1 on the edge),
  2. an operator-approved local export of those bytes (this module, only when include_raw=True),
  3. sanitized derived data given to inference (unchanged; nothing here feeds inference).
Historical metadata that was never recorded is written as "unknown", never back-filled from the
current process.
"""

import hashlib
import json
import re
import shutil
from datetime import UTC, datetime
from pathlib import Path

from analysis.bundle_verify import FORMAT, verify_bundle
from analysis.evidence import sanitize_data
from contracts.models import uid

FORMAT_VERSION = 1
BUNDLE_ID = re.compile(r"^[A-Za-z0-9_-]{8,80}$")
DOWNLOADABLE = ("manifest.json", "report.json", "report.md")

HASH_POLICY = {
    "algorithm": "sha256",
    "scope": (
        "SHA-256 over the exact returned memory bytes: returned_length bytes starting at base_address "
        "in the stated address_space, in the byte order returned by the debugger, computed at the edge "
        "before any redaction."
    ),
    "not_proof_of_authenticity": (
        "A matching hash shows the exported bytes are unchanged relative to the bytes the edge hashed. "
        "It does not prove they were read from genuine hardware."
    ),
}
LIMITATIONS = [
    "Memory and registers are separate debugger reads; they are not an atomic snapshot.",
    "DMA and peripherals may change memory even while the CPU is halted.",
    "Region instruction mode is a profile assumption; decoding does not prove reachability.",
    "Findings are observations or hypotheses unless explicitly marked validated.",
]


def default_export_root(project_root: Path) -> Path:
    return project_root / "exports"


def _capture_entry(capture, profile, acquisitions, raw_state):
    data = capture.model_dump()
    evidence = data.pop("evidence")
    region = next(
        (
            r
            for r in profile.regions
            if r.address_space == capture.address_space
            and r.start <= capture.base_address
            and capture.base_address + capture.returned_length <= r.end
        ),
        None,
    )
    acquisition = acquisitions.get(capture.evidence_id)
    status, artifact, note = raw_state.get(capture.evidence_id, ("unavailable", None, "raw not offered"))
    return {
        "evidence_id": capture.evidence_id,
        "address_space": capture.address_space,
        "region_name": region.name if region else None,
        "base_address": capture.base_address,
        "requested_length": capture.requested_length,
        "returned_length": capture.returned_length,
        "partial": capture.partial,
        "timestamp": capture.timestamp,
        "source_mode": capture.source_mode,
        "target_state_at_capture": capture.target_state,
        "generation": capture.generation,
        "consistency": capture.consistency,
        "content_hash": capture.content_hash,
        "raw_status": status,
        "raw_artifact": artifact,
        "raw_note": note,
        "decoder": {
            "version_recorded": evidence["decoder"],
            "architecture": evidence["architecture"],
            "endianness": evidence["endianness"],
            "instruction_mode": evidence["instruction_mode"],
            "settings_source": evidence["settings_source"],
        },
        "instructions": evidence["instructions"],
        "strings": evidence["strings"],
        "uncertainties": evidence["uncertainties"],
        "provenance": evidence["provenance"],
        "acquisition": acquisition.model_dump()
        if acquisition
        else {"status": "unknown", "note": "captured before acquisition metadata was recorded"},
    }


def _register_entries(subject, acquisitions_by_register):
    entries = []
    captures, registers = subject.captures, subject.registers
    for index, register in enumerate(registers):
        paired, basis = None, "unknown"
        if register.evidence_id in acquisitions_by_register:
            paired, basis = acquisitions_by_register[register.evidence_id], "acquisition_record"
        elif len(captures) == len(registers):
            paired, basis = captures[index].evidence_id, "index_order_assumed"
        entries.append(
            {
                "evidence_id": register.evidence_id,
                "timestamp": register.timestamp,
                "values": register.values,
                "target_state_at_capture": register.target_state,
                "generation": register.generation,
                "source_mode": register.source_mode,
                "mode_information": register.mode_information,
                "paired_capture_evidence_id": paired,
                "pairing_basis": basis,
                "atomic_with_memory": False,
            }
        )
    return entries


def _bundle_section(manifest, verify_hint):
    lines = [
        "",
        "## Evidence bundle",
        "",
        f"Bundle: `{manifest['bundle_id']}` (format {FORMAT} v{FORMAT_VERSION}). Manifest: `manifest.json`.",
        f"Hash scope: {manifest['hash_policy']['scope']}",
        manifest["hash_policy"]["not_proof_of_authenticity"],
        "",
    ]
    for c in manifest["captures"]:
        where = f"`{c['raw_artifact']}`" if c["raw_artifact"] else f"not included ({c['raw_status']})"
        lines.append(
            f"- `{c['evidence_id']}` -> raw bytes: {where}; sha256 `{c['content_hash']}`; "
            f"{c['returned_length']}/{c['requested_length']} bytes at {c['address_space']} 0x{c['base_address']:08x}"
        )
    claim = manifest["verification_claim"]
    lines += ["", claim["statement"], "", f"Verify offline: `{verify_hint}`", ""]
    return "\n".join(lines)


def build_bundle(*, kind, subject, profile, report_json, report_md, builds, raw_by_id, out_root, inference):
    """Write a bundle directory atomically and return (path, manifest)."""
    subject_id = subject.run_id if kind == "run" else subject.plan_id
    bundle_id = uid()
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    name = f"{kind.replace('_', '-')}-{subject_id[:8]}-{stamp}-{bundle_id[:8]}"
    out_root = Path(out_root)
    out_root.mkdir(parents=True, exist_ok=True)
    final, partial = out_root / name, out_root / (name + ".partial")
    if partial.exists():
        shutil.rmtree(partial)
    (partial / "captures").mkdir(parents=True)
    try:
        acquisitions = {a.evidence_id: a for a in subject.acquisitions}
        by_register = {
            a.register_evidence_id: a.evidence_id for a in subject.acquisitions if a.register_evidence_id
        }

        raw_state, artifacts = {}, []
        for capture in subject.captures:
            offered = raw_by_id.get(capture.evidence_id)
            if offered is None:
                raw_state[capture.evidence_id] = ("unavailable", None, "raw bytes were not offered")
                continue
            raw, note = offered
            if raw is None:
                raw_state[capture.evidence_id] = ("unavailable", None, note)
                continue
            if hashlib.sha256(raw).hexdigest() != capture.content_hash or len(raw) != capture.returned_length:
                raw_state[capture.evidence_id] = (
                    "unavailable",
                    None,
                    "offered bytes did not match the recorded hash; discarded",
                )
                continue
            relative = f"captures/{capture.evidence_id}.bin"
            (partial / relative).write_bytes(raw)
            raw_state[capture.evidence_id] = ("included", relative, note)

        captures = [_capture_entry(c, profile, acquisitions, raw_state) for c in subject.captures]
        included = sum(c["raw_status"] == "included" for c in captures)
        total = len(captures)
        if total and included == total:
            statement = (
                "Raw bytes are included for every capture: hashes, byte counts, address ranges and "
                "Capstone output can be recomputed offline."
            )
            availability = "available"
        elif included:
            statement = (
                f"Raw bytes are included for {included} of {total} captures. The others are metadata-only "
                "and cannot be independently verified."
            )
            availability = "partial"
        else:
            statement = (
                "This bundle has NO raw bytes. It is a metadata-only record: independent hash and "
                "disassembly verification is unavailable and no verification is claimed."
            )
            availability = "unavailable"

        manifest = {
            "format": FORMAT,
            "format_version": FORMAT_VERSION,
            "bundle_id": bundle_id,
            "created_at": datetime.now(UTC).isoformat(),
            "subject": {"kind": kind, "id": subject_id},
            "producer": builds,
            "modes": {
                "target_backend": getattr(subject, "target_backend", None)
                or (subject.captures[0].source_mode if subject.captures else "unknown"),
                "inference": inference,
            },
            "target_profile": profile.model_dump(),
            "hash_policy": HASH_POLICY,
            "raw_policy": {
                "included_for": included,
                "captures": total,
                "note": "Raw bytes are exported only on explicit operator request and only if the edge "
                "retained them locally; they are never sent to inference.",
            },
            "verification_claim": {
                "independent_hash_and_decode_verification": availability,
                "statement": statement,
            },
            "captures": captures,
            "registers": _register_entries(subject, by_register),
            "findings": [f.model_dump() for f in getattr(subject, "findings", [])],
            "limitations": LIMITATIONS,
            "artifacts": [],
        }
        verify_hint = f"uv run python scripts/verify_bundle.py exports/{name}"
        markdown = report_md.rstrip() + "\n" + _bundle_section(manifest, verify_hint)
        (partial / "report.md").write_text(markdown, encoding="utf-8")
        (partial / "report.json").write_text(
            json.dumps(sanitize_data(report_json), indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        for relative, role in [
            *[(c["raw_artifact"], "raw_bytes") for c in captures if c["raw_artifact"]],
            ("report.json", "report_json"),
            ("report.md", "report_markdown"),
        ]:
            path = partial / relative
            artifacts.append(
                {
                    "path": relative,
                    "role": role,
                    "bytes": path.stat().st_size,
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }
            )
        manifest["artifacts"] = artifacts
        (partial / "manifest.json").write_text(
            json.dumps(sanitize_data(manifest), indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        partial.rename(final)
    except BaseException:
        shutil.rmtree(partial, ignore_errors=True)
        raise
    return final, manifest


def summarize(path: Path):
    """Summary of an on-disk bundle, or None if it is not a readable bundle."""
    try:
        manifest = json.loads((path / "manifest.json").read_text(encoding="utf-8"))
        if manifest.get("format") != FORMAT:
            return None
        result = verify_bundle(path)
    except (OSError, ValueError):
        return None
    captures = manifest.get("captures", [])
    return {
        "bundle_id": path.name,
        "created_at": manifest.get("created_at", ""),
        "subject_kind": manifest.get("subject", {}).get("kind", "unknown"),
        "subject_id": manifest.get("subject", {}).get("id", "unknown"),
        "target_backend": manifest.get("modes", {}).get("target_backend", "unknown"),
        "captures": len(captures),
        "raw_included": sum(c.get("raw_status") == "included" for c in captures),
        "verification": result.status,
        "failed_checks": [f"{c.name}: {c.detail}" for c in result.failures][:5],
        "unverifiable_checks": len(result.unverifiable),
    }


def list_bundles(root: Path):
    if not root.is_dir():
        return []
    found = [
        summarize(p)
        for p in sorted(root.iterdir(), reverse=True)
        if p.is_dir() and not p.name.endswith(".partial")
    ]
    return [s for s in found if s]
