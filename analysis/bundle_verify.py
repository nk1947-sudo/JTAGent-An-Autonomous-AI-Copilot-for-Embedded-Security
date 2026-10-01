"""Offline verification of a JTAGent evidence bundle. No edge, orchestrator or hardware is used.

Outcomes:
  VERIFIED     every check passed and every capture had raw bytes, so hashes, lengths, address
               ranges and Capstone output were recomputed from the bundle itself.
  INCOMPLETE   nothing failed, but at least one capture has no raw bytes: its hash and
               disassembly cannot be independently reproduced. This is NOT verification.
  FAILED       a check contradicted the bundle (modified bytes, mismatched metadata, missing or
               altered artifacts, disagreeing reports).
  UNSUPPORTED  not a bundle this verifier understands (unknown format or version).

A matching hash shows integrity relative to the bytes in the bundle. It is not proof that the
bytes came from genuine hardware.
"""

import hashlib
import json
import posixpath
from dataclasses import dataclass, field
from pathlib import Path

import capstone

from analysis.evidence import decode_instructions, extract_strings

FORMAT = "jtagent-evidence-bundle"
SUPPORTED_VERSIONS = (1,)
REQUIRED_MANIFEST_KEYS = (
    "format",
    "format_version",
    "bundle_id",
    "created_at",
    "subject",
    "target_profile",
    "hash_policy",
    "captures",
    "registers",
    "artifacts",
)
REQUIRED_CAPTURE_KEYS = (
    "evidence_id",
    "address_space",
    "base_address",
    "requested_length",
    "returned_length",
    "partial",
    "content_hash",
    "raw_status",
    "decoder",
    "instructions",
    "strings",
)


@dataclass
class Check:
    name: str
    status: str  # pass | fail | skip | warn
    detail: str = ""


@dataclass
class Result:
    status: str = "VERIFIED"
    checks: list = field(default_factory=list)

    def add(self, name, status, detail=""):
        self.checks.append(Check(name, status, detail))

    @property
    def failures(self):
        return [c for c in self.checks if c.status == "fail"]

    @property
    def unverifiable(self):
        return [c for c in self.checks if c.status == "skip"]

    def finish(self):
        if self.status == "UNSUPPORTED":
            return self
        self.status = "FAILED" if self.failures else "INCOMPLETE" if self.unverifiable else "VERIFIED"
        return self

    def as_dict(self):
        return {
            "status": self.status,
            "checks": [c.__dict__ for c in self.checks],
            "failed": len(self.failures),
            "unverifiable": len(self.unverifiable),
        }


def exit_code(result):
    return {"VERIFIED": 0, "FAILED": 1, "INCOMPLETE": 2, "UNSUPPORTED": 3}[result.status]


def _sha256(path: Path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe(root: Path, relative):
    if not isinstance(relative, str) or not relative:
        return None
    normal = posixpath.normpath(relative)
    if normal.startswith(("/", "..")) or "\\" in relative or ":" in relative or normal != relative:
        return None
    target = (root / relative).resolve()
    try:
        target.relative_to(root.resolve())
    except ValueError:
        return None
    return target


def _region_for(profile, capture):
    base, length = capture["base_address"], capture["returned_length"]
    for region in profile.get("regions", []):
        if (
            region.get("address_space") == capture["address_space"]
            and region.get("start", 1) <= base
            and base + length <= region.get("end", 0)
        ):
            return region
    return None


def _load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def verify_bundle(bundle_dir) -> Result:
    root = Path(bundle_dir)
    result = Result()
    manifest_path = root / "manifest.json"
    if not manifest_path.is_file():
        result.status = "UNSUPPORTED"
        result.add("manifest_present", "fail", "manifest.json not found")
        return result
    try:
        manifest = _load_json(manifest_path)
    except (OSError, ValueError) as exc:
        result.status = "UNSUPPORTED"
        result.add("manifest_parse", "fail", type(exc).__name__)
        return result
    if not isinstance(manifest, dict) or manifest.get("format") != FORMAT:
        result.status = "UNSUPPORTED"
        result.add("format", "fail", f"expected {FORMAT!r}")
        return result
    if manifest.get("format_version") not in SUPPORTED_VERSIONS:
        result.status = "UNSUPPORTED"
        result.add("format_version", "fail", f"got {manifest.get('format_version')!r}")
        return result
    result.add("manifest_format", "pass", f"{FORMAT} v{manifest['format_version']}")

    missing = [k for k in REQUIRED_MANIFEST_KEYS if k not in manifest]
    if missing:
        result.add("manifest_required_fields", "fail", "missing: " + ", ".join(missing))
        return result.finish()
    result.add("manifest_required_fields", "pass")

    policy = manifest["hash_policy"]
    if policy.get("algorithm") != "sha256" or not policy.get("scope"):
        result.add("hash_policy", "fail", "algorithm/scope not declared as sha256 with an explicit scope")
    else:
        result.add("hash_policy", "pass", "sha256 over exact returned bytes; integrity, not authenticity")

    # 1. Artifacts: presence, size, digest, and path safety.
    listed = {}
    for artifact in manifest["artifacts"]:
        path = _safe(root, artifact.get("path"))
        name = f"artifact:{artifact.get('path')}"
        if path is None:
            result.add(name, "fail", "unsafe or malformed path")
        elif not path.is_file():
            result.add(name, "fail", "listed artifact is missing")
        elif path.stat().st_size != artifact.get("bytes"):
            result.add(name, "fail", "size differs from manifest")
        elif _sha256(path) != artifact.get("sha256"):
            result.add(name, "fail", "sha256 differs from manifest (artifact modified)")
        else:
            result.add(name, "pass")
            listed[artifact["path"]] = path
    present = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}
    extra = sorted(present - set(listed) - {"manifest.json"} - {a.get("path") for a in manifest["artifacts"]})
    if extra:
        result.add("unlisted_files", "warn", ", ".join(extra[:5]))

    # 2. Captures.
    profile = manifest["target_profile"]
    ids = [c.get("evidence_id") for c in manifest["captures"]]
    if len(ids) != len(set(ids)):
        result.add("capture_ids_unique", "fail", "duplicate evidence ids")
    installed = capstone.__version__
    for capture in manifest["captures"]:
        eid = capture.get("evidence_id", "?")
        gaps = [k for k in REQUIRED_CAPTURE_KEYS if k not in capture]
        if gaps:
            result.add(f"capture:{eid}:fields", "fail", "missing: " + ", ".join(gaps))
            continue
        if capture["partial"] != (capture["returned_length"] != capture["requested_length"]):
            result.add(f"capture:{eid}:partial_flag", "fail", "partial flag contradicts lengths")
        if capture["returned_length"] > capture["requested_length"]:
            result.add(f"capture:{eid}:length", "fail", "returned exceeds requested")
        region = _region_for(profile, capture)
        if region is None:
            result.add(
                f"capture:{eid}:range", "fail", "bytes lie outside every region in the recorded profile"
            )
        elif not region.get("approved", False):
            result.add(f"capture:{eid}:range", "fail", f"region {region.get('name')} was not approved")
        else:
            result.add(f"capture:{eid}:range", "pass", region.get("name", ""))

        raw_path = _safe(root, capture.get("raw_artifact")) if capture.get("raw_artifact") else None
        if capture["raw_status"] != "included" or raw_path is None:
            if capture["raw_status"] == "included":
                result.add(
                    f"capture:{eid}:raw", "fail", "manifest says included but the artifact path is unsafe"
                )
            else:
                result.add(
                    f"capture:{eid}:raw",
                    "skip",
                    f"no raw bytes ({capture['raw_status']}): hash, byte count and disassembly "
                    "cannot be independently reproduced",
                )
            continue
        if not raw_path.is_file():
            result.add(f"capture:{eid}:raw", "fail", "raw artifact missing")
            continue
        raw = raw_path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != capture["content_hash"]:
            result.add(f"capture:{eid}:hash", "fail", "recomputed sha256 differs from content_hash")
            continue
        result.add(f"capture:{eid}:hash", "pass", "sha256 recomputed from raw bytes")
        if len(raw) != capture["returned_length"]:
            result.add(
                f"capture:{eid}:byte_count",
                "fail",
                f"{len(raw)} bytes, manifest says {capture['returned_length']}",
            )
        else:
            result.add(f"capture:{eid}:byte_count", "pass", f"{len(raw)} bytes")

        decoder = capture["decoder"]
        mode, endian = decoder.get("instruction_mode"), decoder.get("endianness")
        base = capture["base_address"]
        strings = extract_strings(raw, base)
        sensitive = any(s.redacted for s in strings)
        expected = []
        if mode in ("arm", "thumb") and not sensitive:
            expected = [
                {"address": i.address, "size": i.size, "mnemonic": i.mnemonic, "operands": i.operands}
                for i in decode_instructions(raw, base, mode, endian)
            ]
        recorded = [
            {k: i.get(k) for k in ("address", "size", "mnemonic", "operands")}
            for i in capture["instructions"]
        ]
        note = ""
        recorded_version = decoder.get("version_recorded", "")
        if recorded_version and not recorded_version.endswith(installed):
            note = f" (recorded {recorded_version}, installed Capstone {installed})"
        if expected == recorded:
            result.add(
                f"capture:{eid}:instructions", "pass", f"{len(expected)} instructions reproduced{note}"
            )
        else:
            result.add(
                f"capture:{eid}:instructions", "fail", "reproduced decode differs from exported" + note
            )
        want = [
            {"address": s.address, "offset": s.offset, "text": s.text, "redacted": s.redacted}
            for s in strings
        ]
        have = [{k: s.get(k) for k in ("address", "offset", "text", "redacted")} for s in capture["strings"]]
        if want == have:
            result.add(f"capture:{eid}:strings", "pass", f"{len(want)} strings reproduced")
        else:
            result.add(f"capture:{eid}:strings", "fail", "reproduced strings differ from exported")

    # 3. Relationships.
    known = set(ids)
    for register in manifest["registers"]:
        paired = register.get("paired_capture_evidence_id")
        if paired is not None and paired not in known:
            result.add(
                f"register:{register.get('evidence_id')}:link", "fail", "paired capture is not in the bundle"
            )
        else:
            result.add(
                f"register:{register.get('evidence_id')}:link",
                "pass",
                "paired with " + paired[:8] if paired else "pairing unknown",
            )
    for capture in manifest["captures"]:
        acquisition = capture.get("acquisition")
        if isinstance(acquisition, dict) and acquisition.get("evidence_id") not in (
            None,
            capture.get("evidence_id"),
        ):
            result.add(
                f"capture:{capture.get('evidence_id')}:acquisition",
                "fail",
                "acquisition names another capture",
            )

    # 4. Reports must agree with the manifest.
    subject = manifest["subject"]
    json_path = listed.get("report.json")
    md_path = listed.get("report.md")
    if json_path is None or md_path is None:
        result.add("reports_present", "fail", "report.json and report.md must both be listed artifacts")
    else:
        try:
            report = _load_json(json_path)
        except ValueError:
            report = None
            result.add("report_json", "fail", "not valid JSON")
        markdown = md_path.read_text(encoding="utf-8")
        if report is not None:
            key = "run_id" if subject.get("kind") == "run" else "plan_id"
            if report.get(key) != subject.get("id"):
                result.add("report_json_subject", "fail", f"{key} does not match manifest subject")
            else:
                result.add("report_json_subject", "pass")
            report_hashes = {c.get("evidence_id"): c.get("content_hash") for c in report.get("captures", [])}
            manifest_hashes = {c["evidence_id"]: c["content_hash"] for c in manifest["captures"]}
            if report_hashes != manifest_hashes:
                result.add("report_json_captures", "fail", "capture ids or hashes differ from manifest")
            else:
                result.add("report_json_captures", "pass", f"{len(manifest_hashes)} captures agree")
        absent = [
            c["evidence_id"]
            for c in manifest["captures"]
            if c["evidence_id"] not in markdown or c["content_hash"] not in markdown
        ]
        if absent:
            result.add(
                "report_markdown_links",
                "fail",
                "evidence id/hash missing from report.md: " + ", ".join(absent[:3]),
            )
        else:
            result.add("report_markdown_links", "pass", "every evidence id and hash appears in report.md")
        unlinked = [
            c["evidence_id"]
            for c in manifest["captures"]
            if c.get("raw_artifact") and c["raw_artifact"] not in markdown
        ]
        if unlinked:
            result.add("report_markdown_artifacts", "fail", "raw artifact path missing from report.md")

    result.add(
        "atomicity",
        "warn",
        "Memory and registers are separate debugger reads and are not an atomic snapshot; "
        "temporal agreement between captures is not implied.",
    )
    return result.finish()
