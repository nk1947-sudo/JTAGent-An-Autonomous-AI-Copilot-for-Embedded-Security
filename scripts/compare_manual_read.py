"""Compare an operator's manual OpenOCD ``mdw`` read with a bundle's raw bytes.

    uv run python scripts/compare_manual_read.py <bundle-dir> <transcript.txt> [--evidence-id ID]

The transcript is the text OpenOCD printed for ``mdw phys 0x402f0400 4`` (32-bit words, e.g.
``0x402f0400: ea00000f e59ff014 e59ff014 e59ff014``). Words are little-endian on this target.

What this does and does not show. The manual read uses a different client (telnet), a different command
(``mdw``, 32-bit accesses rather than ``read_memory`` with 8-bit width), and different parsing (this
script, not the edge adapter), and it is compared without the JTAGent policy or hashing code. It is
NOT independent of OpenOCD itself, the JTAG adapter, the DAP path or the halted core. Two reads taken at
different times need not match; see docs/live-validation-procedure.md for how temporal consistency is
established. Exit codes: 0 match, 1 mismatch, 3 unusable input.
"""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

LINE = re.compile(r"^\s*(?:0x)?([0-9a-fA-F]{8}):\s+((?:[0-9a-fA-F]{8}\s*)+)$")


def parse_mdw(text):
    """Return (start_address, bytes) from ``mdw`` output; raises ValueError if it is not contiguous words."""
    address, data = None, b""
    for line in text.splitlines():
        match = LINE.match(line)
        if not match:
            continue
        here = int(match.group(1), 16)
        if address is None:
            address = here
        elif here != address + len(data):
            raise ValueError("mdw lines are not contiguous")
        for word in match.group(2).split():
            data += int(word, 16).to_bytes(4, "little")
    if address is None:
        raise ValueError("no mdw output lines found")
    return address, data


def compare(bundle, transcript, evidence_id=None):
    manifest = json.loads((Path(bundle) / "manifest.json").read_text(encoding="utf-8"))
    captures = [c for c in manifest["captures"] if evidence_id in (None, c["evidence_id"])]
    if len(captures) != 1 or captures[0]["raw_status"] != "included":
        raise ValueError("need exactly one capture with raw bytes included (use --evidence-id)")
    capture = captures[0]
    raw = (Path(bundle) / capture["raw_artifact"]).read_bytes()
    address, manual = parse_mdw(transcript)
    if address != capture["base_address"]:
        raise ValueError(f"manual read starts at 0x{address:08x}, capture at 0x{capture['base_address']:08x}")
    span = min(len(manual), len(raw))
    return {
        "evidence_id": capture["evidence_id"],
        "compared_bytes": span,
        "match": span > 0 and manual[:span] == raw[:span],
        "bundle_sha256_of_compared": hashlib.sha256(raw[:span]).hexdigest(),
        "manual_sha256_of_compared": hashlib.sha256(manual[:span]).hexdigest(),
        "manual_bytes": len(manual),
        "capture_bytes": len(raw),
        "note": "Same OpenOCD, adapter and DAP path; independent of JTAGent's policy, parser and hashing.",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("transcript", type=Path)
    parser.add_argument("--evidence-id")
    args = parser.parse_args(argv)
    try:
        result = compare(args.bundle, args.transcript.read_text(encoding="utf-8"), args.evidence_id)
    except (OSError, ValueError, KeyError) as exc:
        print(f"Unusable input: {exc}", file=sys.stderr)
        return 3
    print(json.dumps(result, indent=2))
    print(
        "MATCH"
        if result["match"]
        else "MISMATCH: repeat with the bracketing procedure before drawing conclusions"
    )
    return 0 if result["match"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
