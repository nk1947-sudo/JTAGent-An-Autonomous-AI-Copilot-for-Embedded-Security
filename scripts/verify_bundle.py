"""Verify a JTAGent evidence bundle offline.

    uv run python scripts/verify_bundle.py exports/<bundle-directory> [--json]

Exit codes: 0 VERIFIED, 1 FAILED, 2 INCOMPLETE (no raw bytes for at least one capture, so hashes
and disassembly could not be reproduced), 3 UNSUPPORTED (not a bundle this tool understands).
Needs only the bundle directory: no edge, orchestrator, network or hardware.
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analysis.bundle_verify import exit_code, verify_bundle


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("bundle", type=Path, help="bundle directory containing manifest.json")
    parser.add_argument("--json", action="store_true", help="print the full result as JSON")
    args = parser.parse_args(argv)
    result = verify_bundle(args.bundle)
    if args.json:
        print(json.dumps(result.as_dict(), indent=2))
    else:
        for check in result.checks:
            if check.status != "pass":
                print(f"[{check.status.upper():4}] {check.name}: {check.detail}")
        passed = sum(c.status == "pass" for c in result.checks)
        print(
            f"{result.status}: {passed} checks passed, {len(result.failures)} failed, "
            f"{len(result.unverifiable)} unverifiable"
        )
        if result.status == "INCOMPLETE":
            print("INCOMPLETE is not verification: raw bytes are missing for at least one capture.")
    return exit_code(result)


if __name__ == "__main__":
    raise SystemExit(main())
