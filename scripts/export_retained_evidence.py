"""Checkpoint everything the running dashboard still holds in memory, before a restart.

    uv run python scripts/export_retained_evidence.py [--base-url http://127.0.0.1:8000]

Runs, Attack Lab plans, captures, register snapshots, analyses and provenance live only in the
orchestrator process. This script signs in through the normal authenticated API (the password is asked
for interactively, or read from JTAGENT_DASHBOARD_PASSWORD; it is never printed, logged or saved), then
writes each retained run and plan as JSON and Markdown under evidence-checkpoints/<UTC time>/ together
with a manifest of SHA-256 digests. That directory is git-ignored.

It cannot recover what was never retained: raw bytes are withheld at the edge, so a checkpoint of an
existing capture holds its hash, decoded instructions and provenance, not its bytes. This is recorded in
the manifest. Nothing here writes to the target, the edge, or any provider.
"""

import argparse
import getpass
import hashlib
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
LIMITATION = (
    "Raw target bytes are withheld at the edge and are not held by the orchestrator, so this checkpoint "
    "preserves hashes, decoded instructions, registers, states and provenance but cannot restore the bytes."
)


def save(directory: Path, name: str, content: bytes, files: list):
    path = directory / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    files.append({"path": name, "bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()})


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--out", type=Path, default=ROOT / "evidence-checkpoints")
    args = parser.parse_args(argv)
    password = os.environ.get("JTAGENT_DASHBOARD_PASSWORD") or getpass.getpass(
        "Dashboard operator password: "
    )
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    directory = args.out / stamp
    files: list = []
    with httpx.Client(base_url=args.base_url, timeout=30, follow_redirects=False) as client:
        login = client.post("/api/login", json={"password": password}, headers={"Origin": args.base_url})
        del password
        if login.status_code != 200:
            print(f"Sign-in failed (HTTP {login.status_code}); nothing was exported.", file=sys.stderr)
            return 1

        def fetch(path):
            response = client.get(path)
            response.raise_for_status()
            return response

        config = fetch("/api/config").json()
        save(directory, "config.json", json.dumps(config, indent=2, sort_keys=True).encode(), files)
        runs = fetch("/api/runs").json()
        plans = fetch("/api/attack-lab/plans").json()
        for run in runs:
            rid = run["run_id"]
            save(directory, f"runs/{rid}.json", fetch(f"/api/runs/{rid}").content, files)
            save(directory, f"runs/{rid}.md", fetch(f"/api/runs/{rid}/report.md").content, files)
            save(directory, f"runs/{rid}.report.json", fetch(f"/api/runs/{rid}/report.json").content, files)
        for plan in plans:
            pid = plan["plan_id"]
            save(directory, f"plans/{pid}.json", json.dumps(plan, indent=2, sort_keys=True).encode(), files)
            save(directory, f"plans/{pid}.md", fetch(f"/api/attack-lab/plans/{pid}/report.md").content, files)
            save(
                directory,
                f"plans/{pid}.report.json",
                fetch(f"/api/attack-lab/plans/{pid}/report.json").content,
                files,
            )
    manifest = {
        "kind": "jtagent-retained-evidence-checkpoint",
        "created_at": datetime.now(UTC).isoformat(),
        "source": args.base_url,
        "runs": len(runs),
        "attack_plans": len(plans),
        "captures": sum(len(p.get("captures", [])) for p in plans),
        "register_snapshots": sum(len(p.get("registers", [])) for p in plans),
        "limitation": LIMITATION,
        "files": files,
    }
    (directory / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(
        f"Checkpointed {manifest['runs']} run(s), {manifest['attack_plans']} plan(s), {manifest['captures']} capture(s), "
        f"{manifest['register_snapshots']} register snapshot(s) to {directory}"
    )
    print(LIMITATION)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
