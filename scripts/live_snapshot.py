"""One bounded, gated live snapshot with an evidence bundle. NOT run without operator authorization.

    uv run python scripts/live_snapshot.py --i-authorize-one-halt-resume

Requires EDGE_API_KEY in the environment (the key of the running edge) and reuses the OpenOCD session
that is already running. It performs exactly one snapshot of one approved range (default 16 bytes at
physical 0x402F0400) and registers pc, lr, sp, cpsr, then verifies restoration and writes a local bundle
that it verifies offline. It never writes memory, resets, sets breakpoints, touches UART, or contacts a
model provider. Everything is checked BEFORE the CPU is touched; any failed precondition exits without a
state change. See docs/live-validation-procedure.md.

Exit codes: 0 all criteria passed, 1 a post-condition or verification criterion failed, 2 a precondition
failed and nothing was changed.
"""

import argparse
import asyncio
import os
import sys
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analysis.bundle_verify import verify_bundle
from contracts.build import load_build, source_drift
from contracts.models import (
    AcquisitionRecord,
    AuditRequest,
    MemoryReadResult,
    RegisterSnapshot,
    RunState,
    TargetProfile,
)
from contracts.status import assess
from edge.service import PolicyError, containing
from orchestrator.bundle import build_bundle, default_export_root
from orchestrator.inference import ScriptedInference
from orchestrator.report import markdown, report_data
from orchestrator.workflow import verify

ROOT = Path(__file__).resolve().parents[1]
REGISTERS = ["pc", "lr", "sp", "cpsr"]


class Criteria:
    def __init__(self):
        self.rows = []

    def check(self, name, ok, detail=""):
        self.rows.append((name, bool(ok), detail))
        return bool(ok)

    @property
    def passed(self):
        return all(ok for _, ok, _ in self.rows)

    def render(self):
        return "\n".join(
            f"[{'PASS' if ok else 'FAIL'}] {name}{': ' + detail if detail else ''}"
            for name, ok, detail in self.rows
        )


async def execute(client, *, address, length, export_root, allow_metadata_only=False):
    """Returns (exit_code, criteria, bundle_path). ``client`` is an authenticated httpx client for the edge."""
    criteria = Criteria()
    build = load_build("orchestrator")

    async def get(path):
        response = await client.get(path)
        response.raise_for_status()
        return response.json()

    # --- Preconditions: nothing below this block changes the target. ---
    status = await get("/api/v1/target/status")
    readiness = assess(status, build, source_drift(build))
    criteria.check(
        "edge status schema v2 and fresh",
        readiness.compatible and not readiness.stale,
        str([b.code for b in readiness.blockers]),
    )
    criteria.check(
        "live readiness (every layer positive)",
        readiness.live_ready,
        ", ".join(b.code for b in readiness.blockers),
    )
    if not (readiness.compatible and readiness.live_ready):
        return 2, criteria, None
    initial = readiness.target.execution_state
    criteria.check("initial state observed", initial in ("running", "halted"), str(initial))
    profile = TargetProfile.model_validate(await get("/api/v1/target/profile"))
    try:
        region = containing(profile.regions, address, length, "physical")
        criteria.check(
            "range inside the approved region", region.approved, f"{region.name} {hex(address)}+{length}"
        )
    except PolicyError as exc:
        criteria.check("range inside the approved region", False, str(exc))
        return 2, criteria, None
    retained = status["retains_raw_locally"]
    criteria.check(
        "edge retains raw bytes locally (RETAIN_RAW_LOCAL)",
        retained or allow_metadata_only,
        "" if retained else "not retained: a metadata-only bundle would result",
    )
    if not (retained or allow_metadata_only):
        return 2, criteria, None
    if initial == "running" and not readiness.snapshots_armed:
        criteria.check("snapshots armed on the edge", False)
        return 2, criteria, None

    # --- The single authorized operation. ---
    session = (
        await client.post(
            "/api/v1/sessions",
            json={
                "target_id": profile.target_id,
                "operations": ["read", "registers", "snapshot", "halt", "resume"],
                "regions": [region.model_dump()],
                "byte_budget": length,
                "operation_limit": 1,
                "ttl_seconds": 30,
            },
        )
    ).json()
    reply = await client.post(
        "/api/v1/snapshots/capture",
        json={
            "target_id": profile.target_id,
            "session_id": session["session_id"],
            "address": address,
            "length": length,
            "address_space": "physical",
            "registers": REGISTERS,
        },
        timeout=15,
    )
    result = reply.json()

    # --- Post-conditions. ---
    after = await get("/api/v1/target/status")
    criteria.check("snapshot succeeded", result.get("success"), str(result.get("error_code")))
    criteria.check("outcome not uncertain", not result.get("outcome_uncertain"))
    criteria.check("no recovery flag afterwards", after["recovery_required"] is False)
    criteria.check(
        "execution state restored to the observed initial state",
        after["target"]["execution_state"] == initial,
        f"{initial} -> {after['target']['execution_state']}",
    )
    if not result.get("success"):
        return 1, criteria, None
    data = result["data"]
    memory = MemoryReadResult.model_validate(data["memory"])
    registers = RegisterSnapshot.model_validate(data["registers"])
    acquisition = AcquisitionRecord.model_validate(
        {**data["acquisition"], "orchestrator_build_id": build.build_id}
    )
    criteria.check(
        "full requested length, not partial", memory.returned_length == length and not memory.partial
    )
    criteria.check("registers captured", set(registers.values) == set(REGISTERS))
    criteria.check(
        "edge recorded restoration and final state",
        acquisition.final_state == initial and not acquisition.recovery_required,
        f"restoration={acquisition.restoration}",
    )

    # --- Evidence bundle and offline verification. ---
    raw = {}
    try:
        reply = await get(f"/api/v1/evidence/{memory.evidence_id}/raw")
        raw[memory.evidence_id] = (
            bytes.fromhex(reply["raw_hex"]),
            "retained locally by the edge; exported by scripts/live_snapshot.py",
        )
    except httpx.HTTPError:
        raw[memory.evidence_id] = (None, "the edge did not retain these bytes")
    run = RunState(
        target_backend="openocd",
        inference_backend="scripted",
        model_id="scripted-demo-v1",
        profile=profile,
        request=AuditRequest(
            target_id=profile.target_id,
            purpose="bootloader inspection",
            region_names=[region.name],
            byte_budget=256,
            collection_limit=1,
        ),
        captures=[memory],
        registers=[registers],
        acquisitions=[acquisition],
        status="completed",
        termination_reason="completed",
        collection_actions=1,
        bytes_requested=length,
        analysis_iterations=1,
    )
    run.findings = verify(
        (await ScriptedInference().analyze(run.captures, run.registers, run.request.purpose)).findings, run
    )
    path, _ = build_bundle(
        kind="run",
        subject=run,
        profile=profile,
        report_json=report_data(run),
        report_md=markdown(run),
        builds={
            "exporter_orchestrator": build.model_dump(),
            "edge_at_export": after["build"],
            "note": "scripts/live_snapshot.py",
        },
        raw_by_id=raw,
        out_root=export_root,
        inference={"backend": "scripted", "model_id": "scripted-demo-v1"},
    )
    verdict = verify_bundle(path)
    criteria.check("bundle verifies offline", verdict.status == "VERIFIED", verdict.status)
    return (0 if criteria.passed else 1), criteria, path


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument(
        "--i-authorize-one-halt-resume",
        action="store_true",
        required=True,
        help="required: confirms the operator authorized ONE halt, read and resume",
    )
    parser.add_argument("--edge-url", default="http://127.0.0.1:8001")
    parser.add_argument("--address", type=lambda v: int(v, 0), default=0x402F0400)
    parser.add_argument("--length", type=int, default=16)
    parser.add_argument("--allow-metadata-only", action="store_true")
    parser.add_argument(
        "--export-dir", type=Path, default=Path(os.getenv("EXPORT_DIR") or default_export_root(ROOT))
    )
    args = parser.parse_args(argv)
    if not 1 <= args.length <= 64:
        parser.error("--length must be 1..64 (the approved window is 64 bytes)")
    key = os.environ.get("EDGE_API_KEY")
    if not key:
        parser.error("EDGE_API_KEY must be set in the environment")

    async def run():
        async with httpx.AsyncClient(
            base_url=args.edge_url, headers={"Authorization": "Bearer " + key}, timeout=15
        ) as client:
            return await execute(
                client,
                address=args.address,
                length=args.length,
                export_root=args.export_dir,
                allow_metadata_only=args.allow_metadata_only,
            )

    code, criteria, path = asyncio.run(run())
    print(criteria.render())
    if path:
        print(f"Bundle: {path}\nVerify again: uv run python scripts/verify_bundle.py {path}")
    if code == 2:
        print("A precondition failed. The target was NOT touched.")
    print("RESULT:", {0: "PASS", 1: "FAIL", 2: "NOT RUN"}[code])
    return code


if __name__ == "__main__":
    raise SystemExit(main())
