"""Failed snapshots retain truthful acquisition attempts without inventing evidence."""

import asyncio
import json
from pathlib import Path

import httpx
import pytest

from analysis.bundle_verify import verify_bundle
from contracts.models import AcquisitionRecord, MemoryReadRequest, SessionRequest, SnapshotRequest
from edge.backends import BackendError
from edge.service import PolicyError
from orchestrator.app import create_app as dashboard_app
from orchestrator.inference import ScriptedInference
from orchestrator.report import markdown, report_data
from orchestrator.workflow import Workflow
from tests.conftest import session_body
from tests.test_status import StatusEdge, live
from tests.test_workflow import LocalEdge, run_state

PASSWORD = "operator-test-password"


def snapshot_request(service, profile, request_id="snapshot"):
    current = service.session(SessionRequest(**session_body(profile)))
    request = SnapshotRequest(
        target_id=profile.target_id,
        session_id=current.session_id,
        request_id=request_id,
        address=0x80000000,
        length=4,
    )
    return current, request


async def signed_in(edge):
    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=dashboard_app(edge, ScriptedInference, PASSWORD)),
        base_url="http://test",
    )
    assert (await client.post("/api/login", json={"password": PASSWORD})).status_code == 200
    return client


async def failed_read(*_):
    raise BackendError("read_failed", False)


async def failed_registers(*_):
    raise BackendError("register_failed", False)


async def test_read_failure_records_halt_and_successful_restoration_without_evidence(service, profile):
    _, request = snapshot_request(service, profile)
    service.backend.read = failed_read

    result = await service.execute(request, "snapshot")

    assert not result.success and result.error_code == "read_failed" and not result.outcome_uncertain
    assert not result.data.get("memory") and not result.data.get("registers")
    attempt = AcquisitionRecord.model_validate(result.data["acquisition"])
    assert attempt.evidence_id is None and attempt.register_evidence_id is None
    assert attempt.initial_state == "running" and attempt.capture_state is None
    assert attempt.final_state == "running" and attempt.restoration == "running"
    assert attempt.halted_by_edge and attempt.error_code == "read_failed"
    assert not attempt.recovery_required and service.backend.generation == 2


async def test_register_failure_preserves_only_actual_memory_evidence(service, profile):
    service.retain_raw = True
    _, request = snapshot_request(service, profile)
    service.backend.registers = failed_registers

    result = await service.execute(request, "snapshot")

    assert not result.success and result.error_code == "register_failed"
    assert result.data["memory"]["evidence_id"] in service.raw
    assert not result.data.get("registers")
    attempt = AcquisitionRecord.model_validate(result.data["acquisition"])
    assert attempt.evidence_id == result.data["memory"]["evidence_id"]
    assert attempt.register_evidence_id is None and attempt.capture_state == "halted"
    assert attempt.final_state == "running" and attempt.restoration == "running"
    assert attempt.error_code == "register_failed" and not attempt.recovery_required


async def test_restore_failure_preserves_primary_error_and_requires_reconciliation(service, profile):
    _, request = snapshot_request(service, profile)
    service.backend.read = failed_read
    original_control = service.backend.control

    async def fail_resume(operation):
        if operation == "resume":
            raise BackendError("resume_disconnected", True)
        await original_control(operation)

    service.backend.control = fail_resume
    result = await service.execute(request, "snapshot")

    assert not result.success and result.error_code == "read_failed" and result.outcome_uncertain
    attempt = AcquisitionRecord.model_validate(result.data["acquisition"])
    assert attempt.error_code == "read_failed"
    assert attempt.restoration_error_code == "restoration_failed_operator_required"
    assert attempt.restoration == "failed" and attempt.recovery_required
    assert attempt.initial_state == "running" and attempt.final_state == "halted"
    assert service.recovery_required and service.backend.state == "halted"
    with pytest.raises(PolicyError, match="operator_reconciliation_required"):
        await service.execute(
            MemoryReadRequest(
                target_id=profile.target_id,
                session_id=request.session_id,
                request_id="after-failed-restore",
                address=0x80000000,
                length=4,
            ),
            "read",
        )


async def test_initial_status_failure_records_unknown_state_without_hardware_action(service, profile):
    _, request = snapshot_request(service, profile)

    async def failed_status():
        raise BackendError("rpc_disconnected", True)

    service.backend.status = failed_status
    result = await service.execute(request, "snapshot")
    attempt = AcquisitionRecord.model_validate(result.data["acquisition"])
    assert not result.success and result.error_code == "rpc_disconnected" and result.outcome_uncertain
    assert attempt.initial_state is None and attempt.final_state is None
    assert attempt.capture_state is None and attempt.evidence_id is None
    assert attempt.restoration == "not_attempted" and not attempt.halted_by_edge
    assert service.backend.generation == 0


async def test_final_status_failure_keeps_capture_but_marks_state_uncertain(service, profile):
    _, request = snapshot_request(service, profile)
    original_status = service.backend.status
    calls = 0

    async def fail_final_status():
        nonlocal calls
        calls += 1
        if calls == 5:
            raise BackendError("final_status_disconnected", False)
        return await original_status()

    service.backend.status = fail_final_status
    result = await service.execute(request, "snapshot")
    attempt = AcquisitionRecord.model_validate(result.data["acquisition"])
    assert not result.success and result.error_code == "final_status_disconnected"
    assert result.data["memory"] and result.data["registers"]
    assert attempt.initial_state == "running" and attempt.final_state is None
    assert attempt.restoration == "failed" and attempt.restoration_error_code
    assert attempt.outcome_uncertain and service.recovery_required


async def test_cancelled_admitted_snapshot_records_attempt_and_cannot_replay(service, profile):
    current, request = snapshot_request(service, profile)
    started = asyncio.Event()
    calls = 0

    async def interrupted_read(*_):
        nonlocal calls
        calls += 1
        started.set()
        await asyncio.Event().wait()

    service.backend.read = interrupted_read
    task = asyncio.create_task(service.execute(request, "snapshot"))
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    cached = await service.execute(request, "snapshot")
    assert not cached.success and cached.error_code == "operation_cancelled"
    assert cached.outcome_uncertain and service.recovery_required
    attempt = AcquisitionRecord.model_validate(cached.data["acquisition"])
    assert attempt.error_code == "operation_cancelled"
    assert attempt.initial_state == "running" and attempt.final_state == "running"
    assert attempt.restoration == "running" and attempt.evidence_id is None
    assert calls == 1 and current.used_operations == 1


async def test_failed_register_result_reaches_run_and_report(service, profile):
    service.backend.registers = failed_registers
    run = run_state(profile)
    await Workflow(run, LocalEdge(service), ScriptedInference(), asyncio.Event(), "test-build").execute()

    assert run.termination_reason == "dependency_failure" and "register_failed" in run.errors
    assert len(run.captures) == len(run.acquisitions) == 1 and not run.registers
    attempt = run.acquisitions[0]
    assert attempt.evidence_id == run.captures[0].evidence_id
    assert attempt.register_evidence_id is None and attempt.orchestrator_build_id == "test-build"
    assert attempt.error_code == "register_failed"
    assert report_data(run)["acquisitions"][0]["error_code"] == "register_failed"
    assert "register_failed" in markdown(run)


async def test_failed_read_appears_in_run_report_and_offline_bundle(service, profile, tmp_path, monkeypatch):
    monkeypatch.setenv("EXPORT_DIR", str(tmp_path / "exports"))
    service.backend.read = failed_read
    client = await signed_in(LocalEdge(service))
    try:
        response = await client.post(
            "/api/runs",
            json={
                "target_id": profile.target_id,
                "purpose": "bootloader inspection",
                "region_names": ["demo-code", "demo-log"],
            },
        )
        assert response.status_code == 200, response.text
        run_id = response.json()["run_id"]
        for _ in range(100):
            run = (await client.get(f"/api/runs/{run_id}")).json()
            if run["status"] not in ("queued", "running"):
                break
            await asyncio.sleep(0.02)
        assert run["status"] == "failed" and not run["captures"]
        assert len(run["acquisitions"]) == 1 and run["acquisitions"][0]["error_code"] == "read_failed"
        report = (await client.get(f"/api/runs/{run_id}/report.md")).text
        assert "## Acquisition attempts without a retained capture" in report
        assert "read_failed" in report and "restoration=running" in report

        exported = await client.post(f"/api/runs/{run_id}/bundle", json={"include_raw": True})
        assert exported.status_code == 200, exported.text
        bundle = Path(exported.json()["path"])
        manifest = json.loads((bundle / "manifest.json").read_text())
        report_json = json.loads((bundle / "report.json").read_text())
        assert manifest["captures"] == [] and len(manifest["acquisitions"]) == 1
        assert manifest["acquisitions"] == report_json["acquisitions"]
        assert manifest["acquisitions"][0]["evidence_id"] is None
        assert verify_bundle(bundle).status == "INCOMPLETE"
    finally:
        await client.aclose()


async def test_attack_plan_keeps_failed_probe_attempt_and_partial_evidence(
    service, profile, monkeypatch, tmp_path
):
    # A mock edge with a physical-shaped status exercises the policy path without hardware.
    monkeypatch.setenv("ATTACK_LAB_LIVE_JTAG", "1")
    monkeypatch.setenv("EXPORT_DIR", str(tmp_path / "exports"))
    service.retain_raw = True
    service.backend.registers = failed_registers
    edge = StatusEdge(service, live(await service.report()))
    client = await signed_in(edge)
    try:
        response = await client.post(
            "/api/attack-lab/plans",
            json={
                "target_id": profile.target_id,
                "module_id": "jtag-debug-lock-audit",
                "objective": "Assess JTAG exposure",
                "authorization_acknowledged": True,
            },
        )
        assert response.status_code == 200, response.text
        plan = response.json()
        plan_id = plan["plan_id"]
        for _ in range(2):
            plan = (await client.post(f"/api/attack-lab/plans/{plan_id}/execute-next")).json()
        decision = await client.post(
            f"/api/attack-lab/plans/{plan_id}/steps/{plan['steps'][2]['step_id']}/decision",
            json={"decision": "approve", "note": "test"},
        )
        assert decision.status_code == 200
        plan = (await client.post(f"/api/attack-lab/plans/{plan_id}/execute-next")).json()
        step = plan["steps"][2]
        assert step["status"] == "blocked" and "register_failed" in step["result"]
        assert len(plan["captures"]) == len(plan["acquisitions"]) == 1
        assert not plan["registers"] and plan["acquisitions"][0]["error_code"] == "register_failed"
        exported = await client.post(f"/api/attack-lab/plans/{plan_id}/bundle", json={"include_raw": True})
        assert exported.status_code == 200, exported.text
        bundle = Path(exported.json()["path"])
        manifest = json.loads((bundle / "manifest.json").read_text())
        assert manifest["captures"][0]["evidence_id"] == plan["captures"][0]["evidence_id"]
        assert manifest["acquisitions"][0]["error_code"] == "register_failed"
        assert manifest["acquisitions"][0]["register_evidence_id"] is None
        assert verify_bundle(bundle).status == "INCOMPLETE"
    finally:
        await client.aclose()
