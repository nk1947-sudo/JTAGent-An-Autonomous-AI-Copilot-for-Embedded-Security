"""API failure paths the operator sees after authentication."""

import json
import time
from pathlib import Path

import httpx
import pytest

from analysis.bundle_verify import verify_bundle
from contracts.models import MemoryReadRequest, SessionRequest
from edge.backends import BackendError
from edge.service import PolicyError
from orchestrator.app import create_app
from orchestrator.inference import ScriptedInference
from tests.conftest import session_body
from tests.test_workflow import LocalEdge, run_state

PASSWORD = "operator-test-password"


async def test_unavailable_edge_blocks_run_but_reports_readiness(service, profile):
    class UnavailableEdge(LocalEdge):
        async def get(self, path):
            if path == "/api/v1/target/status":
                raise RuntimeError("edge unavailable")
            return await super().get(path)

    app = create_app(UnavailableEdge(service), ScriptedInference, PASSWORD)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        await client.post("/api/login", json={"password": PASSWORD})
        readiness = (await client.get("/api/readiness")).json()
        blocked = await client.post("/api/runs", json=run_state(profile).request.model_dump())
        assert readiness["edge"] == "unreachable" and not readiness["run_ready"]
        assert blocked.status_code == 409 and not app.state.runs


async def test_expired_operator_cookie_and_edge_session_are_refused(service, profile, monkeypatch):
    app = create_app(LocalEdge(service), ScriptedInference, PASSWORD)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        await client.post("/api/login", json={"password": PASSWORD})
        assert (await client.get("/api/readiness")).status_code == 200
        later = time.time() + 3601
        monkeypatch.setattr(time, "time", lambda: later)
        assert (await client.get("/api/readiness")).status_code == 401

    current = service.session(SessionRequest(**session_body(profile)))
    current.expires_at = later - 1
    with pytest.raises(PolicyError, match="session_expired"):
        await service.execute(
            MemoryReadRequest(
                target_id=profile.target_id,
                session_id=current.session_id,
                address=0x80000000,
                length=4,
            ),
            "read",
        )


async def test_uncertain_restoration_survives_run_report_and_bundle(service, profile, monkeypatch, tmp_path):
    monkeypatch.setenv("EXPORT_DIR", str(tmp_path / "exports"))

    async def failed_read(*_):
        raise BackendError("read_failed", False)

    original_control = service.backend.control

    async def failed_resume(operation):
        if operation == "resume":
            raise BackendError("resume_disconnected", True)
        return await original_control(operation)

    service.backend.read = failed_read
    service.backend.control = failed_resume
    app = create_app(LocalEdge(service), ScriptedInference, PASSWORD)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        await client.post("/api/login", json={"password": PASSWORD})
        started = await client.post("/api/runs", json=run_state(profile).request.model_dump())
        assert started.status_code == 200
        run_id = started.json()["run_id"]
        await app.state.tasks[run_id]
        report = (await client.get(f"/api/runs/{run_id}/report.json")).json()
        attempt = report["acquisitions"][0]
        assert attempt["error_code"] == "read_failed"
        assert attempt["restoration_error_code"] == "restoration_failed_operator_required"
        assert attempt["outcome_uncertain"] and attempt["recovery_required"]
        assert attempt["final_state"] == "halted" and report["captures"] == []

        exported = await client.post(f"/api/runs/{run_id}/bundle", json={"include_raw": False})
        assert exported.status_code == 200
        bundle = Path(exported.json()["path"])
        manifest = json.loads((bundle / "manifest.json").read_text())
        assert manifest["acquisitions"][0] == attempt
        assert verify_bundle(bundle).status == "INCOMPLETE"
