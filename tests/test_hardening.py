import asyncio
import json

import httpx

from analysis.evidence import sanitize_data
from contracts.models import SessionRequest, SnapshotRequest
from edge.app import create_app
from edge.backends import BackendError, ReplayBackend
from edge.service import EdgeService
from orchestrator.inference import ScriptedInference
from orchestrator.workflow import Workflow, verify
from tests.conftest import session_body
from tests.test_workflow import LocalEdge, run_state


async def test_chunked_body_stops_at_limit(service):
    sent = 0

    async def chunks():
        nonlocal sent
        for _ in range(100):
            sent += 1
            yield b"x" * 1024

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(service, "test-edge-key-123456")), base_url="http://edge"
    ) as client:
        response = await client.post("/api/v1/memory/read", content=chunks())
    assert response.status_code == 413
    assert sent == 33


async def test_failed_collection_restores_running_cpu(service, profile):
    async def fail(*args):
        raise BackendError("unreadable")

    service.backend.read = fail
    s = service.session(SessionRequest(**session_body(profile)))
    req = SnapshotRequest(target_id=profile.target_id, session_id=s.session_id, address=0x80000000, length=16)
    result = await service.execute(req, "snapshot")
    assert not result.success
    assert service.backend.state == "running"


async def test_replay_full_graph_preserves_capture_date(profile):
    backend = ReplayBackend("fixtures/replay.json")
    profile.capabilities = ["read", "registers", "snapshot"]
    profile.provenance = backend.manifest["provenance"]
    service = EdgeService(backend, profile)
    run = run_state(profile)
    run.target_backend = "replay"
    await Workflow(run, LocalEdge(service), ScriptedInference(), asyncio.Event()).execute()
    assert run.status == "completed", run.errors
    assert all(c.timestamp == backend.manifest["captured_at"] for c in run.captures)
    assert all(c.source_mode == "replay" and c.evidence.approved_hex is None for c in run.captures)
    assert all(r.timestamp == backend.manifest["captured_at"] for r in run.registers)


async def test_verifier_normalizes_observation_title(service, profile):
    run = run_state(profile)
    await Workflow(run, LocalEdge(service), ScriptedInference(), asyncio.Event()).execute()
    finding = run.findings[0].model_copy(update={"title": "Confirmed root shell and buffer overflow"})
    checked = verify([finding], run)[0]
    assert checked.title == "Captured printable string"
    assert checked.severity == "info"
    finding.addresses = []
    assert verify([finding], run)[0].status == "rejected"


def test_redaction_does_not_corrupt_json():
    data = {"explanation": "token=abc", "limitations": ["password=xyz"], "count": 2}
    assert json.loads(json.dumps(sanitize_data(data))) == {
        "explanation": "[REDACTED]",
        "limitations": ["[REDACTED]"],
        "count": 2,
    }


async def test_operator_cancel_interrupts_active_inference(service, profile):
    from orchestrator.app import create_app as dashboard_app

    entered = asyncio.Event()

    class SlowInference(ScriptedInference):
        async def analyze(self, *args):
            entered.set()
            await asyncio.sleep(60)

    app = dashboard_app(LocalEdge(service), SlowInference, "operator-test-password")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        await client.post("/api/login", json={"password": "operator-test-password"})
        response = await client.post("/api/runs", json=run_state(profile).request.model_dump())
        rid = response.json()["run_id"]
        await asyncio.wait_for(entered.wait(), 2)
        assert service.backend.state == "running"
        assert (await client.post(f"/api/runs/{rid}/cancel")).status_code == 200
        await asyncio.wait_for(app.state.tasks[rid], 2)
        run = (await client.get(f"/api/runs/{rid}")).json()
        assert run["status"] == "cancelled"
        assert len(run["captures"]) == 2
        assert run["termination_reason"] == "operator_cancelled"
