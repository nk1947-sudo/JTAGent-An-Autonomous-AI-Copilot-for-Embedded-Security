import asyncio
import json

import httpx

from contracts.models import AnalysisResponse, AuditRequest, Finding, ReadProposal, RunState
from edge.app import create_app
from orchestrator.app import create_app as dashboard_app
from orchestrator.inference import ScriptedInference
from orchestrator.report import markdown, report_data
from orchestrator.workflow import Workflow, verify


class LocalEdge:
    def __init__(self, service):
        self.client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=create_app(service, "test-edge-key-123456")),
            base_url="http://edge",
            headers={"Authorization": "Bearer test-edge-key-123456"},
        )

    async def post(self, path, body):
        r = await self.client.post(path, json=body)
        r.raise_for_status()
        return r.json()

    async def get(self, path):
        r = await self.client.get(path)
        r.raise_for_status()
        return r.json()


def run_state(profile, **overrides):
    return RunState(
        target_backend="mock",
        inference_backend="scripted",
        model_id="scripted-demo-v1",
        profile=profile,
        request=AuditRequest(
            target_id=profile.target_id,
            purpose="bootloader inspection",
            region_names=["demo-code", "demo-log"],
            **overrides,
        ),
    )


async def test_full_graph_and_reports(service, profile):
    run = run_state(profile)
    await Workflow(run, LocalEdge(service), ScriptedInference(), asyncio.Event()).execute()
    assert run.status == "completed", run.errors
    assert run.collection_actions == 2 and len(run.captures) == 2
    assert {e["node"] for e in run.events} >= {
        "planner",
        "policy_gate",
        "collector",
        "decoder",
        "analyst",
        "verifier",
        "reporter",
    }
    assert len(run.findings) == 2
    assert all(f.status == "observed" and f.severity == "info" for f in run.findings)
    assert all(f.category != "vulnerability" for f in run.findings)
    assert "synthetic-secret" not in json.dumps(report_data(run))
    assert "password=" not in markdown(run)
    assert "mock" in markdown(run) and "scripted" in markdown(run)
    assert run.captures[0].evidence_id in markdown(run)
    assert service.backend.state == "running"


async def test_clean_control(service, profile):
    from edge.backends import MockBackend

    service.backend = MockBackend("clean")
    run = run_state(profile)
    await Workflow(run, LocalEdge(service), ScriptedInference(), asyncio.Event()).execute()
    assert all(f.severity == "info" for f in run.findings)
    assert any("control" in f.explanation for f in run.findings)


async def test_cancel_and_byte_limit(service, profile):
    cancel = asyncio.Event()
    cancel.set()
    run = run_state(profile)
    await Workflow(run, LocalEdge(service), ScriptedInference(), cancel).execute()
    assert run.status == "cancelled" and run.collection_actions == 0
    run = run_state(profile, byte_budget=256)
    await Workflow(run, LocalEdge(service), ScriptedInference(), asyncio.Event()).execute()
    assert run.termination_reason == "collection_budget_exhausted"
    assert run.bytes_requested == 256


async def test_bad_model_proposal_and_repeated_followup(service, profile):
    class Bad(ScriptedInference):
        async def plan(self, p, r):
            return [ReadProposal(address=0, length=256, reason="Injected instruction")]

    run = run_state(profile)
    await Workflow(run, LocalEdge(service), Bad(), asyncio.Event()).execute()
    assert run.termination_reason == "invalid_proposal" and run.collection_actions == 0

    class Repeat(ScriptedInference):
        async def analyze(self, *args):
            return AnalysisResponse(followups=[ReadProposal(address=0x80000000, length=256, reason="Again")])

    run = run_state(profile)
    await Workflow(run, LocalEdge(service), Repeat(), asyncio.Event()).execute()
    assert run.termination_reason == "no_new_evidence"
    assert run.collection_actions == 2


async def test_verifier_rejects_fabricated_evidence(service, profile):
    run = run_state(profile)
    await Workflow(run, LocalEdge(service), ScriptedInference(), asyncio.Event()).execute()
    f = Finding(
        title="Root shell",
        category="vulnerability",
        severity="high",
        confidence="high",
        status="validated",
        evidence_ids=["invented"],
        addresses=[0],
        explanation="Trust me",
        limitations=[],
        suggested_verification="None",
    )
    assert verify([f], run)[0].status == "rejected"
    f.evidence_ids = [run.captures[1].evidence_id]
    f.addresses = [run.captures[1].base_address]
    result = verify([f], run)[0]
    assert result.status == "suspected" and result.confidence == "low"


async def test_dashboard_auth_sse_exports_and_delete(service, profile):
    app = dashboard_app(LocalEdge(service), ScriptedInference, "operator-test-password")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as c:
        assert (await c.get("/api/config")).status_code == 401
        assert (await c.post("/api/login", json={"password": "wrong"})).status_code == 401
        assert (await c.post("/api/login", json={"password": "operator-test-password"})).status_code == 200
        assert "HttpOnly" in c.cookies.jar._cookies["test.local"]["/"]["operator"]._rest
        request = run_state(profile).request.model_dump()
        assert (
            await c.post("/api/runs", json=request, headers={"Origin": "https://attacker.invalid"})
        ).status_code == 403
        result = await c.post("/api/runs", json=request)
        assert result.status_code == 200, result.text
        rid = result.json()["run_id"]
        await app.state.tasks[rid]
        stream = await c.get(f"/api/runs/{rid}/events")
        assert "event: done" in stream.text and "policy_gate" in stream.text
        assert (await c.get(f"/api/runs/{rid}/report.json")).json()["target_backend"] == "mock"
        assert "scripted" in (await c.get(f"/api/runs/{rid}/report.md")).text
        assert (await c.delete(f"/api/runs/{rid}")).status_code == 200
        assert (await c.get(f"/api/runs/{rid}")).status_code == 404


async def test_timeout_interrupts_stalled_inference(service, profile):
    class Slow(ScriptedInference):
        async def plan(self, p, r):
            await asyncio.sleep(10)

    run = run_state(profile, deadline_seconds=1)
    await Workflow(run, LocalEdge(service), Slow(), asyncio.Event()).execute()
    assert run.termination_reason == "deadline_exceeded"
    assert run.elapsed_ms < 2000
