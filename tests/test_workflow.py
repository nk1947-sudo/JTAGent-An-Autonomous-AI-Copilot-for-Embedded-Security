import asyncio
import json

import httpx

from contracts.models import AnalysisResponse, AuditRequest, Finding, ReadProposal, RunState
from edge.app import create_app
from orchestrator.app import create_app as dashboard_app
from orchestrator.inference import ScriptedInference
from orchestrator.report import describe_cpsr, markdown, report_data
from orchestrator.workflow import Workflow, verify


class LocalEdge:
    def __init__(self, service):
        self.client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=create_app(service, "test-edge-key-123456")),
            base_url="http://edge",
            headers={"Authorization": "Bearer test-edge-key-123456"},
        )

    async def post(self, path, body, timeout_seconds=12):
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

    snapshot = run.registers[0]
    f.evidence_ids = [snapshot.evidence_id]
    f.addresses = [snapshot.values["pc"]]
    f.explanation = "The captured PC points to 0xdeadbeef."
    result = verify([f], run)[0]
    assert result.status == "rejected"
    assert "contradicted the cited snapshot" in result.limitations[-1]

    f.explanation = f"The captured PC points to 0x{snapshot.values['pc']:x}."
    assert verify([f], run)[0].status == "suspected"


async def test_dashboard_auth_sse_exports_and_delete(service, profile):
    app = dashboard_app(LocalEdge(service), ScriptedInference, "operator-test-password")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as c:
        assert (await c.get("/api/config")).status_code == 401
        assert (await c.post("/api/login", json={"password": "wrong"})).status_code == 401
        assert (await c.post("/api/login", json={"password": "operator-test-password"})).status_code == 200
        assert "HttpOnly" in c.cookies.jar._cookies["test.local"]["/"]["operator"]._rest
        config = (await c.get("/api/config")).json()
        assert {item["id"] for item in config["dependencies"]} == {
            "edge",
            "debugger",
            "target",
            "operations",
            "uart",
            "inference",
        }
        assert config["pricing"] == {
            "input_usd_per_million": None,
            "output_usd_per_million": None,
        }
        assert (await c.get("/api/runs")).json() == []
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
        history = (await c.get("/api/runs")).json()
        assert history[0]["run_id"] == rid
        assert history[0]["capture_count"] == 2
        assert history[0]["status"] == "completed"
        assert (await c.delete(f"/api/runs/{rid}")).status_code == 200
        assert (await c.get("/api/runs")).json() == []
        assert (await c.get(f"/api/runs/{rid}")).status_code == 404
        assert (await c.post("/api/logout")).status_code == 200
        assert (await c.get("/api/config")).status_code == 401


async def test_dashboard_uart_proxy_uses_the_bounded_audit_timeout(service):
    class UartEdge(LocalEdge):
        timeout = None

        async def post(self, path, body, timeout_seconds=12):
            if path == "/api/v1/uart/audit":
                self.timeout = timeout_seconds
                return {"status": "completed"}
            return await super().post(path, body, timeout_seconds)

    edge = UartEdge(service)
    app = dashboard_app(edge, ScriptedInference, "operator-test-password")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as c:
        await c.post("/api/login", json={"password": "operator-test-password"})
        result = await c.post("/api/uart/audit", json={"mode": "interrupt", "timeout_seconds": 37})
        assert result.status_code == 200
        assert edge.timeout == 42


async def test_attack_lab_recommendations_and_hitl_state_machine(service, profile, monkeypatch):
    monkeypatch.setenv("ATTACK_LAB_LIVE_JTAG", "1")

    class PhysicalJtagEdge(LocalEdge):
        async def get(self, path):
            result = await super().get(path)
            if path == "/api/v1/target/status":
                # A consistent OpenOCD-shaped v2 status; a bare backend swap is rightly refused.
                result["target_backend"] = "openocd"
                result["debugger"].update(applicable=True, reachable=True, version_ok=True)
            return result

    app = dashboard_app(PhysicalJtagEdge(service), ScriptedInference, "operator-test-password")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as c:
        await c.post("/api/login", json={"password": "operator-test-password"})
        recommendations = await c.post(
            "/api/attack-lab/recommendations",
            json={
                "target_id": profile.target_id,
                "objective": "Assess JTAG debug lock and halt exposure",
            },
        )
        assert recommendations.status_code == 200, recommendations.text
        selected = recommendations.json()[0]
        assert selected["module_id"] == "jtag-debug-lock-audit"
        assert selected["supported"] is True

        rejected = await c.post(
            "/api/attack-lab/plans",
            json={
                "target_id": profile.target_id,
                "module_id": selected["module_id"],
                "objective": "Assess JTAG debug lock and halt exposure",
                "authorization_acknowledged": False,
            },
        )
        assert rejected.status_code == 422

        response = await c.post(
            "/api/attack-lab/plans",
            json={
                "target_id": profile.target_id,
                "module_id": selected["module_id"],
                "objective": "Assess JTAG debug lock and halt exposure",
                "authorization_acknowledged": True,
            },
        )
        assert response.status_code == 200, response.text
        plan = response.json()
        plan_id = plan["plan_id"]
        assert plan["status"] == "awaiting_approval"
        assert plan["steps"][2]["status"] == "pending_approval"

        for _ in range(2):
            plan = (await c.post(f"/api/attack-lab/plans/{plan_id}/execute-next")).json()
        approval = await c.post(
            f"/api/attack-lab/plans/{plan_id}/steps/{plan['steps'][2]['step_id']}/decision",
            json={"decision": "approve", "note": "Authorized dry run"},
        )
        assert approval.json()["steps"][2]["status"] == "approved"
        completed = (await c.post(f"/api/attack-lab/plans/{plan_id}/execute-next")).json()
        assert completed["status"] == "completed"
        assert "REAL OPENOCD JTAG probe" in completed["steps"][2]["result"]
        assert completed["steps"][2]["state_changing"] is True
        assert completed["evidence_ids"]
        assert len(completed["captures"]) == 1
        assert completed["captures"][0]["evidence"]["instructions"]
        assert len(completed["registers"]) == 1
        advice = await c.post(
            "/api/debugger/advice",
            json={
                "plan_id": plan_id,
                "objective": "Explain the captured control flow and propose the next bounded action",
            },
        )
        assert advice.status_code == 200, advice.text
        assert {item["operation"] for item in advice.json()["actions"]} == {
            "disassemble",
            "inspect_registers",
        }
        patch = await c.post(
            "/api/workbench/patch-preview",
            json={
                "plan_id": plan_id,
                "address": profile.regions[0].start,
                "original_hex": "00000000",
                "replacement_hex": "0000a0e1",
                "instruction_mode": "arm",
            },
        )
        assert patch.status_code == 200, patch.text
        patch_data = patch.json()
        assert patch_data["live_execution_enabled"] is False
        assert patch_data["replacement_instructions"][0]["mnemonic"] == "mov"
        assert "Offline preview only" in patch_data["warnings"][0]
        report = (await c.get(f"/api/attack-lab/plans/{plan_id}/report.json")).json()
        assert report["physical_execution_performed"] is True
        markdown_report = (await c.get(f"/api/attack-lab/plans/{plan_id}/report.md")).text
        assert "Physical execution performed: **YES**" in markdown_report
        assert (await c.post(f"/api/attack-lab/plans/{plan_id}/abort")).status_code == 409


async def test_external_hardware_plan_never_claims_physical_execution(service, profile):
    app = dashboard_app(LocalEdge(service), ScriptedInference, "operator-test-password")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as c:
        await c.post("/api/login", json={"password": "operator-test-password"})
        plan = (
            await c.post(
                "/api/attack-lab/plans",
                json={
                    "target_id": profile.target_id,
                    "module_id": "fault-injection-campaign-design",
                    "objective": "Design a bounded boot fault-injection campaign",
                    "authorization_acknowledged": True,
                },
            )
        ).json()
        plan_id = plan["plan_id"]
        plan = (await c.post(f"/api/attack-lab/plans/{plan_id}/execute-next")).json()
        decision = await c.post(
            f"/api/attack-lab/plans/{plan_id}/steps/{plan['steps'][1]['step_id']}/decision",
            json={"decision": "approve", "note": "Design review only"},
        )
        assert decision.status_code == 200
        plan = (await c.post(f"/api/attack-lab/plans/{plan_id}/execute-next")).json()
        assert plan["status"] == "blocked"
        assert "NO PHYSICAL ATTACK" in plan["steps"][1]["result"]
        report = (await c.get(f"/api/attack-lab/plans/{plan_id}/report.json")).json()
        assert report["physical_execution_performed"] is False
        assert (
            "Physical execution performed: **NO**"
            in (await c.get(f"/api/attack-lab/plans/{plan_id}/report.md")).text
        )


async def test_timeout_interrupts_stalled_inference(service, profile):
    class Slow(ScriptedInference):
        async def plan(self, p, r):
            await asyncio.sleep(10)

    run = run_state(profile, deadline_seconds=1)
    await Workflow(run, LocalEdge(service), Slow(), asyncio.Event()).execute()
    assert run.termination_reason == "deadline_exceeded"
    assert run.elapsed_ms < 2000


def test_cpsr_decode_matches_captured_live_value():
    # 0x600000b3 was read from the AM335x on 2026-09-29: Z,C set, I masked, T set, mode 0b10011.
    assert describe_cpsr(0x600000B3) == ("Supervisor mode, Thumb state, flags -ZC-, interrupt masks I-")
    assert "reserved" in describe_cpsr(0x0)


async def test_markdown_carries_verifiable_evidence(service, profile):
    run = run_state(profile)
    await Workflow(run, LocalEdge(service), ScriptedInference(), asyncio.Event()).execute()
    text = markdown(run)
    first = run.captures[0]
    assert f"CPU state at capture: {first.target_state}" in text
    assert "## Register snapshots" in text and "not an atomic snapshot" in text
    assert f"0x{first.evidence.instructions[0].address:08x}" in text
    assert all(f"{name} = 0x" in text for name in run.registers[0].values)
