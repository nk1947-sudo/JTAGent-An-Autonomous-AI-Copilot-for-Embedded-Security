"""Attack Plan deletion is bounded to terminal in-memory plans."""

import asyncio
import tempfile
import threading
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
import pytest

import orchestrator.app as orchestrator_module
from orchestrator.app import create_app
from orchestrator.inference import ScriptedInference
from tests.test_status import StatusEdge, live
from tests.test_workflow import LocalEdge

PASSWORD = "operator-test-password"
ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def export_root(monkeypatch):
    with tempfile.TemporaryDirectory(prefix="plan-delete-", dir=ROOT / "tmp") as directory:
        monkeypatch.setenv("EXPORT_DIR", directory)
        yield Path(directory)


@asynccontextmanager
async def signed_in(service, edge=None):
    app = create_app(edge or LocalEdge(service), ScriptedInference, PASSWORD)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        assert (await client.post("/api/login", json={"password": PASSWORD})).status_code == 200
        yield app, client


async def create_plan(client, profile, run_id=None):
    response = await client.post(
        "/api/attack-lab/plans",
        json={
            "target_id": profile.target_id,
            "module_id": "jtag-debug-lock-audit",
            "objective": "Assess JTAG exposure",
            "run_id": run_id,
            "authorization_acknowledged": True,
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


async def test_delete_requires_auth_and_terminal_state(service, profile):
    async with signed_in(service) as (app, client):
        plan = await create_plan(client, profile)
        path = f"/api/attack-lab/plans/{plan['plan_id']}"
        unauthenticated = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")
        async with unauthenticated:
            assert (await unauthenticated.delete(path)).status_code == 401
        assert (await client.delete(path, headers={"Origin": "https://evil.example"})).status_code == 403
        for state in ("ready", "awaiting_approval", "running", "paused"):
            app.state.attack_plans[plan["plan_id"]].status = state
            response = await client.delete(path)
            assert response.status_code == 409
            assert response.json()["detail"] == "Complete or abort the plan before deletion"
            assert (await client.get(path)).status_code == 200
        app.state.attack_plans[plan["plan_id"]].status = "ready"
        assert (await client.post(path + "/abort")).json()["status"] == "aborted"
        assert (await client.delete(path)).json() == {"deleted": True}
        assert (await client.get(path)).status_code == 404
        missing = await client.delete(path)
        assert missing.status_code == 404 and missing.json()["detail"] == "Attack plan not found"


@pytest.mark.parametrize("terminal", ["completed", "simulation_completed", "blocked", "aborted"])
async def test_all_terminal_states_can_be_deleted(service, profile, terminal):
    async with signed_in(service) as (app, client):
        plan = await create_plan(client, profile)
        app.state.attack_plans[plan["plan_id"]].status = terminal
        assert (await client.delete(f"/api/attack-lab/plans/{plan['plan_id']}")).json() == {"deleted": True}


async def test_capacity_recovers_without_erasing_other_plans_or_exports(service, profile, export_root):
    async with signed_in(service) as (_app, client):
        started = await client.post(
            "/api/runs",
            json={
                "target_id": profile.target_id,
                "purpose": "bootloader inspection",
                "region_names": ["demo-code", "demo-log"],
            },
        )
        assert started.status_code == 200, started.text
        run_id = started.json()["run_id"]
        for _ in range(100):
            run = (await client.get(f"/api/runs/{run_id}")).json()
            if run["status"] not in ("queued", "running"):
                break
            await asyncio.sleep(0.02)
        assert run["status"] == "completed" and run["captures"]
        evidence_ids = [capture["evidence_id"] for capture in run["captures"]]
        plans = [await create_plan(client, profile, run_id) for _ in range(20)]
        assert (
            await client.post(
                "/api/attack-lab/plans",
                json={
                    "target_id": profile.target_id,
                    "module_id": "jtag-debug-lock-audit",
                    "objective": "Assess JTAG exposure",
                    "authorization_acknowledged": True,
                },
            )
        ).status_code == 429
        first = plans[0]["plan_id"]
        other = plans[1]["plan_id"]
        assert plans[1]["evidence_ids"] == evidence_ids
        assert (await client.post(f"/api/attack-lab/plans/{first}/abort")).status_code == 200
        exported = await client.post(f"/api/attack-lab/plans/{first}/bundle", json={"include_raw": False})
        assert exported.status_code == 200, exported.text
        manifest = Path(exported.json()["path"]) / "manifest.json"
        assert manifest.is_file()

        assert (await client.delete(f"/api/attack-lab/plans/{first}")).json() == {"deleted": True}
        replacement = await create_plan(client, profile)
        assert replacement["plan_id"] not in {item["plan_id"] for item in plans}
        assert len((await client.get("/api/attack-lab/plans")).json()) == 20
        assert (await client.get(f"/api/attack-lab/plans/{other}")).json()["evidence_ids"] == evidence_ids
        assert [
            capture["evidence_id"] for capture in (await client.get(f"/api/runs/{run_id}")).json()["captures"]
        ] == evidence_ids
        assert manifest.is_file()
        bundle_id = manifest.parent.name
        assert (await client.get(f"/api/exports/{bundle_id}/manifest.json")).status_code == 200


async def test_delete_rejects_in_flight_bundle(service, profile, export_root, monkeypatch):
    started, release = threading.Event(), threading.Event()
    original = orchestrator_module.build_bundle

    def slow_bundle(**kwargs):
        started.set()
        if not release.wait(5):
            raise AssertionError("test did not release bundle writer")
        return original(**kwargs)

    monkeypatch.setattr(orchestrator_module, "build_bundle", slow_bundle)
    async with signed_in(service) as (_app, client):
        plan = await create_plan(client, profile)
        path = f"/api/attack-lab/plans/{plan['plan_id']}"
        assert (await client.post(path + "/abort")).status_code == 200
        bundle_task = asyncio.create_task(client.post(path + "/bundle", json={"include_raw": False}))
        try:
            assert await asyncio.to_thread(started.wait, 3)
            rejected = await client.delete(path)
            assert rejected.status_code == 409 and rejected.json()["detail"] == "Plan is in use"
        finally:
            release.set()
        bundle = await bundle_task
        assert bundle.status_code == 200, bundle.text
        assert (await client.delete(path)).json() == {"deleted": True}
        assert Path(bundle.json()["path"]).joinpath("manifest.json").is_file()


async def test_delete_rejects_in_flight_and_queued_plan_work(service, profile, export_root, monkeypatch):
    monkeypatch.setenv("ATTACK_LAB_LIVE_JTAG", "1")
    started, release = asyncio.Event(), asyncio.Event()

    class SlowStatusEdge(StatusEdge):
        delay_once = False

        async def get(self, path):
            if path == "/api/v1/target/status" and self.delay_once:
                self.delay_once = False
                started.set()
                await release.wait()
            return await super().get(path)

    edge = SlowStatusEdge(service, live(await service.report()))
    async with signed_in(service, edge) as (_app, client):
        plan = await create_plan(client, profile)
        path = f"/api/attack-lab/plans/{plan['plan_id']}"
        queued_plan = await create_plan(client, profile)
        queued_path = f"/api/attack-lab/plans/{queued_plan['plan_id']}"
        assert (await client.post(queued_path + "/abort")).status_code == 200
        for _ in range(2):
            plan = (await client.post(path + "/execute-next")).json()
        assert (
            await client.post(
                path + f"/steps/{plan['steps'][2]['step_id']}/decision",
                json={"decision": "approve", "note": "mock test"},
            )
        ).status_code == 200
        edge.delay_once = True
        execution = asyncio.create_task(client.post(path + "/execute-next"))
        try:
            await asyncio.wait_for(started.wait(), 3)
            bundle = asyncio.create_task(client.post(queued_path + "/bundle", json={"include_raw": False}))
            await asyncio.sleep(0.05)
            assert not bundle.done()
            queued_rejected = await client.delete(queued_path)
            assert queued_rejected.status_code == 409 and queued_rejected.json()["detail"] == "Plan is in use"
            rejected = await client.delete(path)
            assert rejected.status_code == 409 and rejected.json()["detail"] == "Plan is in use"
        finally:
            release.set()
        executed, exported = await asyncio.gather(execution, bundle)
        assert executed.status_code == 200, executed.text
        assert executed.json()["status"] == "completed"
        assert exported.status_code == 200, exported.text
        assert (await client.delete(queued_path)).json() == {"deleted": True}
        assert (await client.delete(path)).json() == {"deleted": True}
        assert (await client.get(path)).status_code == 404
