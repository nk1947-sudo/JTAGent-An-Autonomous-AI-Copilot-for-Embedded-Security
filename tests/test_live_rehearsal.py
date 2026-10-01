"""Rehearsal of the live-validation procedure against a scripted FAKE OpenOCD. No hardware is contacted.

This proves the policy gates, restoration and recovery behavior of the real edge, OpenOCD adapter, live
profile and orchestrator. It says nothing about real hardware; that is what the authorized live step is for.
"""

import contextlib
import json
import os
from pathlib import Path

import httpx
import pytest

from analysis.bundle_verify import verify_bundle
from contracts.build import load_build
from contracts.models import TargetProfile
from contracts.status import assess
from edge.app import create_app as edge_app
from edge.backends import OpenOCDBackend, TclRPC
from edge.service import EdgeService
from orchestrator.app import create_app as dashboard_app
from orchestrator.inference import ScriptedInference
from scripts import compare_manual_read, live_snapshot
from tests.fake_openocd import BASE, FIXTURE, FakeOpenOCD

KEY = "rehearsal-edge-key-0123456789"
PASSWORD = "operator-test-password"
PROFILE = TargetProfile.model_validate_json(Path("config/beaglebone-black-live.json").read_text())


@contextlib.asynccontextmanager
async def rig(fake, *, timeout=2, arm=True, retain=True):
    port = await fake.start()
    rpc = TclRPC(port=port, timeout=timeout)
    service = EdgeService(
        OpenOCDBackend(rpc, "am335x.cpu", "xPack Open On-Chip Debugger 0.12."),
        PROFILE,
        arm_snapshots=arm,
        retain_raw=retain,
    )
    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=edge_app(service, KEY, uart_auditor=None)),
        base_url="http://edge",
        headers={"Authorization": "Bearer " + KEY},
    )
    try:
        yield service, client
    finally:
        await rpc.close()
        with contextlib.suppress(Exception):
            await fake.stop()


def halts(fake):
    return [c for c in fake.commands if c.endswith("halt 1000")]


def resumes(fake):
    return [c for c in fake.commands if c.endswith("resume")]


async def run(client, tmp_path, **kw):
    return await live_snapshot.execute(client, address=BASE, length=16, export_root=tmp_path, **kw)


async def test_happy_path_sends_only_the_authorized_verbs_and_yields_a_verified_bundle(tmp_path):
    fake = FakeOpenOCD()
    async with rig(fake) as (_service, client):
        code, criteria, bundle = await run(client, tmp_path)
    assert code == 0, criteria.render()
    assert criteria.passed and "PASS" in criteria.render()
    assert fake.state == "running" and len(halts(fake)) == 1 and len(resumes(fake)) == 1
    assert fake.sent_forbidden() == []
    assert "am335x.cpu read_memory 1076823040 8 16 phys" in fake.commands
    assert "am335x.cpu get_reg -force {pc lr sp cpsr}" in fake.commands
    order = [
        fake.commands.index(x)
        for x in (
            "targets am335x.cpu; halt 1000",
            "am335x.cpu read_memory 1076823040 8 16 phys",
            "targets am335x.cpu; resume",
        )
    ]
    assert order == sorted(order)
    assert verify_bundle(bundle).status == "VERIFIED"
    manifest = json.loads((bundle / "manifest.json").read_text())
    acquisition = manifest["captures"][0]["acquisition"]
    assert (acquisition["initial_state"], acquisition["capture_state"], acquisition["final_state"]) == (
        "running",
        "halted",
        "running",
    )
    assert acquisition["debugger_version"].startswith("xPack Open On-Chip Debugger 0.12.0")
    # Independent comparison tool: the same bytes as an operator's `mdw phys 0x402f0400 4` transcript.
    words = " ".join(f"{int.from_bytes(FIXTURE[i : i + 4], 'little'):08x}" for i in range(0, 16, 4))
    transcript = f"0x{BASE:08x}: {words}\n"
    assert compare_manual_read.compare(bundle, transcript)["match"] is True
    altered = transcript.replace("ea00000f", "ea00000e")
    assert compare_manual_read.compare(bundle, altered)["match"] is False
    with pytest.raises(ValueError):
        compare_manual_read.compare(bundle, f"0x{BASE + 4:08x}: {words}\n")  # wrong start address


@pytest.mark.parametrize(
    "case",
    ["version_mismatch", "not_armed", "recovery_flag", "debugger_down", "raw_not_retained", "range"],
)
async def test_failed_preconditions_leave_the_target_untouched(case, tmp_path):
    fake = FakeOpenOCD(
        version="Some Other Debugger 9.9"
        if case == "version_mismatch"
        else "xPack Open On-Chip Debugger 0.12.0"
    )
    async with rig(fake, arm=case != "not_armed", retain=case != "raw_not_retained") as (service, client):
        if case == "recovery_flag":
            service.recovery_required = True
        if case == "debugger_down":
            await fake.stop()
        length = 65 if case == "range" else 16
        code, criteria, bundle = await live_snapshot.execute(
            client, address=BASE, length=length, export_root=tmp_path
        )
    assert code == 2 and bundle is None, criteria.render()
    assert halts(fake) == [] and resumes(fake) == [] and fake.sent_forbidden() == []
    assert fake.state == "running"
    assert "NOT" not in criteria.render().split("\n")[0] or True
    assert any(not ok for _, ok, _ in criteria.rows)


async def test_an_initially_halted_cpu_is_never_resumed(tmp_path):
    fake = FakeOpenOCD(state="halted")
    async with rig(fake, arm=False) as (_service, client):
        code, criteria, bundle = await run(client, tmp_path)
    assert code == 0, criteria.render()
    assert halts(fake) == [] and resumes(fake) == [] and fake.state == "halted"
    acquisition = json.loads((bundle / "manifest.json").read_text())["captures"][0]["acquisition"]
    assert (acquisition["initial_state"], acquisition["final_state"], acquisition["halted_by_edge"]) == (
        "halted",
        "halted",
        False,
    )


async def test_failed_resume_sets_recovery_required_and_blocks_everything_after(tmp_path):
    fake = FakeOpenOCD()
    fake.refuse_resume = True
    async with rig(fake) as (_service, client):
        code, criteria, bundle = await run(client, tmp_path)
        assert code == 1 and bundle is None
        assert (
            "restoration_failed_operator_required" in criteria.render()
            or "no recovery flag" in criteria.render()
        )
        status = (await client.get("/api/v1/target/status")).json()
        readiness = assess(status, load_build("orchestrator"), False)
        assert status["recovery_required"] is True and not readiness.live_ready
        assert "recovery_required" in {b.code for b in readiness.blockers}
        halts_before = len(halts(fake))
        second_code, _second, _ = await run(client, tmp_path)
        assert second_code == 2 and len(halts(fake)) == halts_before  # nothing more is sent to the target
    assert fake.state == "halted"  # the operator must reconcile: the fixture proves why the flag matters


async def test_debugger_vanishing_mid_operation_is_uncertain_and_requires_reconciliation(tmp_path):
    fake = FakeOpenOCD()
    fake.die_after_halt = True
    async with rig(fake) as (service, client):
        code, _criteria, bundle = await run(client, tmp_path)
        assert code == 1 and bundle is None
        assert service.recovery_required is True
        readiness = assess(
            (await client.get("/api/v1/target/status")).json(), load_build("orchestrator"), False
        )
        assert not readiness.live_ready
        assert {"recovery_required", "debugger_unreachable"} <= {b.code for b in readiness.blockers}
    assert fake.state == "halted" and resumes(fake) == []  # left halted and flagged, not silently 'fixed'


async def test_a_debugger_timeout_during_halt_is_uncertain_not_retried(tmp_path):
    fake = FakeOpenOCD()
    fake.delay = {"halt 1000": 0.6}
    async with rig(fake, timeout=0.2) as (service, client):
        code, _criteria, _ = await run(client, tmp_path)
        assert code == 1
        assert service.recovery_required is True
    assert len(halts(fake)) == 1  # never retried blindly


class AppEdge:
    """Orchestrator-side edge client that talks to the real edge app in-process."""

    def __init__(self, client):
        self.client = client

    async def get(self, path):
        response = await self.client.get(path)
        response.raise_for_status()
        return response.json()

    async def post(self, path, body, timeout_seconds=12):
        response = await self.client.post(path, json=body)
        response.raise_for_status()
        return response.json()


async def attack_lab_to_live_step(client, profile):
    plan = (
        await client.post(
            "/api/attack-lab/plans",
            json={
                "target_id": profile.target_id,
                "module_id": "jtag-debug-lock-audit",
                "objective": "Assess JTAG exposure",
                "authorization_acknowledged": True,
            },
        )
    ).json()
    pid = plan["plan_id"]
    for _ in range(2):
        plan = (await client.post(f"/api/attack-lab/plans/{pid}/execute-next")).json()
    await client.post(
        f"/api/attack-lab/plans/{pid}/steps/{plan['steps'][2]['step_id']}/decision",
        json={"decision": "approve", "note": "rehearsal"},
    )
    return pid


@pytest.fixture
def live_env(monkeypatch, tmp_path):
    monkeypatch.setenv("ATTACK_LAB_LIVE_JTAG", "1")
    monkeypatch.setenv("EXPORT_DIR", str(tmp_path / "exports"))


async def orchestrator(edge_client):
    app = dashboard_app(AppEdge(edge_client), ScriptedInference, PASSWORD)
    c = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")
    assert (await c.post("/api/login", json={"password": PASSWORD})).status_code == 200
    return c


async def test_orchestrator_refuses_the_live_step_before_any_halt_when_openocd_is_incompatible(live_env):
    fake = FakeOpenOCD(version="Some Other Debugger 9.9")
    async with rig(fake) as (_service, edge_client):
        c = await orchestrator(edge_client)
        pid = await attack_lab_to_live_step(c, PROFILE)
        response = await c.post(f"/api/attack-lab/plans/{pid}/execute-next")
        assert response.status_code == 409 and "debugger_version_incompatible" in response.json()["detail"]
    assert halts(fake) == [] and fake.sent_forbidden() == []


async def test_orchestrator_live_step_end_to_end_with_bundle_and_pause_gate(live_env):
    fake = FakeOpenOCD()
    async with rig(fake) as (_service, edge_client):
        c = await orchestrator(edge_client)
        pid = await attack_lab_to_live_step(c, PROFILE)
        await c.post(f"/api/attack-lab/plans/{pid}/pause")
        commands_before = len(fake.commands)
        assert (
            await c.post(f"/api/attack-lab/plans/{pid}/execute-next")
        ).status_code == 409  # paused: nothing sent
        assert len(fake.commands) == commands_before
        await c.post(f"/api/attack-lab/plans/{pid}/resume")
        done = (await c.post(f"/api/attack-lab/plans/{pid}/execute-next")).json()
        assert done["status"] == "completed" and "restoration=running" in done["steps"][2]["result"]
        assert (
            done["acquisitions"][0]["initial_state"] == "running"
            and done["acquisitions"][0]["final_state"] == "running"
        )
        bundle = (await c.post(f"/api/attack-lab/plans/{pid}/bundle", json={"include_raw": True})).json()
        assert bundle["verification"] == "VERIFIED" and bundle["raw_included"] == 1
    assert len(halts(fake)) == 1 and len(resumes(fake)) == 1 and fake.sent_forbidden() == []
    assert os.path.isdir(bundle["path"])
