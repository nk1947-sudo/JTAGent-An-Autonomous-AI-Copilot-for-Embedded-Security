"""Status v2, build identity and fail-closed readiness. Offline fixtures; no hardware is contacted."""

import copy
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from contracts.build import load_build, source_drift, source_fingerprint
from contracts.models import EdgeStatus
from contracts.status import assess, unreachable
from edge.backends import BackendError
from edge.service import EdgeService
from orchestrator.app import create_app as dashboard_app
from orchestrator.inference import ScriptedInference
from tests.test_workflow import LocalEdge

PASSWORD = "operator-test-password"


@pytest.fixture
def build():
    return load_build("orchestrator")


async def v2(service, **patch):
    """A real v2 status from the edge service, optionally altered to simulate other edges."""
    raw = await service.report()
    for dotted, value in patch.items():
        target = raw
        *parents, leaf = dotted.split(".")
        for key in parents:
            target = target[key]
        target[leaf] = value
    return raw


def live(raw):
    raw["target_backend"] = "openocd"
    raw["debugger"].update(applicable=True, reachable=True, version_ok=True, version="OpenOCD 0.12.0")
    return raw


async def test_current_edge_status_is_versioned_and_carries_loaded_build(service, build):
    raw = await service.report()
    status = EdgeStatus.model_validate(raw)
    assert (status.schema_name, status.schema_version) == ("jtagent.edge.status", 2)
    assert status.build.component == "edge" and status.build.source_fingerprint == build.source_fingerprint
    assert status.build.build_id.endswith(status.build.source_fingerprint[:12])
    assert status.application == "ok" and status.snapshots_armed and not status.retains_raw_locally
    assert status.debugger.applicable is False  # mock: the debugger layer is not applicable
    readiness = assess(raw, build, drift=False)
    assert readiness.compatible and readiness.run_ready and not readiness.live_ready
    assert "not_live_backend" in {b.code for b in readiness.blockers}


async def test_build_identity_is_cached_and_drift_is_separate(build, tmp_path):
    assert load_build("orchestrator") is build  # computed once per process
    assert source_drift(build) is False
    (tmp_path / "edge").mkdir()
    (tmp_path / "edge" / "a.py").write_text("x = 1\n")
    first = source_fingerprint(tmp_path)
    (tmp_path / "edge" / "a.py").write_text("x = 2\n")
    assert source_fingerprint(tmp_path) != first  # a changed file changes a fresh fingerprint only


@pytest.mark.parametrize(
    "mutate,code",
    [
        (
            lambda r: {k: r[k] for k in ("state", "target_backend", "generation", "capabilities")},
            "legacy_flat_schema",
        ),
        (lambda r: {**r, "schema_version": 3}, "unsupported_schema_version"),
        (lambda r: {**r, "schema_version": True}, "unsupported_schema_version"),
        (lambda r: {**r, "schema_name": "other"}, "malformed_status"),
        (lambda r: {k: v for k, v in r.items() if k != "target"}, "malformed_status"),
        (lambda r: {**r, "recovery_required": "no"}, "malformed_status"),
        (lambda r: {**r, "observed_at": "yesterday"}, "malformed_status"),
        (lambda r: ["not", "an", "object"], "malformed_status"),
        (lambda r: {"unexpected": True}, "malformed_status"),
    ],
)
async def test_old_or_malformed_status_is_incompatible_never_ready(service, build, mutate, code):
    readiness = assess(mutate(await service.report()), build, drift=False)
    assert readiness.edge == "incompatible" and not readiness.compatible
    assert not readiness.run_ready and not readiness.live_ready
    assert code in {b.code for b in readiness.blockers}


async def test_live_readiness_requires_every_layer(service, build):
    ok = assess(live(await service.report()), build, drift=False)
    assert ok.live_ready and ok.run_ready and not ok.blockers

    def blockers(**patch):
        raw = live(copy.deepcopy(patch.pop("base")))
        for dotted, value in patch.items():
            target = raw
            *parents, leaf = dotted.split(".")
            for key in parents:
                target = target[key]
            target[leaf] = value
        result = assess(raw, build, drift=False)
        assert not result.live_ready
        return {b.code for b in result.blockers}

    base = await service.report()
    assert "debugger_unreachable" in blockers(base=base, **{"debugger.reachable": False})
    assert "debugger_unknown" in blockers(base=base, **{"debugger.reachable": None})
    assert "debugger_version_incompatible" in blockers(base=base, **{"debugger.version_ok": False})
    assert "debugger_version_incompatible" in blockers(base=base, **{"debugger.version_ok": None})
    assert "target_communication_failed" in blockers(base=base, **{"target.communication": "failed"})
    assert "target_communication_unknown" in blockers(base=base, **{"target.communication": "unknown"})
    assert "execution_state_unknown" in blockers(base=base, **{"target.execution_state": None})
    assert "execution_state_unknown" in blockers(base=base, **{"target.execution_state": "reset"})
    assert "recovery_required" in blockers(base=base, recovery_required=True)
    assert "snapshots_not_armed" in blockers(base=base, snapshots_armed=False)


async def test_stale_status_blocks_and_missing_edge_never_reads_ready(service, build):
    raw = await service.report()
    old = datetime.now(UTC) + timedelta(seconds=120)
    stale = assess(raw, build, drift=False, received_at=old)
    assert stale.stale and not stale.run_ready and "status_stale" in {b.code for b in stale.blockers}
    gone = unreachable(build, False, "ConnectError")
    assert gone.edge == "unreachable" and not gone.run_ready and not gone.live_ready
    assert gone.blockers[0].code == "edge_unreachable"


async def test_edge_service_report_survives_debugger_outage(profile):
    class Down:
        mode, generation, version_prefix, version = "openocd", 0, "OpenOCD 0.12.", None

        async def status(self):
            raise BackendError("rpc_unavailable")

    raw = await EdgeService(Down(), profile).report()
    status = EdgeStatus.model_validate(raw)
    assert status.debugger.reachable is False and status.target.communication == "unknown"
    assert status.debugger.error_code == "rpc_unavailable"
    assert not status.live_operations.allowed and "debugger_unreachable" in status.live_operations.blockers


class StatusEdge(LocalEdge):
    """Edge double whose status is replaced. Every other path is the real local edge."""

    def __init__(self, service, status=None, error=None):
        super().__init__(service)
        self.status, self.error, self.posts = status, error, []

    async def get(self, path):
        if path == "/api/v1/target/status":
            if self.error:
                raise self.error
            return self.status
        return await super().get(path)

    async def post(self, path, body, timeout_seconds=12):
        self.posts.append(path)
        return await super().post(path, body, timeout_seconds)


async def signed_in(app):
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")
    assert (await client.post("/api/login", json={"password": PASSWORD})).status_code == 200
    return client


AUDIT = {
    "target_id": "demo-armv7",
    "purpose": "bootloader inspection",
    "region_names": ["demo-code", "demo-log"],
}


async def test_flat_legacy_edge_is_visible_and_blocks_audits_server_side(service, profile):
    legacy = {
        "state": "running",
        "target_backend": "openocd",
        "generation": 0,
        "capabilities": [],
        "recovery_required": False,
    }
    edge = StatusEdge(service, legacy)
    client = await signed_in(dashboard_app(edge, ScriptedInference, PASSWORD))
    config = (await client.get("/api/config")).json()
    assert config["readiness"]["edge"] == "incompatible"
    assert config["readiness"]["blockers"][0]["code"] == "legacy_flat_schema"
    tiles = {d["id"]: d for d in config["dependencies"]}
    assert tiles["edge"]["status"] == "degraded" and tiles["operations"]["status"] != "ready"
    blocked = await client.post("/api/runs", json={**AUDIT, "target_id": profile.target_id})
    assert blocked.status_code == 409 and "legacy_flat_schema" in blocked.json()["detail"]
    assert not any("snapshots" in p or "sessions" in p for p in edge.posts)


async def test_unreachable_edge_degrades_config_instead_of_failing(service):
    edge = StatusEdge(service, error=httpx.ConnectError("down"))
    client = await signed_in(dashboard_app(edge, ScriptedInference, PASSWORD))
    response = await client.get("/api/config")
    assert response.status_code == 200
    body = response.json()
    assert body["readiness"]["edge"] == "unreachable" and body["profile"] is None
    assert body["target"]["state"] is None  # unknown, never assumed
    assert (await client.post("/api/runs", json=AUDIT)).status_code == 409


async def test_recovery_required_blocks_audit_start(service, profile):
    service.recovery_required = True
    client = await signed_in(dashboard_app(LocalEdge(service), ScriptedInference, PASSWORD))
    blocked = await client.post("/api/runs", json={**AUDIT, "target_id": profile.target_id})
    assert blocked.status_code == 409 and "recovery_required" in blocked.json()["detail"]
    assert (await client.get("/api/readiness")).json()["recovery_required"] is True


async def test_current_mock_edge_still_runs_audits(service, profile):
    client = await signed_in(dashboard_app(LocalEdge(service), ScriptedInference, PASSWORD))
    started = await client.post("/api/runs", json={**AUDIT, "target_id": profile.target_id})
    assert started.status_code == 200, started.text
    readiness = (await client.get("/api/readiness")).json()
    assert (
        readiness["compatible"] and readiness["run_ready"] and readiness["edge_build"]["component"] == "edge"
    )
    health = (await client.get("/healthz")).json()
    assert health["build"]["component"] == "orchestrator" and health["build"]["build_id"]


async def test_live_step_is_rejected_server_side_when_debugger_is_down(service, profile, monkeypatch):
    monkeypatch.setenv("ATTACK_LAB_LIVE_JTAG", "1")
    raw = live(await service.report())
    raw["debugger"]["reachable"] = False
    edge = StatusEdge(service, raw)
    client = await signed_in(dashboard_app(edge, ScriptedInference, PASSWORD))
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
    for _ in range(2):
        plan = (await client.post(f"/api/attack-lab/plans/{plan['plan_id']}/execute-next")).json()
    await client.post(
        f"/api/attack-lab/plans/{plan['plan_id']}/steps/{plan['steps'][2]['step_id']}/decision",
        json={"decision": "approve", "note": "test"},
    )
    posts_before = len(edge.posts)
    response = await client.post(f"/api/attack-lab/plans/{plan['plan_id']}/execute-next")
    assert response.status_code == 409
    assert (
        "debugger_unreachable" in response.json()["detail"]
        and "Hardware operation blocked" in response.json()["detail"]
    )
    assert len(edge.posts) == posts_before  # no session or snapshot was requested
    current = (await client.get(f"/api/attack-lab/plans/{plan['plan_id']}")).json()
    assert current["steps"][2]["status"] == "approved" and not current["captures"]  # retry stays possible


async def test_workflow_records_acquisition_metadata(service, profile):
    import asyncio

    from orchestrator.workflow import Workflow
    from tests.test_workflow import run_state

    run = run_state(profile)
    await Workflow(run, LocalEdge(service), ScriptedInference(), asyncio.Event(), "test-build").execute()
    assert len(run.acquisitions) == len(run.captures) == 2
    acquisition = run.acquisitions[0]
    assert acquisition.evidence_id == run.captures[0].evidence_id
    assert acquisition.register_evidence_id == run.registers[0].evidence_id
    assert acquisition.initial_state == "running" and acquisition.final_state == "running"
    assert (
        acquisition.halted_by_edge
        and acquisition.restoration == "running"
        and not acquisition.recovery_required
    )
    assert acquisition.orchestrator_build_id == "test-build" and acquisition.edge_build_id
