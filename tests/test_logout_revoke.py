"""Logout revokes only its edge sessions and preserves uncertain outcomes."""

import asyncio
import time

import httpx

from contracts.models import SessionRequest, TargetRequest
from edge.app import create_app as edge_app
from edge.backends import BackendError
from orchestrator.app import create_app
from orchestrator.inference import ScriptedInference
from tests.conftest import session_body
from tests.test_workflow import LocalEdge, run_state

PASSWORD = "operator-test-password"


async def sign_in(client):
    assert (await client.post("/api/login", json={"password": PASSWORD})).status_code == 200


async def test_edge_revocation_blocks_reuse_and_restores_owned_lease(service, profile):
    current = service.session(SessionRequest(**session_body(profile)))
    request = TargetRequest(target_id=profile.target_id, session_id=current.session_id)
    assert (await service.execute(request, "halt")).success
    assert service.backend.state == "halted" and service.lease

    edge = LocalEdge(service)
    unauthenticated = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=edge_app(service, "test-edge-key-123456")),
        base_url="http://edge",
    )
    async with unauthenticated:
        assert (await unauthenticated.delete(f"/api/v1/sessions/{current.session_id}")).status_code == 401
    assert (await edge.delete(f"/api/v1/sessions/{current.session_id}")) == {"revoked": True}
    assert service.backend.state == "running" and service.lease is None
    assert (await edge.delete(f"/api/v1/sessions/{current.session_id}")) == {"revoked": False}
    assert current.session_id not in service.sessions
    assert service.ledger[(current.session_id, request.request_id)][1].success
    response = await edge.client.post("/api/v1/target/resume", json=request.model_dump())
    assert response.status_code == 403 and response.json()["detail"] == "session_revoked"
    response = await edge.client.post("/api/v1/target/halt", json=request.model_dump())
    assert response.status_code == 403 and response.json()["detail"] == "session_revoked"


async def test_failed_lease_restoration_requires_reconciliation(service, profile):
    current = service.session(SessionRequest(**session_body(profile)))
    request = TargetRequest(target_id=profile.target_id, session_id=current.session_id)
    assert (await service.execute(request, "halt")).success
    original_control = service.backend.control

    async def fail_resume(operation):
        if operation == "resume":
            raise BackendError("resume_disconnected", True)
        return await original_control(operation)

    service.backend.control = fail_resume
    edge = LocalEdge(service)
    response = await edge.client.delete(f"/api/v1/sessions/{current.session_id}")
    assert response.status_code == 503
    assert response.json()["detail"] == "revocation_restoration_failed_operator_required"
    assert current.session_id not in service.sessions
    assert service.recovery_required and service.lease
    assert service.backend.state == "halted"


async def test_logout_cancels_owned_run_and_revokes_only_its_sessions(service, profile):
    entered = asyncio.Event()

    class WaitingInference(ScriptedInference):
        async def plan(self, *args):
            entered.set()
            await asyncio.Event().wait()

    app = create_app(LocalEdge(service), WaitingInference, PASSWORD)
    transport = httpx.ASGITransport(app=app)
    async with (
        httpx.AsyncClient(transport=transport, base_url="http://test") as first,
        httpx.AsyncClient(transport=transport, base_url="http://test") as second,
    ):
        await sign_in(first)
        await sign_in(second)
        created = await first.post("/api/runs", json=run_state(profile).request.model_dump())
        assert created.status_code == 200
        run_id = created.json()["run_id"]
        await asyncio.wait_for(entered.wait(), 2)
        owned_session = next(iter(service.sessions))
        unrelated = service.session(SessionRequest(**session_body(profile))).session_id

        logout = await first.post("/api/logout")
        assert logout.status_code == 200
        assert logout.json() == {"authenticated": False, "edge_sessions_revoked": True}
        assert app.state.runs[run_id].status == "cancelled"
        assert owned_session not in service.sessions and unrelated in service.sessions
        assert (await first.get("/api/runs")).status_code == 401
        assert (await second.get("/api/runs")).status_code == 200


async def test_logout_waits_for_session_creation_before_revoking(service, profile):
    creating = asyncio.Event()
    release = asyncio.Event()

    class SlowEdge(LocalEdge):
        async def post(self, path, body, timeout_seconds=12):
            if path == "/api/v1/sessions":
                creating.set()
                await release.wait()
            return await super().post(path, body, timeout_seconds)

    app = create_app(SlowEdge(service), ScriptedInference, PASSWORD)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        await sign_in(client)
        started = await client.post("/api/runs", json=run_state(profile).request.model_dump())
        assert started.status_code == 200
        await asyncio.wait_for(creating.wait(), 2)
        logging_out = asyncio.create_task(client.post("/api/logout"))
        await asyncio.sleep(0)
        release.set()
        response = await logging_out
        assert response.status_code == 200
        assert response.json()["edge_sessions_revoked"]
        assert not service.sessions


async def test_logout_reports_edge_revocation_failure_after_local_signout(service, profile):
    class FailingDelete(LocalEdge):
        async def delete(self, path):
            raise RuntimeError("edge unreachable")

    app = create_app(FailingDelete(service), ScriptedInference, PASSWORD)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        await sign_in(client)
        started = await client.post("/api/runs", json=run_state(profile).request.model_dump())
        await app.state.tasks[started.json()["run_id"]]
        response = await client.post("/api/logout")
        assert response.status_code == 503
        assert response.json() == {"authenticated": False, "edge_sessions_revoked": False}
        assert (await client.get("/api/runs")).status_code == 401
        assert service.sessions  # Edge TTL still applies when it is unreachable.


async def test_logout_bounds_total_wait_for_unresponsive_edge(service, profile):
    class HangingDelete(LocalEdge):
        calls = 0

        async def delete(self, path):
            self.calls += 1
            await asyncio.Event().wait()

    edge = HangingDelete(service)
    app = create_app(edge, ScriptedInference, PASSWORD)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        await sign_in(client)
        for _ in range(2):
            started = await client.post("/api/runs", json=run_state(profile).request.model_dump())
            assert started.status_code == 200
            await app.state.tasks[started.json()["run_id"]]

        response = await asyncio.wait_for(client.post("/api/logout"), timeout=7)
        assert response.status_code == 503
        assert response.json() == {"authenticated": False, "edge_sessions_revoked": False}
        assert edge.calls == 2
        assert (await client.get("/api/runs")).status_code == 401


async def test_logout_does_not_trust_edge_clock_for_expiry(service, profile):
    class SkewedEdge(LocalEdge):
        async def post(self, path, body, timeout_seconds=12):
            result = await super().post(path, body, timeout_seconds)
            if path == "/api/v1/sessions":
                result["expires_at"] = time.time() - 1000
            return result

    app = create_app(SkewedEdge(service), ScriptedInference, PASSWORD)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        await sign_in(client)
        started = await client.post("/api/runs", json=run_state(profile).request.model_dump())
        await app.state.tasks[started.json()["run_id"]]
        assert service.sessions
        response = await client.post("/api/logout")
        assert response.status_code == 200 and response.json()["edge_sessions_revoked"]
        assert not service.sessions
