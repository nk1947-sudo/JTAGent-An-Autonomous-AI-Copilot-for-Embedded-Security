"""Nebius must not receive live-target data without an explicit operator opt-in."""

import httpx
import pytest

from contracts.models import (
    AttackPlan,
    AttackRecommendationSelection,
    EvidenceBundle,
    Finding,
    MemoryReadResult,
    ReadProposal,
)
from orchestrator.app import create_app
from tests.test_workflow import LocalEdge, run_state


class NebiusProbe:
    mode = "nebius"
    model_id = "nvidia/test-model"

    def __init__(self):
        self.calls = []
        self.usage = []

    async def plan(self, profile, request):
        self.calls.append("plan")
        return [ReadProposal(address=0, length=16, reason="test")]

    async def recommend_attacks(self, *args):
        self.calls.append("recommend")
        raise AssertionError("provider method should be blocked")

    async def debugger_assist(self, *args):
        self.calls.append("debugger")
        raise AssertionError("provider method should be blocked")


class LiveStatusEdge(LocalEdge):
    """Mock edge data labeled OpenOCD to test guards without contacting hardware."""

    async def get(self, path):
        result = await super().get(path)
        if path == "/api/v1/target/status":
            result["target_backend"] = "openocd"
            result["debugger"].update(applicable=True, reachable=True, version_ok=True)
        return result


def live_capture(profile, evidence_id="live-evidence-fixture", source_mode="openocd"):
    region = next(region for region in profile.regions if region.approved)
    evidence = EvidenceBundle(
        evidence_id=evidence_id,
        base_address=region.start,
        length=16,
        content_hash="a" * 64,
        source_mode=source_mode,
        provenance="synthetic test fixture; no hardware contacted",
        endianness=profile.endianness,
        instruction_mode=region.instruction_mode,
        settings_source="test fixture",
        decoder="fixture",
    )
    return MemoryReadResult(
        requested_length=16,
        returned_length=16,
        base_address=region.start,
        address_space=region.address_space,
        evidence_id=evidence_id,
        content_hash="a" * 64,
        source_mode=source_mode,
        target_state="running",
        generation=0,
        partial=False,
        consistency="synthetic test fixture",
        evidence=evidence,
    )


def make_client(app):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


@pytest.mark.parametrize("route", ["audit", "recommendation", "debugger"])
async def test_live_target_nebius_calls_are_denied_by_default(service, profile, monkeypatch, route):
    monkeypatch.delenv("NEBIUS_LIVE_EVIDENCE_ENABLED", raising=False)
    provider = NebiusProbe()
    app = create_app(LiveStatusEdge(service), lambda: provider, "operator-test-password")
    async with make_client(app) as client:
        assert (
            await client.post("/api/login", json={"password": "operator-test-password"})
        ).status_code == 200
        if route == "audit":
            response = await client.post("/api/runs", json=run_state(profile).request.model_dump())
        elif route == "recommendation":
            response = await client.post(
                "/api/attack-lab/recommendations",
                json={"target_id": profile.target_id, "objective": "Review debug exposure"},
            )
        else:
            plan = AttackPlan(
                target_id=profile.target_id,
                module_id="jtag-debug-lock-audit",
                category="jtag",
                objective="Review debug exposure",
                risk="low",
                status="ready",
                execution_mode="evidence_review",
                authorization_acknowledged=True,
                steps=[],
                captures=[live_capture(profile)],
            )
            app.state.attack_plans[plan.plan_id] = plan
            response = await client.post(
                "/api/debugger/advice",
                json={"plan_id": plan.plan_id, "objective": "Review captured evidence"},
            )
        assert response.status_code == 403, response.text
        assert "NEBIUS_LIVE_EVIDENCE_ENABLED=1" in response.text
        assert provider.calls == []
        if route == "audit":
            assert app.state.runs == {}


@pytest.mark.parametrize("live", [False, True])
async def test_mock_nebius_and_explicit_live_opt_in_preserve_provider_path(
    service, profile, monkeypatch, live
):
    if live:
        monkeypatch.setenv("NEBIUS_LIVE_EVIDENCE_ENABLED", "1")
        edge = LiveStatusEdge(service)
    else:
        monkeypatch.delenv("NEBIUS_LIVE_EVIDENCE_ENABLED", raising=False)
        edge = LocalEdge(service)
    provider = NebiusProbe()
    app = create_app(edge, lambda: provider, "operator-test-password")
    async with make_client(app) as client:
        assert (
            await client.post("/api/login", json={"password": "operator-test-password"})
        ).status_code == 200
        response = await client.post("/api/runs", json=run_state(profile).request.model_dump())
        assert response.status_code == 200, response.text
        run = response.json()
        await app.state.tasks[run["run_id"]]
        assert provider.calls == ["plan"]
        assert app.state.runs[run["run_id"]].termination_reason == "invalid_proposal"
        assert not app.state.runs[run["run_id"]].captures


async def test_cached_live_nebius_recommendation_still_requires_current_approval(
    service, profile, monkeypatch
):
    monkeypatch.setenv("NEBIUS_LIVE_EVIDENCE_ENABLED", "1")
    provider = NebiusProbe()

    async def recommend(*args):
        provider.calls.append("recommend")
        return AttackRecommendationSelection(
            module_ids=["jtag-debug-lock-audit"], rationale="synthetic test recommendation"
        )

    provider.recommend_attacks = recommend
    app = create_app(LiveStatusEdge(service), lambda: provider, "operator-test-password")
    async with make_client(app) as client:
        assert (
            await client.post("/api/login", json={"password": "operator-test-password"})
        ).status_code == 200
        body = {"target_id": profile.target_id, "objective": "Review debug exposure"}
        first = await client.post("/api/attack-lab/recommendations", json=body)
        assert first.status_code == 200, first.text
        assert provider.calls == ["recommend"]

        monkeypatch.delenv("NEBIUS_LIVE_EVIDENCE_ENABLED")
        cached = await client.post("/api/attack-lab/recommendations", json=body)
        assert cached.status_code == 403, cached.text
        assert "NEBIUS_LIVE_EVIDENCE_ENABLED=1" in cached.text
        assert provider.calls == ["recommend"]


async def test_recommendation_cache_refreshes_when_run_evidence_and_findings_change(service, profile):
    class RecommendationProbe:
        mode = "scripted"
        model_id = "scripted-test-v1"

        def __init__(self):
            self.findings = []

        async def recommend_attacks(self, _profile, findings, _objective):
            self.findings.append([finding.title for finding in findings])
            return AttackRecommendationSelection(
                module_ids=["jtag-debug-lock-audit"], rationale="synthetic test recommendation"
            )

    provider = RecommendationProbe()
    app = create_app(LocalEdge(service), lambda: provider, "operator-test-password")
    run = run_state(profile)
    app.state.runs[run.run_id] = run
    run.captures.append(live_capture(profile, "mock-evidence-1", "mock"))
    async with make_client(app) as client:
        assert (
            await client.post("/api/login", json={"password": "operator-test-password"})
        ).status_code == 200
        body = {
            "target_id": profile.target_id,
            "run_id": run.run_id,
            "objective": "Review debug exposure",
        }
        first = await client.post("/api/attack-lab/recommendations", json=body)
        assert first.status_code == 200, first.text
        assert first.json()[0]["evidence_ids"] == ["mock-evidence-1"]
        assert provider.findings == [[]]

        run.captures.append(live_capture(profile, "mock-evidence-2", "mock"))
        run.findings.append(
            Finding(
                title="New synthetic observation",
                category="observation",
                severity="info",
                confidence="high",
                status="observed",
                evidence_ids=["mock-evidence-2"],
                addresses=[],
                explanation="Synthetic fixture changed after the first recommendation.",
                limitations=["Mock data only"],
                suggested_verification="None",
            )
        )
        refreshed = await client.post("/api/attack-lab/recommendations", json=body)
        assert refreshed.status_code == 200, refreshed.text
        assert refreshed.json()[0]["evidence_ids"] == ["mock-evidence-1", "mock-evidence-2"]
        assert provider.findings == [[], ["New synthetic observation"]]


async def test_recommendation_cache_snapshot_is_consistent_across_edge_await(service, profile):
    class RecommendationProbe:
        mode = "scripted"
        model_id = "scripted-test-v1"

        def __init__(self):
            self.findings = []

        async def recommend_attacks(self, _profile, findings, _objective):
            self.findings.append([finding.title for finding in findings])
            return AttackRecommendationSelection(
                module_ids=["jtag-debug-lock-audit"], rationale="synthetic test recommendation"
            )

    provider = RecommendationProbe()
    run = run_state(profile)
    run.captures.append(live_capture(profile, "mock-evidence-1", "mock"))

    class MutatingEdge(LocalEdge):
        async def get(self, path):
            result = await super().get(path)
            if path == "/api/v1/uart/status":
                run.captures.append(live_capture(profile, "mock-evidence-2", "mock"))
                run.findings.append(
                    Finding(
                        title="Observation added during edge await",
                        category="observation",
                        severity="info",
                        confidence="high",
                        status="observed",
                        evidence_ids=["mock-evidence-2"],
                        addresses=[],
                        explanation="Synthetic fixture changed during the request.",
                        limitations=["Mock data only"],
                        suggested_verification="None",
                    )
                )
            return result

    app = create_app(MutatingEdge(service), lambda: provider, "operator-test-password")
    app.state.runs[run.run_id] = run
    async with make_client(app) as client:
        assert (
            await client.post("/api/login", json={"password": "operator-test-password"})
        ).status_code == 200
        body = {
            "target_id": profile.target_id,
            "run_id": run.run_id,
            "objective": "Review debug exposure",
        }
        response = await client.post("/api/attack-lab/recommendations", json=body)
        assert response.status_code == 200, response.text
        assert response.json()[0]["evidence_ids"] == ["mock-evidence-1", "mock-evidence-2"]
        assert provider.findings == [["Observation added during edge await"]]


async def test_recommendation_cache_is_scoped_to_inference_identity(service, profile):
    class RecommendationProbe:
        def __init__(self, mode, model_id, module_id):
            self.mode = mode
            self.model_id = model_id
            self.module_id = module_id
            self.calls = 0

        async def recommend_attacks(self, _profile, _findings, _objective):
            self.calls += 1
            return AttackRecommendationSelection(module_ids=[self.module_id], rationale=self.model_id)

    first_provider = RecommendationProbe("scripted", "scripted-test-v1", "jtag-debug-lock-audit")
    second_provider = RecommendationProbe("ollama", "local-test-v2", "firmware-integrity-assessment")
    switched = False
    app = create_app(
        LocalEdge(service),
        lambda: second_provider if switched else first_provider,
        "operator-test-password",
    )
    run = run_state(profile)
    app.state.runs[run.run_id] = run
    async with make_client(app) as client:
        assert (
            await client.post("/api/login", json={"password": "operator-test-password"})
        ).status_code == 200
        body = {
            "target_id": profile.target_id,
            "run_id": run.run_id,
            "objective": "Review debug exposure",
        }
        first = await client.post("/api/attack-lab/recommendations", json=body)
        assert first.status_code == 200, first.text
        assert first.json()[0]["rationale"] == "scripted-test-v1"

        switched = True
        second = await client.post("/api/attack-lab/recommendations", json=body)
        assert second.status_code == 200, second.text
        assert second.json()[0]["rationale"] == "local-test-v2"
        assert first_provider.calls == 1
        assert second_provider.calls == 1
