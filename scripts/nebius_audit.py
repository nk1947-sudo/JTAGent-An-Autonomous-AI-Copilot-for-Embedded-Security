"""Opt-in full LangGraph audit using synthetic target evidence and Nebius inference."""

import argparse
import asyncio
import json
import sys
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from contracts.models import AuditRequest, RunState, TargetProfile
from edge.app import create_app
from edge.backends import MockBackend
from edge.service import EdgeService
from orchestrator.inference import NebiusInference
from orchestrator.workflow import Workflow


class LocalEdge:
    def __init__(self, service):
        key = "local-nebius-audit-key"
        self.client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=create_app(service, key)),
            base_url="http://edge",
            headers={"Authorization": "Bearer " + key},
        )

    async def post(self, path, body):
        response = await self.client.post(path, json=body)
        response.raise_for_status()
        return response.json()

    async def close(self):
        await self.client.aclose()


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--allow-paid-inference", action="store_true")
    args = parser.parse_args()
    if not args.allow_paid_inference:
        parser.error("--allow-paid-inference is required; this command calls the real provider")

    profile = TargetProfile.model_validate_json(Path("config/demo.json").read_text())
    service = EdgeService(MockBackend("demo"), profile, arm_snapshots=True)
    provider = NebiusInference()
    edge = LocalEdge(service)
    run = RunState(
        target_backend="mock",
        inference_backend=provider.mode,
        model_id=provider.model_id,
        profile=profile,
        request=AuditRequest(
            target_id=profile.target_id,
            purpose="bootloader inspection",
            region_names=["demo-code", "demo-log"],
            byte_budget=1024,
            collection_limit=4,
            iteration_limit=2,
            deadline_seconds=120,
        ),
    )
    try:
        await Workflow(run, edge, provider, asyncio.Event()).execute()
    finally:
        await edge.close()

    print(
        json.dumps(
            {
                "status": run.status,
                "termination_reason": run.termination_reason,
                "model": run.model_id,
                "captures": len(run.captures),
                "register_snapshots": len(run.registers),
                "findings": [
                    {
                        "category": finding.category,
                        "status": finding.status,
                        "confidence": finding.confidence,
                        "evidence_count": len(finding.evidence_ids),
                    }
                    for finding in run.findings
                ],
                "provider_usage": run.provider_usage,
                "nodes": [event["node"] for event in run.events],
                "errors": run.errors,
            }
        )
    )
    if run.status != "completed" or not run.captures:
        raise SystemExit(1)


if __name__ == "__main__":
    asyncio.run(main())
