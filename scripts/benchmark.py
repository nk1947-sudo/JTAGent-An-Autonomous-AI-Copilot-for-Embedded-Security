"""Small offline ASGI benchmark; no provider or physical target; prints measured samples."""

import asyncio
import json
import platform
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from contracts.models import AuditRequest, RunState, TargetProfile
from edge.backends import MockBackend
from edge.service import EdgeService
from orchestrator.inference import ScriptedInference
from orchestrator.workflow import Workflow
from tests.test_workflow import LocalEdge


def samples(values):
    ordered = sorted(values)
    return {
        "n": len(values),
        "p50_ms": round(statistics.median(values), 3),
        "p95_ms": round(ordered[max(0, int(0.95 * len(ordered)) - 1)], 3),
    }


async def main():
    tools, inference, total = [], [], []
    profile = TargetProfile.model_validate_json(Path("config/demo.json").read_text())
    for _ in range(20):
        service = EdgeService(MockBackend(), profile, arm_snapshots=True)
        edge = LocalEdge(service)
        run = RunState(
            target_backend="mock",
            inference_backend="scripted",
            model_id="scripted-demo-v1",
            profile=profile,
            request=AuditRequest(
                target_id=profile.target_id,
                purpose="bootloader inspection",
                region_names=["demo-code", "demo-log"],
            ),
        )
        await Workflow(run, edge, ScriptedInference(), asyncio.Event()).execute()
        assert run.status == "completed"
        tools.extend(run.tool_latencies_ms)
        inference.extend(run.inference_latencies_ms)
        total.append(run.elapsed_ms)
        await edge.client.aclose()
    print(
        json.dumps(
            {
                "environment": platform.platform(),
                "python": platform.python_version(),
                "transport": "in-process ASGI; browser test separately uses loopback HTTP",
                "mode": "mock + scripted; not hardware or paid inference performance",
                "edge_tools": samples(tools),
                "scripted_analysis": samples(inference),
                "end_to_end": samples(total),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    asyncio.run(main())
