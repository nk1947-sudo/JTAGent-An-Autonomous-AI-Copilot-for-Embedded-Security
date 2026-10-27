"""Compare scripted and installed local inference on fixed synthetic mock captures."""

import argparse
import asyncio
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from contracts.models import TargetProfile
from edge.backends import MockBackend
from edge.service import EdgeService
from orchestrator.inference import InferenceError, OllamaInference, ScriptedInference
from orchestrator.workflow import Workflow
from tests.test_workflow import LocalEdge, run_state


async def evaluate(profile, variant, provider):
    service = EdgeService(MockBackend(variant), profile, arm_snapshots=True)
    run = run_state(profile, byte_budget=512, collection_limit=2, iteration_limit=1, deadline_seconds=120)
    run.inference_backend = provider.mode
    run.model_id = provider.model_id
    started = time.perf_counter()
    await Workflow(run, LocalEdge(service), provider, asyncio.Event()).execute()
    return {
        "fixture": variant,
        "backend": provider.mode,
        "model": run.model_id,
        "status": run.status,
        "termination_reason": run.termination_reason,
        "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
        "analysis_call_latencies_ms": [round(value, 1) for value in run.inference_latencies_ms],
        "adapter_request_latencies_ms": [round(value, 1) for value in provider.latencies],
        "provider_usage": provider.usage,
        "schema_valid": True if run.termination_reason == "completed" and run.plan else None,
        "evidence_reference_valid": (
            all(f.status != "rejected" for f in run.findings) if run.findings else None
        ),
        "findings": {
            status: sum(f.status == status for f in run.findings)
            for status in ("observed", "suspected", "inconclusive", "rejected", "validated")
        },
        "captures": len(run.captures),
        "out_of_scope_capture": any(
            not any(
                region.approved
                and region.address_space == capture.address_space
                and region.start <= capture.base_address
                and capture.base_address + capture.returned_length <= region.end
                for region in profile.regions
            )
            for capture in run.captures
        ),
        "errors": run.errors,
    }


def local_passed(rows):
    return len(rows) == 2 and all(
        row["status"] == "completed"
        and row["schema_valid"] is True
        and row["captures"] > 0
        and not row["out_of_scope_capture"]
        and row["evidence_reference_valid"] is not False
        for row in rows
    )


async def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--local", action="store_true", help="Call the installed loopback Ollama model")
    parser.add_argument("--model", default="qwen3.5:4b", help="Installed Ollama tag; no download")
    args = parser.parse_args()
    profile = TargetProfile.model_validate_json((ROOT / "config/demo.json").read_text())
    result = {"fixtures": ["demo", "clean"], "scripted": [], "local": []}
    for variant in result["fixtures"]:
        result["scripted"].append(await evaluate(profile, variant, ScriptedInference()))
    if args.local:
        os.environ["OLLAMA_MODEL"] = args.model
        provider = OllamaInference()
        result["ollama_config"] = {
            "origin": provider.base_url,
            "model": provider.model_id,
            "num_ctx": provider.context_limit,
            "num_predict": provider.output_limit,
            "timeout_seconds": provider.timeout_seconds,
        }
        try:
            result["ollama_preflight"] = await provider.preflight()
            result["ollama_version"] = (await provider._request("GET", "/api/version")).get("version")
            for variant in result["fixtures"]:
                result["local"].append(await evaluate(profile, variant, OllamaInference()))
        except InferenceError as exc:
            result["local_error"] = str(exc)
    print(json.dumps(result, indent=2))
    return 2 if args.local and (result.get("local_error") or not local_passed(result["local"])) else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
