"""Completed local runs preserve the checked model identity in exports."""

import asyncio

from orchestrator.inference import ScriptedInference
from orchestrator.report import markdown, report_data
from orchestrator.workflow import Workflow
from tests.test_workflow import LocalEdge, run_state


async def test_local_model_digest_reaches_report(service, profile):
    class CheckedLocal(ScriptedInference):
        mode, model_id, model_digest = "ollama", "qwen3.5:4b", "a" * 64

    run = run_state(profile)
    run.inference_backend = "ollama"
    run.model_id = "qwen3.5:4b"
    await Workflow(run, LocalEdge(service), CheckedLocal(), asyncio.Event()).execute()

    identity = "qwen3.5:4b@sha256:" + "a" * 64
    assert run.status == "completed" and run.model_id == identity
    assert report_data(run)["model_id"] == identity
    assert identity in markdown(run)
