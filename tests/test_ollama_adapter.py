"""The local adapter uses installed models and bounded typed responses."""

import json

import httpx
import pytest

from contracts.models import AuditRequest
from orchestrator.inference import InferenceError, OllamaInference, configured_inference

DIGEST = "a" * 64


async def test_local_planner_uses_schema_limits_and_reported_usage(profile, monkeypatch):
    monkeypatch.setenv("OLLAMA_MODEL", "qwen3.5:4b")
    monkeypatch.delenv("OLLAMA_BASE_URL", raising=False)
    seen = []

    def reply(request):
        seen.append(request)
        if request.url.path == "/api/tags":
            return httpx.Response(200, json={"models": [{"name": "qwen3.5:4b", "digest": DIGEST}]})
        body = json.loads(request.content)
        assert request.url.path == "/api/chat"
        assert body["model"] == "qwen3.5:4b" and body["stream"] is False
        assert body["think"] is False and body["format"]["type"] == "object"
        assert body["options"] == {"temperature": 0, "num_ctx": 8192, "num_predict": 1536}
        assert "tools" not in body and "Authorization" not in request.headers
        return httpx.Response(
            200,
            json={
                "model": "qwen3.5:4b",
                "done": True,
                "done_reason": "stop",
                "message": {
                    "content": json.dumps(
                        {
                            "address": 0x80000000,
                            "length": 16,
                            "address_space": "virtual",
                            "reason": "Synthetic scope",
                        }
                    )
                },
                "prompt_eval_count": 100,
                "eval_count": 25,
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(reply)) as client:
        provider = OllamaInference(client)
        request = AuditRequest(
            target_id=profile.target_id,
            purpose="bootloader inspection",
            region_names=["demo-code"],
        )
        proposals = await provider.plan(profile, request)
    assert proposals[0].address == 0x80000000 and proposals[0].length == 16
    assert provider.model_digest == DIGEST and provider.model_id == "qwen3.5:4b"
    assert provider.usage == [{"prompt_tokens": 100, "completion_tokens": 25, "total_tokens": 125}]
    assert len(provider.latencies) == len(seen) == 3


@pytest.mark.parametrize(
    "name,value",
    [
        ("OLLAMA_BASE_URL", "https://ollama.com"),
        ("OLLAMA_BASE_URL", "http://192.168.1.10:11434"),
        ("OLLAMA_BASE_URL", "http://127.0.0.1:11434/other"),
        ("OLLAMA_MODEL", ""),
        ("OLLAMA_NUM_CTX", "1024"),
        ("OLLAMA_NUM_PREDICT", "4096"),
        ("OLLAMA_TIMEOUT_SECONDS", "0"),
    ],
)
def test_local_configuration_is_bounded(monkeypatch, name, value):
    for setting in (
        "OLLAMA_BASE_URL",
        "OLLAMA_MODEL",
        "OLLAMA_NUM_CTX",
        "OLLAMA_NUM_PREDICT",
        "OLLAMA_TIMEOUT_SECONDS",
    ):
        monkeypatch.delenv(setting, raising=False)
    monkeypatch.setenv(name, value)
    with pytest.raises(InferenceError):
        OllamaInference()


async def test_preflight_requires_exact_installed_model(monkeypatch):
    monkeypatch.setenv("INFERENCE_BACKEND", "ollama")
    monkeypatch.setenv("OLLAMA_MODEL", "qwen3.5:4b")
    assert configured_inference().mode == "ollama"

    def reply(request):
        return httpx.Response(200, json={"models": [{"name": "qwen3.5:9b", "digest": DIGEST}]})

    async with httpx.AsyncClient(transport=httpx.MockTransport(reply)) as client:
        with pytest.raises(InferenceError, match="not installed"):
            await OllamaInference(client).preflight()


async def test_large_prompt_fails_before_generation(monkeypatch):
    monkeypatch.delenv("OLLAMA_BASE_URL", raising=False)

    def reply(request):
        assert request.url.path == "/api/tags"
        return httpx.Response(200, json={"models": [{"name": "qwen3.5:4b", "digest": DIGEST}]})

    async with httpx.AsyncClient(transport=httpx.MockTransport(reply)) as client:
        with pytest.raises(InferenceError, match="context budget"):
            await OllamaInference(client).tool(
                "submit_analysis", {"type": "object"}, {"evidence": "x" * 9000}
            )
