import httpx
import pytest

from orchestrator.inference import InferenceError
from scripts.hosted_observation import ObservedNebius


async def test_synthetic_request_budget_and_observation(monkeypatch):
    for key, value in {
        "NEBIUS_BASE_URL": "https://api.tokenfactory.nebius.com/v1",
        "NEBIUS_MODEL": "nvidia/test-model",
        "NEBIUS_API_KEY": "synthetic-provider-key",
        "NEBIUS_VERIFIED_CONTEXT_TOKENS": "32768",
    }.items():
        monkeypatch.setenv(key, value)
    attempts = []

    def reply(request):
        attempts.append(request.method)
        if len(attempts) == 1:
            return httpx.Response(503)
        return httpx.Response(
            200,
            json={
                "model": "nvidia/test-model",
                "usage": {"prompt_tokens": 12, "completion_tokens": 3, "total_tokens": 15},
                "choices": [
                    {
                        "finish_reason": "tool_calls",
                        "message": {
                            "tool_calls": [{"function": {"name": "inspect_memory", "arguments": "{}"}}]
                        },
                    }
                ],
            },
        )

    original_client = httpx.AsyncClient
    monkeypatch.setattr(
        "scripts.hosted_observation.httpx.AsyncClient",
        lambda **kwargs: original_client(transport=httpx.MockTransport(reply), **kwargs),
    )
    provider = ObservedNebius(max_completions=1)
    try:
        assert await provider.tool("inspect_memory", {"type": "object"}, {}) == {}
        with pytest.raises(InferenceError, match="budget exhausted"):
            await provider.tool("inspect_memory", {"type": "object"}, {})
        assert provider.observation() == {
            "requested_model": "nvidia/test-model",
            "returned_models": ["nvidia/test-model"],
            "logical_completions": 1,
            "post_attempts": 2,
            "retries": 1,
            "usage": [{"prompt_tokens": 12, "completion_tokens": 3, "total_tokens": 15}],
        }
        assert attempts == ["POST", "POST"]
    finally:
        await provider.close()
