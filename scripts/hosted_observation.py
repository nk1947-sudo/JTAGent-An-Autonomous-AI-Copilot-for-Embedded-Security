"""Bound and summarize paid synthetic chat requests without recording prompt content."""

import httpx

from orchestrator.inference import InferenceError, NebiusInference


class ObservedNebius(NebiusInference):
    def __init__(self, max_completions: int):
        self.logical_completions = 0
        self.post_attempts = 0
        self.returned_models = []
        self.max_completions = max_completions
        super().__init__()
        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.request_timeout_seconds, connect=5),
            follow_redirects=False,
            event_hooks={"request": [self._count_attempt]},
        )

    async def _count_attempt(self, request):
        if request.method == "POST":
            self.post_attempts += 1

    async def _request(self, method, path, payload=None):
        if method == "POST":
            if self.logical_completions >= self.max_completions:
                raise InferenceError("Synthetic verification completion budget exhausted")
            self.logical_completions += 1
        result = await super()._request(method, path, payload)
        if method == "POST":
            self.returned_models.append(result.get("model") if isinstance(result, dict) else None)
        return result

    def observation(self):
        return {
            "requested_model": self.model_id,
            "returned_models": self.returned_models,
            "logical_completions": self.logical_completions,
            "post_attempts": self.post_attempts,
            "retries": self.post_attempts - self.logical_completions,
            "usage": self.usage,
        }

    async def close(self):
        await self.client.aclose()
