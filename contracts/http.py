import asyncio

from starlette.responses import JSONResponse


class BoundedBody:
    """Bound streaming request bytes before parsing, including chunked requests."""

    def __init__(self, app, limit=32768):
        self.app, self.limit = app, limit

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] not in ("POST", "PUT", "PATCH"):
            return await self.app(scope, receive, send)
        chunks, length = [], 0
        try:
            async with asyncio.timeout(5):
                while True:
                    message = await receive()
                    if message["type"] == "http.disconnect":
                        return
                    body = message.get("body", b"")
                    length += len(body)
                    if length > self.limit:
                        return await JSONResponse({"detail": "request_too_large"}, status_code=413)(
                            scope, receive, send
                        )
                    chunks.append(body)
                    if not message.get("more_body", False):
                        break
        except TimeoutError:
            return await JSONResponse({"detail": "request_timeout"}, status_code=408)(scope, receive, send)
        pending = True

        async def buffered():
            nonlocal pending
            if pending:
                pending = False
                return {"type": "http.request", "body": b"".join(chunks), "more_body": False}
            return await receive()

        return await self.app(scope, buffered, send)
