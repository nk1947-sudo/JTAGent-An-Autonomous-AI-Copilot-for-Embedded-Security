import asyncio
import json
import os
import secrets
import time
from contextlib import asynccontextmanager
from pathlib import Path

# No external tracing of firmware evidence, regardless of inherited shell configuration.
os.environ["LANGSMITH_TRACING"] = "false"
os.environ["LANGCHAIN_TRACING_V2"] = "false"

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from contracts.http import BoundedBody
from contracts.models import AuditRequest, RunState, TargetProfile
from orchestrator.inference import configured_inference
from orchestrator.report import markdown, report_data
from orchestrator.workflow import Workflow

ROOT = Path(__file__).resolve().parents[1]


class EdgeClient:
    def __init__(self, url, key):
        self.url, self.key = url.rstrip("/"), key

    async def request(self, method, path, body=None):
        async with httpx.AsyncClient(timeout=httpx.Timeout(12, connect=3), follow_redirects=False) as client:
            r = await client.request(
                method, self.url + path, json=body, headers={"Authorization": "Bearer " + self.key}
            )
            if r.status_code >= 300:
                raise RuntimeError("Edge HTTP " + str(r.status_code))
            return r.json()

    async def post(self, path, body):
        return await self.request("POST", path, body)

    async def get(self, path):
        return await self.request("GET", path)


class Login(BaseModel):
    password: str = Field(max_length=256)


def create_app(edge=None, inference_factory=None, password=None):
    edge = edge or EdgeClient(os.getenv("EDGE_API_URL", "http://127.0.0.1:8001"), os.environ["EDGE_API_KEY"])
    inference_factory = inference_factory or configured_inference
    password = password or os.environ.get("DASHBOARD_PASSWORD")
    if not password or len(password) < 12:
        raise ValueError("DASHBOARD_PASSWORD requires at least 12 characters")
    runs, tasks, cancellations, login_sessions = {}, {}, {}, {}
    created = {}
    failures = []
    secure_cookie = os.getenv("COOKIE_SECURE", "0") == "1"

    async def purge():
        while True:
            await asyncio.sleep(30)
            for rid, started in list(created.items()):
                if (
                    time.time() - started > 3600
                    and rid in runs
                    and runs[rid].status not in ("running", "queued")
                ):
                    runs.pop(rid, None)
                    tasks.pop(rid, None)
                    cancellations.pop(rid, None)
                    created.pop(rid, None)

    @asynccontextmanager
    async def lifespan(app):
        cleaner = asyncio.create_task(purge())
        yield
        cleaner.cancel()
        for task in tasks.values():
            if not task.done():
                task.cancel()
        await asyncio.gather(cleaner, *tasks.values(), return_exceptions=True)

    app = FastAPI(title="SiliconSentinel orchestrator", docs_url=None, redoc_url=None, lifespan=lifespan)
    app.state.runs = runs
    app.add_middleware(BoundedBody)
    app.state.tasks = tasks

    async def auth(request: Request):
        token = request.cookies.get("operator", "")
        if login_sessions.get(token, 0) < time.time():
            raise HTTPException(401, "Sign in required")
        if request.method not in ("GET", "HEAD"):
            origin = request.headers.get("origin")
            expected = os.getenv("PUBLIC_ORIGIN", str(request.base_url).rstrip("/"))
            if origin and origin != expected:
                raise HTTPException(403, "Origin not allowed")

    @app.middleware("http")
    async def headers(request, call_next):
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; connect-src 'self'; style-src 'self'; script-src 'self'; frame-ancestors 'none'"
        )
        return response

    @app.exception_handler(RequestValidationError)
    async def invalid(request, exc):
        return JSONResponse({"detail": "Invalid request schema"}, status_code=422)

    @app.get("/healthz")
    async def health():
        return {"status": "ok"}

    @app.post("/api/login")
    async def login(body: Login, response: Response, request: Request):
        current = time.time()
        failures[:] = [t for t in failures if current - t < 60]
        if len(failures) >= 10:
            raise HTTPException(429, "Try again later")
        origin = request.headers.get("origin")
        if origin and origin != os.getenv("PUBLIC_ORIGIN", str(request.base_url).rstrip("/")):
            raise HTTPException(403, "Origin not allowed")
        if not secrets.compare_digest(body.password, password):
            failures.append(current)
            raise HTTPException(401, "Invalid password")
        token = secrets.token_urlsafe(32)
        for old, exp in list(login_sessions.items()):
            if exp < current:
                login_sessions.pop(old)
        if len(login_sessions) >= 32:
            raise HTTPException(429, "Session capacity")
        login_sessions[token] = current + 3600
        response.set_cookie(
            "operator", token, httponly=True, samesite="strict", secure=secure_cookie, max_age=3600
        )
        return {"authenticated": True}

    @app.post("/api/logout", dependencies=[Depends(auth)])
    async def logout(request: Request, response: Response):
        login_sessions.pop(request.cookies.get("operator", ""), None)
        response.delete_cookie("operator")
        return {"authenticated": False}

    @app.get("/api/config", dependencies=[Depends(auth)])
    async def config():
        try:
            profile = await edge.get("/api/v1/target/profile")
            status = await edge.get("/api/v1/target/status")
            inference = inference_factory()
            return {
                "profile": profile,
                "target": status,
                "inference_backend": inference.mode,
                "model_id": inference.model_id,
                "budgets": {"actions": 12, "bytes": 16384, "iterations": 4, "seconds": 120},
            }
        except Exception:  # noqa: BLE001 -- sanitize errors at the public boundary
            raise HTTPException(503, "Target or inference configuration unavailable; no fallback") from None

    @app.post("/api/runs", dependencies=[Depends(auth)], response_model=RunState)
    async def start(body: AuditRequest):
        if any(r.status in ("running", "queued") for r in runs.values()):
            raise HTTPException(409, "One audit at a time owns this target")
        if len(runs) >= 20:
            raise HTTPException(429, "Delete old runs to free in-memory capacity")
        try:
            profile = TargetProfile.model_validate(await edge.get("/api/v1/target/profile"))
            status = await edge.get("/api/v1/target/status")
            inference = inference_factory()
        except Exception:  # noqa: BLE001 -- sanitize errors at the public boundary
            raise HTTPException(503, "Dependency unavailable; no fallback") from None
        allowed = {r.name for r in profile.regions if r.approved}
        if body.target_id != profile.target_id or not set(body.region_names) <= allowed:
            raise HTTPException(403, "Scope not allowed")
        run = RunState(
            target_backend=status["target_backend"],
            inference_backend=inference.mode,
            model_id=inference.model_id,
            profile=profile,
            request=body,
        )
        runs[run.run_id] = run
        created[run.run_id] = time.time()
        cancellations[run.run_id] = asyncio.Event()
        workflow = Workflow(run, edge, inference, cancellations[run.run_id])
        tasks[run.run_id] = asyncio.create_task(workflow.execute())
        return run

    def get_run(rid):
        if rid not in runs:
            raise HTTPException(404, "Run expired or not found")
        return runs[rid]

    @app.get("/api/runs/{rid}", dependencies=[Depends(auth)], response_model=RunState)
    async def get(rid: str):
        return get_run(rid)

    @app.post("/api/runs/{rid}/cancel", dependencies=[Depends(auth)])
    async def cancel(rid: str):
        run = get_run(rid)
        cancellations[rid].set()
        if not tasks[rid].done():
            tasks[rid].cancel()
        # If cancellation arrived before the task's first turn, execute() cannot finalize.
        if run.status == "queued":
            run.status, run.termination_reason = "cancelled", "operator_cancelled"
        return {"cancellation_requested": True}

    @app.delete("/api/runs/{rid}", dependencies=[Depends(auth)])
    async def delete(rid: str):
        if get_run(rid).status in ("running", "queued"):
            raise HTTPException(409, "Cancel before deletion")
        runs.pop(rid)
        created.pop(rid, None)
        tasks.pop(rid, None)
        cancellations.pop(rid, None)
        return {"deleted": True}

    @app.get("/api/runs/{rid}/events", dependencies=[Depends(auth)])
    async def events(rid: str, request: Request):
        run = get_run(rid)

        async def stream():
            cursor = 0
            while True:
                if await request.is_disconnected():
                    return
                if login_sessions.get(request.cookies.get("operator", ""), 0) < time.time():
                    return
                while cursor < len(run.events):
                    yield "data: " + json.dumps(run.events[cursor]) + "\n\n"
                    cursor += 1
                if run.status not in ("queued", "running"):
                    yield "event: done\ndata: {}\n\n"
                    return
                yield ": heartbeat\n\n"
                await asyncio.sleep(0.1)

        return StreamingResponse(
            stream(), media_type="text/event-stream", headers={"X-Accel-Buffering": "no"}
        )

    @app.get("/api/runs/{rid}/report.json", dependencies=[Depends(auth)])
    async def json_report(rid: str):
        return JSONResponse(
            report_data(get_run(rid)), headers={"Content-Disposition": f'attachment; filename="{rid}.json"'}
        )

    @app.get("/api/runs/{rid}/report.md", dependencies=[Depends(auth)])
    async def md_report(rid: str):
        return PlainTextResponse(
            markdown(get_run(rid)), headers={"Content-Disposition": f'attachment; filename="{rid}.md"'}
        )

    if (ROOT / "web/dist").exists():
        app.mount("/", StaticFiles(directory=ROOT / "web/dist", html=True), name="dashboard")
    return app
