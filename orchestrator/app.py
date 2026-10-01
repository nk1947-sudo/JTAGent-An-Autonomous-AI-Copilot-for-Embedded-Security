import asyncio
import json
import math
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
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from contracts.build import load_build, source_drift
from contracts.http import BoundedBody
from contracts.models import (
    AcquisitionRecord,
    AttackDecision,
    AttackPlan,
    AttackPlanRequest,
    AttackRecommendation,
    AttackRecommendationRequest,
    AuditRequest,
    BundleRequest,
    BundleResult,
    BundleSummary,
    DebuggerAdvice,
    DebuggerAdviceRequest,
    MemoryReadResult,
    PatchPreview,
    PatchPreviewRequest,
    Readiness,
    RegisterSnapshot,
    RunState,
    RunSummary,
    TargetProfile,
    UartAuditRequest,
    now,
)
from contracts.status import assess, unreachable
from orchestrator.attack_lab import (
    attack_report_data,
    attack_report_markdown,
    build_plan,
    recommendation,
    update_status,
)
from orchestrator.bundle import (
    BUNDLE_ID,
    DOWNLOADABLE,
    build_bundle,
    default_export_root,
    list_bundles,
    summarize,
)
from orchestrator.inference import configured_inference
from orchestrator.report import markdown, report_data
from orchestrator.workbench import preview_patch
from orchestrator.workflow import Workflow

ROOT = Path(__file__).resolve().parents[1]


def optional_rate(name):
    value = os.getenv(name, "").strip()
    if not value:
        return None
    try:
        rate = float(value)
    except ValueError:
        return None
    return rate if math.isfinite(rate) and rate >= 0 else None


class EdgeClient:
    def __init__(self, url, key):
        self.url, self.key = url.rstrip("/"), key

    async def request(self, method, path, body=None, timeout_seconds=12):
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(timeout_seconds, connect=3), follow_redirects=False
        ) as client:
            r = await client.request(
                method, self.url + path, json=body, headers={"Authorization": "Bearer " + self.key}
            )
            if r.status_code >= 300:
                raise RuntimeError("Edge HTTP " + str(r.status_code))
            return r.json()

    async def post(self, path, body, timeout_seconds=12):
        return await self.request("POST", path, body, timeout_seconds)

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
    runs, tasks, cancellations, login_sessions, attack_plans = {}, {}, {}, {}, {}
    recommendation_cache = {}
    created = {}
    failures = []
    secure_cookie = os.getenv("COOKIE_SECURE", "0") == "1"
    build = load_build("orchestrator")
    export_root = Path(os.getenv("EXPORT_DIR") or default_export_root(ROOT))
    drift_cache = [0.0, False]

    def own_drift():
        if time.monotonic() - drift_cache[0] > 5:
            drift_cache[:] = [time.monotonic(), source_drift(build)]
        return drift_cache[1]

    async def current_readiness() -> Readiness:
        """Fresh, fail-closed assessment. Never served from a cache: every gate calls this."""
        try:
            raw = await edge.get("/api/v1/target/status")
        except Exception as exc:  # noqa: BLE001 -- reported as a blocker, not raised
            return unreachable(build, own_drift(), type(exc).__name__)
        return assess(raw, build, own_drift())

    def blocked(readiness: Readiness, live: bool):
        if readiness.edge == "unreachable" or not readiness.compatible:
            reasons = readiness.blockers
        else:
            reasons = [b for b in readiness.blockers if live or b.code != "not_live_backend"]
        codes = "; ".join(f"{b.code}: {b.message}" for b in reasons) or "readiness not established"
        return HTTPException(409, ("Hardware operation" if live else "Audit") + " blocked. " + codes)

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
    app.state.attack_plans = attack_plans
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
        # Liveness and loaded-code identity only; readiness is /api/readiness.
        return {"status": "ok", "build": build.model_dump()}

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

    @app.get("/api/readiness", dependencies=[Depends(auth)], response_model=Readiness)
    async def readiness_route():
        return await current_readiness()

    @app.get("/api/config", dependencies=[Depends(auth)])
    async def config():
        checked_at = now()
        edge_started = time.perf_counter()
        readiness = await current_readiness()
        profile = uart = None
        if readiness.edge != "unreachable":
            try:
                profile = await edge.get("/api/v1/target/profile")
                uart = await edge.get("/api/v1/uart/status")
            except Exception:  # noqa: BLE001 -- surfaced as a degraded edge below
                profile = uart = None
        edge_latency_ms = (time.perf_counter() - edge_started) * 1000
        try:
            inference_started = time.perf_counter()
            inference = inference_factory()
            inference_latency_ms = (time.perf_counter() - inference_started) * 1000
        except Exception:  # noqa: BLE001 -- sanitize errors at the public boundary
            raise HTTPException(503, "Inference configuration unavailable; no fallback") from None
        uart = uart or {"enabled": False}
        debugger, target = readiness.debugger, readiness.target
        live_backend = readiness.target_backend == "openocd"

        def tile(id_, label, status, detail, latency=edge_latency_ms):
            return {
                "id": id_,
                "label": label,
                "status": status,
                "detail": detail,
                "latency_ms": latency,
                "checked_at": checked_at,
            }

        target_ok = bool(
            target
            and target.communication == "ok"
            and target.execution_state in ("running", "halted", "captured")
            and not readiness.recovery_required
        )
        return {
            "profile": profile,
            "target": {
                "state": target.execution_state if target else None,
                "target_backend": readiness.target_backend,
                "recovery_required": readiness.recovery_required,
            },
            "readiness": readiness.model_dump(),
            "uart": uart,
            "inference_backend": inference.mode,
            "model_id": inference.model_id,
            "budgets": {"actions": 12, "bytes": 16384, "iterations": 4, "seconds": 120},
            "dependencies": [
                tile(
                    "edge",
                    "Edge API",
                    "ready" if readiness.edge == "ok" and not readiness.stale else "degraded",
                    (readiness.edge_build.build_id if readiness.edge_build else readiness.edge)
                    + (" · source changed on disk" if readiness.edge_source_drift else ""),
                ),
                tile(
                    "debugger",
                    "Debugger (OpenOCD)",
                    "not applicable"
                    if debugger and not debugger.applicable
                    else "ready"
                    if debugger and debugger.reachable and debugger.version_ok
                    else "degraded",
                    (debugger.version or debugger.error_code or "unknown") if debugger else "unknown",
                ),
                tile(
                    "target",
                    "CPU target",
                    "ready" if target_ok else "degraded",
                    (target.execution_state or target.communication if target else "unknown")
                    + (" · " + readiness.read_prerequisite if readiness.read_prerequisite else ""),
                ),
                tile(
                    "operations",
                    "Hardware operations",
                    "ready" if readiness.live_ready else "blocked" if live_backend else "not applicable",
                    "ok" if readiness.live_ready else ", ".join(b.code for b in readiness.blockers) or "none",
                ),
                tile(
                    "uart",
                    "UART",
                    "ready" if uart.get("enabled") else "disabled",
                    f"{uart.get('port', 'not configured')} · {uart.get('baud', '-')}",
                ),
                tile(
                    "inference",
                    "Inference",
                    "configured",
                    inference.model_id,
                    inference_latency_ms,
                ),
            ],
            "pricing": {
                "input_usd_per_million": optional_rate("NEBIUS_INPUT_USD_PER_MILLION"),
                "output_usd_per_million": optional_rate("NEBIUS_OUTPUT_USD_PER_MILLION"),
            },
            "attack_lab": {"live_jtag_enabled": os.getenv("ATTACK_LAB_LIVE_JTAG") == "1"},
        }

    @app.post("/api/uart/audit", dependencies=[Depends(auth)])
    async def uart_audit(req: UartAuditRequest):
        try:
            # The operator may need most of the bounded audit window to power-cycle
            # the board. Keep the proxy alive slightly longer than the edge job.
            return await edge.post(
                "/api/v1/uart/audit", req.model_dump(), timeout_seconds=req.timeout_seconds + 5
            )
        except Exception:  # noqa: BLE001 -- sanitize edge and serial errors
            raise HTTPException(503, "UART audit unavailable or failed") from None

    @app.post("/api/runs", dependencies=[Depends(auth)], response_model=RunState)
    async def start(body: AuditRequest):
        if any(r.status in ("running", "queued") for r in runs.values()):
            raise HTTPException(409, "One audit at a time owns this target")
        if len(runs) >= 20:
            raise HTTPException(429, "Delete old runs to free in-memory capacity")
        try:
            readiness = await current_readiness()
            if not readiness.run_ready:
                raise blocked(readiness, live=False)
            profile = TargetProfile.model_validate(await edge.get("/api/v1/target/profile"))
            inference = inference_factory()
        except HTTPException:
            raise
        except Exception:  # noqa: BLE001 -- sanitize errors at the public boundary
            raise HTTPException(503, "Dependency unavailable; no fallback") from None
        allowed = {r.name for r in profile.regions if r.approved}
        if body.target_id != profile.target_id or not set(body.region_names) <= allowed:
            raise HTTPException(403, "Scope not allowed")
        run = RunState(
            target_backend=readiness.target_backend,
            inference_backend=inference.mode,
            model_id=inference.model_id,
            profile=profile,
            request=body,
        )
        runs[run.run_id] = run
        created[run.run_id] = time.time()
        cancellations[run.run_id] = asyncio.Event()
        workflow = Workflow(run, edge, inference, cancellations[run.run_id], build.build_id)
        tasks[run.run_id] = asyncio.create_task(workflow.execute())
        return run

    @app.get("/api/runs", dependencies=[Depends(auth)], response_model=list[RunSummary])
    async def list_runs():
        return [
            RunSummary(
                run_id=run.run_id,
                created_at=run.created_at,
                status=run.status,
                purpose=run.request.purpose,
                target_backend=run.target_backend,
                inference_backend=run.inference_backend,
                model_id=run.model_id,
                capture_count=len(run.captures),
                bytes_requested=run.bytes_requested,
                elapsed_ms=run.elapsed_ms,
                termination_reason=run.termination_reason,
            )
            for run in reversed(runs.values())
        ]

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

    @app.post(
        "/api/attack-lab/recommendations",
        dependencies=[Depends(auth)],
        response_model=list[AttackRecommendation],
    )
    async def recommend_attack_modules(body: AttackRecommendationRequest):
        profile = TargetProfile.model_validate(await edge.get("/api/v1/target/profile"))
        if body.target_id != profile.target_id:
            raise HTTPException(403, "Target not authorized")
        source_run = get_run(body.run_id) if body.run_id else None
        findings = source_run.findings if source_run else []
        evidence_ids = [capture.evidence_id for capture in source_run.captures] if source_run else []
        uart = await edge.get("/api/v1/uart/status")
        cache_key = (body.target_id, body.run_id, body.objective.strip().lower())
        if cache_key in recommendation_cache:
            return recommendation_cache[cache_key]
        try:
            selected = await asyncio.wait_for(
                inference_factory().recommend_attacks(profile, findings, body.objective), timeout=65
            )
        except TimeoutError:
            raise HTTPException(
                504, "Attack recommendation timed out after 65 seconds; no automatic paid retry"
            ) from None
        except Exception:  # noqa: BLE001 -- never silently substitute model recommendations
            raise HTTPException(503, "Attack recommendation model unavailable; no fallback") from None
        result = [
            recommendation(
                module_id,
                selected.rationale,
                evidence_ids,
                profile,
                bool(uart.get("enabled")),
                os.getenv("ATTACK_LAB_LIVE_JTAG") == "1",
            )
            for module_id in dict.fromkeys(selected.module_ids)
        ]
        recommendation_cache[cache_key] = result
        return result

    @app.get("/api/attack-lab/plans", dependencies=[Depends(auth)], response_model=list[AttackPlan])
    async def list_attack_plans():
        return list(reversed(attack_plans.values()))

    @app.post("/api/attack-lab/plans", dependencies=[Depends(auth)], response_model=AttackPlan)
    async def create_attack_plan(body: AttackPlanRequest):
        if not body.authorization_acknowledged:
            raise HTTPException(422, "Authorization acknowledgement required")
        if len(attack_plans) >= 20:
            raise HTTPException(429, "Attack plan capacity reached")
        profile = TargetProfile.model_validate(await edge.get("/api/v1/target/profile"))
        if body.target_id != profile.target_id:
            raise HTTPException(403, "Target not authorized")
        source_run = get_run(body.run_id) if body.run_id else None
        data = recommendation(
            body.module_id,
            "Operator selected a catalogued module.",
            [capture.evidence_id for capture in source_run.captures] if source_run else [],
            profile,
            bool((await edge.get("/api/v1/uart/status")).get("enabled")),
            os.getenv("ATTACK_LAB_LIVE_JTAG") == "1",
        )
        plan = build_plan(body, data)
        attack_plans[plan.plan_id] = plan
        return plan

    def get_attack_plan(plan_id):
        if plan_id not in attack_plans:
            raise HTTPException(404, "Attack plan not found")
        return attack_plans[plan_id]

    @app.get("/api/attack-lab/plans/{plan_id}", dependencies=[Depends(auth)], response_model=AttackPlan)
    async def get_attack_plan_route(plan_id: str):
        return get_attack_plan(plan_id)

    @app.post(
        "/api/attack-lab/plans/{plan_id}/steps/{step_id}/decision",
        dependencies=[Depends(auth)],
        response_model=AttackPlan,
    )
    async def decide_attack_step(plan_id: str, step_id: str, body: AttackDecision):
        plan = get_attack_plan(plan_id)
        if plan.status in ("completed", "simulation_completed", "aborted"):
            raise HTTPException(409, "Plan is terminal")
        step = next((candidate for candidate in plan.steps if candidate.step_id == step_id), None)
        if not step or not step.requires_approval or step.status != "pending_approval":
            raise HTTPException(409, "Step is not awaiting approval")
        step.status = "approved" if body.decision == "approve" else "rejected"
        plan.events.append(
            {
                "time": now(),
                "actor": "operator",
                "message": f"{'Approved' if body.decision == 'approve' else 'Rejected'} step {step.step_id}",
                "note": body.note,
            }
        )
        update_status(plan)
        return plan

    @app.post(
        "/api/attack-lab/plans/{plan_id}/execute-next",
        dependencies=[Depends(auth)],
        response_model=AttackPlan,
    )
    async def execute_attack_step(plan_id: str):
        plan = get_attack_plan(plan_id)
        if plan.status in ("paused", "completed", "simulation_completed", "blocked", "aborted"):
            raise HTTPException(409, "Plan cannot execute in its current state")
        step = next(
            (candidate for candidate in plan.steps if candidate.status in ("ready", "approved")), None
        )
        if not step:
            raise HTTPException(409, "No approved step is ready")
        if step.operation == "jtag_snapshot_probe" and os.getenv("ATTACK_LAB_LIVE_JTAG") == "1":
            # Re-derived from a fresh edge status under the same rules as an audit; the browser's
            # disabled button is a convenience, not the policy boundary.
            readiness = await current_readiness()
            if not readiness.live_ready:
                raise blocked(readiness, live=True)
        plan.status = "running"
        # The only physical executor is a bounded snapshot using the edge's existing restore-on-exit
        # primitive. It never forwards write, firmware, glitch, pulse, or arbitrary command material.
        if step.operation == "jtag_snapshot_probe":
            if os.getenv("ATTACK_LAB_LIVE_JTAG") != "1":
                step.status = "blocked"
                step.result = "Real JTAG execution is disabled. Set ATTACK_LAB_LIVE_JTAG=1 and restart after reviewing the recovery path."
            else:
                profile = TargetProfile.model_validate(await edge.get("/api/v1/target/profile"))
                target_status = await edge.get("/api/v1/target/status")
                region = next((candidate for candidate in profile.regions if candidate.approved), None)
                if target_status.get("target_backend") != "openocd":
                    step.status = "blocked"
                    step.result = (
                        "NO PHYSICAL ATTACK was performed. The live JTAG executor requires the "
                        "OpenOCD target backend; mock and replay targets cannot satisfy this step."
                    )
                elif not region or not {"snapshot", "halt", "resume"} <= set(profile.capabilities):
                    step.status = "blocked"
                    step.result = "The live profile does not authorize snapshot plus halt/resume restoration."
                else:
                    length = min(64, region.end - region.start)
                    session = await edge.post(
                        "/api/v1/sessions",
                        {
                            "target_id": profile.target_id,
                            "regions": [region.model_dump()],
                            "operations": ["read", "registers", "snapshot", "halt", "resume"],
                            "byte_budget": length,
                            "operation_limit": 1,
                            "ttl_seconds": 10,
                        },
                    )
                    result = await edge.post(
                        "/api/v1/snapshots/capture",
                        {
                            "target_id": profile.target_id,
                            "session_id": session["session_id"],
                            "address": region.start,
                            "length": length,
                            "address_space": region.address_space,
                        },
                        timeout_seconds=12,
                    )
                    if not result.get("success"):
                        step.status = "blocked"
                        step.result = (
                            f"Physical JTAG probe failed safely: {result.get('error_code', 'unknown error')}"
                        )
                    else:
                        after = await edge.get("/api/v1/target/status")
                        memory = result["data"]["memory"]
                        capture = MemoryReadResult.model_validate(memory)
                        register_capture = RegisterSnapshot.model_validate(result["data"]["registers"])
                        plan.captures.append(capture)
                        plan.registers.append(register_capture)
                        if result["data"].get("acquisition"):
                            plan.acquisitions.append(
                                AcquisitionRecord.model_validate(
                                    {**result["data"]["acquisition"], "orchestrator_build_id": build.build_id}
                                )
                            )
                        evidence_id = memory["evidence_id"]
                        if evidence_id not in plan.evidence_ids:
                            plan.evidence_ids.append(evidence_id)
                        step.status = "completed"
                        step.result = (
                            f"REAL {target_status['target_backend'].upper()} JTAG probe: read {memory['returned_length']} bytes "
                            f"at 0x{memory['base_address']:08x}; captured registers; restoration={result['data']['restoration']}; "
                            f"target state after probe={after['state']}; evidence={evidence_id[:8]}."
                        )
        elif step.operation in ("evidence_review", "register_review"):
            step.status = "completed"
            step.result = (
                f"Reviewed {len(plan.evidence_ids)} linked evidence captures; no target command sent."
            )
        elif step.operation == "uart_observation":
            step.status = "completed"
            step.result = (
                "UART action approved as a dry run. Arm the dedicated bounded UART audit separately."
            )
        elif step.operation in ("fault_injection_design", "side_channel_design"):
            step.status = "blocked"
            step.result = (
                "Design completed, but NO PHYSICAL ATTACK was performed. Dedicated external "
                "hardware and a hardware execution adapter are required."
            )
        else:
            step.status = "completed"
            step.result = (
                "Simulation completed. NO PHYSICAL ATTACK was performed; the physical or "
                "state-changing execution adapter is not enabled."
            )
        plan.events.append(
            {
                "time": now(),
                "actor": "executor",
                "message": f"{step.status.title()} {step.title} ({'physical' if step.operation == 'jtag_snapshot_probe' and step.status == 'completed' else 'bounded'})",
            }
        )
        update_status(plan)
        return plan

    @app.post(
        "/api/attack-lab/plans/{plan_id}/pause",
        dependencies=[Depends(auth)],
        response_model=AttackPlan,
    )
    async def pause_attack_plan(plan_id: str):
        plan = get_attack_plan(plan_id)
        if plan.status in ("completed", "simulation_completed", "blocked", "aborted"):
            raise HTTPException(409, "Plan is terminal")
        plan.status = "paused"
        plan.events.append({"time": now(), "actor": "operator", "message": "Plan paused"})
        return plan

    @app.post(
        "/api/attack-lab/plans/{plan_id}/resume",
        dependencies=[Depends(auth)],
        response_model=AttackPlan,
    )
    async def resume_attack_plan(plan_id: str):
        plan = get_attack_plan(plan_id)
        if plan.status != "paused":
            raise HTTPException(409, "Plan is not paused")
        plan.status = "ready"
        update_status(plan)
        plan.events.append({"time": now(), "actor": "operator", "message": "Plan resumed"})
        return plan

    @app.post(
        "/api/attack-lab/plans/{plan_id}/abort",
        dependencies=[Depends(auth)],
        response_model=AttackPlan,
    )
    async def abort_attack_plan(plan_id: str):
        plan = get_attack_plan(plan_id)
        if plan.status in ("completed", "simulation_completed"):
            raise HTTPException(409, "Plan is complete")
        plan.status = "aborted"
        for step in plan.steps:
            if step.status not in ("completed", "rejected"):
                step.status = "aborted"
        plan.events.append({"time": now(), "actor": "operator", "message": "Plan aborted"})
        return plan

    @app.get("/api/attack-lab/plans/{plan_id}/report.json", dependencies=[Depends(auth)])
    async def attack_json_report(plan_id: str):
        return JSONResponse(
            attack_report_data(get_attack_plan(plan_id)),
            headers={"Content-Disposition": f'attachment; filename="{plan_id}.attack.json"'},
        )

    @app.get("/api/attack-lab/plans/{plan_id}/report.md", dependencies=[Depends(auth)])
    async def attack_markdown_report(plan_id: str):
        return PlainTextResponse(
            attack_report_markdown(get_attack_plan(plan_id)),
            headers={"Content-Disposition": f'attachment; filename="{plan_id}.attack.md"'},
        )

    async def gather_raw(captures, include_raw):
        """Raw bytes for a local export only: operator-requested and edge-retained. Never for inference."""
        offered = {}
        for capture in captures:
            eid = capture.evidence_id
            if not include_raw:
                offered[eid] = (None, "raw bytes not requested by the operator for this export")
                continue
            try:
                reply = await edge.get(f"/api/v1/evidence/{eid}/raw")
                offered[eid] = (
                    bytes.fromhex(reply["raw_hex"]),
                    "retained locally by the edge; exported at the operator's explicit request",
                )
            except Exception:  # noqa: BLE001 -- absence is reported, not an error
                approved = capture.evidence.approved_hex
                offered[eid] = (
                    (bytes.fromhex(approved), "bytes were already approved for display (synthetic target)")
                    if approved
                    else (
                        None,
                        (
                            "the edge did not retain these bytes (RETAIN_RAW_LOCAL is off, the capture "
                            "predates retention, or the edge restarted); they cannot be recovered"
                        ),
                    )
                )
        return offered

    async def write_bundle(kind, subject, report_json, report_md, inference, include_raw):
        readiness = await current_readiness()
        profile = (
            TargetProfile.model_validate(await edge.get("/api/v1/target/profile"))
            if readiness.edge != "unreachable"
            else None
        )
        if profile is None:
            profile = subject.profile if kind == "run" else None
        if profile is None:
            raise HTTPException(
                503, "The target profile is required to write a bundle and the edge is unreachable"
            )
        raw = await gather_raw(subject.captures, include_raw)
        builds = {
            "exporter_orchestrator": build.model_dump(),
            "edge_at_export": readiness.edge_build.model_dump() if readiness.edge_build else None,
            "note": "Builds at export time. Per-capture historical builds are in each acquisition record.",
        }
        path, _ = await asyncio.to_thread(
            build_bundle,
            kind=kind,
            subject=subject,
            profile=profile,
            report_json=report_json,
            report_md=report_md,
            builds=builds,
            raw_by_id=raw,
            out_root=export_root,
            inference=inference,
        )
        summary = await asyncio.to_thread(summarize, path)
        return BundleResult(
            **summary,
            path=str(path),
            note="Local-only export. Delete the directory to remove it; nothing was sent to a provider.",
        )

    @app.post("/api/runs/{rid}/bundle", dependencies=[Depends(auth)], response_model=BundleResult)
    async def run_bundle(rid: str, body: BundleRequest):
        run = get_run(rid)
        if run.status in ("running", "queued"):
            raise HTTPException(409, "Wait for the run to finish before exporting a bundle")
        inference = {"backend": run.inference_backend, "model_id": run.model_id}
        return await write_bundle("run", run, report_data(run), markdown(run), inference, body.include_raw)

    @app.post(
        "/api/attack-lab/plans/{plan_id}/bundle", dependencies=[Depends(auth)], response_model=BundleResult
    )
    async def attack_bundle(plan_id: str, body: BundleRequest):
        plan = get_attack_plan(plan_id)
        inference = {"recorded": False, "note": "Attack Lab plans do not record the recommending backend"}
        return await write_bundle(
            "attack_plan",
            plan,
            attack_report_data(plan),
            attack_report_markdown(plan),
            inference,
            body.include_raw,
        )

    @app.get("/api/exports", dependencies=[Depends(auth)], response_model=list[BundleSummary])
    async def exports():
        return await asyncio.to_thread(list_bundles, export_root)

    @app.get("/api/exports/{bundle_id}/{artifact}", dependencies=[Depends(auth)])
    async def export_artifact(bundle_id: str, artifact: str):
        if not BUNDLE_ID.match(bundle_id) or artifact not in DOWNLOADABLE:
            raise HTTPException(404, "Unknown export")
        path = export_root / bundle_id / artifact
        if not path.is_file():
            raise HTTPException(404, "Unknown export")
        return FileResponse(
            path, headers={"Content-Disposition": f'attachment; filename="{bundle_id}-{artifact}"'}
        )

    @app.post(
        "/api/debugger/advice",
        dependencies=[Depends(auth)],
        response_model=DebuggerAdvice,
    )
    async def debugger_advice(body: DebuggerAdviceRequest):
        plan = get_attack_plan(body.plan_id)
        if plan.target_id != (await edge.get("/api/v1/target/profile"))["target_id"]:
            raise HTTPException(403, "Target not authorized")
        if not plan.captures:
            raise HTTPException(409, "The selected plan has no captured JTAG evidence")
        profile = TargetProfile.model_validate(await edge.get("/api/v1/target/profile"))
        try:
            return await asyncio.wait_for(
                inference_factory().debugger_assist(profile, plan, body.objective), timeout=65
            )
        except TimeoutError:
            raise HTTPException(504, "Debugger agent timed out after 65 seconds") from None
        except Exception:  # noqa: BLE001 -- sanitize model/provider failures
            raise HTTPException(503, "Debugger agent unavailable; no fallback") from None

    @app.post(
        "/api/workbench/patch-preview",
        dependencies=[Depends(auth)],
        response_model=PatchPreview,
    )
    async def patch_preview(body: PatchPreviewRequest):
        plan = get_attack_plan(body.plan_id)
        profile = TargetProfile.model_validate(await edge.get("/api/v1/target/profile"))
        if plan.target_id != profile.target_id:
            raise HTTPException(403, "Target not authorized")
        try:
            return preview_patch(body, plan, profile)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None

    if (ROOT / "web/dist").exists():
        app.mount("/", StaticFiles(directory=ROOT / "web/dist", html=True), name="dashboard")
    return app
