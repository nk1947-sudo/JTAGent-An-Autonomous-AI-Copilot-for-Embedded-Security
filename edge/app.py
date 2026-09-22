import os
import secrets
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from analysis import evidence
from contracts.http import BoundedBody
from contracts.models import (
    MemoryReadRequest,
    RegisterRequest,
    SessionRequest,
    SnapshotRequest,
    TargetProfile,
    TargetRequest,
    ToolResult,
    WriteRequest,
)
from edge.backends import BackendError, MockBackend, OpenOCDBackend, ReplayBackend, TclRPC
from edge.service import EdgeService, PolicyError

ROOT = Path(__file__).resolve().parents[1]


def configured_service():
    mode = os.getenv("TARGET_BACKEND", "mock")
    profile_path = os.getenv("TARGET_PROFILE")
    profile = TargetProfile.model_validate_json(Path(profile_path or ROOT / "config/demo.json").read_text())
    if mode == "mock":
        backend = MockBackend(os.getenv("MOCK_VARIANT", "demo"))
    elif mode == "replay":
        backend = ReplayBackend(os.environ["REPLAY_MANIFEST"])
        profile = TargetProfile.model_validate(backend.manifest["profile"])
        profile.provenance = backend.manifest["provenance"] + "; captured " + backend.manifest["captured_at"]
        profile.capabilities = ["read", "registers", "snapshot"]
    elif mode == "openocd":
        if not profile_path or not profile.verified_for_live:
            raise ValueError("Live mode requires an explicitly verified TARGET_PROFILE")
        backend = OpenOCDBackend(
            TclRPC(port=int(os.getenv("OPENOCD_PORT", "6666"))),
            os.environ["OPENOCD_TARGET"],
            os.environ["OPENOCD_VERSION_PREFIX"],
        )
    else:
        raise ValueError("Unknown target backend; no fallback")
    evidence.EXTRA_SENSITIVE = tuple(filter(None, os.getenv("REDACT_VALUES", "").split("|")))
    return EdgeService(
        backend,
        profile,
        int(os.getenv("MAX_READ_BYTES", "4096")),
        arm_snapshots=mode == "mock" or os.getenv("ARM_SNAPSHOTS") == "1",
    )


def create_app(service=None, api_key=None):
    service = service or configured_service()
    api_key = api_key or os.environ.get("EDGE_API_KEY")
    if not api_key or len(api_key) < 16:
        raise ValueError("EDGE_API_KEY must contain at least 16 characters")
    app = FastAPI(title="SiliconSentinel edge", docs_url=None, redoc_url=None)
    app.state.service = service
    app.add_middleware(BoundedBody)

    async def auth(authorization: str = Header(default="")):
        if not secrets.compare_digest(authorization, "Bearer " + api_key):
            raise HTTPException(401, "Authentication required")

    @app.exception_handler(PolicyError)
    async def policy_error(request, exc):
        return JSONResponse({"detail": str(exc)}, status_code=403)

    @app.exception_handler(BackendError)
    async def backend_error(request, exc):
        return JSONResponse({"detail": exc.code}, status_code=503)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        return JSONResponse({"detail": "Invalid request schema"}, status_code=422)

    @app.get("/healthz")
    async def health():
        return {"status": "ok"}

    @app.get("/api/v1/target/profile", dependencies=[Depends(auth)], response_model=TargetProfile)
    async def profile():
        return service.profile

    @app.get("/api/v1/target/status", dependencies=[Depends(auth)])
    async def status():
        async with service.lock:
            return {
                "state": await service.backend.status(),
                "target_backend": service.backend.mode,
                "generation": service.backend.generation,
                "capabilities": service.profile.capabilities,
                "recovery_required": service.recovery_required,
            }

    @app.post("/api/v1/sessions", dependencies=[Depends(auth)])
    async def session(req: SessionRequest):
        return service.session(req)

    @app.post("/api/v1/memory/read", dependencies=[Depends(auth)], response_model=ToolResult)
    async def read(req: MemoryReadRequest):
        return await service.execute(req, "read")

    @app.post("/api/v1/registers/read", dependencies=[Depends(auth)], response_model=ToolResult)
    async def registers(req: RegisterRequest):
        return await service.execute(req, "registers")

    @app.post("/api/v1/snapshots/capture", dependencies=[Depends(auth)], response_model=ToolResult)
    async def snapshot(req: SnapshotRequest):
        return await service.execute(req, "snapshot")

    @app.post("/api/v1/target/halt", dependencies=[Depends(auth)], response_model=ToolResult)
    async def halt(req: TargetRequest):
        return await service.execute(req, "halt")

    @app.post("/api/v1/target/resume", dependencies=[Depends(auth)], response_model=ToolResult)
    async def resume(req: TargetRequest):
        return await service.execute(req, "resume")

    @app.post("/api/v1/target/step", dependencies=[Depends(auth)], response_model=ToolResult)
    async def step(req: TargetRequest):
        return await service.execute(req, "step")

    @app.post("/api/v1/memory/write", dependencies=[Depends(auth)], response_model=ToolResult)
    async def write(req: WriteRequest):
        return await service.execute(req, "write")

    return app
