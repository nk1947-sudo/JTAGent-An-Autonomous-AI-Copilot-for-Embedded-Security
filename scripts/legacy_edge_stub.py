"""FIXTURE ONLY: an edge that speaks the old unversioned flat status (schema v1).

Used by browser and unit tests to prove the orchestrator and dashboard fail closed against an edge
running older code. It serves a synthetic profile, never touches hardware and holds no evidence.
"""

import json
import os
import secrets
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException

ROOT = Path(__file__).resolve().parents[1]


def create_app():
    key = os.environ["EDGE_API_KEY"]
    app = FastAPI(docs_url=None, redoc_url=None)

    async def auth(authorization: str = Header(default="")):
        if not secrets.compare_digest(authorization, "Bearer " + key):
            raise HTTPException(401, "Authentication required")

    @app.get("/healthz")
    async def health():
        return {"status": "ok"}  # no build identity: this is the old shape

    @app.get("/api/v1/target/profile", dependencies=[Depends(auth)])
    async def profile():
        return json.loads((ROOT / "config/demo.json").read_text())

    @app.get("/api/v1/target/status", dependencies=[Depends(auth)])
    async def status():
        return {
            "state": "running",
            "target_backend": "mock",
            "generation": 0,
            "capabilities": ["read", "registers", "snapshot"],
            "recovery_required": False,
        }

    @app.get("/api/v1/uart/status", dependencies=[Depends(auth)])
    async def uart():
        return {"enabled": False}

    return app
