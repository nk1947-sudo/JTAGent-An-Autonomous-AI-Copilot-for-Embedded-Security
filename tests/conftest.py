from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from contracts.models import TargetProfile
from edge.app import create_app
from edge.backends import MockBackend
from edge.service import EdgeService


@pytest.fixture
def profile():
    return TargetProfile.model_validate_json(Path("config/demo.json").read_text())


@pytest.fixture
def service(profile):
    return EdgeService(MockBackend(), profile, arm_snapshots=True)


@pytest.fixture
def client(service):
    with TestClient(create_app(service, "test-edge-key-123456")) as client:
        client.headers["Authorization"] = "Bearer test-edge-key-123456"
        yield client


def session_body(profile):
    return {
        "target_id": profile.target_id,
        "regions": [r.model_dump() for r in profile.regions if r.approved],
        "operations": profile.capabilities,
    }
