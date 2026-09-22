import asyncio
import time

import pytest

from analysis.evidence import derive
from contracts.models import MemoryReadRequest, SessionRequest, SnapshotRequest, TargetRequest
from edge.backends import BackendError
from tests.conftest import session_body


def new_session(client, profile):
    result = client.post("/api/v1/sessions", json=session_body(profile))
    assert result.status_code == 200
    return result.json()["session_id"]


def request(profile, sid, **extra):
    return {"target_id": profile.target_id, "session_id": sid, "address": 0x80000000, "length": 256, **extra}


@pytest.mark.parametrize(
    "address,length,space",
    [
        (-1, 1, "virtual"),
        (True, 1, "virtual"),
        ("0x80000000", 1, "virtual"),
        (2**32, 1, "virtual"),
        (2**32 - 1, 2, "virtual"),
        (0x800000FF, 2, "virtual"),
        (0x80000000, 4097, "virtual"),
        (0x80000000, True, "virtual"),
        (0x80000000, 4, "physical"),
        (0x80002000, 4, "virtual"),
        (0x80000000, 4, "mmio"),
    ],
)
def test_bad_ranges(client, profile, address, length, space):
    sid = new_session(client, profile)
    r = client.post(
        "/api/v1/memory/read", json=request(profile, sid, address=address, length=length, address_space=space)
    )
    assert r.status_code in (403, 422)


def test_auth_and_widening(client, profile):
    assert client.get("/api/v1/target/status", headers={"Authorization": ""}).status_code == 401
    assert client.get("/healthz").status_code == 200
    body = session_body(profile)
    body["regions"][0]["start"] = 0
    assert client.post("/api/v1/sessions", json=body).status_code == 403
    assert client.get("/api/v1/target/halt").status_code == 405


def test_snapshot_restores_redacts_and_rejects_register(client, profile, service):
    sid = new_session(client, profile)
    r = client.post("/api/v1/snapshots/capture", json=request(profile, sid, address=0x80001000)).json()
    assert r["success"]
    assert r["data"]["restoration"] == "running"
    evidence = r["data"]["memory"]["evidence"]
    assert evidence["approved_hex"] is None
    assert "synthetic-secret" not in str(r)
    assert any(s["redacted"] for s in evidence["strings"])
    assert service.backend.state == "running"
    assert (
        client.post(
            "/api/v1/registers/read",
            json={"target_id": profile.target_id, "session_id": sid, "names": ["evil;reset"]},
        ).status_code
        == 403
    )


def test_budgets_and_idempotency(client, profile, service):
    body = session_body(profile)
    body["byte_budget"] = 256
    sid = client.post("/api/v1/sessions", json=body).json()["session_id"]
    req = request(profile, sid, request_id="same")
    a = client.post("/api/v1/snapshots/capture", json=req).json()
    b = client.post("/api/v1/snapshots/capture", json=req).json()
    assert a == b
    assert service.backend.generation == 2
    assert client.post("/api/v1/memory/read", json=request(profile, sid)).status_code == 403
    req["length"] = 1
    assert client.post("/api/v1/snapshots/capture", json=req).status_code == 403


async def test_initially_halted_partial_and_generation(service, profile):
    service.backend.state = "halted"
    service.backend.memory[0x80000000] = bytearray(b"abc")
    s = service.session(SessionRequest(**session_body(profile)))
    req = SnapshotRequest(**request(profile, s.session_id))
    result = await service.execute(req, "snapshot")
    assert result.data["memory"]["partial"]
    assert result.data["memory"]["returned_length"] == 3
    assert service.backend.state == "halted"
    assert service.backend.generation == 0


async def test_disconnect_restore_uncertain(service, profile):
    async def fail(operation):
        raise BackendError("disconnected", True)

    service.backend.control = fail
    s = service.session(SessionRequest(**session_body(profile)))
    r = await service.execute(SnapshotRequest(**request(profile, s.session_id)), "snapshot")
    assert not r.success and r.outcome_uncertain
    assert service.recovery_required


async def test_concurrent_snapshot_serializes(service, profile):
    s = service.session(SessionRequest(**session_body(profile)))
    results = await asyncio.gather(
        *(service.execute(SnapshotRequest(**request(profile, s.session_id)), "snapshot") for _ in range(4))
    )
    assert all(r.success for r in results)
    assert service.backend.state == "running" and service.backend.generation == 8


async def test_control_lease_and_stale_generation(service, profile):
    s = service.session(SessionRequest(**session_body(profile)))
    req = TargetRequest(target_id=profile.target_id, session_id=s.session_id)
    assert (await service.execute(req, "halt")).success
    owner, generation = service.lease
    await service.recover_lease(owner, generation, 0)
    assert service.backend.state == "running"
    from edge.service import PolicyError

    with pytest.raises(PolicyError, match="stale"):
        await service.execute(
            MemoryReadRequest(**request(profile, s.session_id, expected_generation=0)), "read"
        )


@pytest.mark.parametrize("mode,data,mnemonic", [("arm", "0000a0e3", "mov"), ("thumb", "0120", "movs")])
def test_decoder_modes(profile, mode, data, mnemonic):
    region = profile.regions[0].model_copy(update={"instruction_mode": mode})
    result = derive(bytes.fromhex(data), region.start, region, profile, "mock", "e")
    assert result.instructions[0].mnemonic == mnemonic
    assert result.instructions[0].address == region.start


def test_big_endian_and_offsets(profile):
    profile.endianness = "big"
    e = derive(bytes.fromhex("e3a00000"), 0x80000000, profile.regions[0], profile, "mock", "e")
    assert e.instructions[0].mnemonic == "mov"
    e = derive(b"\x00hello\x00world", 0x80001000, profile.regions[1], profile, "mock", "e")
    assert [s.offset for s in e.strings] == [1, 7]


def test_missing_memory_not_zero_success(client, profile, service):
    sid = new_session(client, profile)
    service.backend.memory = {}
    r = client.post("/api/v1/memory/read", json=request(profile, sid)).json()
    assert not r["success"] and r["error_code"] == "unreadable"


def test_expiry_and_write(client, profile, service):
    sid = new_session(client, profile)
    body = request(profile, sid, length=1, data_hex="aa")
    assert client.post("/api/v1/memory/write", json=body).json()["data"]["dry_run"]
    assert service.backend.memory[0x80000000][0] == 0
    body["dry_run"] = False
    assert client.post("/api/v1/memory/write", json=body).json()["success"]
    assert service.backend.memory[0x80000000][0] == 0xAA
    service.sessions[sid].expires_at = time.time() - 1
    assert client.post("/api/v1/memory/read", json=request(profile, sid)).status_code == 403
