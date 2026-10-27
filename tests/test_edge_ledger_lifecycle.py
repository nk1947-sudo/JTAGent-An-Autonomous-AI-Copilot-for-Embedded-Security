"""Ledger recovery must never turn an old request ID into another operation."""

import asyncio
import time

import pytest

from contracts.models import MemoryReadRequest, SessionRequest, SnapshotRequest, ToolResult
from edge.backends import BackendError
from edge.service import PolicyError
from tests.conftest import session_body


def session(service, profile):
    return service.session(SessionRequest(**session_body(profile)))


def read_request(profile, session_id, request_id="read", length=4):
    return MemoryReadRequest(
        target_id=profile.target_id,
        session_id=session_id,
        request_id=request_id,
        address=0x80000000,
        length=length,
    )


def ledger_result(request_id, uncertain=False):
    return ToolResult(
        success=not uncertain,
        request_id=request_id,
        duration_ms=0,
        provenance="mock",
        outcome_uncertain=uncertain,
    )


def test_expired_definitive_entries_reclaim_capacity_without_erasing_evidence(service, profile):
    service.retain_raw = True
    old = session(service, profile)
    first = asyncio.run(service.execute(read_request(profile, old.session_id, "old"), "read"))
    evidence_id = first.data["evidence_id"]
    retained = service.raw[evidence_id]
    for index in range(1023):
        service.ledger[(old.session_id, f"old-{index}")] = ("signature", ledger_result(f"old-{index}"))
    assert len(service.ledger) == 1024
    old.expires_at = time.time() - 1

    current = session(service, profile)
    result = asyncio.run(service.execute(read_request(profile, current.session_id, "new"), "read"))

    assert result.success
    assert len(service.ledger) == 1
    assert (current.session_id, "new") in service.ledger
    assert service.raw[evidence_id] == retained


def test_duplicate_and_conflicting_request_ids_keep_one_backend_operation(service, profile):
    current = session(service, profile)
    calls = 0
    original_read = service.backend.read

    async def counted_read(*args):
        nonlocal calls
        calls += 1
        return await original_read(*args)

    service.backend.read = counted_read
    request = read_request(profile, current.session_id)
    first = asyncio.run(service.execute(request, "read"))
    second = asyncio.run(service.execute(request, "read"))
    assert first == second and calls == 1 and current.used_operations == 1
    with pytest.raises(PolicyError, match="request_id_conflict"):
        asyncio.run(service.execute(read_request(profile, current.session_id, length=8), "read"))
    assert calls == 1 and current.used_operations == 1


def test_concurrent_duplicate_waits_for_pending_result(service, profile):
    async def scenario():
        current = session(service, profile)
        request = read_request(profile, current.session_id)
        started, release = asyncio.Event(), asyncio.Event()
        calls = 0
        original_read = service.backend.read

        async def paused_read(*args):
            nonlocal calls
            calls += 1
            started.set()
            await release.wait()
            return await original_read(*args)

        service.backend.read = paused_read
        first = asyncio.create_task(service.execute(request, "read"))
        await started.wait()
        duplicate = asyncio.create_task(service.execute(request, "read"))
        await asyncio.sleep(0)
        assert not duplicate.done()
        release.set()
        first_result, second_result = await asyncio.gather(first, duplicate)
        assert first_result == second_result and calls == 1 and current.used_operations == 1

    asyncio.run(scenario())


def test_uncertain_outcome_remains_a_tombstone_after_session_expiry(service, profile):
    current = session(service, profile)
    calls = 0

    async def uncertain_read(*_):
        nonlocal calls
        calls += 1
        raise BackendError("disconnected", True)

    service.backend.read = uncertain_read
    request = read_request(profile, current.session_id)
    first = asyncio.run(service.execute(request, "read"))
    assert not first.success and first.outcome_uncertain and service.recovery_required
    current.expires_at = time.time() - 1
    second = asyncio.run(service.execute(request, "read"))
    assert first == second and calls == 1
    assert (current.session_id, request.request_id) in service.ledger
    with pytest.raises(PolicyError, match="request_id_conflict"):
        asyncio.run(service.execute(read_request(profile, current.session_id, length=8), "read"))


def test_unreclaimable_capacity_does_not_charge_or_invoke_backend(service, profile):
    current = session(service, profile)
    for index in range(1024):
        service.ledger[(f"expired-{index}", "uncertain")] = (
            "signature",
            ledger_result("uncertain", uncertain=True),
        )
    with pytest.raises(PolicyError, match="operation_ledger_full_restart_required"):
        asyncio.run(service.execute(read_request(profile, current.session_id), "read"))
    assert len(service.ledger) == 1024
    assert current.used_operations == current.used_bytes == 0


def test_cancelled_snapshot_keeps_uncertain_result_and_cannot_replay(service, profile):
    async def scenario():
        current = session(service, profile)
        request = SnapshotRequest(**read_request(profile, current.session_id).model_dump())
        started = asyncio.Event()
        calls = 0

        async def paused_control(operation):
            nonlocal calls
            assert operation == "halt"
            calls += 1
            started.set()
            await asyncio.Event().wait()

        service.backend.control = paused_control
        task = asyncio.create_task(service.execute(request, "snapshot"))
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        result = await service.execute(request, "snapshot")
        assert not result.success and result.error_code == "operation_cancelled"
        assert result.outcome_uncertain and service.recovery_required
        assert calls == 1 and current.used_operations == 1

    asyncio.run(scenario())
