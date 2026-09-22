import asyncio
import hashlib
import time

from analysis.evidence import derive
from contracts.models import (
    InspectionSession,
    MemoryReadResult,
    RegisterSnapshot,
    ToolResult,
    uid,
)
from edge.backends import BackendError


class PolicyError(Exception):
    pass


def containing(regions, address, length, space):
    if address + length > 2**32:
        raise PolicyError("address_overflow")
    for region in regions:
        if (
            region.approved
            and region.address_space == space
            and region.start <= address
            and address + length <= region.end
        ):
            return region
    raise PolicyError("range_not_approved")


class EdgeService:
    def __init__(self, backend, profile, max_read=4096, arm_snapshots=False):
        self.backend, self.profile = backend, profile
        self.max_read, self.arm_snapshots = min(max_read, 4096), arm_snapshots
        self.lock = asyncio.Lock()
        self.sessions, self.ledger = {}, {}
        self.lease = None
        self.recovery_required = False

    def session(self, request):
        self.sessions = {k: v for k, v in self.sessions.items() if v.expires_at > time.time()}
        if len(self.sessions) >= 32:
            raise PolicyError("session_capacity")
        if request.target_id != self.profile.target_id:
            raise PolicyError("unknown_target")
        if not set(request.operations) <= set(self.profile.capabilities):
            raise PolicyError("operation_not_permitted")
        for r in request.regions:
            containing(self.profile.regions, r.start, r.end - r.start, r.address_space)
        session = InspectionSession(**request.model_dump(), expires_at=time.time() + request.ttl_seconds)
        self.sessions[session.session_id] = session
        return session

    def validate(self, req, operation):
        session = self.sessions.get(req.session_id)
        if not session or session.expires_at <= time.time():
            raise PolicyError("session_expired")
        if req.target_id != session.target_id or req.target_id != self.profile.target_id:
            raise PolicyError("unknown_target")
        if operation not in session.operations:
            raise PolicyError("operation_not_permitted")
        if self.recovery_required:
            raise PolicyError("operator_reconciliation_required")
        if self.lease and self.lease[0] != session.session_id:
            raise PolicyError("target_owned_by_another_session")
        if req.expected_generation is not None and req.expected_generation != self.backend.generation:
            raise PolicyError("stale_generation")
        if session.used_operations >= session.operation_limit:
            raise PolicyError("operation_budget_exhausted")
        length = getattr(req, "length", 0)
        if length:
            if length > self.max_read:
                raise PolicyError("read_too_large")
            containing(session.regions, req.address, length, req.address_space)
            containing(self.profile.regions, req.address, length, req.address_space)
        names = getattr(req, "names", getattr(req, "registers", []))
        if not set(names) <= set(self.profile.registers):
            raise PolicyError("register_not_permitted")
        if session.used_bytes + length > session.byte_budget:
            raise PolicyError("byte_budget_exhausted")
        session.used_operations += 1
        session.used_bytes += length
        return session

    async def read(self, req):
        region = containing(self.profile.regions, req.address, req.length, req.address_space)
        state = await self.backend.status()
        raw = await self.backend.read(req.address, req.length, req.address_space)
        if len(raw) > req.length:
            raise BackendError("invalid_backend_length")
        evidence = derive(raw, req.address, region, self.profile, self.backend.mode, uid())
        return MemoryReadResult(
            requested_length=req.length,
            returned_length=len(raw),
            base_address=req.address,
            address_space=req.address_space,
            evidence_id=evidence.evidence_id,
            content_hash=evidence.content_hash,
            source_mode=self.backend.mode,
            target_state=state,
            generation=self.backend.generation,
            partial=len(raw) != req.length,
            consistency="Bounded sequential capture; DMA/peripherals may change even while CPU halted",
            evidence=evidence,
        )

    async def registers(self, names):
        values = await self.backend.registers(names)
        return RegisterSnapshot(
            values=values,
            target_state=await self.backend.status(),
            generation=self.backend.generation,
            source_mode=self.backend.mode,
        )

    async def snapshot(self, req, session):
        original = await self.backend.status()
        halted_here = False
        result = {}
        try:
            if original == "running":
                if not self.arm_snapshots or not {"halt", "resume"} <= set(session.operations):
                    raise PolicyError("snapshot_requires_locally_armed_halt_resume")
                halted_here = True  # Includes uncertain halt outcomes; reconcile before any restoration.
                await self.backend.control("halt")
            elif original not in ("halted", "captured"):
                raise BackendError("target_state_unknown")
            result["memory"] = (await self.read(req)).model_dump()
            result["registers"] = (await self.registers(req.registers)).model_dump()
        finally:
            if halted_here:
                try:
                    # Local restoration deadline is independent of graph lifetime and session expiry.
                    async with asyncio.timeout(3):
                        current = await self.backend.status()
                        if current == "halted":
                            await self.backend.control("resume")
                        elif current != "running":
                            raise BackendError("restore_state_uncertain", True)
                    result["restoration"] = "running"
                except (BackendError, TimeoutError):
                    self.recovery_required = True
                    raise BackendError("restoration_failed_operator_required", True) from None
            else:
                result["restoration"] = "unchanged"
        result["initial_state"] = original
        result["generation_after"] = self.backend.generation
        return result

    async def recover_lease(self, owner, generation, ttl):
        await asyncio.sleep(ttl)
        async with self.lock:
            if self.lease == (owner, generation):
                try:
                    await self.backend.control("resume")
                    self.lease = None
                except BackendError:
                    self.recovery_required = True

    async def execute(self, req, operation):
        started = time.perf_counter()
        signature = hashlib.sha256((operation + req.model_dump_json()).encode()).hexdigest()
        key = (req.session_id, req.request_id)
        async with self.lock:
            if key in self.ledger:
                previous_signature, result = self.ledger[key]
                if previous_signature != signature:
                    raise PolicyError("request_id_conflict")
                return result
            session = self.validate(req, operation)
            if len(self.ledger) >= 1024:
                raise PolicyError("operation_ledger_full_restart_required")
            try:
                async with asyncio.timeout(8):
                    if operation == "snapshot":
                        data = await self.snapshot(req, session)
                    elif operation == "read":
                        data = (await self.read(req)).model_dump()
                    elif operation == "registers":
                        data = (await self.registers(req.names)).model_dump()
                    elif operation == "write":
                        payload = bytes.fromhex(req.data_hex)
                        if len(payload) != req.length:
                            raise PolicyError("write_length_mismatch")
                        region = containing(self.profile.regions, req.address, req.length, req.address_space)
                        if region.kind != "ram":
                            raise PolicyError("write_requires_ram")
                        if not req.dry_run:
                            if self.backend.mode != "mock":
                                raise PolicyError("live_write_disabled")
                            await self.backend.write(req.address, payload)
                        data = {
                            "dry_run": req.dry_run,
                            "address": req.address,
                            "length": req.length,
                            "sha256": hashlib.sha256(payload).hexdigest(),
                        }
                    else:
                        if self.backend.mode != "mock":
                            raise PolicyError("independent_live_control_disabled_use_snapshot")
                        prior = await self.backend.status()
                        if operation == "halt" and prior == "running" and "resume" not in session.operations:
                            raise PolicyError("halt_requires_restore_permission")
                        await self.backend.control(operation)
                        if operation == "halt" and prior == "running" or operation == "step" and self.lease:
                            self.lease = (session.session_id, self.backend.generation)
                            asyncio.create_task(
                                self.recover_lease(*self.lease, min(10, session.expires_at - time.time()))
                            )
                        elif operation == "resume":
                            self.lease = None
                        data = {"state": await self.backend.status(), "generation": self.backend.generation}
                result = ToolResult(
                    success=True,
                    request_id=req.request_id,
                    data=data,
                    duration_ms=(time.perf_counter() - started) * 1000,
                    provenance=self.backend.mode,
                )
            except (BackendError, TimeoutError) as exc:
                uncertain = getattr(
                    exc, "uncertain", operation in ("halt", "resume", "step", "write", "snapshot")
                )
                if uncertain:
                    self.recovery_required = True
                result = ToolResult(
                    success=False,
                    request_id=req.request_id,
                    duration_ms=(time.perf_counter() - started) * 1000,
                    error_code=getattr(exc, "code", "edge_timeout"),
                    outcome_uncertain=uncertain,
                    provenance=self.backend.mode,
                )
            self.ledger[key] = (signature, result)
            return result
