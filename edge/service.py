import asyncio
import hashlib
import re
import time
from collections import OrderedDict

from analysis.evidence import derive
from contracts.build import load_build, source_drift
from contracts.models import (
    STATUS_SCHEMA_NAME,
    STATUS_SCHEMA_VERSION,
    AcquisitionRecord,
    DebuggerStatus,
    EdgeStatus,
    InspectionSession,
    LiveGate,
    MemoryReadResult,
    RegisterSnapshot,
    TargetStatus,
    ToolResult,
    now,
    uid,
)
from contracts.status import live_blockers
from edge.backends import BackendError

RAW_RETAINED_LIMIT = 64
EVIDENCE_ID = re.compile(r"^[0-9a-fA-F-]{36}$")
ACQUISITION_METHOD = {
    "openocd": "openocd_tcl_halt+read_memory+get_reg+resume",
    "mock": "synthetic_mock_backend",
    "replay": "replay_manifest",
}


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
    def __init__(self, backend, profile, max_read=4096, arm_snapshots=False, retain_raw=False):
        self.backend, self.profile = backend, profile
        # Raw bytes are kept only when the operator arms RETAIN_RAW_LOCAL on this edge; they are
        # served to local exports, never to inference, and vanish when the process ends.
        self.retain_raw, self.raw = retain_raw, OrderedDict()
        self.build, self._drift = None, (0.0, None)
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

    def identity(self):
        if self.build is None:
            self.build = load_build("edge")
        return self.build

    def drift(self):
        checked, value = self._drift
        if time.monotonic() - checked > 5:
            value = source_drift(self.identity())
            self._drift = (time.monotonic(), value)
        return value

    async def report(self):
        """Versioned, non-raising status: debugger endpoint, target communication, execution state."""
        live = self.backend.mode == "openocd"
        debugger = DebuggerStatus(
            applicable=live, expected_version_prefix=getattr(self.backend, "version_prefix", None)
        )
        target = TargetStatus(communication="unknown")
        try:
            state = await self.backend.status()
            debugger.reachable, debugger.version_ok = (True, True) if live else (None, None)
            target = TargetStatus(communication="ok", execution_state=state)
        except BackendError as exc:
            code = exc.code
            debugger.error_code = code
            if code in ("rpc_unavailable", "rpc_disconnected", "unexpected_rpc_frame", "rpc_reply_too_large"):
                debugger.reachable = False
            elif code == "openocd_version_mismatch":
                debugger.reachable, debugger.version_ok = True, False
            else:
                debugger.reachable, debugger.version_ok = True, True
                target = TargetStatus(communication="failed")
        except TimeoutError:
            debugger.error_code = "edge_timeout"
        debugger.version = getattr(self.backend, "version", None)
        state = target.execution_state
        needs_halt = None
        if live and state == "running":
            needs_halt = (
                "Reads may fail while the CPU runs; a bounded snapshot briefly halts and then resumes it. "
                + (
                    "Snapshots are armed locally."
                    if self.arm_snapshots
                    else "Snapshots are NOT armed (ARM_SNAPSHOTS)."
                )
            )
        blockers = live_blockers(
            self.backend.mode, debugger, target, self.recovery_required, self.arm_snapshots
        )
        return EdgeStatus(
            schema_name=STATUS_SCHEMA_NAME,
            schema_version=STATUS_SCHEMA_VERSION,
            observed_at=now(),
            application="ok",
            build=self.identity(),
            source_drift=self.drift(),
            debugger=debugger,
            target=target,
            state=state,
            target_backend=self.backend.mode,
            generation=self.backend.generation,
            capabilities=self.profile.capabilities,
            recovery_required=self.recovery_required,
            snapshots_armed=self.arm_snapshots,
            retains_raw_locally=self.retain_raw,
            read_prerequisite=needs_halt,
            live_operations=LiveGate(allowed=live and not blockers, blockers=blockers),
        ).model_dump()

    def raw_evidence(self, evidence_id):
        """Locally retained bytes for an authorized local export, or None."""
        return self.raw.get(evidence_id) if EVIDENCE_ID.match(evidence_id) else None

    async def read(self, req):
        region = containing(self.profile.regions, req.address, req.length, req.address_space)
        state = await self.backend.status()
        try:
            raw = await self.backend.read(req.address, req.length, req.address_space)
        except BackendError as exc:
            if exc.code == "memory_read_failed" and state == "running":
                # Prerequisite, not a protocol fault: the debugger could not read while the CPU ran.
                raise BackendError("memory_read_failed_target_running") from None
            raise
        if len(raw) > req.length:
            raise BackendError("invalid_backend_length")
        evidence = derive(raw, req.address, region, self.profile, self.backend.mode, uid())
        if self.retain_raw:
            self.raw[evidence.evidence_id] = bytes(raw)
            while len(self.raw) > RAW_RETAINED_LIMIT:
                self.raw.popitem(last=False)
        return MemoryReadResult(
            timestamp=getattr(self.backend, "manifest", {}).get("captured_at", now()),
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
        state = await self.backend.status()
        try:
            values = await self.backend.registers(names)
        except BackendError as exc:
            if exc.code == "register_read_failed" and state == "running":
                raise BackendError("register_read_failed_target_running") from None
            raise
        return RegisterSnapshot(
            timestamp=getattr(self.backend, "manifest", {}).get("captured_at", now()),
            values=values,
            target_state=state,
            generation=self.backend.generation,
            source_mode=self.backend.mode,
        )

    async def snapshot(self, req, session):
        started = time.perf_counter()
        original = await self.backend.status()
        generation_before = self.backend.generation
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
        try:
            final = await self.backend.status()
        except BackendError:
            final = None  # Unknown, not assumed: recorded as such in the acquisition record.
        result["acquisition"] = AcquisitionRecord(
            evidence_id=result["memory"]["evidence_id"],
            register_evidence_id=result["registers"]["evidence_id"],
            method=ACQUISITION_METHOD.get(self.backend.mode, self.backend.mode),
            backend=self.backend.mode,
            debugger_version=getattr(self.backend, "version", None),
            halted_by_edge=halted_here,
            initial_state=original,
            capture_state=result["memory"]["target_state"],
            final_state=final,
            restoration=result["restoration"],
            recovery_required=self.recovery_required,
            generation_before=generation_before,
            generation_after=self.backend.generation,
            edge_build_id=self.identity().build_id,
            duration_ms=(time.perf_counter() - started) * 1000,
        ).model_dump()
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
