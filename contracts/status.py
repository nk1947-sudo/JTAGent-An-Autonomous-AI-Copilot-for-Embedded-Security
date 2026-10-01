"""Status v2 rules shared by the edge and the orchestrator.

The edge reports what it knows, but the orchestrator never trusts the edge's own verdict:
``live_blockers`` is recomputed from the validated fields, and anything missing, malformed,
old, stale or unknown stays a blocker. There is no code path that turns absence into readiness.
"""

from datetime import UTC, datetime

from pydantic import ValidationError

from contracts.models import (
    STATUS_SCHEMA_NAME,
    STATUS_SCHEMA_VERSION,
    Blocker,
    BuildIdentity,
    EdgeStatus,
    Readiness,
    now,
)

MAX_STATUS_AGE_SECONDS = 15.0
KNOWN_EXECUTION_STATES = ("running", "halted", "captured")
MESSAGES = {
    "debugger_unreachable": "The OpenOCD debugger endpoint is not reachable from the edge.",
    "debugger_unknown": "Debugger reachability was not reported.",
    "debugger_version_incompatible": "OpenOCD does not match the reviewed version prefix.",
    "target_communication_failed": "The debugger answered but the target did not respond correctly.",
    "target_communication_unknown": "Target communication has not been established.",
    "execution_state_unknown": "The CPU execution state is unknown or not one of running/halted.",
    "recovery_required": "A previous operation left the target in an uncertain state; reconcile locally.",
    "snapshots_not_armed": "The CPU is running and snapshots (a brief halt) are not armed on the edge.",
    "not_live_backend": "The edge is not using the OpenOCD backend; no physical operation is possible.",
    "legacy_flat_schema": "The edge serves the old unversioned flat status; restart it on current code.",
    "unsupported_schema_version": "The edge status schema version is not supported by this orchestrator.",
    "malformed_status": "The edge status response is missing required fields or is malformed.",
    "status_stale": "The edge status is older than the freshness limit.",
    "edge_unreachable": "The edge service could not be reached.",
}


def blocker(code, detail=""):
    return Blocker(code=code, message=MESSAGES.get(code, code) + (f" ({detail})" if detail else ""))


def live_blockers(backend, debugger, target, recovery_required, snapshots_armed):
    """Reasons a hardware operation must not start. Empty list means every layer is positive."""
    codes = []
    if backend == "openocd":
        if debugger.reachable is None:
            codes.append("debugger_unknown")
        elif debugger.reachable is False:
            codes.append("debugger_unreachable")
        elif debugger.version_ok is not True:
            codes.append("debugger_version_incompatible")
    else:
        codes.append("not_live_backend")
    if target.communication == "failed":
        codes.append("target_communication_failed")
    elif target.communication != "ok":
        codes.append("target_communication_unknown")
    state = target.execution_state
    if state not in KNOWN_EXECUTION_STATES:
        codes.append("execution_state_unknown")
    if recovery_required:
        codes.append("recovery_required")
    if state == "running" and not snapshots_armed:
        codes.append("snapshots_not_armed")
    return codes


def _empty(orchestrator_build, edge, incompat, blockers, drift, **extra):
    return Readiness(
        checked_at=now(),
        edge=edge,
        compatible=False,
        incompatibilities=incompat,
        run_ready=False,
        live_ready=False,
        blockers=blockers,
        orchestrator_build=orchestrator_build,
        orchestrator_source_drift=drift,
        **extra,
    )


def unreachable(orchestrator_build: BuildIdentity, drift: bool, reason="") -> Readiness:
    b = [blocker("edge_unreachable", reason)]
    return _empty(orchestrator_build, "unreachable", [], b, drift)


def assess(raw, orchestrator_build: BuildIdentity, drift: bool, received_at=None) -> Readiness:
    """Validate a raw edge status payload and decide readiness. Never raises."""
    received_at = received_at or datetime.now(UTC)

    def incompatible(code, detail="", version=None):
        b = blocker(code, detail)
        return _empty(orchestrator_build, "incompatible", [b], [b], drift, schema_version=version)

    if not isinstance(raw, dict):
        return incompatible("malformed_status", "not a JSON object")
    version = raw.get("schema_version")
    if version is None:
        if "state" in raw and "target_backend" in raw:
            return incompatible("legacy_flat_schema")
        return incompatible("malformed_status", "no schema_version")
    if not isinstance(version, int) or isinstance(version, bool) or version != STATUS_SCHEMA_VERSION:
        return incompatible("unsupported_schema_version", f"got {version!r}, need {STATUS_SCHEMA_VERSION}")
    if raw.get("schema_name") != STATUS_SCHEMA_NAME:
        return incompatible("malformed_status", "wrong schema_name", version)
    try:
        status = EdgeStatus.model_validate(raw)
    except ValidationError as exc:
        fields = ", ".join(sorted({".".join(map(str, e["loc"])) for e in exc.errors()}))[:200]
        return incompatible("malformed_status", fields, version)

    age = None
    try:
        age = (received_at - datetime.fromisoformat(status.observed_at)).total_seconds()
    except ValueError:
        return incompatible("malformed_status", "observed_at", version)
    stale = age > MAX_STATUS_AGE_SECONDS or age < -MAX_STATUS_AGE_SECONDS

    blockers = live_blockers(
        status.target_backend,
        status.debugger,
        status.target,
        status.recovery_required,
        status.snapshots_armed,
    )
    if stale:
        blockers.append("status_stale")
    live = status.target_backend == "openocd"
    run_blockers = [c for c in blockers if c != "not_live_backend"]
    return Readiness(
        checked_at=now(),
        edge="ok",
        schema_version=version,
        compatible=True,
        run_ready=not run_blockers,
        live_ready=live and not blockers,
        blockers=[blocker(c) for c in blockers],
        status_age_seconds=age,
        stale=stale,
        target_backend=status.target_backend,
        debugger=status.debugger,
        target=status.target,
        snapshots_armed=status.snapshots_armed,
        recovery_required=status.recovery_required,
        read_prerequisite=status.read_prerequisite,
        edge_build=status.build,
        orchestrator_build=orchestrator_build,
        edge_source_drift=status.source_drift,
        orchestrator_source_drift=drift,
    )
