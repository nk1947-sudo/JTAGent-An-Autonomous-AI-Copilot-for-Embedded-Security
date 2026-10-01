"""Shared contracts. Range ends are exclusive; addresses are strict unsigned integers."""

from datetime import UTC, datetime
from typing import Annotated, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, model_validator

Address = Annotated[StrictInt, Field(ge=0, le=0xFFFFFFFF)]
Count = Annotated[StrictInt, Field(ge=1, le=4096)]
Mode = Literal["mock", "replay", "openocd"]
Operation = Literal["read", "registers", "snapshot", "halt", "resume", "step", "write"]


def now() -> str:
    return datetime.now(UTC).isoformat()


def uid() -> str:
    return str(uuid4())


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Region(Model):
    name: str
    start: Address
    end: Annotated[StrictInt, Field(ge=1, le=0x100000000)]
    kind: Literal["ram", "rom"]
    address_space: Literal["virtual", "physical"] = "virtual"
    executable: bool = False
    instruction_mode: Literal["arm", "thumb"] = "arm"
    approved: bool = True

    @model_validator(mode="after")
    def ordered(self):
        if self.end <= self.start:
            raise ValueError("Region end must exceed start")
        return self


class TargetProfile(Model):
    target_id: str
    architecture: Literal["arm"] = "arm"
    endianness: Literal["little", "big"] = "little"
    address_width: Literal[32] = 32
    address_spaces: list[Literal["virtual", "physical"]] = ["virtual"]
    regions: list[Region]
    registers: list[str] = ["pc", "lr", "sp", "cpsr"]
    capabilities: list[Operation] = ["read", "registers", "snapshot"]
    provenance: str
    verified_for_live: bool = False


class SessionRequest(Model):
    target_id: str
    operations: list[Operation] = ["read", "registers", "snapshot"]
    regions: list[Region]
    byte_budget: Annotated[StrictInt, Field(ge=1, le=16384)] = 16384
    operation_limit: Annotated[StrictInt, Field(ge=1, le=24)] = 24
    ttl_seconds: Annotated[StrictInt, Field(ge=1, le=120)] = 120


class InspectionSession(SessionRequest):
    session_id: str = Field(default_factory=uid)
    expires_at: float
    used_bytes: int = 0
    used_operations: int = 0
    local_execution_policy: str = "Snapshot restoration only; live independent control disabled"


class TargetRequest(Model):
    target_id: str
    session_id: str
    request_id: str = Field(default_factory=uid)
    expected_generation: Annotated[StrictInt, Field(ge=0)] | None = None


class MemoryReadRequest(TargetRequest):
    address: Address
    length: Count = 256
    address_space: Literal["virtual", "physical"] = "virtual"


class RegisterRequest(TargetRequest):
    names: list[str] = Field(default=["pc", "lr", "sp", "cpsr"], min_length=1, max_length=16)


class SnapshotRequest(MemoryReadRequest):
    registers: list[str] = Field(default=["pc", "lr", "sp", "cpsr"], max_length=16)


class WriteRequest(MemoryReadRequest):
    data_hex: str = Field(pattern=r"^(?:[0-9a-fA-F]{2}){1,4096}$")
    dry_run: bool = True


class StringObservation(Model):
    address: Address
    offset: int
    text: str
    redacted: bool = False


class Instruction(Model):
    address: Address
    size: int
    mnemonic: str
    operands: str


class EvidenceBundle(Model):
    evidence_id: str
    base_address: Address
    length: int
    content_hash: str
    source_mode: Mode
    provenance: str
    architecture: str = "arm"
    endianness: str
    instruction_mode: str
    settings_source: str
    decoder: str
    strings: list[StringObservation] = []
    instructions: list[Instruction] = []
    approved_hex: str | None = None
    withheld_reason: str | None = None
    uncertainties: list[str] = []


class MemoryReadResult(Model):
    requested_length: int
    returned_length: int
    base_address: Address
    address_space: str
    evidence_id: str
    content_hash: str
    timestamp: str = Field(default_factory=now)
    source_mode: Mode
    target_state: str
    generation: int
    partial: bool
    consistency: str
    evidence: EvidenceBundle


class RegisterSnapshot(Model):
    values: dict[str, int]
    timestamp: str = Field(default_factory=now)
    evidence_id: str = Field(default_factory=uid)
    target_state: str
    generation: int
    source_mode: Mode
    mode_information: str = "Profile mode; CPSR evidence is not an automatic override"


class BuildIdentity(Model):
    """Non-secret identity of the code a process actually loaded; see contracts/build.py."""

    component: Literal["edge", "orchestrator"]
    version: str
    commit: str | None = None
    dirty: StrictBool | None = None
    source_fingerprint: str
    build_id: str
    process_started_at: str
    pid: StrictInt
    python: str


STATUS_SCHEMA_NAME = "jtagent.edge.status"
STATUS_SCHEMA_VERSION = 2


class DebuggerStatus(Model):
    applicable: StrictBool
    reachable: StrictBool | None = None
    version_ok: StrictBool | None = None
    version: str | None = None
    expected_version_prefix: str | None = None
    error_code: str | None = None


class TargetStatus(Model):
    communication: Literal["ok", "failed", "unknown"]
    execution_state: str | None = None


class LiveGate(Model):
    allowed: StrictBool
    blockers: list[str]


class EdgeStatus(Model):
    """Edge status v2. The unversioned flat shape (state, target_backend, ...) is schema v1."""

    schema_name: Literal["jtagent.edge.status"]
    schema_version: int
    observed_at: str
    application: Literal["ok"]
    build: BuildIdentity
    source_drift: StrictBool | None = None
    debugger: DebuggerStatus
    target: TargetStatus
    state: str | None = None
    target_backend: Mode
    generation: Annotated[StrictInt, Field(ge=0)]
    capabilities: list[Operation]
    recovery_required: StrictBool
    snapshots_armed: StrictBool
    retains_raw_locally: StrictBool
    read_prerequisite: str | None = None
    live_operations: LiveGate


class Blocker(Model):
    code: str
    message: str


class Readiness(Model):
    """Orchestrator's fail-closed assessment. Missing information is never positive readiness."""

    checked_at: str
    edge: Literal["ok", "unreachable", "incompatible"]
    schema_version: int | None = None
    compatible: bool
    incompatibilities: list[Blocker] = []
    run_ready: bool
    live_ready: bool
    blockers: list[Blocker] = []
    status_age_seconds: float | None = None
    stale: bool = False
    target_backend: Mode | None = None
    debugger: DebuggerStatus | None = None
    target: TargetStatus | None = None
    snapshots_armed: bool | None = None
    recovery_required: bool | None = None
    read_prerequisite: str | None = None
    edge_build: BuildIdentity | None = None
    orchestrator_build: BuildIdentity
    edge_source_drift: bool | None = None
    orchestrator_source_drift: bool


class AcquisitionRecord(Model):
    """How one snapshot was obtained. Absent for captures made before this was recorded."""

    evidence_id: str
    register_evidence_id: str | None = None
    method: str
    backend: Mode
    debugger_version: str | None = None
    halted_by_edge: bool
    initial_state: str
    capture_state: str
    final_state: str | None = None
    restoration: str
    recovery_required: bool
    generation_before: int
    generation_after: int
    edge_build_id: str | None = None
    orchestrator_build_id: str | None = None
    duration_ms: float | None = None


class BundleRequest(Model):
    include_raw: bool = False


class BundleSummary(Model):
    bundle_id: str
    created_at: str
    subject_kind: str
    subject_id: str
    target_backend: str
    captures: int
    raw_included: int
    verification: Literal["VERIFIED", "INCOMPLETE", "FAILED", "UNSUPPORTED"]
    failed_checks: list[str] = []
    unverifiable_checks: int = 0


class BundleResult(BundleSummary):
    path: str
    note: str


class ToolResult(Model):
    success: bool
    request_id: str
    duration_ms: float
    error_code: str | None = None
    retryable: bool = False
    provenance: str
    outcome_uncertain: bool = False
    data: dict | None = None


class UartAuditRequest(Model):
    mode: Literal["observe", "interrupt", "credential_check"] = "observe"
    timeout_seconds: Annotated[StrictInt, Field(ge=10, le=120)] = 90


class UartAuditResult(Model):
    audit_id: str = Field(default_factory=uid)
    mode: Literal["observe", "interrupt", "credential_check"]
    status: Literal["completed", "partial", "failed"]
    port: str
    baud: int
    started_at: str
    finished_at: str = Field(default_factory=now)
    transcript_hash: str
    transcript_bytes: int
    transcript_excerpt: str
    uboot_version: str | None = None
    kernel_version: str | None = None
    boot_observed: bool = False
    autoboot_interrupt_window: bool = False
    uboot_prompt_obtained: bool = False
    default_credentials_advertised: bool = False
    configured_login_attempted: bool = False
    configured_login_succeeded: bool = False
    root_without_additional_prompt: bool = False
    observations: list[str] = []
    errors: list[str] = []


class Finding(Model):
    title: str = Field(max_length=200)
    category: Literal["observation", "hypothesis", "vulnerability"]
    severity: Literal["info", "low", "medium", "high"]
    confidence: Literal["low", "medium", "high"]
    status: Literal["observed", "suspected", "validated", "inconclusive", "rejected"]
    evidence_ids: list[str]
    addresses: list[Address]
    explanation: str = Field(max_length=2000)
    limitations: list[str]
    suggested_verification: str


class ReadProposal(Model):
    address: Address
    length: Count = 256
    address_space: Literal["virtual", "physical"] = "virtual"
    reason: str = Field(max_length=300)


class AnalysisResponse(Model):
    findings: list[Finding] = Field(default=[], max_length=12)
    followups: list[ReadProposal] = Field(default=[], max_length=3)


class AuditRequest(Model):
    target_id: str
    purpose: Literal["firmware triage", "bootloader inspection", "crash investigation"]
    region_names: list[str] = Field(min_length=1, max_length=8)
    byte_budget: Annotated[StrictInt, Field(ge=256, le=16384)] = 16384
    collection_limit: Annotated[StrictInt, Field(ge=1, le=12)] = 12
    iteration_limit: Annotated[StrictInt, Field(ge=1, le=4)] = 4
    deadline_seconds: Annotated[StrictInt, Field(ge=1, le=120)] = 120


class RunState(Model):
    run_id: str = Field(default_factory=uid)
    status: str = "queued"
    target_backend: Mode
    inference_backend: Literal["scripted", "nebius"]
    model_id: str
    profile: TargetProfile
    request: AuditRequest
    created_at: str = Field(default_factory=now)
    captures: list[MemoryReadResult] = []
    registers: list[RegisterSnapshot] = []
    acquisitions: list[AcquisitionRecord] = []
    visited_regions: list[str] = []
    plan: list[ReadProposal] = []
    findings: list[Finding] = []
    events: list[dict] = []
    errors: list[str] = []
    bytes_requested: int = 0
    collection_actions: int = 0
    analysis_iterations: int = 0
    termination_reason: str | None = None
    elapsed_ms: float = 0
    tool_latencies_ms: list[float] = []
    inference_latencies_ms: list[float] = []
    provider_usage: list[dict] = []


class RunSummary(Model):
    run_id: str
    created_at: str
    status: str
    purpose: Literal["firmware triage", "bootloader inspection", "crash investigation"]
    target_backend: Mode
    inference_backend: Literal["scripted", "nebius"]
    model_id: str
    capture_count: int
    bytes_requested: int
    elapsed_ms: float
    termination_reason: str | None = None


AttackModuleId = Literal[
    "jtag-debug-lock-audit",
    "debug-console-exposure",
    "firmware-integrity-assessment",
    "fault-injection-campaign-design",
    "side-channel-capture-plan",
]
AttackCategory = Literal["jtag", "debug_interface", "firmware", "fault_injection", "side_channel"]
AttackRisk = Literal["low", "medium", "high", "critical"]


class AttackRecommendationRequest(Model):
    target_id: str
    objective: str = Field(min_length=3, max_length=500)
    run_id: str | None = None


class AttackRecommendationSelection(Model):
    module_ids: list[AttackModuleId] = Field(min_length=1, max_length=5)
    rationale: str = Field(max_length=1000)


class AttackRecommendation(Model):
    module_id: AttackModuleId
    category: AttackCategory
    title: str
    summary: str
    rationale: str
    risk: AttackRisk
    execution_mode: Literal["evidence_review", "live_jtag", "simulation", "external_hardware_required"]
    prerequisites: list[str]
    evidence_ids: list[str] = []
    supported: bool


class AttackPlanRequest(Model):
    target_id: str
    module_id: AttackModuleId
    objective: str = Field(min_length=3, max_length=500)
    run_id: str | None = None
    authorization_acknowledged: bool


class AttackStep(Model):
    step_id: str = Field(default_factory=uid)
    title: str
    description: str
    operation: Literal[
        "evidence_review",
        "register_review",
        "jtag_snapshot_probe",
        "uart_observation",
        "cpu_control_simulation",
        "firmware_patch_simulation",
        "fault_injection_design",
        "side_channel_design",
    ]
    risk: AttackRisk
    state_changing: bool = False
    requires_approval: bool = False
    status: Literal["ready", "pending_approval", "approved", "rejected", "completed", "blocked", "aborted"]
    result: str | None = None


class AttackPlan(Model):
    plan_id: str = Field(default_factory=uid)
    created_at: str = Field(default_factory=now)
    target_id: str
    module_id: AttackModuleId
    category: AttackCategory
    objective: str
    risk: AttackRisk
    status: Literal[
        "awaiting_approval",
        "ready",
        "running",
        "paused",
        "simulation_completed",
        "completed",
        "blocked",
        "aborted",
    ]
    execution_mode: Literal["evidence_review", "live_jtag", "simulation", "external_hardware_required"]
    authorization_acknowledged: bool
    evidence_ids: list[str] = []
    captures: list[MemoryReadResult] = []
    registers: list[RegisterSnapshot] = []
    acquisitions: list[AcquisitionRecord] = []
    steps: list[AttackStep]
    events: list[dict] = []


class AttackDecision(Model):
    decision: Literal["approve", "reject"]
    note: str = Field(default="", max_length=300)


DebuggerOperation = Literal[
    "capture_memory",
    "inspect_registers",
    "disassemble",
    "set_breakpoint",
    "single_step",
    "resume_bounded",
    "propose_patch",
]


class DebuggerAdviceRequest(Model):
    plan_id: str
    objective: str = Field(min_length=3, max_length=500)


class DebuggerAction(Model):
    operation: DebuggerOperation
    rationale: str = Field(max_length=500)
    address: Address | None = None
    length: Annotated[StrictInt, Field(ge=1, le=4096)] | None = None
    count: Annotated[StrictInt, Field(ge=1, le=16)] | None = None
    requires_approval: bool = True


class DebuggerAdvice(Model):
    summary: str = Field(max_length=1000)
    hypothesis: str = Field(max_length=1000)
    observations: list[str] = Field(default=[], max_length=12)
    actions: list[DebuggerAction] = Field(default=[], max_length=6)
    limitations: list[str] = Field(default=[], max_length=8)


class PatchPreviewRequest(Model):
    plan_id: str
    address: Address
    original_hex: str = Field(pattern=r"^(?:[0-9a-fA-F]{2}){1,64}$")
    replacement_hex: str = Field(pattern=r"^(?:[0-9a-fA-F]{2}){1,64}$")
    instruction_mode: Literal["arm", "thumb"]

    @model_validator(mode="after")
    def equal_patch_lengths(self):
        if len(self.original_hex) != len(self.replacement_hex):
            raise ValueError("Patch replacement must preserve byte length")
        return self


class PatchInstruction(Model):
    address: Address
    bytes_hex: str
    mnemonic: str
    operands: str


class PatchPreview(Model):
    patch_id: str = Field(default_factory=uid)
    plan_id: str
    address: Address
    length: int
    instruction_mode: Literal["arm", "thumb"]
    original_hex: str
    replacement_hex: str
    original_sha256: str
    replacement_sha256: str
    original_instructions: list[PatchInstruction]
    replacement_instructions: list[PatchInstruction]
    live_execution_enabled: bool = False
    warnings: list[str]
