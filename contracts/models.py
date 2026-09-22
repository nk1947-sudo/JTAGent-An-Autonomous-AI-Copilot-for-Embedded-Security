"""Shared contracts. Range ends are exclusive; addresses are strict unsigned integers."""

from datetime import UTC, datetime
from typing import Annotated, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, StrictInt, model_validator

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


class ToolResult(Model):
    success: bool
    request_id: str
    duration_ms: float
    error_code: str | None = None
    retryable: bool = False
    provenance: str
    outcome_uncertain: bool = False
    data: dict | None = None


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
