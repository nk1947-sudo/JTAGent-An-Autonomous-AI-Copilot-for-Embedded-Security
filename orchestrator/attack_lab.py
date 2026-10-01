"""Policy catalog and HITL state transitions for the non-destructive Attack Lab."""

from copy import deepcopy

from contracts.models import AttackPlan, AttackStep, now
from orchestrator.report import evidence_lines

CATALOG = {
    "jtag-debug-lock-audit": {
        "category": "jtag",
        "title": "JTAG exposure and debug-lock audit",
        "summary": "Review debug capabilities, target state, registers, and lock assumptions without writing memory.",
        "risk": "medium",
        "execution_mode": "live_jtag",
        "prerequisites": ["Authorized target", "Stable JTAG connection", "Approved memory profile"],
        "steps": [
            (
                "Review JTAG capability evidence",
                "Compare the declared debug operations with collected target evidence.",
                "evidence_review",
                "low",
                False,
                False,
            ),
            (
                "Review processor security state",
                "Inspect captured registers for evidence relevant to debug state; do not infer locks without proof.",
                "register_review",
                "low",
                False,
                False,
            ),
            (
                "Execute real JTAG snapshot probe",
                "Temporarily halt through OpenOCD, read up to 64 approved SRAM bytes and registers, then verify restoration.",
                "jtag_snapshot_probe",
                "medium",
                True,
                True,
            ),
        ],
    },
    "debug-console-exposure": {
        "category": "debug_interface",
        "title": "UART and debug-console exposure assessment",
        "summary": "Correlate boot output, U-Boot interruption, and configured-account checks with captured evidence.",
        "risk": "medium",
        "execution_mode": "simulation",
        "prerequisites": ["Authorized target", "Configured UART port", "Recovery path"],
        "steps": [
            (
                "Review prior console evidence",
                "Inspect existing UART observations and audit findings.",
                "evidence_review",
                "low",
                False,
                False,
            ),
            (
                "Approve active UART observation",
                "Queue a bounded UART observation; physical power remains operator-controlled.",
                "uart_observation",
                "medium",
                True,
                True,
            ),
        ],
    },
    "firmware-integrity-assessment": {
        "category": "firmware",
        "title": "Firmware integrity and persistence assessment",
        "summary": "Review boot-chain evidence and simulate a reversible firmware modification plan without producing a rootkit.",
        "risk": "critical",
        "execution_mode": "simulation",
        "prerequisites": [
            "Verified firmware backup",
            "Recovery image",
            "Signature and rollback documentation",
        ],
        "steps": [
            (
                "Inventory firmware evidence",
                "Review hashes, executable regions, strings, and bootloader observations.",
                "evidence_review",
                "low",
                False,
                False,
            ),
            (
                "Simulate integrity-control test",
                "Describe a reversible patch-validation experiment; no patch bytes are generated or written.",
                "firmware_patch_simulation",
                "critical",
                True,
                True,
            ),
        ],
    },
    "fault-injection-campaign-design": {
        "category": "fault_injection",
        "title": "Fault-injection campaign design",
        "summary": "Design bounded clock, voltage, reset, or EM glitch trials and their success criteria.",
        "risk": "critical",
        "execution_mode": "external_hardware_required",
        "prerequisites": [
            "Dedicated glitch hardware",
            "Independent current limiting",
            "Recovery image",
            "Operator safety review",
        ],
        "steps": [
            (
                "Define trigger and observation",
                "Select an evidence-backed boot event and measurable outcome.",
                "evidence_review",
                "low",
                False,
                False,
            ),
            (
                "Approve bounded campaign design",
                "Create timing windows and attempt limits; no pulse is emitted by SiliconSentinel.",
                "fault_injection_design",
                "critical",
                True,
                True,
            ),
        ],
    },
    "side-channel-capture-plan": {
        "category": "side_channel",
        "title": "Side-channel acquisition plan",
        "summary": "Design repeatable power, timing, or EM measurements correlated with known firmware execution.",
        "risk": "high",
        "execution_mode": "external_hardware_required",
        "prerequisites": [
            "Capture instrument",
            "Probe and trigger setup",
            "Repeatable test input",
            "Authorized dataset location",
        ],
        "steps": [
            (
                "Choose evidence-backed trigger",
                "Link acquisition to a captured address or boot event.",
                "evidence_review",
                "low",
                False,
                False,
            ),
            (
                "Approve acquisition design",
                "Specify sample rate, trace count, stop conditions, and data handling.",
                "side_channel_design",
                "high",
                True,
                True,
            ),
        ],
    },
}


def recommendation(module_id, rationale, evidence_ids, profile, uart_enabled, live_jtag_enabled=False):
    item = CATALOG[module_id]
    supported = True
    if module_id == "debug-console-exposure":
        supported = uart_enabled
    elif item["execution_mode"] == "external_hardware_required":
        supported = False
    elif module_id == "jtag-debug-lock-audit":
        supported = live_jtag_enabled and {"registers", "snapshot", "halt", "resume"} <= set(
            profile.capabilities
        )
    return {
        "module_id": module_id,
        **{key: value for key, value in item.items() if key != "steps"},
        "rationale": rationale,
        "evidence_ids": evidence_ids,
        "supported": supported,
    }


def build_plan(request, recommendation_data):
    item = CATALOG[request.module_id]
    steps = [
        AttackStep(
            title=title,
            description=description,
            operation=operation,
            risk=risk,
            state_changing=state_changing,
            requires_approval=requires_approval,
            status="pending_approval" if requires_approval else "ready",
        )
        for title, description, operation, risk, state_changing, requires_approval in deepcopy(item["steps"])
    ]
    return AttackPlan(
        target_id=request.target_id,
        module_id=request.module_id,
        category=item["category"],
        objective=request.objective,
        risk=item["risk"],
        status="awaiting_approval" if any(step.requires_approval for step in steps) else "ready",
        execution_mode=item["execution_mode"],
        authorization_acknowledged=request.authorization_acknowledged,
        evidence_ids=recommendation_data.get("evidence_ids", []),
        steps=steps,
        events=[{"time": now(), "actor": "planner", "message": "Created bounded catalog plan"}],
    )


def update_status(plan):
    if plan.status in ("aborted", "paused"):
        return
    if any(step.status == "pending_approval" for step in plan.steps):
        plan.status = "awaiting_approval"
    elif all(step.status in ("completed", "rejected", "blocked") for step in plan.steps):
        if any(step.status == "blocked" for step in plan.steps):
            plan.status = "blocked"
        elif plan.execution_mode == "simulation":
            plan.status = "simulation_completed"
        elif plan.execution_mode == "external_hardware_required":
            plan.status = "blocked"
        else:
            plan.status = "completed"
    else:
        plan.status = "ready"


def physical_execution_performed(plan):
    return plan.execution_mode == "live_jtag" and any(
        step.operation == "jtag_snapshot_probe" and step.status == "completed" for step in plan.steps
    )


def attack_report_data(plan):
    return {
        **plan.model_dump(),
        "physical_execution_performed": physical_execution_performed(plan),
        "report_scope": "Attack Lab plan, HITL decisions, and bounded execution results",
        "safety_boundary": "No firmware writes, rootkit payloads, glitch pulses, or arbitrary commands are supported.",
    }


def attack_report_markdown(plan):
    physical = physical_execution_performed(plan)
    lines = [
        f"# Attack Lab report: {plan.module_id}",
        "",
        f"- Plan ID: `{plan.plan_id}`",
        f"- Target: `{plan.target_id}`",
        f"- Status: **{plan.status}**",
        f"- Execution mode: `{plan.execution_mode}`",
        f"- Physical execution performed: **{'YES' if physical else 'NO'}**",
        f"- Risk: `{plan.risk}`",
        "",
        "## Objective",
        "",
        plan.objective,
        "",
        "## Steps",
        "",
    ]
    for index, step in enumerate(plan.steps, 1):
        lines += [
            f"### {index}. {step.title}",
            "",
            f"- Status: `{step.status}`",
            f"- Operation: `{step.operation}`",
            f"- HITL approval required: `{step.requires_approval}`",
            f"- State-changing: `{step.state_changing}`",
            f"- Result: {step.result or 'Not executed'}",
            "",
        ]
    lines += [
        "## Evidence",
        "",
        *(f"- `{evidence_id}`" for evidence_id in plan.evidence_ids),
        "",
        "## Inspected evidence",
        "",
        *evidence_lines(plan.captures, plan.registers, plan.acquisitions),
        "",
        "## Safety boundary",
        "",
        "No firmware writes, rootkit payloads, glitch pulses, or arbitrary commands are supported.",
    ]
    return "\n".join(lines) + "\n"
