import asyncio
import time
from typing import TypedDict

from langgraph.graph import END, START, StateGraph

from analysis.evidence import sanitize
from contracts.models import MemoryReadResult, RegisterSnapshot, SnapshotRequest, now
from edge.service import PolicyError, containing


class WorkflowState(TypedDict):
    run_id: str


class StopRun(Exception):
    pass


def verify(findings, run):
    evidence = {c.evidence_id: c for c in run.captures}
    registers = {r.evidence_id: r for r in run.registers}
    verified = []
    for original in findings:
        finding = original.model_copy(deep=True)
        known = evidence.keys() | registers.keys()
        valid = bool(finding.evidence_ids) and bool(finding.addresses) and set(finding.evidence_ids) <= known
        for address in finding.addresses:
            valid &= any(
                c.base_address <= address < c.base_address + c.returned_length
                for eid, c in evidence.items()
                if eid in finding.evidence_ids
            ) or any(
                address in r.values.values() for eid, r in registers.items() if eid in finding.evidence_ids
            )
        valid &= all(c.source_mode == run.target_backend for c in run.captures)
        valid &= all(r.source_mode == run.target_backend for r in run.registers)
        exact_string = any(
            finding.explanation == "String observed: " + s.text
            and s.address in finding.addresses
            and c.evidence_id in finding.evidence_ids
            and not s.redacted
            for c in run.captures
            for s in c.evidence.strings
        )
        if not valid:
            finding.status = "rejected"
            finding.confidence = "low"
            finding.limitations.append("Verifier rejected missing or inconsistent evidence references.")
        elif exact_string and finding.category == "observation":
            finding.status, finding.severity = "observed", "info"
            finding.title = "Captured printable string"
            finding.limitations.append(
                "Only the cited printable bytes are established; behavior is unverified."
            )
        else:
            finding.status = "inconclusive" if finding.status == "inconclusive" else "suspected"
            finding.confidence = "low"
            finding.limitations.append(
                "Evidence references checked; semantic claim not independently validated."
            )
        verified.append(finding)
    return verified


class Workflow:
    def __init__(self, run, edge, inference, cancelled):
        self.run, self.edge, self.inference, self.cancelled = run, edge, inference, cancelled
        self.queue, self.proposals, self.visited = [], [], set()
        self.session_id = None
        self.started = time.perf_counter()
        graph = StateGraph(WorkflowState)
        for name in ("planner", "policy_gate", "collector", "decoder", "analyst", "verifier", "reporter"):
            graph.add_node(name, getattr(self, name))
        graph.add_edge(START, "planner")
        graph.add_edge("planner", "policy_gate")
        graph.add_edge("policy_gate", "collector")
        graph.add_conditional_edges("collector", lambda _: "collector" if self.queue else "decoder")
        graph.add_edge("decoder", "analyst")
        graph.add_edge("analyst", "verifier")
        graph.add_conditional_edges("verifier", lambda _: "policy_gate" if self.proposals else "reporter")
        graph.add_edge("reporter", END)
        self.graph = graph.compile()  # No persistence, interrupts or replay of side effects in the MVP.

    def event(self, node, message, **data):
        self.run.events.append(
            {
                "id": len(self.run.events),
                "time": now(),
                "node": node,
                "message": sanitize(message),
                "target_backend": self.run.target_backend,
                "inference_backend": self.run.inference_backend,
                **data,
            }
        )

    def check(self):
        if self.cancelled.is_set():
            self.run.termination_reason = "operator_cancelled"
            raise StopRun()
        if time.perf_counter() - self.started > self.run.request.deadline_seconds:
            self.run.termination_reason = "deadline_exceeded"
            raise StopRun()

    async def planner(self, state):
        self.check()
        self.event("planner", "Preparing a bounded plan for the operator-selected scope")
        p = self.run.profile
        regions = [r for r in p.regions if r.name in self.run.request.region_names and r.approved]
        operations = ["read", "registers", "snapshot"]
        if self.run.target_backend != "replay" and {"halt", "resume"} <= set(p.capabilities):
            operations += ["halt", "resume"]
        self.session_id = (
            await self.edge.post(
                "/api/v1/sessions",
                {
                    "target_id": p.target_id,
                    "regions": [r.model_dump() for r in regions],
                    "operations": operations,
                    "byte_budget": self.run.request.byte_budget,
                    "operation_limit": self.run.request.collection_limit,
                    "ttl_seconds": self.run.request.deadline_seconds,
                },
            )
        )["session_id"]
        self.proposals = await self.inference.plan(p, self.run.request)
        self.run.plan = list(self.proposals)
        return {}

    async def policy_gate(self, state):
        self.check()
        selected = [r for r in self.run.profile.regions if r.name in self.run.request.region_names]
        if self.run.analysis_iterations >= self.run.request.iteration_limit:
            self.run.termination_reason = "analysis_budget_exhausted"
            raise StopRun()
        for proposal in self.proposals:
            key = (proposal.address, proposal.length, proposal.address_space)
            try:
                containing(selected, proposal.address, proposal.length, proposal.address_space)
            except PolicyError:
                self.event("policy_gate", "Rejected out-of-scope proposal")
                self.run.termination_reason = "invalid_proposal"
                raise StopRun() from None
            if key not in self.visited:
                self.queue.append(proposal)
                self.visited.add(key)
        self.proposals = []
        if not self.queue:
            self.run.termination_reason = "no_new_evidence"
            raise StopRun()
        self.event(
            "policy_gate", "Approved schema-valid reads within selected local ranges", count=len(self.queue)
        )
        return {}

    async def collector(self, state):
        self.check()
        p = self.queue.pop(0)
        req = self.run.request
        if (
            self.run.collection_actions >= req.collection_limit
            or self.run.bytes_requested + p.length > req.byte_budget
        ):
            self.run.termination_reason = "collection_budget_exhausted"
            raise StopRun()
        self.run.collection_actions += 1
        self.run.bytes_requested += p.length
        self.event("collector", f"Capture {p.length} bytes at 0x{p.address:08x}", reason=sanitize(p.reason))
        body = SnapshotRequest(
            target_id=self.run.profile.target_id,
            session_id=self.session_id,
            address=p.address,
            length=p.length,
            address_space=p.address_space,
        ).model_dump()
        result = await self.edge.post("/api/v1/snapshots/capture", body)
        self.run.tool_latencies_ms.append(result["duration_ms"])
        if not result["success"]:
            self.run.errors.append(result["error_code"])
            self.run.termination_reason = "dependency_failure"
            raise StopRun()
        capture = MemoryReadResult.model_validate(result["data"]["memory"])
        self.run.captures.append(capture)
        self.run.registers.append(RegisterSnapshot.model_validate(result["data"]["registers"]))
        self.run.visited_regions.append(
            f"{capture.address_space}:0x{capture.base_address:08x}+{capture.returned_length}"
        )
        if capture.partial:
            self.run.errors.append("Partial read at " + hex(capture.base_address))
        self.event(
            "collector",
            "Snapshot returned; target restoration completed locally",
            evidence_id=capture.evidence_id,
            restoration=result["data"]["restoration"],
        )
        return {}

    async def decoder(self, state):
        self.check()
        self.event("decoder", "Using edge-derived Capstone instructions and offset-attributed strings")
        return {}

    async def analyst(self, state):
        self.check()
        self.run.analysis_iterations += 1
        self.event("analyst", "Interpreting compact evidence; target data is untrusted")
        started = time.perf_counter()
        self.analysis = await self.inference.analyze(
            self.run.captures, self.run.registers, self.run.request.purpose
        )
        self.run.inference_latencies_ms.append((time.perf_counter() - started) * 1000)
        self.run.provider_usage = list(self.inference.usage)
        return {}

    async def verifier(self, state):
        self.check()
        self.run.findings = verify(self.analysis.findings, self.run)
        self.proposals = self.analysis.followups
        self.event(
            "verifier", "Checked references, addresses and claim status", findings=len(self.run.findings)
        )
        return {}

    async def reporter(self, state):
        self.run.termination_reason = "completed"
        self.event("reporter", "Report available with scope, provenance and limitations")
        return {}

    async def execute(self):
        self.run.status = "running"
        try:
            async with asyncio.timeout(self.run.request.deadline_seconds):
                await self.graph.ainvoke({"run_id": self.run.run_id}, config={"recursion_limit": 80})
        except StopRun:
            pass
        except asyncio.CancelledError:
            self.run.termination_reason = "operator_cancelled"
        except TimeoutError:
            self.run.termination_reason = "deadline_exceeded"
        except Exception as exc:  # noqa: BLE001 -- finalize without exposing payloads
            # Do not serialize exception payloads, URLs, headers or target bytes.
            self.run.errors.append(type(exc).__name__)
            self.run.termination_reason = "dependency_failure"
            self.event("error", "A dependency failed; inspect local configuration. No fixture fallback.")
        self.run.elapsed_ms = (time.perf_counter() - self.started) * 1000
        reason = self.run.termination_reason
        self.run.status = (
            "completed"
            if reason == "completed"
            else "cancelled"
            if reason == "operator_cancelled"
            else "partial"
            if self.run.captures
            else "failed"
        )
        self.event("finished", reason or "unknown")
