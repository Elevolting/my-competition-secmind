from __future__ import annotations

from dataclasses import dataclass

from secmind.schemas import AgentState, ClaimStatus, RunStatus
from secmind.secret_scrubber import scrub_text
from secmind.task_context import require_resolved_task_contract


@dataclass(frozen=True, slots=True)
class MemoryCandidate:
    accepted: bool
    content: str | None
    reason: str


def curate_episodic_memory(state: AgentState) -> MemoryCandidate:
    """Create a bounded, scrubbed memory only from verifier-closed evidence."""

    if state.status != RunStatus.COMPLETED or state.report is None:
        return MemoryCandidate(False, None, "Only completed reported runs are eligible for memory.")

    contract = require_resolved_task_contract(state)

    evidence_ids = {item.evidence_id for item in state.evidence}
    if any(not finding.evidence_ids or not set(finding.evidence_ids) <= evidence_ids for finding in state.findings):
        return MemoryCandidate(False, None, "A finding has incomplete immutable evidence.")

    unresolved_or_invalid = {
        ClaimStatus.CANDIDATE,
        ClaimStatus.SUPPORTED,
        ClaimStatus.INSUFFICIENT,
        ClaimStatus.REJECTED,
        ClaimStatus.CONFLICTED,
    }
    if any(claim.status in unresolved_or_invalid for claim in state.claims):
        return MemoryCandidate(False, None, "One or more claims are unresolved, rejected, or conflicted.")

    finding_ids = {item.finding_id for item in state.findings}
    if finding_ids:
        verified_finding_ids = {
            claim.subject_ref
            for claim in state.claims
            if claim.status == ClaimStatus.VERIFIED and claim.subject_ref in finding_ids
        }
        if verified_finding_ids != finding_ids:
            return MemoryCandidate(False, None, "Every remembered finding must have a verified claim.")

    tools = sorted({name for step in state.plan for name in step.tool_candidates[:1]})
    rules = sorted({finding.rule_id for finding in state.findings})
    content = scrub_text(
        f"Objective: {contract.objective}\n"
        f"Outcome: {state.report.executive_summary}\n"
        f"Tools: {', '.join(tools)}\n"
        f"Finding rules: {', '.join(rules)}"
    )[:16_000]
    return MemoryCandidate(True, content, "Verifier-closed, evidence-complete content was scrubbed for memory.")


__all__ = ["MemoryCandidate", "curate_episodic_memory"]
