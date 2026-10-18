from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from secmind.evidence_graph import EvidenceGraph, VerifiedReportProjection
from secmind.outcomes import GradeResult
from secmind.schemas import (
    ClaimStatus,
    Finding,
    InvocationStatus,
    OutcomeContract,
    RunStatus,
    StepStatus,
)
from secmind.task_contract import ObligationSet, ObligationStatus, TaskObligation


@dataclass(frozen=True)
class CompletionSnapshot:
    graph: EvidenceGraph
    findings: tuple[Finding, ...]
    contracts: tuple[OutcomeContract, ...]
    contract_grades: Mapping[str, tuple[GradeResult, ...]] = field(default_factory=dict)
    step_statuses: Mapping[str, StepStatus] = field(default_factory=dict)
    invocation_statuses: tuple[InvocationStatus, ...] = ()
    pending_approval_ids: tuple[str, ...] = ()
    report_claim_ids: tuple[str, ...] = ()
    unscanned_scope: tuple[str, ...] = ()
    tool_failures: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    requested_status: RunStatus = RunStatus.RUNNING
    ledger_valid: bool = True
    input_hashes_valid: bool = True
    artifact_hashes_valid: bool = True
    obligations: tuple[TaskObligation, ...] = ()
    obligation_set: ObligationSet | None = None


@dataclass(frozen=True)
class CompletionResult:
    status: RunStatus
    reasons: tuple[str, ...]
    projection: VerifiedReportProjection
    satisfied_contract_ids: tuple[str, ...]
    unsatisfied_contract_ids: tuple[str, ...]

    @property
    def may_report(self) -> bool:
        return self.status in {
            RunStatus.COMPLETED,
            RunStatus.PARTIAL,
            RunStatus.DENIED,
            RunStatus.FAILED,
            RunStatus.RECOVERY_REQUIRED,
        }


class CompletionGate:
    """Only deterministic component allowed to decide whether a run may report completion."""

    TERMINAL_STEPS = {
        StepStatus.SUCCEEDED,
        StepStatus.FAILED,
        StepStatus.SKIPPED,
        StepStatus.CANCELLED,
    }

    def evaluate(self, snapshot: CompletionSnapshot) -> CompletionResult:
        projection = snapshot.graph.verified_report_projection(snapshot.findings)
        reasons: list[str] = []
        satisfied: list[str] = []
        unsatisfied: list[str] = []

        if not snapshot.ledger_valid:
            reasons.append("Ledger hash-chain verification failed.")
        if not snapshot.input_hashes_valid:
            reasons.append("Input hash verification failed.")
        if not snapshot.artifact_hashes_valid:
            reasons.append("Artifact hash verification failed.")
        if reasons:
            return self._result(RunStatus.FAILED, reasons, projection, satisfied, unsatisfied)

        if snapshot.requested_status == RunStatus.DENIED:
            return self._result(
                RunStatus.DENIED,
                ["The policy plane denied the run."],
                projection,
                satisfied,
                unsatisfied,
            )
        if snapshot.requested_status == RunStatus.FAILED:
            return self._result(
                RunStatus.FAILED,
                ["The run entered a terminal failure state."],
                projection,
                satisfied,
                unsatisfied,
            )
        if snapshot.requested_status == RunStatus.RECOVERY_REQUIRED:
            return self._result(
                RunStatus.RECOVERY_REQUIRED,
                ["The run requires operator recovery."],
                projection,
                satisfied,
                unsatisfied,
            )

        uncertain_invocations = {
            InvocationStatus.PENDING,
            InvocationStatus.RUNNING,
            InvocationStatus.RECOVERY_REQUIRED,
        }
        if snapshot.pending_approval_ids or any(
            status in uncertain_invocations for status in snapshot.invocation_statuses
        ):
            reasons.append("The run has unconsumed approvals or uncertain invocations.")
            return self._result(
                RunStatus.RECOVERY_REQUIRED,
                reasons,
                projection,
                satisfied,
                unsatisfied,
            )

        nonterminal_steps = sorted(
            step_id for step_id, status in snapshot.step_statuses.items() if status not in self.TERMINAL_STEPS
        )
        if nonterminal_steps:
            reasons.append(f"Steps are not terminal: {', '.join(nonterminal_steps)}.")
            return self._result(
                RunStatus.RECOVERY_REQUIRED,
                reasons,
                projection,
                satisfied,
                unsatisfied,
            )

        pending_verification = sorted(
            claim.claim_id
            for claim in snapshot.graph.claims
            if claim.status in {ClaimStatus.CANDIDATE, ClaimStatus.SUPPORTED}
        )
        if pending_verification:
            reasons.append(f"Claims have not reached a verifier terminal state: {', '.join(pending_verification)}.")
            return self._result(
                RunStatus.RECOVERY_REQUIRED,
                reasons,
                projection,
                satisfied,
                unsatisfied,
            )

        unresolved_claims = {
            claim.claim_id
            for claim in snapshot.graph.claims
            if claim.status in {ClaimStatus.CONFLICTED, ClaimStatus.INSUFFICIENT}
        }
        verified_claim_ids = {claim.claim_id for claim in snapshot.graph.claims if claim.status == ClaimStatus.VERIFIED}
        unverified_report_claims = sorted(set(snapshot.report_claim_ids) - verified_claim_ids)
        if unverified_report_claims:
            reasons.append(f"The report references unverified claims: {', '.join(unverified_report_claims)}.")
            return self._result(RunStatus.FAILED, reasons, projection, satisfied, unsatisfied)

        obligation_rows = (
            snapshot.obligation_set.task_obligations if snapshot.obligation_set is not None else snapshot.obligations
        )
        critical_open = sorted(
            item.obligation_id
            for item in obligation_rows
            if item.critical and item.status not in {ObligationStatus.SATISFIED, ObligationStatus.WAIVED}
        )
        if critical_open:
            reasons.append("Critical answer obligations remain unresolved: " + ", ".join(critical_open) + ".")
        if snapshot.obligation_set is not None and not snapshot.obligation_set.complete:
            reasons.append(
                "Answer obligation aggregate is "
                f"{snapshot.obligation_set.composite_status.value}: {snapshot.obligation_set.reason}."
            )

        for contract in sorted(snapshot.contracts, key=lambda item: item.contract_id):
            grades = snapshot.contract_grades.get(contract.contract_id, ())
            producers = {
                claim.claim_id
                for claim in snapshot.graph.claims
                if claim.status == ClaimStatus.VERIFIED
                and claim.producer == contract.step_id
                and claim.claim_type in contract.expected_claim_types
            }
            complete_links = all(self._has_verified_support(snapshot.graph, claim_id) for claim_id in producers)
            grades_pass = bool(grades) and all(item.passed for item in grades)
            if producers and complete_links and grades_pass:
                satisfied.append(contract.contract_id)
            else:
                unsatisfied.append(contract.contract_id)

        required_unsatisfied = sorted(
            contract.contract_id
            for contract in snapshot.contracts
            if contract.contract_id in unsatisfied and not contract.allow_partial
        )
        hard_contract_failure = bool(required_unsatisfied)
        if hard_contract_failure:
            reasons.append("Non-partial outcome contracts were not satisfied: " + ", ".join(required_unsatisfied) + ".")
            return self._result(RunStatus.FAILED, reasons, projection, satisfied, unsatisfied)

        optional_step_ids = {contract.step_id for contract in snapshot.contracts if contract.allow_partial}
        blocking_tool_failures = sorted(
            step_id for step_id in snapshot.tool_failures if step_id not in optional_step_ids
        )
        blocking_step_failures = sorted(
            step_id
            for step_id, status in snapshot.step_statuses.items()
            if status in {StepStatus.FAILED, StepStatus.SKIPPED, StepStatus.CANCELLED}
            and step_id not in optional_step_ids
        )

        partial = bool(
            required_unsatisfied
            or critical_open
            or unresolved_claims
            or projection.excluded_finding_ids
            or snapshot.unscanned_scope
            or blocking_tool_failures
            or snapshot.limitations
            or snapshot.requested_status in {RunStatus.PARTIAL, RunStatus.CANCELLED}
            or blocking_step_failures
        )
        if required_unsatisfied:
            reasons.append(f"Required outcome contracts were not satisfied: {', '.join(required_unsatisfied)}.")
        if unresolved_claims:
            reasons.append(f"Claims remain conflicted or insufficient: {', '.join(sorted(unresolved_claims))}.")
        if projection.excluded_finding_ids:
            reasons.append("Unverified findings were excluded from the report projection.")
        if snapshot.unscanned_scope:
            reasons.append("The audit did not cover all requested scope.")
        if blocking_tool_failures:
            reasons.append("One or more audit tools failed.")
        reasons.extend(snapshot.limitations)
        status = RunStatus.PARTIAL if partial else RunStatus.COMPLETED
        return self._result(status, reasons, projection, satisfied, unsatisfied)

    @staticmethod
    def _has_verified_support(graph: EvidenceGraph, claim_id: str) -> bool:
        return any(
            link.relation.value == "supports"
            and link.verifier_status == ClaimStatus.VERIFIED
            and graph.evidence_is_publishable(link.evidence_id)
            for link in graph.links_for_claim(claim_id)
        )

    @staticmethod
    def _result(
        status: RunStatus,
        reasons: list[str],
        projection: VerifiedReportProjection,
        satisfied: list[str],
        unsatisfied: list[str],
    ) -> CompletionResult:
        return CompletionResult(
            status=status,
            reasons=tuple(dict.fromkeys(reasons)),
            projection=projection,
            satisfied_contract_ids=tuple(sorted(satisfied)),
            unsatisfied_contract_ids=tuple(sorted(unsatisfied)),
        )
