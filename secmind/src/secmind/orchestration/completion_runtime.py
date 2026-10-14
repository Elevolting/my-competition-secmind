"""Completion-gate graph node extracted from the orchestration façade."""

from __future__ import annotations

from typing import Any
from uuid import NAMESPACE_URL, uuid5

from secmind.completion_gate import CompletionSnapshot
from secmind.evidence_graph import EvidenceGraph
from secmind.investigation.contracts import CompletionOutcome, CompletionReceipt, seal_contract
from secmind.investigation.evidence import ReplanContext
from secmind.orchestration.eirs_runtime import effective_answer_payload
from secmind.orchestration.evidence_projection import (
    build_investigation_evidence_graph,
    build_requirement_obligations,
    outcome_grade_summary,
    verified_direct_first_finding_ids,
    verify_input_artifacts,
)
from secmind.orchestration.obligation_runtime import (
    critical_investigation_requirements,
    current_obligation_set,
    merge_investigation_obligations,
    refresh_obligation_set,
)
from secmind.orchestration.tool_projection_runtime import (
    verify_evidence_artifacts,
    verify_primary_receipt_artifact,
)
from secmind.outcomes import GradeResult, GradeStatus
from secmind.schemas import ClaimStatus, RunStatus, StepStatus


class CompletionQuiescenceError(RuntimeError):
    """The durable control plane did not become quiet inside the bounded wait."""


async def completion_gate(host: Any, value: Any) -> Any:
    state = host._state(value)
    pending_outbox = await host._await_outbox_quiescence(state.run_id)
    if pending_outbox:
        raise CompletionQuiescenceError("durable outbox did not quiesce within the bounded completion wait")
    graph = EvidenceGraph(claims=state.claims, evidence=state.evidence, links=state.evidence_links)
    contract_grades = {
        contract_id: tuple(
            GradeResult(
                grader_id=str(item["grader_id"]),
                status=GradeStatus(str(item["status"])),
                reason=str(item["reason"]),
                requested_evidence_types=tuple(item.get("requested_evidence_types", [])),
            )
            for item in grades
        )
        for contract_id, grades in state.contract_grades.items()
    }
    failed_steps = tuple(
        step_id for step_id, runtime in state.step_runtime.items() if runtime.status == StepStatus.FAILED
    )
    ledger_valid = host.ledger.verify(state.run_id)
    artifact_hashes_valid = verify_evidence_artifacts(host, state.evidence) and verify_primary_receipt_artifact(
        host, state
    )
    obligation_set = current_obligation_set(state)
    if state.resolved_task_contract is not None:
        obligation_set = refresh_obligation_set(
            state,
            effective_answer_payload(state) if state.report is not None else {},
            evidence_ids=[item.evidence_id for item in state.evidence],
        )
    evidence_graph = build_investigation_evidence_graph(state, graph)
    obligations = build_requirement_obligations(state, evidence_graph)
    critical_requirements = critical_investigation_requirements(state, obligations)
    if obligation_set is not None:
        obligation_set = merge_investigation_obligations(state, obligation_set, obligations)
    result = host.completion_gate.evaluate(
        CompletionSnapshot(
            graph=graph,
            findings=tuple(state.findings),
            contracts=tuple(state.outcome_contracts),
            contract_grades=contract_grades,
            step_statuses={key: item.status for key, item in state.step_runtime.items()},
            pending_approval_ids=tuple(item.request_id for item in state.pending_approvals),
            tool_failures=failed_steps,
            requested_status=state.status,
            ledger_valid=ledger_valid,
            artifact_hashes_valid=artifact_hashes_valid,
            obligations=tuple(state.obligation_status),
            obligation_set=obligation_set,
        )
    )
    optional_contract_ids = {item.contract_id for item in state.outcome_contracts if item.allow_partial}
    state.audit_coverage["optional_outcome_contracts"] = {
        "unsatisfied_contract_ids": sorted(optional_contract_ids.intersection(result.unsatisfied_contract_ids)),
        "satisfied_contract_ids": sorted(optional_contract_ids.intersection(result.satisfied_contract_ids)),
        "affects_terminal_status": False,
    }
    state.status = result.status
    state.completion_reasons = list(result.reasons)
    direct_first_finding_ids = verified_direct_first_finding_ids(state)
    investigation_findings = [item for item in state.findings if item.finding_id not in direct_first_finding_ids]
    high_risk_requirements = [item for item in obligations if item.source_type == "high_risk_finding"]
    state.audit_coverage["optional_high_risk_assurance"] = {
        "finding_ids": sorted(
            item.finding_id for item in investigation_findings if item.severity in {"HIGH", "CRITICAL"}
        ),
        "satisfied_obligation_ids": sorted(
            item.obligation_id for item in high_risk_requirements if item.status.value == "satisfied"
        ),
        "unsatisfied_obligation_ids": sorted(
            item.obligation_id for item in high_risk_requirements if item.status.value != "satisfied"
        ),
        "affects_terminal_status": False,
    }
    active_steps = host.coordinator.active_step_lease_ids(state.run_id) if host.coordinator is not None else []
    active_invocations = host.broker.active_invocation_ids(state.run_id)
    unsettled = (
        host.investigation_store.unsettled_reservation_ids(state.run_id) if host.investigation_store is not None else []
    )
    snapshot = host.investigation_completion.build_snapshot(
        snapshot_id=str(
            uuid5(
                NAMESPACE_URL,
                f"secmind:completion-snapshot:{state.run_id}:{state.state_version}:{state.transition_counter + 1}",
            )
        ),
        run_id=state.run_id,
        run_state_version=state.state_version,
        run_fence=max(1, state.lease.fence),
        quiet_epoch=state.transition_counter + 1,
        active_sessions=[],
        active_step_leases=active_steps,
        active_invocations=active_invocations,
        unsettled_reservations=unsettled,
        pending_approvals=sorted(
            {
                *[item.request_id for item in state.pending_approvals],
                *([state.pending_approval.request_id] if state.pending_approval is not None else []),
            }
        ),
        pending_clarifications=(
            [state.pending_clarification.request_id] if state.pending_clarification is not None else []
        ),
        open_evidence_requests=sorted(state.active_evidence_request_ids),
        pending_replan=False,
        cancel_intent=state.cancel_requested,
        unprojected_outbox_ordinals=pending_outbox,
        input_integrity=verify_input_artifacts(state),
        artifact_integrity=artifact_hashes_valid,
        evidence_integrity=ledger_valid,
        ledger_integrity=ledger_valid,
        requirement_obligations=sorted(item.obligation_id for item in critical_requirements),
        outcome_grades=outcome_grade_summary(state),
        report_claim_ids=sorted(item.claim_id for item in state.claims if item.status == ClaimStatus.VERIFIED),
        unscanned_scope=list(result.projection.excluded_finding_ids),
        # CompletionGate reasons are an output of the first projection, not
        # facts that the legacy investigation evaluator may feed back into the
        # next status decision.
        limitations=[],
    )
    replan_context = ReplanContext(
        plan_revision=state.replan_count,
        supplement_round=state.verification_rounds,
        budget_available=(
            state.audit_coverage.get("augmentation_status") != "skipped"
            and state.budget.steps_used < state.budget.max_steps
            and state.budget.tool_calls_used < state.budget.max_tool_calls
            and len(state.plan) < state.budget.max_steps
        ),
        approved_independent_source_available=False,
    )
    evaluation = host.investigation_completion.evaluate(
        snapshot,
        obligations=critical_requirements,
        evidence_graph=evidence_graph,
        findings=[],
        replan_context=replan_context,
    )
    supplement_proposals = host.gap_supplement_planner.propose(
        evaluation.gaps,
        claims=state.claims,
        plan=state.plan,
        manifests=host.broker.registry.manifests(),
        scenario=state.scenario,
        supplement_round=state.verification_rounds,
    )
    if supplement_proposals:
        replan_context = ReplanContext(
            plan_revision=state.replan_count,
            supplement_round=state.verification_rounds,
            budget_available=replan_context.budget_available,
            approved_independent_source_available=True,
        )
        evaluation = host.investigation_completion.evaluate(
            snapshot,
            obligations=critical_requirements,
            evidence_graph=evidence_graph,
            findings=[],
            replan_context=replan_context,
        )
    forced_outcome = {
        RunStatus.DENIED: CompletionOutcome.DENIED,
        RunStatus.CANCELLED: CompletionOutcome.CANCELLED,
        RunStatus.FAILED: CompletionOutcome.RECOVERY_REQUIRED,
        RunStatus.RECOVERY_REQUIRED: CompletionOutcome.RECOVERY_REQUIRED,
    }.get(result.status)
    if (
        forced_outcome is None
        and evaluation.outcome == CompletionOutcome.SUPPLEMENT
        and supplement_proposals
        and host._materialize_completion_gap_supplement(state, supplement_proposals)
    ):
        state.completion_reasons = sorted({*state.completion_reasons, evaluation.rationale})
        return await host._checkpoint(
            state,
            "completion.supplement.requested",
            {
                "gap_ids": [item.gap_id for item in evaluation.gaps],
                "proposal_tools": [item.tool_name for item in supplement_proposals],
                "supplement_round": state.verification_rounds,
            },
            "schedule",
        )
    if forced_outcome is None and evaluation.outcome == CompletionOutcome.SUPPLEMENT:
        evaluation = host.investigation_completion.evaluate(
            snapshot,
            obligations=critical_requirements,
            evidence_graph=evidence_graph,
            findings=[],
            replan_context=ReplanContext(
                plan_revision=state.replan_count,
                supplement_round=state.verification_rounds,
                budget_available=replan_context.budget_available,
                approved_independent_source_available=False,
            ),
        )
    if forced_outcome is None and evaluation.outcome == CompletionOutcome.CONTINUE:
        raise CompletionQuiescenceError("completion control plane still contains active work")
    state.status = result.status
    if evaluation.unsatisfied_obligation_ids:
        state.audit_coverage["investigation_unsatisfied_obligation_ids"] = list(evaluation.unsatisfied_obligation_ids)
    if forced_outcome is None and evaluation.unsatisfied_obligation_ids and state.status == RunStatus.COMPLETED:
        state.status = RunStatus.PARTIAL
    final_outcome = forced_outcome or {
        RunStatus.COMPLETED: CompletionOutcome.COMPLETE,
        RunStatus.PARTIAL: CompletionOutcome.PARTIAL,
        RunStatus.CANCELLED: CompletionOutcome.CANCELLED,
        RunStatus.WAITING_APPROVAL: CompletionOutcome.AWAITING_APPROVAL,
        RunStatus.WAITING_CLARIFICATION: CompletionOutcome.AWAITING_USER_DECISION,
        RunStatus.DENIED: CompletionOutcome.DENIED,
        RunStatus.FAILED: CompletionOutcome.RECOVERY_REQUIRED,
        RunStatus.RECOVERY_REQUIRED: CompletionOutcome.RECOVERY_REQUIRED,
    }.get(state.status, CompletionOutcome.PARTIAL)
    final_rationale = (
        {
            CompletionOutcome.DENIED: "the policy plane denied the run before terminal reporting",
            CompletionOutcome.CANCELLED: "the operator cancelled the run before terminal reporting",
            CompletionOutcome.RECOVERY_REQUIRED: "the run failed closed and requires durable recovery",
        }.get(forced_outcome)
        if forced_outcome is not None
        else (
            evaluation.rationale
            if evaluation.outcome in {CompletionOutcome.COMPLETE, CompletionOutcome.PARTIAL}
            else "legacy investigation gaps were projected as typed partial limitations"
        )
    )
    state.completion_reasons = sorted({*state.completion_reasons, final_rationale or evaluation.rationale})
    receipt = seal_contract(
        CompletionReceipt,
        digest_field="receipt_digest",
        receipt_id=str(uuid5(NAMESPACE_URL, f"secmind:completion-receipt:{snapshot.snapshot_id}")),
        run_id=state.run_id,
        snapshot_id=snapshot.snapshot_id,
        decision=(
            CompletionOutcome.PARTIAL
            if final_outcome == CompletionOutcome.COMPLETE and state.status != RunStatus.COMPLETED
            else final_outcome
        ),
        satisfied_obligation_ids=(list(evaluation.satisfied_obligation_ids)),
        unsatisfied_obligation_ids=(
            [] if final_outcome == CompletionOutcome.COMPLETE else list(evaluation.unsatisfied_obligation_ids)
        ),
        verification_receipt_ids=sorted(
            item.verifier_receipt_id for item in critical_requirements if item.verifier_receipt_id is not None
        ),
        gate_rule_version="authoritative-task-obligation-gate-v0.8.4",
    )
    # Keep the complete, digest-sealed pair in durable private state.  Public
    # coverage exposes only a bounded digest summary (see public_coverage.py),
    # while the terminal validator can still prove run/snapshot/receipt
    # linkage instead of trusting two opaque identifier strings.
    state.audit_coverage["completion_proof"] = {
        "snapshot": snapshot.model_dump(mode="json"),
        "receipt": receipt.model_dump(mode="json"),
    }
    state.completion_snapshot_id = snapshot.snapshot_id
    state.completion_receipt_id = receipt.receipt_id
    return await host._checkpoint(
        state,
        "completion.gated",
        {
            "status": state.status.value,
            "reasons": list(state.completion_reasons),
            "verified_claim_ids": list(result.projection.claim_ids),
            "excluded_finding_ids": list(result.projection.excluded_finding_ids),
            "satisfied_contract_ids": list(result.satisfied_contract_ids),
            "unsatisfied_contract_ids": list(result.unsatisfied_contract_ids),
            "snapshot_id": snapshot.snapshot_id,
            "receipt_id": receipt.receipt_id,
            "completion_outcome": receipt.decision.value,
        },
        "report",
        completion_snapshot=snapshot,
        completion_receipt=receipt,
        completion_obligations=tuple(obligations),
    )


__all__ = ["CompletionQuiescenceError", "completion_gate"]
