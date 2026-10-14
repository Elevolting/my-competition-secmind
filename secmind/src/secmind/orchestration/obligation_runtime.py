"""Single durable completion-obligation projection for the supervisor graph."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from secmind.answer_revision_contracts import CompositeStatus
from secmind.investigation.contracts import (
    ObligationStatus as InvestigationObligationStatus,
)
from secmind.investigation.contracts import (
    RequirementObligation,
)
from secmind.schemas import AgentState, RunStatus
from secmind.task_contract import (
    CompositeObligation,
    CompositeObligationStatus,
    ObligationKind,
    ObligationSet,
    ObligationStage,
    TaskObligation,
    evaluate_obligation_set,
)

RUNTIME_KEY = "completion_obligation_set"


def refresh_obligation_set(
    state: AgentState,
    answer: Mapping[str, Any],
    *,
    evidence_ids: Sequence[str] = (),
) -> ObligationSet:
    """Evaluate once, persist the sealed set, then project legacy state rows."""

    contract = state.resolved_task_contract
    if contract is None:
        raise ValueError("resolved task contract is required for obligation evaluation")
    result = evaluate_obligation_set(
        contract.obligations,
        answer,
        scoring_mode=contract.scoring_mode,
        evidence_ids=list(evidence_ids),
    )
    state.obligation_status = [item.model_copy(deep=True) for item in result.task_obligations]
    state.audit_coverage[RUNTIME_KEY] = result.model_dump(mode="json")
    return result


def current_obligation_set(state: AgentState) -> ObligationSet | None:
    """Load the durable authority and fail closed on stale compatibility rows."""

    raw = state.audit_coverage.get(RUNTIME_KEY)
    if not isinstance(raw, Mapping):
        return None
    try:
        result = ObligationSet.model_validate(raw)
    except (TypeError, ValueError):
        return None
    projected = tuple(_row_identity(item) for item in result.task_obligations)
    state_rows = tuple(_row_identity(item) for item in state.obligation_status)
    if projected != state_rows:
        return None
    return result


def merge_investigation_obligations(
    state: AgentState,
    answer_set: ObligationSet,
    requirements: Sequence[RequirementObligation],
) -> ObligationSet:
    """Fold scenario/evidence/enhancement requirements into the same set.

    The ``resolved_task_contract`` requirements are compatibility projections
    of ``answer_set`` and are intentionally not duplicated. Only requirements
    explicitly compiled as optional or assurance-only remain non-critical.
    In particular, ``allow_partial`` outcome contracts and the independent
    corroboration target for a high-risk finding affect assurance, not whether
    the requested answer itself was completed.
    """

    merged = list(answer_set.obligations)
    outcome_contracts = {item.contract_id: item for item in state.outcome_contracts}
    for requirement in sorted(requirements, key=lambda item: item.obligation_id):
        if requirement.source_type in {
            "resolved_task_contract",
            "task_obligation_set_receipt",
        }:
            continue
        outcome_contract = outcome_contracts.get(requirement.source_ref)
        optional = bool(
            requirement.source_type in {"optional_enhancement", "high_risk_finding"}
            or (
                requirement.source_type == "outcome_contract"
                and outcome_contract is not None
                and outcome_contract.allow_partial
            )
        )
        stage = {
            "canonical_primary_baseline": ObligationStage.PRIMARY,
            "high_risk_finding": ObligationStage.EVIDENCE,
            "outcome_contract": ObligationStage.ENHANCEMENT if optional else ObligationStage.SCENARIO,
        }.get(requirement.source_type, ObligationStage.SCENARIO)
        status = {
            InvestigationObligationStatus.SATISFIED: CompositeObligationStatus.SATISFIED,
            InvestigationObligationStatus.CONTRADICTED: CompositeObligationStatus.CONFLICTED,
            InvestigationObligationStatus.WAIVED: CompositeObligationStatus.WAIVED,
            InvestigationObligationStatus.CANCELLED: CompositeObligationStatus.BLOCKED,
            InvestigationObligationStatus.OPEN: CompositeObligationStatus.UNVERIFIED,
            InvestigationObligationStatus.UNVERIFIED: CompositeObligationStatus.UNVERIFIED,
        }[requirement.status]
        merged.append(
            CompositeObligation(
                obligation_id=requirement.obligation_id,
                kind=(
                    ObligationKind.OPTIONAL_ENHANCEMENT
                    if optional
                    else (
                        ObligationKind.CORE_ANSWER
                        if stage == ObligationStage.PRIMARY
                        else ObligationKind.EVIDENCE_COVERAGE
                    )
                ),
                target_fields=[requirement.source_ref],
                acceptance_rule="evidence_bound",
                critical=not optional,
                evidence_ids=list(requirement.satisfied_by_evidence_ids),
                reason=requirement.requirement_summary,
                stage=stage,
                status=status,
            )
        )
    result = ObligationSet(scoring_mode=answer_set.scoring_mode, obligations=tuple(merged))
    state.obligation_status = [item.model_copy(deep=True) for item in result.task_obligations]
    state.audit_coverage[RUNTIME_KEY] = result.model_dump(mode="json")
    return result


def critical_investigation_requirements(
    state: AgentState,
    requirements: Sequence[RequirementObligation],
) -> tuple[RequirementObligation, ...]:
    """Return only legacy requirements that are allowed to decide run status.

    The sealed :class:`ObligationSet` is authoritative for typed answer
    fields.  The investigation evaluator remains useful for control-plane and
    evidence work, but must not re-open compatibility projections or optional
    assurance goals as a second completion gate.
    """

    outcome_contracts = {item.contract_id: item for item in state.outcome_contracts}
    critical: list[RequirementObligation] = []
    for requirement in requirements:
        if requirement.source_type in {
            "resolved_task_contract",
            "optional_enhancement",
            "high_risk_finding",
        }:
            continue
        if requirement.source_type == "outcome_contract":
            contract = outcome_contracts.get(requirement.source_ref)
            if contract is not None and contract.allow_partial:
                continue
        critical.append(requirement)
    return tuple(critical)


def clamp_run_status(result: ObligationSet, requested: RunStatus) -> RunStatus:
    """Make typed epistemic status and terminal run status agree.

    Existing policy/integrity terminals are never relaxed. Any unresolved,
    insufficient, conflicted or blocked critical answer remains ``PARTIAL``;
    only a platform policy denial may be ``DENIED``.
    """

    if requested in {
        RunStatus.DENIED,
        RunStatus.FAILED,
        RunStatus.RECOVERY_REQUIRED,
        RunStatus.CANCELLED,
        RunStatus.WAITING_APPROVAL,
        RunStatus.WAITING_CLARIFICATION,
    }:
        return requested
    if result.composite_status == CompositeStatus.COMPLETED:
        return requested
    return RunStatus.PARTIAL


def _row_identity(item: TaskObligation) -> tuple[Any, ...]:
    return (
        item.obligation_id,
        item.kind.value,
        tuple(item.target_fields),
        item.acceptance_rule,
        item.critical,
        item.status.value,
        tuple(item.evidence_ids),
        item.reason,
    )


__all__ = [
    "RUNTIME_KEY",
    "clamp_run_status",
    "critical_investigation_requirements",
    "current_obligation_set",
    "merge_investigation_obligations",
    "refresh_obligation_set",
]
