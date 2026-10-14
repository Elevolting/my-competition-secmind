"""Typed-answer facade over the authoritative completion obligation set.

Historically this module implemented a second rule table and a second status
aggregator. That let ``PublishedAnswer.status`` disagree with the supervisor's
``AgentState.obligation_status``. Public imports remain here, but all rule
compilation and aggregation now live in :mod:`secmind.task_contract`.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from secmind.answer_revision_contracts import CompositeStatus, Obligation, ProviderIdentity, ScoringMode
from secmind.domain_answers import (
    DomainAnswerBase,
    EvidenceGapAnswer,
    ExactAnswer,
    FindingAnswer,
    PatchValidationAnswer,
    PolicyDecisionAnswer,
    ReverseBehaviorAnswer,
    TimelineAnswer,
    normalize_domain_answer,
)
from secmind.task_contract import (
    CompositeObligation,
    CompositeObligationStatus,
    ObligationKind,
    ObligationSet,
    ObligationStage,
    TaskObligation,
    compile_obligation_templates,
    evaluate_obligation_set,
)
from secmind.task_contract import (
    derive_composite_status as _derive_composite_status,
)

_ANSWER_MODELS: dict[ScoringMode, type[DomainAnswerBase]] = {
    ScoringMode.SECURITY_FINDING: FindingAnswer,
    ScoringMode.REVERSE_BEHAVIOR: ReverseBehaviorAnswer,
    ScoringMode.EVIDENCE_GAP: EvidenceGapAnswer,
    ScoringMode.AGENT_POLICY_COMPLIANCE: PolicyDecisionAnswer,
    ScoringMode.FORENSIC_ATTRIBUTION: TimelineAnswer,
    ScoringMode.EXACT_ANSWER_WITH_EVIDENCE: ExactAnswer,
    ScoringMode.PATCH_VALIDATOR: PatchValidationAnswer,
}

_MODE_DOMAINS: dict[ScoringMode, frozenset[str]] = {
    ScoringMode.SECURITY_FINDING: frozenset({"code_audit_and_patch", "code", "security_finding"}),
    ScoringMode.REVERSE_BEHAVIOR: frozenset({"forensics_static_reverse", "reverse", "reverse_behavior"}),
    ScoringMode.EVIDENCE_GAP: frozenset({"orchestration_recovery_uncertainty", "evidence_gap"}),
    ScoringMode.AGENT_POLICY_COMPLIANCE: frozenset({"agent_safety", "policy", "agent_policy_compliance"}),
    ScoringMode.FORENSIC_ATTRIBUTION: frozenset({"logs_ir_hunting", "forensics", "forensic_attribution"}),
    ScoringMode.EXACT_ANSWER_WITH_EVIDENCE: frozenset(
        {
            "complex_input_understanding",
            "api_assessment",
            "logs_ir_hunting",
            "forensics",
            "exact_answer_with_evidence",
        }
    ),
    ScoringMode.PATCH_VALIDATOR: frozenset({"code_audit_and_patch", "code", "patch_validator"}),
}


def coerce_mode(value: ScoringMode | str) -> ScoringMode:
    if isinstance(value, ScoringMode):
        return value
    try:
        return ScoringMode(str(value).casefold())
    except ValueError as exc:
        raise ValueError(f"unsupported scoring_mode: {value}") from exc


def answer_model(mode: ScoringMode) -> type[DomainAnswerBase]:
    return _ANSWER_MODELS[mode]


def coerce_answer(mode: ScoringMode, answer: DomainAnswerBase | Mapping[str, Any]) -> DomainAnswerBase:
    if isinstance(answer, DomainAnswerBase):
        if not isinstance(answer, _ANSWER_MODELS[mode]):
            raise ValueError(f"answer schema does not match scoring_mode {mode.value}")
        return answer
    if not isinstance(answer, Mapping):
        raise TypeError("answer must be a typed domain answer or object")
    raw = dict(answer)
    if {"answer_kind", "execution_status", "epistemic_status"}.issubset(raw):
        return _ANSWER_MODELS[mode].model_validate(raw)
    typed = normalize_domain_answer(mode.value, raw)
    supplied_extensions = raw.get("extensions")
    if isinstance(supplied_extensions, Mapping):
        merged = dict(typed.extensions)
        merged.update(supplied_extensions)
        object.__setattr__(typed, "extensions", merged)
    return typed


def build_obligations(
    mode: ScoringMode,
    answer: DomainAnswerBase,
    provider: ProviderIdentity | None,
) -> list[CompositeObligation]:
    """Compatibility helper projected from the one canonical evaluator."""

    _ = provider
    templates = compile_obligation_templates("published", mode.value)
    return list(
        evaluate_obligation_set(
            templates,
            answer.model_dump(mode="python"),
            scoring_mode=mode.value,
        ).obligations
    )


def task_obligations(value: ObligationSet) -> tuple[TaskObligation, ...]:
    """Explicit compatibility projection for state schema consumers."""

    return value.task_obligations


def derive_composite_status(
    obligations: Iterable[CompositeObligation | Obligation],
) -> tuple[CompositeStatus, str]:
    """Delegate old answer-obligation rows to the canonical aggregator."""

    projected: list[CompositeObligation] = []
    for item in obligations:
        if isinstance(item, CompositeObligation):
            projected.append(item)
            continue
        projected.append(
            CompositeObligation(
                obligation_id=(item.obligation_id if len(item.obligation_id) >= 8 else f"compat-{item.obligation_id}"),
                kind=ObligationKind.CORE_ANSWER,
                target_fields=[item.field],
                acceptance_rule="any_nonempty",
                critical=item.critical,
                evidence_ids=list(item.evidence_ids),
                reason=item.reason,
                stage=ObligationStage.PRIMARY,
                status={
                    "satisfied": CompositeObligationStatus.SATISFIED,
                    "unverified": CompositeObligationStatus.UNVERIFIED,
                    "contradicted": CompositeObligationStatus.CONFLICTED,
                    "waived": CompositeObligationStatus.WAIVED,
                }[item.status],
            )
        )
    return _derive_composite_status(projected)


__all__ = [
    "CompositeObligation",
    "ObligationSet",
    "_MODE_DOMAINS",
    "answer_model",
    "build_obligations",
    "coerce_answer",
    "coerce_mode",
    "derive_composite_status",
    "task_obligations",
]
