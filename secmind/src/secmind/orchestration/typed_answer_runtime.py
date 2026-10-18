"""Durable typed answer projection for the Primary/EIRS/report path.

The public ``AgentState.answer_revisions`` field belongs to the legacy JSON
pointer dialect.  The product path uses the immutable ``PublishedAnswer``
envelope instead.  This module keeps that envelope and its typed revisions in
the durable ``audit_coverage`` projection so checkpoints and replay carry one
validated authority chain without changing the public schema version.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from secmind.answer_revision_contracts import (
    ActorPatch,
    ApiOperationPatch,
    ExactAnswerPatch,
    FindingPatch,
    ProviderIdentity,
    ReceiptBinding,
    RevisionField,
    RevisionOperation,
    ScoringMode,
    TimelineEventPatch,
)
from secmind.answer_revisions import apply_revision, publish_answer, revise
from secmind.domain_answers import normalize_domain_answer
from secmind.orchestration.obligation_runtime import current_obligation_set
from secmind.published_answer_models import PublishedAnswer, PublishedAnswerRevision
from secmind.schemas import AgentState

RUNTIME_KEY = "typed_answer_runtime"
_DOMAIN_BY_MODE = {
    ScoringMode.SECURITY_FINDING: "code_audit_and_patch",
    ScoringMode.REVERSE_BEHAVIOR: "forensics_static_reverse",
    ScoringMode.EVIDENCE_GAP: "orchestration_recovery_uncertainty",
    ScoringMode.AGENT_POLICY_COMPLIANCE: "agent_safety",
    ScoringMode.FORENSIC_ATTRIBUTION: "logs_ir_hunting",
    ScoringMode.EXACT_ANSWER_WITH_EVIDENCE: "complex_input_understanding",
    ScoringMode.PATCH_VALIDATOR: "code_audit_and_patch",
}


def publish_baseline_answer(state: AgentState) -> PublishedAnswer | None:
    """Create the typed answer only after the immutable baseline is admitted."""

    baseline = state.published_baseline
    receipt = state.raw_primary_receipt
    contract = state.resolved_task_contract
    if baseline is None or receipt is None or contract is None:
        return None
    existing = _load_runtime(state)
    if existing is not None:
        active, _revisions = existing
        return project_active_answer(state, active)
    route = state.audit_coverage.get("primary_route")
    provider_name = route.get("provider") if isinstance(route, dict) else None
    if not isinstance(provider_name, str) or not provider_name.strip():
        return None
    try:
        mode = ScoringMode(str(contract.scoring_mode).casefold())
        answer_payload = dict(baseline.answer_payload)
        answer = normalize_domain_answer(mode.value, answer_payload)
        if answer.task_id != answer_payload.get("task_id"):
            return None
        provider = ProviderIdentity(
            provider=provider_name,
            model_id=receipt.model_id,
            request_id=receipt.receipt_id,
            request_digest=receipt.request_sha256,
            response_digest=receipt.response_sha256,
            response_schema_digest=receipt.response_schema_sha256,
            provider_requests=max(1, receipt.provider_requests),
        )
        binding = ReceiptBinding.create(
            receipt_id=receipt.receipt_id,
            provider=provider.provider,
            model_id=receipt.model_id,
            request_digest=receipt.request_sha256,
            response_digest=receipt.response_sha256,
            response_schema_digest=receipt.response_schema_sha256,
            context_digest=receipt.context_sha256,
            raw_digest=receipt.response_artifact_id,
        )
        published = publish_answer(
            answer_id=f"answer-{baseline.projection_id}",
            run_id=state.run_id,
            task_id=answer.task_id,
            scoring_mode=mode,
            domain=_answer_domain(contract.primary_domain, mode),
            provider=provider,
            receipt=binding,
            answer=answer,
            obligations=current_obligation_set(state),
        )
    except (TypeError, ValueError):
        return None
    _save_runtime(state, published, (), base=published)
    return project_active_answer(state, published)


def project_active_answer(state: AgentState, active: PublishedAnswer | None = None) -> PublishedAnswer:
    """Replay and project the durable active typed answer into ``AgentReport``."""

    if active is None:
        loaded = _load_runtime(state)
        if loaded is None:
            raise ValueError("typed answer runtime is absent or invalid")
        active, _revisions = loaded
    if state.report is None:
        raise ValueError("typed answer projection requires a report")
    state.report = state.report.model_copy(
        update={
            "answer_type": active.answer.answer_kind,
            "answer_payload": active.answer.model_dump(mode="json"),
            "coverage": dict(state.audit_coverage),
        }
    )
    return active


def active_answer(state: AgentState) -> PublishedAnswer | None:
    loaded = _load_runtime(state)
    return None if loaded is None else loaded[0]


def revise_active_answer(
    state: AgentState,
    *,
    operation: RevisionOperation,
    field: RevisionField,
    payload: FindingPatch | TimelineEventPatch | ActorPatch | ApiOperationPatch | ExactAnswerPatch | None,
    target_id: str | None,
    reason: str,
    evidence_ids: Sequence[str],
) -> tuple[PublishedAnswer, PublishedAnswerRevision] | None:
    """Apply one typed revision and persist its replayable chain."""

    loaded = _load_runtime(state)
    if loaded is None:
        return None
    base, revisions = loaded
    try:
        active, revision = revise(
            base,
            operation=operation,
            field=field,
            payload=payload,
            target_id=target_id,
            reason=reason,
            evidence_ids=evidence_ids,
        )
    except (TypeError, ValueError):
        return None
    if any(item.revision_id == revision.revision_id for item in revisions):
        return project_active_answer(state, base), revision
    _save_runtime(state, active, (*revisions, revision), base=_published_base(state, base))
    project_active_answer(state, active)
    return active, revision


def replay_typed_answer(state: AgentState) -> PublishedAnswer | None:
    """Validate the persisted chain exactly as a recovery/replay worker would."""

    loaded = _load_runtime(state)
    return None if loaded is None else loaded[0]


def _load_runtime(state: AgentState) -> tuple[PublishedAnswer, tuple[PublishedAnswerRevision, ...]] | None:
    raw = state.audit_coverage.get(RUNTIME_KEY)
    if not isinstance(raw, Mapping):
        return None
    try:
        base = PublishedAnswer.model_validate(raw["published_answer"])
        active = PublishedAnswer.model_validate(raw["active_answer"])
        revisions = tuple(PublishedAnswerRevision.model_validate(item) for item in raw.get("revisions", ()))
        if base.revision_number != 0 or base.revision_ids or active.receipt != base.receipt:
            return None
        replayed = base
        for revision in revisions:
            replayed = apply_revision(replayed, revision)
        if replayed != active or active.answer_digest != replayed.answer_digest:
            return None
        return active, revisions
    except (TypeError, ValueError):
        return None


def _save_runtime(
    state: AgentState,
    active: PublishedAnswer,
    revisions: Sequence[PublishedAnswerRevision],
    *,
    base: PublishedAnswer,
) -> None:
    state.audit_coverage[RUNTIME_KEY] = {
        "version": "typed-answer-runtime-1",
        "published_answer": base.model_dump(mode="json"),
        "active_answer": active.model_dump(mode="json"),
        "revisions": [item.model_dump(mode="json") for item in revisions],
        "base_answer_digest": base.answer_digest,
        "active_answer_digest": active.answer_digest,
        "revision_ids": list(active.revision_ids),
    }


def _published_base(state: AgentState, fallback: PublishedAnswer) -> PublishedAnswer:
    raw = state.audit_coverage.get(RUNTIME_KEY)
    if isinstance(raw, Mapping):
        try:
            return PublishedAnswer.model_validate(raw["published_answer"])
        except (TypeError, ValueError):
            pass
    return fallback.model_copy(update={"revision_ids": (), "revision_number": 0})


def _answer_domain(value: str | None, mode: ScoringMode) -> str:
    candidate = value.strip() if isinstance(value, str) else ""
    accepted = {
        ScoringMode.SECURITY_FINDING: {"code_audit_and_patch", "code", "security_finding"},
        ScoringMode.REVERSE_BEHAVIOR: {"forensics_static_reverse", "reverse", "reverse_behavior"},
        ScoringMode.EVIDENCE_GAP: {"orchestration_recovery_uncertainty", "evidence_gap"},
        ScoringMode.AGENT_POLICY_COMPLIANCE: {"agent_safety", "policy", "agent_policy_compliance"},
        ScoringMode.FORENSIC_ATTRIBUTION: {"logs_ir_hunting", "forensics", "forensic_attribution"},
        ScoringMode.EXACT_ANSWER_WITH_EVIDENCE: {
            "complex_input_understanding",
            "api_assessment",
            "logs_ir_hunting",
            "forensics",
            "exact_answer_with_evidence",
        },
        ScoringMode.PATCH_VALIDATOR: {"code_audit_and_patch", "code", "patch_validator"},
    }[mode]
    return candidate if candidate in accepted else _DOMAIN_BY_MODE[mode]


__all__ = [
    "RUNTIME_KEY",
    "active_answer",
    "project_active_answer",
    "publish_baseline_answer",
    "replay_typed_answer",
    "revise_active_answer",
]
