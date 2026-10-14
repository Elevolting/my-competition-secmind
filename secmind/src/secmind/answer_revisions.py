"""Compatibility facade for the typed published-answer collaborator API."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any, cast

from pydantic import BaseModel

from secmind.answer_revision_contracts import (
    ActorPatch,
    ApiOperationPatch,
    CompositeStatus,
    ExactAnswerPatch,
    FindingPatch,
    Obligation,
    ProviderIdentity,
    ReceiptBinding,
    RevisionError,
    RevisionField,
    RevisionOperation,
    RevisionPayload,
    ScoringMode,
    TimelineEventPatch,
    canonical_digest,
)
from secmind.answer_revision_materializer import apply_revision, validate_revision
from secmind.answer_revision_obligations import ObligationSet, coerce_mode
from secmind.published_answer_models import (
    PublishedAnswer,
    PublishedAnswerRevision,
    answer_digest,
    revision_digest,
)


def publish_answer(
    *,
    answer_id: str,
    run_id: str,
    task_id: str,
    scoring_mode: ScoringMode | str,
    domain: str,
    provider: ProviderIdentity,
    receipt: ReceiptBinding,
    answer: Any,
    obligations: ObligationSet | None = None,
) -> PublishedAnswer:
    """Validate and publish one typed answer before any revision is admitted."""

    return PublishedAnswer(
        answer_id=answer_id,
        run_id=run_id,
        task_id=task_id,
        scoring_mode=coerce_mode(scoring_mode),
        domain=domain,
        provider=provider,
        receipt=receipt,
        answer=answer,
        obligations=obligations or ObligationSet(scoring_mode="unknown"),
    )


def make_revision(
    base: PublishedAnswer,
    *,
    operation: RevisionOperation | str,
    field: RevisionField | str,
    payload: RevisionPayload | Mapping[str, Any] | None = None,
    target_id: str | None = None,
    reason: str,
    evidence_ids: Iterable[str] = (),
) -> PublishedAnswerRevision:
    """Build one typed revision bound to the current answer digest."""

    op = RevisionOperation(str(operation).casefold())
    revision_field = RevisionField(str(field).casefold())
    typed_payload = _coerce_payload(revision_field, payload)
    effective_target = target_id or (_payload_id(typed_payload) if typed_payload is not None else None)
    identity = {
        "answer_id": base.answer_id,
        "number": base.revision_number + 1,
        "field": revision_field.value,
        "target": effective_target,
        "operation": op.value,
    }
    return PublishedAnswerRevision.create(
        revision_id=f"revision-{canonical_digest(identity)}",
        answer_id=base.answer_id,
        run_id=base.run_id,
        revision_number=base.revision_number + 1,
        base_answer_digest=base.answer_digest,
        operation=op,
        field=revision_field,
        target_id=effective_target,
        payload=typed_payload,
        evidence_ids=tuple(sorted({str(item) for item in evidence_ids if str(item).strip()})),
        reason=reason,
    )


def revise(
    base: PublishedAnswer,
    *,
    operation: RevisionOperation | str,
    field: RevisionField | str,
    payload: RevisionPayload | Mapping[str, Any] | None = None,
    target_id: str | None = None,
    reason: str,
    evidence_ids: Iterable[str] = (),
) -> tuple[PublishedAnswer, PublishedAnswerRevision]:
    revision = make_revision(
        base,
        operation=operation,
        field=field,
        payload=payload,
        target_id=target_id,
        reason=reason,
        evidence_ids=evidence_ids,
    )
    return apply_revision(base, revision), revision


def _coerce_payload(
    field: RevisionField,
    payload: RevisionPayload | Mapping[str, Any] | None,
) -> RevisionPayload | None:
    if payload is None:
        return None
    from secmind.answer_revision_contracts import (
        ActorPatch,
        ApiOperationPatch,
        ExactAnswerPatch,
        FindingPatch,
        TimelineEventPatch,
    )

    if isinstance(payload, (FindingPatch, TimelineEventPatch, ActorPatch, ApiOperationPatch, ExactAnswerPatch)):
        typed = payload
    else:
        model = cast(
            type[BaseModel],
            {
                RevisionField.FINDINGS: FindingPatch,
                RevisionField.TIMELINE: TimelineEventPatch,
                RevisionField.ACTOR: ActorPatch,
                RevisionField.API_OPERATION: ApiOperationPatch,
                RevisionField.EXACT_ANSWER: ExactAnswerPatch,
            }[field],
        )
        typed = cast(RevisionPayload, model.model_validate(payload))
    if _payload_field(typed) != field:
        raise ValueError("typed payload does not match revision field")
    return typed


def _payload_field(payload: RevisionPayload) -> RevisionField:
    from secmind.published_answer_models import _payload_field as resolve_field

    return resolve_field(payload)


def _payload_id(payload: RevisionPayload) -> str:
    from secmind.published_answer_models import _payload_id as resolve_id

    return resolve_id(payload)


apply_published_answer_revision = apply_revision
create_published_answer_revision = make_revision

__all__ = [
    "ActorPatch",
    "ApiOperationPatch",
    "CompositeStatus",
    "ExactAnswerPatch",
    "FindingPatch",
    "Obligation",
    "ObligationSet",
    "ProviderIdentity",
    "PublishedAnswer",
    "PublishedAnswerRevision",
    "ReceiptBinding",
    "RevisionError",
    "RevisionField",
    "RevisionOperation",
    "RevisionPayload",
    "ScoringMode",
    "TimelineEventPatch",
    "answer_digest",
    "apply_published_answer_revision",
    "apply_revision",
    "canonical_digest",
    "create_published_answer_revision",
    "make_revision",
    "publish_answer",
    "revise",
    "revision_digest",
    "validate_revision",
]
