"""Immutable answer/revision envelopes for the typed Primary projection."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, Self, cast

from pydantic import BaseModel, ConfigDict, Field, model_validator

from secmind.answer_revision_contracts import (
    SHA256_PATTERN,
    CompositeStatus,
    ProviderIdentity,
    ReceiptBinding,
    RevisionField,
    RevisionOperation,
    RevisionPayload,
    ScoringMode,
    canonical_digest,
)
from secmind.answer_revision_obligations import (
    _MODE_DOMAINS,
    ObligationSet,
    answer_model,
    coerce_answer,
    coerce_mode,
)
from secmind.domain_answers import DomainAnswer, DomainAnswerBase


class PublishedAnswer(BaseModel):
    """Immutable typed answer projection and its derived completion contract."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    answer_id: str = Field(min_length=1, max_length=256)
    run_id: str = Field(min_length=1, max_length=256)
    task_id: str = Field(min_length=1, max_length=256)
    scoring_mode: ScoringMode
    domain: str = Field(min_length=1, max_length=128)
    provider: ProviderIdentity
    receipt: ReceiptBinding
    answer: DomainAnswer
    answer_digest: str = Field(default="", pattern=r"^[a-f0-9]{0,64}$")
    status: CompositeStatus = CompositeStatus.PARTIAL
    obligations: ObligationSet = Field(default_factory=lambda: ObligationSet(scoring_mode="unknown"))
    revision_ids: tuple[str, ...] = ()
    revision_number: int = Field(default=0, ge=0)
    published_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @model_validator(mode="before")
    @classmethod
    def normalize_input(cls, value: Any) -> Any:
        if not isinstance(value, Mapping):
            return value
        payload = dict(value)
        mode = coerce_mode(payload.get("scoring_mode", ScoringMode.SECURITY_FINDING))
        supplied_obligations = payload.get("obligations")
        if isinstance(supplied_obligations, Mapping) and "scoring_mode" not in supplied_obligations:
            # v0.8.4 checkpoints carried the removed second obligation
            # dialect. It was always derived, so recovery safely discards and
            # deterministically recompiles it from the typed answer.
            payload.pop("obligations", None)
            payload.pop("status", None)
        raw_answer = payload.get("answer")
        if raw_answer is None:
            fields = set(answer_model(mode).model_fields)
            raw_answer = {key: payload.pop(key) for key in list(payload) if key in fields}
        if not isinstance(raw_answer, DomainAnswerBase):
            raw_answer = coerce_answer(mode, raw_answer if isinstance(raw_answer, Mapping) else {})
        payload["answer"] = raw_answer
        payload.setdefault("task_id", raw_answer.task_id)
        payload.setdefault("domain", mode.value)
        provider = payload.get("provider")
        if hasattr(provider, "model_dump") and not isinstance(provider, ProviderIdentity):
            provider = cast(BaseModel, provider).model_dump(mode="python")
            payload["provider"] = provider
        if isinstance(provider, str):
            payload["provider"] = _provider_from_shorthand(provider, payload)
        provider_name = (
            provider.provider
            if isinstance(provider, ProviderIdentity)
            else (
                str(provider.get("provider") or "unknown")
                if isinstance(provider, Mapping)
                else str(provider or "unknown")
            )
        )
        receipt = payload.get("receipt")
        if hasattr(receipt, "model_dump") and not isinstance(receipt, ReceiptBinding):
            payload["receipt"] = ReceiptBinding.from_raw_primary(receipt, provider=provider_name)
        elif isinstance(receipt, Mapping) and "receipt_digest" not in receipt:
            payload["receipt"] = _receipt_from_mapping(receipt)
        return payload

    @model_validator(mode="after")
    def validate_and_derive(self) -> Self:
        if self.answer.task_id != self.task_id:
            raise ValueError("answer task_id does not match PublishedAnswer")
        if (
            self.receipt.provider != self.provider.provider
            or self.receipt.model_id != self.provider.model_id
            or self.receipt.response_digest != self.provider.response_digest
        ):
            raise ValueError("receipt and provider identities do not match")
        if self.domain not in _MODE_DOMAINS[self.scoring_mode]:
            raise ValueError(f"domain {self.domain!r} is not valid for scoring_mode {self.scoring_mode.value}")
        expected = answer_digest(self)
        if self.answer_digest and self.answer_digest != expected:
            raise ValueError("answer_digest does not match answer content")
        object.__setattr__(self, "answer_digest", expected)
        templates = (
            list(self.obligations.task_obligations)
            if self.obligations.obligations and self.obligations.scoring_mode == self.scoring_mode.value
            else None
        )
        evidence_ids = sorted(
            {evidence_id for item in self.obligations.obligations for evidence_id in item.evidence_ids}
        )
        derived = ObligationSet.from_answer(
            scoring_mode=self.scoring_mode,
            answer=self.answer,
            provider=self.provider,
            templates=templates,
            evidence_ids=evidence_ids,
        )
        object.__setattr__(self, "obligations", derived)
        object.__setattr__(self, "status", derived.status)
        return self

    def apply_revision(self, revision: PublishedAnswerRevision) -> PublishedAnswer:
        from secmind.answer_revision_materializer import apply_revision

        return apply_revision(self, revision)


class PublishedAnswerRevision(BaseModel):
    """One immutable typed correction against exactly one answer digest."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    revision_id: str = Field(min_length=1, max_length=256)
    answer_id: str = Field(min_length=1, max_length=256)
    run_id: str = Field(min_length=1, max_length=256)
    revision_number: int = Field(ge=1)
    base_answer_digest: str = Field(pattern=SHA256_PATTERN)
    operation: RevisionOperation
    field: RevisionField
    target_id: str | None = Field(default=None, max_length=256)
    payload: RevisionPayload | None = None
    evidence_ids: tuple[str, ...] = ()
    reason: str = Field(min_length=1, max_length=2_000)
    revision_digest: str = Field(default="", pattern=r"^[a-f0-9]{0,64}$")
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @model_validator(mode="before")
    @classmethod
    def normalize_aliases(cls, value: Any) -> Any:
        if not isinstance(value, Mapping):
            return value
        payload = dict(value)
        for source, target in (
            ("action", "operation"),
            ("revision_type", "operation"),
            ("section", "field"),
            ("target_type", "field"),
            ("value", "payload"),
            ("replacement", "payload"),
            ("correction", "payload"),
        ):
            if target not in payload and source in payload:
                payload[target] = payload[source]
        if payload.get("operation") == "replace_field":
            payload["operation"] = "replace"
        field_aliases = {
            "finding": "findings",
            "timeline_event": "timeline",
            "actors": "actor",
            "api_operations": "api_operation",
            "exact": "exact_answer",
        }
        if payload.get("field") in field_aliases:
            payload["field"] = field_aliases[payload["field"]]
        return payload

    @model_validator(mode="after")
    def validate_shape_and_digest(self) -> Self:
        if self.operation == RevisionOperation.RETRACT:
            if not self.target_id:
                raise ValueError("retract revision requires target_id")
            if self.payload is not None:
                raise ValueError("retract revision cannot include a replacement payload")
        elif self.payload is None:
            raise ValueError(f"{self.operation.value} revision requires a typed payload")
        if self.operation == RevisionOperation.REPLACE and not self.target_id:
            raise ValueError("replace revision requires target_id")
        if self.payload is not None:
            expected = _payload_field(self.payload)
            if expected != self.field:
                raise ValueError(f"payload type {expected.value} does not match revision field {self.field.value}")
            if self.target_id is not None and _payload_id(self.payload) != self.target_id:
                raise ValueError("revision target_id does not match typed payload id")
        digest = revision_digest(self)
        if self.revision_digest not in {"", "0" * 64} and self.revision_digest != digest:
            raise ValueError("revision_digest does not match revision content")
        object.__setattr__(self, "revision_digest", digest)
        return self

    def apply_to(self, base: PublishedAnswer) -> PublishedAnswer:
        from secmind.answer_revision_materializer import apply_revision

        return apply_revision(base, self)

    @classmethod
    def create(cls, **values: Any) -> Self:
        return cls.model_validate(values)


def answer_digest(answer: PublishedAnswer | DomainAnswerBase | Mapping[str, Any]) -> str:
    if isinstance(answer, PublishedAnswer):
        payload = {
            "answer_id": answer.answer_id,
            "run_id": answer.run_id,
            "task_id": answer.task_id,
            "scoring_mode": answer.scoring_mode.value,
            "domain": answer.domain,
            "provider": answer.provider.model_dump(mode="json"),
            "receipt": answer.receipt.model_dump(mode="json"),
            "answer": answer.answer.model_dump(mode="json"),
            "revision_number": answer.revision_number,
        }
    elif isinstance(answer, DomainAnswerBase):
        payload = answer.model_dump(mode="json")
    else:
        payload = dict(answer)
    return canonical_digest(payload)


def revision_digest(revision: PublishedAnswerRevision) -> str:
    return canonical_digest(revision.model_dump(mode="json", exclude={"revision_digest", "created_at"}))


def _payload_field(payload: RevisionPayload) -> RevisionField:
    from secmind.answer_revision_contracts import (
        ActorPatch,
        ApiOperationPatch,
        FindingPatch,
        TimelineEventPatch,
    )

    if isinstance(payload, FindingPatch):
        return RevisionField.FINDINGS
    if isinstance(payload, TimelineEventPatch):
        return RevisionField.TIMELINE
    if isinstance(payload, ActorPatch):
        return RevisionField.ACTOR
    if isinstance(payload, ApiOperationPatch):
        return RevisionField.API_OPERATION
    return RevisionField.EXACT_ANSWER


def _payload_id(payload: RevisionPayload) -> str:
    from secmind.answer_revision_contracts import (
        ActorPatch,
        ApiOperationPatch,
        FindingPatch,
        TimelineEventPatch,
    )

    if isinstance(payload, FindingPatch):
        return payload.finding_id
    if isinstance(payload, TimelineEventPatch):
        return payload.event_id
    if isinstance(payload, ActorPatch):
        return payload.actor_id
    if isinstance(payload, ApiOperationPatch):
        return payload.operation_id
    return payload.answer_id


def _provider_from_shorthand(provider: str, values: Mapping[str, Any]) -> ProviderIdentity:
    return ProviderIdentity(
        provider=provider,
        model_id=str(values.get("model_id") or provider),
        request_id=str(values.get("request_id") or "unknown-request"),
        request_digest=str(values.get("request_digest") or "0" * 64),
        response_digest=str(values.get("response_digest") or "0" * 64),
        response_schema_digest=str(values.get("response_schema_digest") or "0" * 64),
        provider_requests=max(1, int(values.get("provider_requests") or 1)),
    )


def _receipt_from_mapping(value: Mapping[str, Any]) -> ReceiptBinding:
    return ReceiptBinding.create(
        receipt_id=str(value.get("receipt_id") or value.get("id") or "unknown-receipt"),
        provider=str(value.get("provider") or "unknown-provider"),
        model_id=str(value.get("model_id") or "unknown-model"),
        request_digest=(
            str(value.get("request_digest") or value.get("request_sha256"))
            if value.get("request_digest") or value.get("request_sha256")
            else None
        ),
        response_digest=str(value.get("response_digest") or value.get("response_sha256") or "0" * 64),
        response_schema_digest=(
            str(value.get("response_schema_digest") or value.get("response_schema_sha256"))
            if value.get("response_schema_digest") or value.get("response_schema_sha256")
            else None
        ),
        context_digest=(
            str(value.get("context_digest") or value.get("context_sha256"))
            if value.get("context_digest") or value.get("context_sha256")
            else None
        ),
        raw_digest=str(value["raw_digest"]) if value.get("raw_digest") else None,
    )


__all__ = [
    "PublishedAnswer",
    "PublishedAnswerRevision",
    "answer_digest",
    "revision_digest",
]
