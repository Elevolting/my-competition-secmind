"""Small immutable contracts for typed published-answer revisions."""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from typing import Any, Literal, Self, TypeAlias

from pydantic import BaseModel, ConfigDict, Field, model_validator

SHA256_PATTERN = r"^[a-f0-9]{64}$"


def canonical_digest(value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class ScoringMode(StrEnum):
    SECURITY_FINDING = "security_finding"
    REVERSE_BEHAVIOR = "reverse_behavior"
    EVIDENCE_GAP = "evidence_gap"
    AGENT_POLICY_COMPLIANCE = "agent_policy_compliance"
    FORENSIC_ATTRIBUTION = "forensic_attribution"
    EXACT_ANSWER_WITH_EVIDENCE = "exact_answer_with_evidence"
    PATCH_VALIDATOR = "patch_validator"


class RevisionOperation(StrEnum):
    REPLACE = "replace"
    RETRACT = "retract"
    SUPPLEMENT = "supplement"


class RevisionField(StrEnum):
    FINDINGS = "findings"
    TIMELINE = "timeline"
    ACTOR = "actor"
    API_OPERATION = "api_operation"
    EXACT_ANSWER = "exact_answer"


class CompositeStatus(StrEnum):
    COMPLETED = "completed"
    COMPLETE = "completed"
    PARTIAL = "partial"
    INCOMPLETE = "partial"
    INSUFFICIENT = "insufficient"
    CONFLICTED = "conflicted"
    BLOCKED = "blocked"
    FAILED = "failed"


class RevisionError(ValueError):
    """A revision cannot be admitted without weakening answer integrity."""


class ReceiptBinding(BaseModel):
    """Hash-bound receipt identity; no provider response payload is writable here."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    receipt_id: str = Field(min_length=1, max_length=256)
    receipt_digest: str = Field(pattern=SHA256_PATTERN)
    provider: str = Field(min_length=1, max_length=128)
    model_id: str = Field(min_length=1, max_length=256)
    request_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    response_digest: str = Field(pattern=SHA256_PATTERN)
    response_schema_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    context_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    raw_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def verify_identity_digest(self) -> Self:
        expected = canonical_digest(self._identity())
        if self.receipt_digest != expected:
            raise ValueError("receipt binding digest is invalid")
        return self

    def _identity(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "provider": self.provider,
            "model_id": self.model_id,
            "request_digest": self.request_digest,
            "response_digest": self.response_digest,
            "response_schema_digest": self.response_schema_digest,
            "context_digest": self.context_digest,
            "raw_digest": self.raw_digest,
        }

    @classmethod
    def create(cls, **values: Any) -> Self:
        payload = dict(values)
        payload.pop("receipt_digest", None)
        identity = {
            "receipt_id": payload["receipt_id"],
            "provider": payload["provider"],
            "model_id": payload["model_id"],
            "request_digest": payload.get("request_digest"),
            "response_digest": payload["response_digest"],
            "response_schema_digest": payload.get("response_schema_digest"),
            "context_digest": payload.get("context_digest"),
            "raw_digest": payload.get("raw_digest"),
        }
        return cls(**identity, receipt_digest=canonical_digest(identity))

    @classmethod
    def from_raw_primary(cls, receipt: Any, *, provider: str) -> Self:
        raw = receipt.model_dump(mode="json") if hasattr(receipt, "model_dump") else dict(receipt)
        response = str(raw.get("response_sha256") or raw.get("response_digest") or "")
        request = str(raw.get("request_sha256") or raw.get("request_digest") or "")
        schema = str(raw.get("response_schema_sha256") or raw.get("response_schema_digest") or "")
        context = str(raw.get("context_sha256") or raw.get("context_digest") or "")
        return cls.create(
            receipt_id=str(raw.get("receipt_id") or "unknown-receipt"),
            provider=provider,
            model_id=str(raw.get("model_id") or "unknown-model"),
            request_digest=request or None,
            response_digest=response,
            response_schema_digest=schema or None,
            context_digest=context or None,
            raw_digest=canonical_digest(raw),
        )


class ProviderIdentity(BaseModel):
    """Provider/request/schema identity required for a scoreable answer."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    provider: str = Field(min_length=1, max_length=128)
    model_id: str = Field(min_length=1, max_length=256)
    request_id: str = Field(min_length=1, max_length=256)
    request_digest: str = Field(pattern=SHA256_PATTERN)
    response_digest: str = Field(pattern=SHA256_PATTERN)
    response_schema_digest: str = Field(pattern=SHA256_PATTERN)
    provider_requests: int = Field(ge=1)

    @classmethod
    def from_receipt(cls, receipt: ReceiptBinding, *, provider: str | None = None, request_id: str = "receipt") -> Self:
        return cls(
            provider=provider or receipt.provider,
            model_id=receipt.model_id,
            request_id=request_id,
            request_digest=receipt.request_digest or "0" * 64,
            response_digest=receipt.response_digest,
            response_schema_digest=receipt.response_schema_digest or "0" * 64,
            provider_requests=1,
        )


class FindingPatch(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    finding_id: str = Field(min_length=1, max_length=256)
    rule_id: str | None = Field(default=None, max_length=128)
    cwe: int | str | None = None
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"] | None = None
    path: str | None = Field(default=None, max_length=2_048)
    line: int | None = Field(default=None, ge=1)
    title: str | None = Field(default=None, max_length=2_000)
    description: str | None = Field(default=None, max_length=10_000)
    remediation: str | None = Field(default=None, max_length=10_000)
    evidence_ids: tuple[str, ...] = ()
    fields: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def require_real_finding(self) -> Self:
        if self.rule_id is None and self.cwe is None:
            raise ValueError("finding patch requires rule_id or cwe")
        if self.path is None or self.line is None:
            raise ValueError("finding patch requires path and line")
        return self


class TimelineEventPatch(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: str = Field(min_length=1, max_length=256)
    timestamp: str = Field(min_length=1, max_length=128)
    event_type: str = Field(min_length=1, max_length=256)
    actor_id: str | None = Field(default=None, max_length=256)
    source_ref: str | None = Field(default=None, max_length=2_048)
    evidence_ids: tuple[str, ...] = ()
    fields: dict[str, Any] = Field(default_factory=dict)


class ActorPatch(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    actor_id: str = Field(min_length=1, max_length=256)
    name: str | None = Field(default=None, max_length=512)
    role: str | None = Field(default=None, max_length=512)
    account: str | None = Field(default=None, max_length=512)
    evidence_ids: tuple[str, ...] = ()
    fields: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def require_real_actor(self) -> Self:
        if not any(value not in {None, ""} for value in (self.name, self.role, self.account)) and not self.fields:
            raise ValueError("actor patch requires a real actor field")
        return self


class ApiOperationPatch(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    operation_id: str = Field(min_length=1, max_length=256)
    method: str = Field(min_length=1, max_length=16)
    path: str = Field(min_length=1, max_length=2_048)
    status_code: int | None = Field(default=None, ge=100, le=599)
    request: dict[str, Any] | None = None
    response: dict[str, Any] | None = None
    evidence_ids: tuple[str, ...] = ()
    fields: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def normalize_method(self) -> Self:
        method = self.method.strip().upper()
        if method not in {"GET", "PUT", "POST", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE"}:
            raise ValueError("unsupported API operation method")
        object.__setattr__(self, "method", method)
        return self


class ExactAnswerPatch(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    answer_id: str = Field(min_length=1, max_length=256)
    value: Any
    evidence_ids: tuple[str, ...] = ()
    source_ref: str | None = Field(default=None, max_length=2_048)


RevisionPayload: TypeAlias = FindingPatch | TimelineEventPatch | ActorPatch | ApiOperationPatch | ExactAnswerPatch


class Obligation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    obligation_id: str = Field(min_length=1, max_length=256)
    field: str = Field(min_length=1, max_length=256)
    required: bool = True
    critical: bool = True
    status: Literal["satisfied", "unverified", "contradicted", "waived"]
    reason: str = Field(min_length=1, max_length=1_000)
    evidence_ids: tuple[str, ...] = ()


__all__ = [
    "ActorPatch",
    "ApiOperationPatch",
    "CompositeStatus",
    "ExactAnswerPatch",
    "FindingPatch",
    "Obligation",
    "ProviderIdentity",
    "ReceiptBinding",
    "RevisionError",
    "RevisionField",
    "RevisionOperation",
    "RevisionPayload",
    "ScoringMode",
    "TimelineEventPatch",
    "SHA256_PATTERN",
    "canonical_digest",
]
