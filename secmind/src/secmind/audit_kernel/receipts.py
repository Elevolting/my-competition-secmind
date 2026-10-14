from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Self

from pydantic import Field, field_validator, model_validator

from secmind.audit_kernel.contracts import (
    SHA256_PATTERN,
    AuditContract,
    content_digest,
)
from secmind.schemas import ModelUsage


class DirectContext(AuditContract):
    """Frozen identity of a Direct review request.

    A Direct and an augmented arm are a valid pair only when this identity is
    identical.  Runtime source text is intentionally represented by digests.
    """

    input_manifest_digest: str = Field(pattern=SHA256_PATTERN)
    audit_profile_digest: str = Field(pattern=SHA256_PATTERN)
    prompt_version: str = Field(min_length=1, max_length=128)
    response_schema_digest: str = Field(pattern=SHA256_PATTERN)
    model_policy_digest: str = Field(pattern=SHA256_PATTERN)
    source_digests: tuple[str, ...] = Field(min_length=1)
    support_digests: tuple[str, ...] = ()
    deadline_at: datetime
    max_output_tokens: int = Field(ge=1)

    @field_validator("source_digests", "support_digests")
    @classmethod
    def normalize_digests(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(sorted(set(values)))
        if any(len(value) != 64 for value in normalized):
            raise ValueError("Direct context requires SHA-256 source digests")
        return normalized

    @property
    def pair_digest(self) -> str:
        return content_digest(self)


class ProviderReceipt(AuditContract):
    """Immutable provider result committed before baseline projection."""

    receipt_id: str = Field(pattern=r"^receipt-[a-f0-9]{64}$")
    run_id: str = Field(min_length=1, max_length=128)
    logical_call_id: str = Field(min_length=1, max_length=128)
    provider_request_id: str = Field(min_length=1, max_length=128)
    request_digest: str = Field(pattern=SHA256_PATTERN)
    response_digest: str = Field(pattern=SHA256_PATTERN)
    pair_digest: str = Field(pattern=SHA256_PATTERN)
    unit_ids: tuple[str, ...] = Field(min_length=1)
    model_id: str = Field(min_length=1, max_length=128)
    prompt_version: str = Field(min_length=1, max_length=128)
    prompt_artifact_id: str | None = Field(default=None, pattern=SHA256_PATTERN)
    response_schema_digest: str = Field(pattern=SHA256_PATTERN)
    parsed_response: dict[str, Any]
    raw_response_ref: str | None = Field(default=None, max_length=256)
    usage: ModelUsage = Field(default_factory=ModelUsage)
    latency_ms: int = Field(ge=0)
    used_fallback: bool = False
    attempt_count: int = Field(ge=1)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    receipt_digest: str = Field(pattern=SHA256_PATTERN)

    @field_validator("unit_ids")
    @classmethod
    def normalize_unit_ids(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(sorted(set(values)))
        if len(normalized) != len(values):
            raise ValueError("provider receipt unit_ids must be unique")
        return normalized

    @model_validator(mode="after")
    def validate_identity(self) -> Self:
        payload = self.model_dump(mode="json", exclude={"receipt_digest"})
        if self.receipt_digest != content_digest(payload):
            raise ValueError("provider receipt digest is invalid")
        expected_id = "receipt-" + content_digest(
            {
                "provider_request_id": self.provider_request_id,
                "request_digest": self.request_digest,
                "response_digest": self.response_digest,
            }
        )
        if self.receipt_id != expected_id:
            raise ValueError("provider receipt id is invalid")
        return self

    @classmethod
    def create(cls, **values: Any) -> Self:
        identity = {
            "provider_request_id": values["provider_request_id"],
            "request_digest": values["request_digest"],
            "response_digest": values["response_digest"],
        }
        payload = {
            **values,
            "receipt_id": "receipt-" + content_digest(identity),
            "raw_response_ref": values.get("raw_response_ref"),
            "prompt_artifact_id": values.get("prompt_artifact_id"),
            "usage": ModelUsage.model_validate(values.get("usage", {})),
            "used_fallback": bool(values.get("used_fallback", False)),
            "attempt_count": int(values.get("attempt_count", 1)),
            "created_at": values.get("created_at", datetime.now(UTC)),
        }
        draft = cls.model_construct(**payload, receipt_digest="0" * 64)
        normalized = draft.model_dump(mode="json", exclude={"receipt_digest"})
        return cls.model_validate({**normalized, "receipt_digest": content_digest(normalized)})


__all__ = ["DirectContext", "ProviderReceipt"]
