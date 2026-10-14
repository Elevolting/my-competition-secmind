"""Stable, secret-free model-gateway contracts.

These models are intentionally independent of the Qwen gateway implementation.
Keeping them here lets persistence, diagnostics, and callers share one contract
without importing the transport facade.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from secmind.model_gateway.identity import canonical_sha256, raw_response_slot_id
from secmind.model_router import PRIMARY_ROUTE_PROFILE
from secmind.schemas import ModelUsage


class ModelGatewayError(RuntimeError):
    """Stable boundary error carrying sanitized, durable gateway diagnostics."""

    def __init__(self, message: str = "Model gateway request failed", *, failure: ModelGatewayFailure | None = None):
        self.failure = failure
        super().__init__(message)


class ModelReadIdleTimeout(TimeoutError):
    """A streaming response stopped producing bytes for the read-idle budget."""


class ModelAttemptSummary(BaseModel):
    """Public-safe summary of one provider or gateway attempt stage."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    ordinal: int = Field(ge=1)
    provider_request_id: str | None = Field(default=None, max_length=200)
    stage: str = Field(default="provider", min_length=1, max_length=64)
    error_type: str | None = Field(default=None, max_length=80)
    status_code: int | None = Field(default=None, ge=100, le=599)
    duration_ms: int = Field(default=0, ge=0)
    retryable: bool = False
    request_digest: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    response_digest: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    route: str = Field(default="general:lightweight", min_length=1, max_length=120)
    route_profile: str = Field(default=PRIMARY_ROUTE_PROFILE, min_length=1, max_length=64)
    model_id: str = Field(default="", max_length=200)
    prompt_version: str = Field(default="", max_length=256)
    prompt_artifact_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    prompt_selection_digest: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    deadline_ms: int = Field(default=0, ge=0)
    remaining_budget_ms: int = Field(default=0, ge=0)
    logical_call_id: str | None = Field(default=None, max_length=128)
    parent_logical_call_id: str | None = Field(default=None, max_length=128)
    prompt_optimizer_attempt_id: str | None = Field(default=None, max_length=160)
    prompt_lineage_reason: str = Field(default="legacy_unbound_prompt", min_length=2, max_length=80)
    lineage_stage: str = Field(default="legacy", min_length=1, max_length=32)
    recovery_kind: str = Field(default="primary", min_length=1, max_length=40)
    recovery_independence: str = Field(default="not_applicable", min_length=1, max_length=32)
    budget_dimension: str | None = Field(default=None, max_length=64)
    retry_after_ms: int | None = Field(default=None, ge=0, le=300_000)
    retry_after_source: Literal["delta_seconds", "http_date"] | None = None
    provider_reported_usage: ModelUsage = Field(default_factory=ModelUsage)
    conservative_reserved_usage: ModelUsage = Field(default_factory=ModelUsage)
    unknown_usage: bool = False


class ModelGatewayFailure(BaseModel):
    """Durable, non-secret failure envelope propagated above the gateway."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    failure_id: str = Field(pattern=r"^[a-f0-9]{64}$")
    error_type: str = Field(min_length=1, max_length=80)
    stage: str = Field(min_length=1, max_length=64)
    message: str = Field(min_length=1, max_length=240)
    status_code: int | None = Field(default=None, ge=100, le=599)
    retryable: bool = False
    request_digest: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    logical_call_id: str | None = Field(default=None, max_length=128)
    route: str = Field(default="general:lightweight", min_length=1, max_length=120)
    route_profile: str = Field(default=PRIMARY_ROUTE_PROFILE, min_length=1, max_length=64)
    model_id: str = Field(default="", max_length=200)
    prompt_version: str = Field(default="", max_length=256)
    deadline_ms: int = Field(default=0, ge=0)
    remaining_budget_ms: int = Field(default=0, ge=0)
    fallback_status: str = Field(default="not_attempted", min_length=1, max_length=32)
    recovery_kind: str = Field(default="primary", min_length=1, max_length=40)
    recovery_independence: str = Field(default="not_applicable", min_length=1, max_length=32)
    budget_dimension: str | None = Field(default=None, max_length=64)
    attempts: list[ModelAttemptSummary] = Field(default_factory=list, max_length=32)


class RetryableModelError(ModelGatewayError):
    """A bounded provider fault carrying safe retry timing metadata."""

    def __init__(
        self,
        message: str = "Model provider request is retryable",
        *,
        retry_after_seconds: float | None = None,
        retry_after_source: Literal["delta_seconds", "http_date"] | None = None,
    ) -> None:
        self.retry_after_seconds = retry_after_seconds
        self.retry_after_source = retry_after_source
        super().__init__(message)


class DurableReceiptError(ModelGatewayError):
    """A paid response receipt exists but cannot be trusted or persisted."""


class ModelResponseTooLargeError(ModelGatewayError):
    """A provider response exceeded the gateway's hard byte ceiling."""

    def __init__(self, limit_bytes: int, *, content_length: int | None = None) -> None:
        super().__init__("Model response exceeds the configured byte limit")
        self.limit_bytes = limit_bytes
        self.content_length = content_length


class RawModelResponseReceipt(BaseModel):
    """Internal, hash-bound pointer to provider content stored as restricted CAS bytes."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0", "1.1"] = "1.1"
    receipt_id: str = Field(pattern=r"^raw-model-response-[a-f0-9]{64}$")
    slot_id: str = Field(pattern=r"^[a-f0-9]{64}$")
    run_id: str = Field(min_length=1, max_length=100)
    logical_call_id: str = Field(min_length=1, max_length=128)
    provider_request_id: str = Field(min_length=1, max_length=128)
    model_id: str = Field(min_length=1, max_length=128)
    candidate_index: int = Field(ge=0)
    repair_index: int = Field(ge=0)
    request_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    provider_request_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    response_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    response_artifact_id: str = Field(pattern=r"^[a-f0-9]{64}$")
    response_schema_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    prompt_version: str = Field(min_length=1, max_length=256)
    prompt_artifact_id: str | None = Field(default=None, max_length=256)
    prompt_selection_digest: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    prompt_optimizer_attempt_id: str | None = Field(default=None, max_length=160)
    prompt_lineage_reason: str = Field(default="legacy_unbound_prompt", min_length=2, max_length=80)
    parent_logical_call_id: str | None = Field(default=None, max_length=128)
    lineage_stage: str = Field(default="legacy", min_length=1, max_length=32)
    duration_ms: int = Field(ge=0)
    used_fallback: bool = False
    usage: ModelUsage = Field(default_factory=ModelUsage)
    provider_reported_usage: ModelUsage = Field(default_factory=ModelUsage)
    conservative_reserved_usage: ModelUsage = Field(default_factory=ModelUsage)
    unknown_usage_attempts: int = Field(default=0, ge=0, le=32)

    @model_validator(mode="after")
    def validate_integrity(self) -> Self:
        if self.response_artifact_id != self.response_sha256:
            raise ValueError("raw response artifact is not bound to the response digest")
        expected_slot = raw_response_slot_id(
            run_id=self.run_id,
            logical_call_id=self.logical_call_id,
            model_id=self.model_id,
            candidate_index=self.candidate_index,
            repair_index=self.repair_index,
            provider_request_sha256=self.provider_request_sha256,
        )
        if self.slot_id != expected_slot:
            raise ValueError("raw response receipt slot identity is invalid")
        excluded = {"receipt_id"}
        if self.schema_version == "1.0":
            # v1.0 receipts predate usage-provenance fields. Keep their
            # original content identity valid while every newly-created v1.1
            # receipt binds the provenance to its hash.
            excluded.update(
                {
                    "provider_reported_usage",
                    "conservative_reserved_usage",
                    "unknown_usage_attempts",
                }
            )
        payload = self.model_dump(mode="json", exclude=excluded)
        if self.receipt_id != f"raw-model-response-{canonical_sha256(payload)}":
            raise ValueError("raw response receipt content identity is invalid")
        return self

    @classmethod
    def create(cls, **values: Any) -> Self:
        schema_version = values.pop("schema_version", "1.1")
        payload = {
            key: value.model_dump(mode="json") if isinstance(value, BaseModel) else value
            for key, value in {**values, "schema_version": schema_version}.items()
        }
        return cls.model_validate(
            {
                **payload,
                "receipt_id": f"raw-model-response-{canonical_sha256(payload)}",
            }
        )


@dataclass(frozen=True, slots=True)
class ProviderAttempt:
    provider_request_id: str
    sequence: int
    model_id: str
    endpoint: str
    duration_ms: int
    status_code: int | None
    succeeded: bool
    retryable: bool
    error_type: str | None
    usage: ModelUsage
    provider_request_sha256: str
    task_kind: str
    lane: str
    router_version: str
    prompt_version: str
    response_sha256: str | None
    prompt_artifact_id: str | None = None
    prompt_selection_digest: str | None = None
    run_id: str | None = None
    logical_call_id: str | None = None
    ordinal: int = 0
    stage: str = "provider"
    deadline_ms: int = 0
    remaining_budget_ms: int = 0
    route: str = "general:lightweight"
    route_profile: str = PRIMARY_ROUTE_PROFILE
    prompt_optimizer_attempt_id: str | None = None
    prompt_lineage_reason: str = "legacy_unbound_prompt"
    parent_logical_call_id: str | None = None
    lineage_stage: str = "legacy"
    recovery_kind: str = "primary"
    recovery_independence: str = "not_applicable"
    retry_after_ms: int | None = None
    retry_after_source: Literal["delta_seconds", "http_date"] | None = None
    provider_reported_usage: ModelUsage = field(default_factory=ModelUsage)
    conservative_reserved_usage: ModelUsage = field(default_factory=ModelUsage)
    unknown_usage: bool = False

    @property
    def request_digest(self) -> str:
        """Compatibility alias for the public diagnostic contract."""

        return self.provider_request_sha256

    def summary(self) -> ModelAttemptSummary:
        ordinal = self.ordinal if self.ordinal > 0 else max(1, self.sequence)
        return ModelAttemptSummary(
            ordinal=ordinal,
            provider_request_id=self.provider_request_id,
            stage=self.stage,
            error_type=self.error_type,
            status_code=self.status_code,
            duration_ms=self.duration_ms,
            retryable=self.retryable,
            request_digest=self.provider_request_sha256,
            response_digest=self.response_sha256,
            route=self.route,
            route_profile=self.route_profile,
            model_id=self.model_id,
            prompt_version=self.prompt_version,
            prompt_artifact_id=self.prompt_artifact_id,
            prompt_selection_digest=self.prompt_selection_digest,
            deadline_ms=self.deadline_ms,
            remaining_budget_ms=self.remaining_budget_ms,
            logical_call_id=self.logical_call_id,
            parent_logical_call_id=self.parent_logical_call_id,
            prompt_optimizer_attempt_id=self.prompt_optimizer_attempt_id,
            prompt_lineage_reason=self.prompt_lineage_reason,
            lineage_stage=self.lineage_stage,
            recovery_kind=self.recovery_kind,
            recovery_independence=self.recovery_independence,
            retry_after_ms=self.retry_after_ms,
            retry_after_source=self.retry_after_source,
            provider_reported_usage=self.provider_reported_usage,
            conservative_reserved_usage=self.conservative_reserved_usage,
            unknown_usage=self.unknown_usage,
        )


@dataclass
class ModelCallMeta:
    model_id: str
    prompt_version: str
    response_sha256: str
    duration_ms: int
    used_fallback: bool
    usage: ModelUsage
    logical_call_id: str = ""
    request_sha256: str = ""
    response_schema_sha256: str = ""
    prompt_artifact_id: str = ""
    prompt_selection_digest: str = ""
    prompt_optimizer_attempt_id: str = ""
    prompt_lineage_reason: str = "legacy_unbound_prompt"
    parent_logical_call_id: str = ""
    lineage_stage: str = "legacy"
    recovery_kind: str = "primary"
    recovery_independence: str = "not_applicable"
    raw_response_artifact_id: str = ""
    replayed_from_receipt: bool = False
    route_task_kind: str = "general"
    route_lane: str = ""
    router_version: str = ""
    route_rationale: str = ""
    route_profile: str = PRIMARY_ROUTE_PROFILE
    deadline_ms: int = 0
    remaining_budget_ms: int = 0
    attempts: tuple[ModelAttemptSummary, ...] = ()
    provider: str = "unknown"
    provider_reported_usage: ModelUsage = field(default_factory=ModelUsage)
    conservative_reserved_usage: ModelUsage = field(default_factory=ModelUsage)
    unknown_usage_attempts: int = 0
