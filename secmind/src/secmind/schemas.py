"""Versioned public contracts shared by API, graph, tools, and persistence.

This is a compatibility façade for schema version 1.7. New behavior belongs in
domain services; models here should contain validation and serialization only.
Future domain splits must re-export existing names from this module until the
next declared schema major version.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import IntEnum, StrEnum
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from secmind.task_contract import (
    BeliefState,
    EvidenceCompilerReceipt,
    PublishedAnswerRevision,
    ResolvedTaskContract,
    TaskObligation,
)

SCHEMA_VERSION = "1.7"


class Scenario(StrEnum):
    CODE_AUDIT = "code_audit"
    LOG_ANALYSIS = "log_analysis"
    INCIDENT_RESPONSE = "incident_response"
    PENETRATION_TEST = "penetration_test"
    API_ASSESSMENT = "api_assessment"
    REVERSE_TRIAGE = "reverse_triage"
    UNKNOWN = "unknown"


class RunStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    WAITING_CLARIFICATION = "waiting_clarification"
    WAITING_APPROVAL = "waiting_approval"
    COMPLETED = "completed"
    PARTIAL = "partial"
    DENIED = "denied"
    FAILED = "failed"
    RECOVERY_REQUIRED = "recovery_required"
    CANCELLED = "cancelled"


class RiskLevel(IntEnum):
    R0 = 0
    R1 = 1
    R2 = 2
    R3 = 3


class ApprovalDecision(StrEnum):
    APPROVE = "approve"
    DENY = "deny"
    EDIT = "edit"


class ToolStatus(StrEnum):
    SUCCESS = "success"
    ERROR = "error"
    TIMEOUT = "timeout"
    DENIED = "denied"


class InvocationStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    RECOVERY_REQUIRED = "recovery_required"
    CANCELLED = "cancelled"


class StepStatus(StrEnum):
    PENDING = "pending"
    READY = "ready"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"


class FailurePolicy(StrEnum):
    FAIL_FAST = "fail_fast"
    CONTINUE = "continue"
    SKIP_DEPENDENTS = "skip_dependents"


class QueueStatus(StrEnum):
    QUEUED = "queued"
    LEASED = "leased"
    WAITING = "waiting"
    RETRY = "retry"
    COMPLETE = "complete"
    CANCELLED = "cancelled"


class ToolHealth(StrEnum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"


class InstructionLayer(IntEnum):
    PLATFORM_SAFETY = 0
    COMPETITION_POLICY = 1
    SCENARIO_POLICY = 2
    OPERATOR_TASK = 3
    SELECTED_SKILL = 4
    RETRIEVED_KNOWLEDGE = 5
    REPOSITORY_CONTENT = 6
    TOOL_OBSERVATION = 7

    def dominates(self, other: InstructionLayer) -> bool:
        """Return true when this layer is at least as authoritative as ``other``."""

        return int(self) <= int(other)


class ContextTaint(StrEnum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    ADVISORY = "advisory"


class DataSensitivity(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    # This is a data-classification label, not a credential.
    SECRET = "secret"  # noqa: S105  # nosec B105
    CREDENTIAL_CANDIDATE = "credential_candidate"


class ClaimStatus(StrEnum):
    CANDIDATE = "candidate"
    SUPPORTED = "supported"
    VERIFIED = "verified"
    REJECTED = "rejected"
    CONFLICTED = "conflicted"
    INSUFFICIENT = "insufficient"


class EvidenceAssurance(StrEnum):
    """What an evidence item is actually entitled to prove.

    Integrity and semantic correctness are intentionally separate.  Model
    output starts as a proposal; it can support an authoritative security
    conclusion only after an independent semantic or human corroboration.
    """

    MODEL_PROPOSED = "model_proposed"
    INTEGRITY_VERIFIED = "integrity_verified"
    SEMANTICALLY_CORROBORATED = "semantically_corroborated"
    HUMAN_CONFIRMED = "human_confirmed"


class EvidenceRelation(StrEnum):
    SUPPORTS = "supports"
    CONTRADICTS = "contradicts"
    DERIVED_FROM = "derived_from"
    DUPLICATES = "duplicates"
    SUPERSEDES = "supersedes"
    INVALIDATES = "invalidates"


class PolicyAction(StrEnum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"


class HookDecision(StrEnum):
    CONTINUE = "continue"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"
    PATCH = "patch"
    ADVISORY = "advisory"


class ClarificationStatus(StrEnum):
    PENDING = "pending"
    RESOLVED_UNCONSUMED = "resolved_unconsumed"
    CONSUMED = "consumed"


class StrategyMode(StrEnum):
    QUICK = "quick"
    BALANCED = "balanced"
    DEEP = "deep"


class ReplanTrigger(StrEnum):
    TOOL_UNAVAILABLE = "tool_unavailable"
    TOOL_OUTPUT_INVALID = "tool_output_invalid"
    EVIDENCE_INSUFFICIENT = "evidence_insufficient"
    EVIDENCE_CONTRADICTION = "evidence_contradiction"
    INPUT_SCOPE_CHANGED = "input_scope_changed"
    BUDGET_PRESSURE = "budget_pressure"
    DEADLINE_PRESSURE = "deadline_pressure"
    DEPENDENCY_FAILURE = "dependency_failure"
    POLICY_REEVALUATION = "policy_reevaluation"


class LogLayer(StrEnum):
    DECISION_AUDIT = "L1"
    RUNTIME = "L2"
    MODEL = "L3"
    TOOL = "L4"
    RAW_SECURITY = "L5"
    NORMALIZED_SECURITY = "L6"


class DataView(StrEnum):
    RAW_RESTRICTED = "raw_restricted"
    OBSERVABLE = "observable"
    PUBLIC_REPORT = "public_report"


class ResumeAction(StrEnum):
    RESUME_FROM_CHECKPOINT = "RESUME_FROM_CHECKPOINT"
    REQUEUE_SAFE_STEP = "REQUEUE_SAFE_STEP"
    RETURN_CACHED_RESULT = "RETURN_CACHED_RESULT"
    WAIT_FOR_APPROVAL = "WAIT_FOR_APPROVAL"
    WAIT_FOR_CLARIFICATION = "WAIT_FOR_CLARIFICATION"
    FINALIZE_OUTBOX = "FINALIZE_OUTBOX"
    CANCEL_AND_REAP = "CANCEL_AND_REAP"
    REQUIRE_OPERATOR_RECOVERY = "REQUIRE_OPERATOR_RECOVERY"
    MARK_PARTIAL = "MARK_PARTIAL"


class AttachmentRef(BaseModel):
    ref: str = Field(min_length=1, description="Upload reference or input-root-relative path")
    name: str | None = None


class TaskRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = SCHEMA_VERSION
    client_request_id: str | None = Field(default=None, min_length=8, max_length=128)
    objective: str = Field(min_length=3, max_length=10_000)
    attachments: list[AttachmentRef] = Field(default_factory=list)
    target_scope: list[str] = Field(default_factory=list)
    constraints: list[str] = Field(default_factory=list)
    expected_outputs: list[str] = Field(default_factory=lambda: ["security_report"])
    autonomy_policy: Literal["graded", "approval_all", "automatic"] = "graded"
    interaction_mode: Literal["interactive", "unattended"] = "interactive"
    primary_domain: str | None = Field(default=None, min_length=1, max_length=128)
    secondary_capabilities: list[str] = Field(default_factory=list, max_length=64)
    scoring_mode: str | None = Field(default=None, min_length=1, max_length=128)
    output_contract: dict[str, Any] = Field(default_factory=dict)
    evaluation_metadata: dict[str, Any] = Field(default_factory=dict)
    task_metadata: dict[str, Any] = Field(default_factory=dict)
    evaluation_contract_digest: str | None = Field(
        default=None,
        pattern=r"^[a-fA-F0-9]{64}$",
    )

    @model_validator(mode="after")
    def validate_evaluation_envelope(self) -> TaskRequest:
        if self.evaluation_metadata and self.task_metadata != self.evaluation_metadata:
            raise ValueError("task_metadata must be an exact compatibility alias of evaluation_metadata")
        if self.evaluation_metadata:
            encoded = json.dumps(
                self.evaluation_metadata,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
                default=str,
            ).encode("utf-8")
            expected = hashlib.sha256(encoded).hexdigest()
            if self.evaluation_contract_digest != expected:
                raise ValueError("evaluation metadata digest mismatch")
        elif self.evaluation_contract_digest is not None or self.task_metadata:
            raise ValueError("evaluation metadata aliases require a non-empty sealed envelope")
        return self


class FieldProvenance(BaseModel):
    source_type: Literal["operator", "attachment", "parser", "default", "clarification"]
    source_ref: str
    locator: str | None = None
    confidence: float = Field(default=1.0, ge=0, le=1)
    content_digest: str = Field(pattern=r"^[a-fA-F0-9]{64}$")


class TaskHint(BaseModel):
    source_ref: str
    objectives: list[str] = Field(default_factory=list)
    scenario_candidates: list[Scenario] = Field(default_factory=list)
    authorized_scope_candidates: list[str] = Field(default_factory=list)
    constraints: list[str] = Field(default_factory=list)
    prohibited_actions: list[str] = Field(default_factory=list)
    expected_outputs: list[str] = Field(default_factory=list)
    success_criteria: list[str] = Field(default_factory=list)
    temporal_scope: str | None = None
    confidence: float = Field(default=0.5, ge=0, le=1)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ParsedAsset(BaseModel):
    parsed_asset_id: str = Field(default_factory=lambda: str(uuid4()))
    parser_id: str
    parser_version: str
    artifact_id: str
    relative_path: str
    media_type: str
    asset_type: str
    content_digest: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    hints: list[TaskHint] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    diagnostics: list[str] = Field(default_factory=list)


class ParserManifest(BaseModel):
    parser_id: str
    version: str
    supported_media_types: list[str] = Field(default_factory=list)
    extensions: list[str] = Field(default_factory=list)
    probe_priority: int = Field(default=100, ge=0, le=10_000)
    max_input_size: int = Field(default=4 * 1024 * 1024, ge=1)
    streaming: bool = False
    output_schema: dict[str, Any] = Field(default_factory=dict)
    trust_level: Literal["platform", "allowlisted"] = "platform"
    package_digest: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    health_status: ToolHealth = ToolHealth.HEALTHY


class ParserRun(BaseModel):
    parser_run_id: str = Field(default_factory=lambda: str(uuid4()))
    run_id: str
    artifact_id: str
    parser_id: str
    parser_version: str
    status: Literal["completed", "partial", "failed", "skipped"]
    parsed_asset_id: str | None = None
    input_digest: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    output_digest: str | None = Field(default=None, pattern=r"^[a-fA-F0-9]{64}$")
    diagnostics: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class TaskSpec(BaseModel):
    schema_version: str = SCHEMA_VERSION
    task_spec_id: str = Field(default_factory=lambda: str(uuid4()))
    run_id: str
    client_request_id: str | None = Field(default=None, min_length=8, max_length=128)
    revision: int = Field(default=1, ge=1)
    parent_revision_digest: str | None = Field(default=None, pattern=r"^[a-fA-F0-9]{64}$")
    objectives: list[str] = Field(min_length=1)
    primary_scenario: Scenario
    primary_domain: str | None = Field(default=None, min_length=1, max_length=128)
    secondary_capabilities: list[str] = Field(default_factory=list, max_length=64)
    scoring_mode: str | None = Field(default=None, min_length=1, max_length=128)
    output_contract: dict[str, Any] = Field(default_factory=dict)
    evaluation_metadata: dict[str, Any] = Field(default_factory=dict)
    evaluation_contract_digest: str | None = Field(default=None, pattern=r"^[a-fA-F0-9]{64}$")
    interaction_mode: Literal["interactive", "unattended"] = "interactive"
    autonomy_policy: Literal["graded", "approval_all", "automatic"] = "graded"
    secondary_scenarios: list[Scenario] = Field(default_factory=list)
    asset_ids: list[str] = Field(default_factory=list)
    authorized_scope: list[str] = Field(default_factory=list)
    temporal_scope: str | None = None
    constraints: list[str] = Field(default_factory=list)
    prohibited_actions: list[str] = Field(default_factory=list)
    expected_outputs: list[str] = Field(default_factory=list)
    success_criteria: list[str] = Field(default_factory=list)
    ambiguities: list[str] = Field(default_factory=list)
    clarification_request_ids: list[str] = Field(default_factory=list)
    parser_run_ids: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0, ge=0, le=1)
    field_provenance: dict[str, list[FieldProvenance]] = Field(default_factory=dict)
    compiler_version: str = "taskspec-1.5"
    policy_version: str = "task-policy-1.5"
    content_digest: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class TaskSpecRef(BaseModel):
    task_spec_id: str
    revision: int = Field(ge=1)
    content_digest: str = Field(pattern=r"^[a-fA-F0-9]{64}$")


class TaskSpecRevision(BaseModel):
    task_spec_id: str
    run_id: str
    revision: int = Field(ge=1)
    content_digest: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    parent_revision_digest: str | None = Field(default=None, pattern=r"^[a-fA-F0-9]{64}$")
    reason: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ClarificationRequest(BaseModel):
    request_id: str = Field(default_factory=lambda: str(uuid4()))
    run_id: str
    task_spec_id: str
    task_spec_revision: int = Field(ge=1)
    questions: list[str] = Field(min_length=1, max_length=10)
    ambiguity_codes: list[str] = Field(default_factory=list)
    status: ClarificationStatus = ClarificationStatus.PENDING
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ClarificationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    resolution_id: str | None = None
    answers: dict[str, str] = Field(default_factory=dict)
    confirmed_scope: list[str] | None = None
    confirmed_scenario: Scenario | None = None
    additional_constraints: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def require_resolution_content(self) -> ClarificationResponse:
        if not (
            self.answers
            or self.confirmed_scope is not None
            or self.confirmed_scenario is not None
            or self.additional_constraints
        ):
            raise ValueError("clarification response must resolve at least one field")
        return self


class InputArtifact(BaseModel):
    artifact_id: str = Field(default_factory=lambda: str(uuid4()))
    original_name: str
    relative_path: str
    sha256: str
    size_bytes: int
    media_type: str = "application/octet-stream"


class ArtifactRef(BaseModel):
    """A verified tool-produced artifact, never an untrusted bare path."""

    artifact_id: str = Field(default_factory=lambda: str(uuid4()))
    ref: str = Field(min_length=1)
    sha256: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    size_bytes: int = Field(ge=0)
    media_type: str = "application/octet-stream"


class RetentionProfile(BaseModel):
    profile_id: str = Field(default_factory=lambda: str(uuid4()))
    name: str = Field(min_length=1, max_length=100)
    layer_ttl_days: dict[LogLayer, int] = Field(
        default_factory=lambda: {
            LogLayer.DECISION_AUDIT: 180,
            LogLayer.RUNTIME: 30,
            LogLayer.MODEL: 14,
            LogLayer.TOOL: 14,
            LogLayer.RAW_SECURITY: 30,
            LogLayer.NORMALIZED_SECURITY: 30,
        }
    )
    max_bytes_per_run: int = Field(default=2 * 1024 * 1024 * 1024, ge=1024)
    raw_access_requires_audit: bool = True
    ledger_deletion_allowed: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @field_validator("layer_ttl_days")
    @classmethod
    def validate_ttl(cls, value: dict[LogLayer, int]) -> dict[LogLayer, int]:
        if set(value) != set(LogLayer):
            raise ValueError("retention profile must define every log layer")
        if any(days < 1 or days > 3650 for days in value.values()):
            raise ValueError("retention TTL must be between 1 and 3650 days")
        return value


class RetentionHold(BaseModel):
    hold_id: str = Field(default_factory=lambda: str(uuid4()))
    run_id: str = Field(min_length=1, max_length=100)
    reason: str = Field(min_length=3, max_length=1_000)
    expires_at: datetime
    actor: str = Field(default="operator", min_length=1, max_length=100)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class RetentionHoldRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    client_request_id: str | None = Field(default=None, min_length=8, max_length=128)
    reason: str = Field(min_length=3, max_length=1_000)
    expires_at: datetime

    @field_validator("expires_at")
    @classmethod
    def validate_expiry(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("retention hold expiry must be timezone-aware")
        if value <= datetime.now(UTC):
            raise ValueError("retention hold expiry must be in the future")
        return value


class LogStream(BaseModel):
    stream_id: str = Field(default_factory=lambda: str(uuid4()))
    run_id: str = Field(min_length=1, max_length=100)
    source: str = Field(min_length=1, max_length=500)
    format: str = Field(min_length=1, max_length=100)
    timezone: str | None = Field(default=None, max_length=100)
    status: Literal["open", "complete", "partial", "failed"] = "open"
    total_size: int = Field(default=0, ge=0)
    digest: str | None = Field(default=None, pattern=r"^[a-fA-F0-9]{64}$")
    view: DataView = DataView.RAW_RESTRICTED
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class LogSegment(BaseModel):
    segment_id: str = Field(default_factory=lambda: str(uuid4()))
    stream_id: str
    sequence: int = Field(ge=1)
    offset: int = Field(ge=0)
    size: int = Field(ge=0)
    digest: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    artifact_id: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    record_start: int | None = Field(default=None, ge=0)
    record_end: int | None = Field(default=None, ge=0)
    status: Literal["stored", "parsed", "partial", "invalid"] = "stored"
    diagnostics: list[str] = Field(default_factory=list)


class NormalizedSecurityEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid4()))
    run_id: str = Field(min_length=1, max_length=100)
    stream_id: str = Field(min_length=1, max_length=100)
    segment_id: str = Field(min_length=1, max_length=100)
    source_offset: int = Field(ge=0)
    occurred_at: datetime | None = None
    event_type: str = Field(min_length=1, max_length=100)
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"] = "UNKNOWN"
    actor: str | None = Field(default=None, max_length=500)
    asset: str | None = Field(default=None, max_length=500)
    source_ip: str | None = Field(default=None, max_length=100)
    destination_ip: str | None = Field(default=None, max_length=100)
    observable: dict[str, Any] = Field(default_factory=dict)
    evidence_ids: list[str] = Field(default_factory=list)
    event_digest: str = Field(pattern=r"^[a-fA-F0-9]{64}$")


class LogQuery(BaseModel):
    after: datetime | None = None
    before: datetime | None = None
    severity: set[Literal["LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"]] = Field(default_factory=set)
    event_types: set[str] = Field(default_factory=set, max_length=100)
    stream_id: str | None = Field(default=None, max_length=100)
    offset: int = Field(default=0, ge=0)
    limit: int = Field(default=100, ge=1, le=1_000)


class ResumeAssessment(BaseModel):
    assessment_id: str = Field(default_factory=lambda: str(uuid4()))
    run_id: str
    action: ResumeAction
    reason_codes: list[str] = Field(min_length=1, max_length=50)
    rationale_summary: str
    state_version: int = Field(ge=0)
    fence: int = Field(ge=0)
    checkpoint_present: bool
    checkpoint_state_version: int | None = Field(default=None, ge=1)
    checkpoint_id: str | None = None
    control_digest: str = Field(default="0" * 64, pattern=r"^[a-fA-F0-9]{64}$")
    runner_resources_collected: bool = False
    step_ids: list[str] = Field(default_factory=list)
    invocation_ids: list[str] = Field(default_factory=list)
    stale_resources: list[str] = Field(default_factory=list)
    assessment_digest: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @model_validator(mode="after")
    def validate_checkpoint_binding(self) -> ResumeAssessment:
        if not self.checkpoint_present and (
            self.checkpoint_state_version is not None or self.checkpoint_id is not None
        ):
            raise ValueError("absent checkpoint cannot have identity or state version")
        return self


class RecoveryRequest(BaseModel):
    """Bind a manual recovery command to one immutable server assessment."""

    model_config = ConfigDict(extra="forbid")

    assessment_id: str = Field(min_length=1, max_length=100)
    assessment_digest: str = Field(pattern=r"^[a-fA-F0-9]{64}$")


class OperatorSession(BaseModel):
    session_id: str = Field(default_factory=lambda: str(uuid4()))
    actor: str = Field(min_length=1, max_length=100)
    role: Literal["operator", "analyst", "verifier"]
    expires_at: datetime
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @model_validator(mode="after")
    def validate_session_window(self) -> OperatorSession:
        if self.expires_at.tzinfo is None:
            raise ValueError("operator session expiry must be timezone-aware")
        if self.expires_at <= self.created_at:
            raise ValueError("operator session expiry must follow creation")
        return self


class ApprovalBatch(BaseModel):
    batch_id: str = Field(default_factory=lambda: str(uuid4()))
    run_id: str
    ready_wave: str
    risk_level: RiskLevel
    parameter_summary_digest: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    request_ids: list[str] = Field(min_length=1, max_length=100)
    actor: str
    status: Literal["pending", "partial", "resolved"] = "pending"
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @field_validator("request_ids")
    @classmethod
    def validate_unique_requests(cls, value: list[str]) -> list[str]:
        if any(not item or len(item) > 100 for item in value):
            raise ValueError("approval request id is invalid")
        if len(value) != len(set(value)):
            raise ValueError("approval batch request ids must be unique")
        return value


class ModelUsage(BaseModel):
    provider_requests: int = Field(default=0, ge=0)
    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    cache_hit_input_tokens: int = Field(default=0, ge=0)
    cache_miss_input_tokens: int = Field(default=0, ge=0)
    cost_units: float = Field(default=0, ge=0)

    @model_validator(mode="after")
    def validate_cache_accounting(self) -> ModelUsage:
        accounted = self.cache_hit_input_tokens + self.cache_miss_input_tokens
        if accounted > self.input_tokens:
            raise ValueError("cache hit and miss tokens cannot exceed input tokens")
        return self

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens

    @property
    def cache_hit_rate(self) -> float | None:
        accounted = self.cache_hit_input_tokens + self.cache_miss_input_tokens
        return None if accounted == 0 else self.cache_hit_input_tokens / accounted


class ContextBudget(BaseModel):
    total_tokens: int = Field(default=16_000, ge=256)
    policy_tokens: int = Field(default=2_400, ge=0)
    task_tokens: int = Field(default=1_600, ge=0)
    skill_tool_tokens: int = Field(default=2_400, ge=0)
    repository_tokens: int = Field(default=4_800, ge=0)
    evidence_tokens: int = Field(default=3_200, ge=0)
    working_output_tokens: int = Field(default=1_600, ge=0)
    used_tokens: int = Field(default=0, ge=0)
    compacted_items: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def validate_partitions(self) -> ContextBudget:
        allocated = (
            self.policy_tokens
            + self.task_tokens
            + self.skill_tool_tokens
            + self.repository_tokens
            + self.evidence_tokens
            + self.working_output_tokens
        )
        if allocated > self.total_tokens:
            raise ValueError("context budget partitions exceed total_tokens")
        if self.used_tokens > self.total_tokens:
            raise ValueError("used_tokens exceeds total_tokens")
        return self


class ContextItemRef(BaseModel):
    context_id: str = Field(default_factory=lambda: str(uuid4()))
    run_id: str
    kind: str
    source: str
    authority_level: InstructionLayer
    taint: ContextTaint
    sensitivity: DataSensitivity = DataSensitivity.INTERNAL
    freshness: datetime = Field(default_factory=lambda: datetime.now(UTC))
    content_hash: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    token_estimate: int = Field(default=0, ge=0)
    artifact_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ContextPackRef(BaseModel):
    pack_id: str = Field(default_factory=lambda: str(uuid4()))
    run_id: str
    step_id: str | None = None
    agent_profile: str
    immutable_policy_refs: list[str] = Field(default_factory=list)
    task_capsule: dict[str, Any] = Field(default_factory=dict)
    repository_slice_refs: list[str] = Field(default_factory=list)
    selected_skill_refs: list[str] = Field(default_factory=list)
    knowledge_refs: list[str] = Field(default_factory=list)
    evidence_handles: list[str] = Field(default_factory=list)
    tool_schema_refs: list[str] = Field(default_factory=list)
    working_summary: str = ""
    token_budget: ContextBudget = Field(default_factory=ContextBudget)
    pack_digest: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class RepositoryIndexRef(BaseModel):
    index_id: str = Field(default_factory=lambda: str(uuid4()))
    run_id: str
    artifact_id: str
    digest: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    file_count: int = Field(default=0, ge=0)
    total_bytes: int = Field(default=0, ge=0)
    languages: list[str] = Field(default_factory=list)
    dependency_files: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class AuditSkillManifest(BaseModel):
    skill_id: str
    version: str
    description: str
    trigger_terms: list[str] = Field(default_factory=list)
    supported_languages: list[str] = Field(default_factory=list)
    scenarios: list[Scenario] = Field(default_factory=lambda: [Scenario.CODE_AUDIT])
    required_capabilities: list[str] = Field(default_factory=list)
    allowed_agent_profiles: list[str] = Field(default_factory=list)
    risk_ceiling: RiskLevel = RiskLevel.R1
    max_turns: int = Field(default=3, ge=1, le=3)
    input_contract: dict[str, Any] = Field(default_factory=dict)
    output_contract: dict[str, Any] = Field(default_factory=dict)
    eval_case_ids: list[str] = Field(default_factory=list)
    package_digest: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    signer: str
    signature: str


class CapabilityDescriptor(BaseModel):
    capability_id: str
    short_description: str
    supported_languages: list[str] = Field(default_factory=list)
    evidence_types: list[str] = Field(default_factory=list)
    risk: RiskLevel
    health: ToolHealth
    expected_latency_ms: int = Field(default=0, ge=0)
    expected_cost_units: float = Field(default=0, ge=0)
    concurrency_key: str = "default"
    version_digest: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    tool_name: str


class AgentProfile(BaseModel):
    profile_id: str
    purpose: str
    allowed_capabilities: list[str] = Field(default_factory=list)
    allowed_skills: list[str] = Field(default_factory=list)
    model_role: str = "worker"
    reasoning_effort: Literal["low", "medium", "high"] = "low"
    max_turns: int = Field(default=3, ge=1, le=3)
    max_context_tokens: int = Field(default=16_000, ge=256)
    max_tool_calls: int = Field(default=3, ge=0, le=3)
    can_request_approval: bool = False
    can_propose_replan: bool = False


class DependencyBinding(BaseModel):
    upstream_step_id: str
    output_name: str
    artifact_id: str | None = None
    expected_media_type: str = "application/json"
    expected_schema: dict[str, Any] = Field(default_factory=dict)
    mount_mode: Literal["read_only", "reference_only"] = "read_only"


class OutcomeContract(BaseModel):
    contract_id: str = Field(default_factory=lambda: str(uuid4()))
    step_id: str
    expected_claim_types: list[str] = Field(default_factory=list)
    required_evidence_types: list[str] = Field(default_factory=list)
    required_tool_versions: dict[str, str] = Field(default_factory=dict)
    required_coverage: dict[str, Any] = Field(default_factory=dict)
    grader_ids: list[str] = Field(default_factory=list)
    confidence_threshold: float = Field(default=0.8, ge=0, le=1)
    allow_partial: bool = True
    partial_conditions: list[str] = Field(default_factory=list)
    contract_digest: str = Field(pattern=r"^[a-fA-F0-9]{64}$")


class Claim(BaseModel):
    claim_id: str = Field(default_factory=lambda: str(uuid4()))
    claim_type: str
    statement: str
    subject_ref: str
    status: ClaimStatus = ClaimStatus.CANDIDATE
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"] = "UNKNOWN"
    confidence: float = Field(default=0, ge=0, le=1)
    producer: str
    version: str = SCHEMA_VERSION


class EvidenceLink(BaseModel):
    link_id: str = Field(default_factory=lambda: str(uuid4()))
    claim_id: str
    evidence_id: str
    relation: EvidenceRelation = EvidenceRelation.SUPPORTS
    weight: float = Field(default=1, ge=0, le=1)
    verifier_status: ClaimStatus = ClaimStatus.CANDIDATE
    grader_id: str | None = None


class VerificationResult(BaseModel):
    claim_id: str
    status: ClaimStatus
    reason_summary: str
    verified_evidence_ids: list[str] = Field(default_factory=list)
    rejected_evidence_ids: list[str] = Field(default_factory=list)
    requested_evidence_types: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0, ge=0, le=1)
    grader_ids: list[str] = Field(default_factory=list)
    evidence_set_digest: str | None = Field(default=None, pattern=r"^[a-fA-F0-9]{64}$")
    evidence_revision: int = Field(default=1, ge=1)


class PlanStep(BaseModel):
    model_config = ConfigDict(extra="forbid")

    step_id: str
    objective: str
    agent_role: str
    capability: str = "code_audit"
    dependencies: list[str] = Field(default_factory=list)
    dependency_bindings: list[DependencyBinding] = Field(default_factory=list)
    tool_candidates: list[str] = Field(default_factory=list)
    skill_ids: list[str] = Field(default_factory=list)
    outcome_contract_id: str | None = None
    context_requirements: dict[str, Any] = Field(default_factory=dict)
    inputs: dict[str, Any] = Field(default_factory=dict)
    success_criteria: list[str] = Field(default_factory=list)
    output_contract: dict[str, Any] = Field(default_factory=dict)
    failure_policy: FailurePolicy = FailurePolicy.SKIP_DEPENDENTS
    concurrency_key: str = "workspace:read"
    estimated_tool_calls: int = Field(default=1, ge=0, le=100)
    estimated_model_calls: int = Field(default=0, ge=0, le=100)
    estimated_tokens: int = Field(default=0, ge=0)
    estimated_cost_units: float = Field(default=0, ge=0)
    risk_hint: RiskLevel = RiskLevel.R0
    max_attempts: int = Field(default=2, ge=1, le=5)


class StrategyProfile(BaseModel):
    strategy_id: StrategyMode
    description: str
    max_parallel_steps: int = Field(default=3, ge=1, le=8)
    max_tool_calls: int = Field(default=12, ge=1, le=100)
    max_model_calls: int = Field(default=0, ge=0, le=100)
    max_runtime_seconds: int = Field(default=600, ge=10, le=7200)
    required_capabilities: list[str] = Field(default_factory=list)
    optional_capabilities: list[str] = Field(default_factory=list)
    profile_digest: str = Field(pattern=r"^[a-fA-F0-9]{64}$")


class PlanCandidate(BaseModel):
    candidate_id: str = Field(default_factory=lambda: str(uuid4()))
    strategy_id: StrategyMode
    steps: list[PlanStep]
    estimated_coverage: float = Field(default=0, ge=0, le=1)
    estimated_latency_ms: int = Field(default=0, ge=0)
    estimated_cost_units: float = Field(default=0, ge=0)
    score: float = 0
    rejection_reasons: list[str] = Field(default_factory=list)
    candidate_digest: str = Field(pattern=r"^[a-fA-F0-9]{64}$")


class RouteRecord(BaseModel):
    route_id: str = Field(default_factory=lambda: str(uuid4()))
    run_id: str
    task_spec_digest: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    scenario: Scenario
    candidate_ids: list[str] = Field(default_factory=list)
    candidate_scores: dict[str, float] = Field(default_factory=dict)
    selected_candidate_id: str | None = None
    selected_strategy: StrategyMode | None = None
    rationale_summary: str
    policy_ids: list[str] = Field(default_factory=list)
    budget_snapshot: dict[str, Any] = Field(default_factory=dict)
    route_digest: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class PlanRevision(BaseModel):
    revision_id: str = Field(default_factory=lambda: str(uuid4()))
    run_id: str
    revision: int = Field(ge=1)
    parent_plan_digest: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    plan_digest: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    trigger: ReplanTrigger
    changed_fields: list[str] = Field(min_length=1)
    rationale_summary: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ScenarioManifest(BaseModel):
    scenario_id: Scenario
    version: str
    maturity: Literal["planned", "scaffolded", "mock-verified", "scenario-verified", "evaluated"]
    accepted_asset_types: list[str] = Field(default_factory=list)
    required_capabilities: list[str] = Field(default_factory=list)
    optional_capabilities: list[str] = Field(default_factory=list)
    strategy_ids: list[StrategyMode] = Field(default_factory=list)
    claim_types: list[str] = Field(default_factory=list)
    evidence_types: list[str] = Field(default_factory=list)
    report_formats: list[str] = Field(default_factory=lambda: ["json", "markdown"])
    risk_ceiling: RiskLevel = RiskLevel.R1
    enabled: bool = False
    package_digest: str = Field(pattern=r"^[a-fA-F0-9]{64}$")


class BudgetState(BaseModel):
    max_steps: int = 12
    max_tool_calls: int = 12
    max_model_calls: int = 20
    max_runtime_seconds: int = 600
    steps_used: int = 0
    tool_calls_used: int = 0
    model_calls_used: int = 0
    max_provider_requests: int = 40
    max_input_tokens: int = 2_000_000
    max_output_tokens: int = 250_000
    max_cost_units: float = 12.0
    max_parallel_steps: int = 3
    usage: ModelUsage = Field(default_factory=ModelUsage)
    context_tokens_used: int = Field(default=0, ge=0)
    reasoning_tokens_used: int = Field(default=0, ge=0)
    cost_reserved: float = Field(default=0, ge=0)
    cost_settled: float = Field(default=0, ge=0)


class Evidence(BaseModel):
    evidence_id: str = Field(default_factory=lambda: str(uuid4()))
    source: str
    summary: str
    artifact_ref: str | None = None
    sha256: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class KnowledgeHit(BaseModel):
    memory_id: str
    content: str
    source: str
    version: str
    confidence: float = Field(ge=0)
    metadata: dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    finding_id: str = Field(default_factory=lambda: str(uuid4()))
    rule_id: str
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"] = "UNKNOWN"
    confidence: Literal["LOW", "MEDIUM", "HIGH", "UNKNOWN"] = "UNKNOWN"
    path: str
    line: int | None = None
    title: str
    description: str
    remediation: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)


class DecisionRecord(BaseModel):
    decision: str
    rationale_summary: str
    evidence_ids: list[str] = Field(default_factory=list)
    policy_ids: list[str] = Field(default_factory=list)
    model_id: str | None = None
    prompt_version: str | None = None
    confidence: float = Field(default=1.0, ge=0, le=1)


class RawPrimaryReceipt(BaseModel):
    """Immutable identity of the one authoritative task-level model response."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = SCHEMA_VERSION
    receipt_id: str = Field(pattern=r"^primary-receipt-[a-f0-9]{64}$")
    run_id: str
    model_id: str
    prompt_version: str
    prompt_artifact_id: str | None = None
    request_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    response_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    response_schema_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    context_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    response_artifact_id: str
    provider_requests: int = Field(default=0, ge=0)
    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    cost_units: float = Field(default=0, ge=0)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class BaselineAdmission(BaseModel):
    """Typed admission decision for model-proposed Primary candidates.

    ``baseline_admitted`` means the response passed the declared schema and
    provenance contract. It deliberately does not claim independent semantic
    corroboration of a vulnerability.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = SCHEMA_VERSION
    admission_id: str = Field(pattern=r"^baseline-admission-[a-f0-9]{64}$")
    run_id: str
    receipt_id: str
    provenance_status: Literal["unbound", "bound", "invalid"]
    semantic_status: Literal["model_proposed", "corroborated", "contradicted", "unresolved"]
    admission_status: Literal["baseline_admitted", "shadow", "rejected"]
    finding_ids: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    semantic_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    admitted_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class PublishedBaselineProjection(BaseModel):
    """Self-contained Primary lane that downstream nodes cannot overwrite."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = SCHEMA_VERSION
    projection_id: str = Field(pattern=r"^baseline-projection-[a-f0-9]{64}$")
    run_id: str
    receipt_id: str
    admission_id: str
    semantic_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    integrity_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    status: RunStatus
    executive_summary: str
    answer_type: str = Field(default="universal", min_length=1, max_length=128)
    answer_payload: dict[str, Any] = Field(default_factory=dict)
    findings: list[Finding] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    decisions: list[DecisionRecord] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    coverage: dict[str, Any] = Field(default_factory=dict)
    published_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ApprovalRequest(BaseModel):
    request_id: str = Field(default_factory=lambda: str(uuid4()))
    run_id: str
    step_id: str
    tool_name: str
    parameters: dict[str, Any]
    target: str
    risk_level: RiskLevel
    reason: str
    expected_impact: str


class ApprovalResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: ApprovalDecision
    resolution_id: str | None = None
    reason: str = ""
    edited_parameters: dict[str, Any] | None = None

    @model_validator(mode="after")
    def require_edited_parameters(self) -> ApprovalResponse:
        if self.decision == ApprovalDecision.EDIT and self.edited_parameters is None:
            raise ValueError("edited_parameters is required for edit decisions")
        return self


class ApprovalResolutionItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_id: str = Field(min_length=1)
    response: ApprovalResponse


class ApprovalBatchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[ApprovalResolutionItem] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def require_unique_request_ids(self) -> ApprovalBatchRequest:
        request_ids = [item.request_id for item in self.items]
        if len(request_ids) != len(set(request_ids)):
            raise ValueError("batch contains duplicate approval request ids")
        return self


class CapabilityGrant(BaseModel):
    grant_id: str = Field(default_factory=lambda: str(uuid4()))
    run_id: str
    actor: str
    allowed_actions: list[str] = Field(default_factory=list)
    allowed_tools: list[str] = Field(default_factory=list)
    target_scope: list[str] = Field(default_factory=list)
    parameter_constraints: dict[str, Any] = Field(default_factory=dict)
    network_constraints: list[str] = Field(default_factory=list)
    max_uses: int = Field(default=1, ge=1)
    uses: int = Field(default=0, ge=0)
    expires_at: datetime
    revocable: bool = True
    revoked_at: datetime | None = None
    grant_digest: str = Field(pattern=r"^[a-fA-F0-9]{64}$")


class PolicyInput(BaseModel):
    policy_version: str
    actor: str
    run_id: str
    step_id: str
    action: str
    resource: str
    target_scope: list[str] = Field(default_factory=list)
    task_constraints: list[str] = Field(default_factory=list)
    tool_manifest_digest: str
    parameters_hash: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    data_classification: DataSensitivity = DataSensitivity.INTERNAL
    network_policy: str = "none"
    workspace_policy: dict[str, Any] = Field(default_factory=dict)
    requested_capabilities: list[str] = Field(default_factory=list)
    current_grants: list[CapabilityGrant] = Field(default_factory=list)
    fence: int = Field(default=0, ge=0)


class PolicyDecision(BaseModel):
    decision_id: str = Field(default_factory=lambda: str(uuid4()))
    action: PolicyAction
    effective_risk: RiskLevel
    policy_ids: list[str] = Field(default_factory=list)
    reason_summary: str
    constrained_parameters: dict[str, Any] = Field(default_factory=dict)
    capability_grant: CapabilityGrant | None = None
    expires_at: datetime | None = None
    decision_input_hash: str = Field(pattern=r"^[a-fA-F0-9]{64}$")


class HookEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid4()))
    run_id: str
    step_id: str | None = None
    event_type: str
    payload: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class HookResult(BaseModel):
    hook_id: str
    event_id: str
    decision: HookDecision = HookDecision.CONTINUE
    patch: dict[str, Any] = Field(default_factory=dict)
    policy_ids: list[str] = Field(default_factory=list)
    additional_context_refs: list[str] = Field(default_factory=list)
    error: str | None = None
    duration_ms: int = Field(default=0, ge=0)
    input_hash: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    output_hash: str = Field(pattern=r"^[a-fA-F0-9]{64}$")


class RunNotebook(BaseModel):
    objective: str
    immutable_constraints: list[str] = Field(default_factory=list)
    verified_facts: list[str] = Field(default_factory=list)
    open_hypotheses: list[str] = Field(default_factory=list)
    rejected_hypotheses: list[str] = Field(default_factory=list)
    completed_steps: list[str] = Field(default_factory=list)
    failed_attempts: list[dict[str, Any]] = Field(default_factory=list)
    active_evidence_handles: list[str] = Field(default_factory=list)
    unresolved_claims: list[str] = Field(default_factory=list)
    next_recommended_actions: list[str] = Field(default_factory=list)
    budget_snapshot: dict[str, Any] = Field(default_factory=dict)
    notebook_digest: str = Field(pattern=r"^[a-fA-F0-9]{64}$")


class ReplayBundleRef(BaseModel):
    replay_id: str = Field(default_factory=lambda: str(uuid4()))
    run_id: str
    artifact_id: str
    manifest_digest: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    ledger_head_hash: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    ledger_head_signature: str | None = None
    mode: Literal["verify-only", "deterministic-replay", "checkpoint-fork"] = "verify-only"
    parent_run_id: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ReplayRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: Literal["verify-only", "deterministic-replay", "checkpoint-fork"] = "verify-only"
    build_if_missing: bool = True
    checkpoint_id: str | None = Field(default=None, min_length=1, max_length=200)
    fork_request_id: str | None = Field(default=None, min_length=8, max_length=128)
    task: TaskRequest | None = None


class InputMutation(BaseModel):
    mutation_id: str = Field(default_factory=lambda: str(uuid4()))
    stage: Literal["normalize", "default", "operator_edit", "trusted_hook_patch", "scope_binding"]
    field_path: str
    previous_digest: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    new_digest: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    actor: str
    reason: str
    policy_ids: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ToolInputEnvelope(BaseModel):
    invocation_id: str
    run_id: str
    step_id: str
    raw_input_ref: str
    observable_input: dict[str, Any]
    execution_input_ref: str
    raw_digest: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    observable_digest: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    execution_digest: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    mutation_chain: list[InputMutation] = Field(default_factory=list)
    scope_binding: list[str] = Field(default_factory=list)
    approval_binding: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ToolManifest(BaseModel):
    name: str
    version: str
    description: str
    scenarios: list[Scenario]
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    risk_level: RiskLevel
    permissions: list[str] = Field(default_factory=list)
    timeout_seconds: int = Field(default=120, ge=1, le=3600)
    idempotent: bool = True
    requires_network: bool = False
    execution: ToolExecutionPolicy = Field(default_factory=lambda: ToolExecutionPolicy())
    capability_tags: list[str] = Field(default_factory=list)
    supported_languages: list[str] = Field(default_factory=list)
    accepted_media_types: list[str] = Field(default_factory=lambda: ["application/octet-stream"])
    rule_bundle_digest: str | None = None
    evidence_types: list[str] = Field(default_factory=lambda: ["finding"])
    platform_risk: RiskLevel | None = None
    concurrency_key: str = "default"
    max_parallelism: int = Field(default=1, ge=1, le=64)
    health_status: ToolHealth = ToolHealth.HEALTHY


class ToolExecutionPolicy(BaseModel):
    """Server-owned sandbox policy; callers cannot override these fields."""

    image_digest: str | None = None
    entrypoint: list[str] = Field(default_factory=list)
    network_policy: Literal["none", "restricted"] = "none"
    cpu_limit: float = Field(default=1.0, gt=0, le=16)
    memory_mb: int = Field(default=512, ge=32, le=32768)
    pids_limit: int = Field(default=64, ge=1, le=4096)
    tmpfs_mb: int = Field(default=64, ge=1, le=4096)
    output_limit_bytes: int = Field(default=10 * 1024 * 1024, ge=1)


class ToolContext(BaseModel):
    run_id: str
    step_id: str
    workspace: str
    allowed_paths: list[str]
    invocation_id: str = Field(default_factory=lambda: str(uuid4()))
    idempotency_key: str = Field(default_factory=lambda: str(uuid4()))
    attempt: int = Field(default=1, ge=1)
    lease_fence: int = Field(default=0, ge=0)
    lease_owner_id: str = "local-worker"
    step_run_id: str | None = None
    run_fence: int = Field(default=0, ge=0)
    step_fence: int = Field(default=0, ge=0)
    usage_reservation_id: str | None = None
    dispatch_permit_id: str | None = None
    work_contract_id: str | None = None
    work_contract_digest: str | None = Field(default=None, pattern=r"^[a-fA-F0-9]{64}$")


class ToolResult(BaseModel):
    invocation_id: str | None = None
    status: ToolStatus
    data: dict[str, Any] = Field(default_factory=dict)
    summary: str = ""
    artifacts: list[ArtifactRef] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    duration_ms: int = 0
    error_code: str | None = None
    error_message: str | None = None


class AuditUnitResult(BaseModel):
    """Public, source-free projection of one v0.7 audit decision.

    Negative and inconclusive outcomes are first-class records. Consumers must
    never infer a negative from the absence of a Finding.
    """

    schema_version: str = SCHEMA_VERSION
    unit_id: str = Field(pattern=r"^unit-[a-f0-9]{64}$")
    path: str = Field(min_length=1, max_length=1024)
    source_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    baseline_verdict: Literal["vulnerable", "not_vulnerable", "inconclusive"]
    final_verdict: Literal["vulnerable", "not_vulnerable", "inconclusive"]
    action: Literal["keep_baseline", "accept_enhancement", "accept_correction"]
    baseline_cwe: int | None = Field(default=None, gt=0)
    cwe: int | None = Field(default=None, gt=0)
    sink_line: int | None = Field(default=None, ge=1)
    confidence: float = Field(ge=0, le=1)
    primary_receipt_id: str = Field(min_length=1, max_length=256)
    decision_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    evidence_ids: list[str] = Field(default_factory=list)
    reason_codes: list[str] = Field(default_factory=list)
    lane: Literal["final", "shadow"] = "final"

    @model_validator(mode="after")
    def validate_positive_locator(self) -> AuditUnitResult:
        if self.final_verdict == "vulnerable" and (self.cwe is None or self.sink_line is None):
            raise ValueError("a vulnerable audit result requires CWE and sink line")
        return self


class AgentReport(BaseModel):
    schema_version: str = SCHEMA_VERSION
    run_id: str
    status: RunStatus
    executive_summary: str
    answer_type: str = Field(default="universal", min_length=1, max_length=128)
    answer_payload: dict[str, Any] = Field(default_factory=dict)
    findings: list[Finding] = Field(default_factory=list)
    decisions: list[DecisionRecord] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    coverage: dict[str, Any] = Field(default_factory=dict)
    unscanned_scope: list[str] = Field(default_factory=list)
    tool_failures: list[dict[str, Any]] = Field(default_factory=list)
    verification_summary: dict[str, Any] = Field(default_factory=dict)
    audit_kernel: str | None = None
    audit_units: list[AuditUnitResult] = Field(default_factory=list)
    claim_ids: list[str] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class SealedAdmissionSnapshot(BaseModel):
    """The only public finding set consumed by terminal report projections."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = SCHEMA_VERSION
    snapshot_id: str = Field(pattern=r"^admission-snapshot-[a-f0-9]{64}$")
    run_id: str
    baseline_projection_id: str | None = None
    baseline_semantic_digest: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    final_semantic_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    report_integrity_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    admitted_finding_ids: list[str] = Field(default_factory=list)
    rejected_finding_ids: list[str] = Field(default_factory=list)
    report: AgentReport
    sealed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class EvidenceGapTicket(BaseModel):
    """Bounded authority for one optional post-Primary investigation step."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = SCHEMA_VERSION
    ticket_id: str = Field(pattern=r"^gap-ticket-[a-f0-9]{64}$")
    run_id: str
    snapshot_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    primary_semantic_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    gap_code: Literal[
        "empty_or_inconclusive_primary",
        "security_sensitive_weak_digest",
        "cwe_uncertain",
        "sink_location_missing",
        "source_sink_trace_missing",
        "primary_tool_conflict",
        "missing_secret_coverage",
        "missing_dependency_coverage",
        "missing_web_workflow_coverage",
        "missing_java_semantic_coverage",
    ]
    target_finding_id: str | None = None
    allowed_patch_class: Literal["add_finding", "correct_cwe", "attach_trace"]
    capability: str
    tool_name: str
    step_id: str
    release_policy: Literal["authoritative", "shadow"]
    max_tool_calls: int = Field(default=1, ge=1, le=2)
    max_runtime_ms: int = Field(default=120_000, ge=1_000, le=120_000)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class StepRuntime(BaseModel):
    step_id: str
    status: StepStatus = StepStatus.PENDING
    attempt: int = Field(default=0, ge=0)
    assigned_worker: str | None = None
    lease_fence: int = Field(default=0, ge=0)
    transition_id: str | None = None
    run_fence: int = Field(default=0, ge=0)
    step_fence: int = Field(default=0, ge=0)
    actual_tool_calls: int = Field(default=0, ge=0)
    tool_invocation_ids: list[str] = Field(default_factory=list)
    actual_tool_name: str | None = None
    actual_tool_version: str | None = None
    observation_indexes: list[int] = Field(default_factory=list)
    artifact_ids: list[str] = Field(default_factory=list)
    last_error: str | None = None


class WorkItem(BaseModel):
    run_id: str
    step_id: str
    capability: str
    tool_name: str
    inputs: dict[str, Any]
    workspace_ref: str
    workspace_snapshot_ref: str | None = None
    autonomy_policy: Literal["graded", "approval_all", "automatic"] = "graded"
    dependency_refs: list[str] = Field(default_factory=list)
    dependency_bindings: list[DependencyBinding] = Field(default_factory=list)
    context_pack_id: str | None = None
    knowledge_refs: list[str] = Field(default_factory=list)
    signed_skill_refs: list[str] = Field(default_factory=list)
    context_pack_digest: str | None = Field(default=None, pattern=r"^[a-fA-F0-9]{64}$")
    context_influence_digest: str | None = Field(default=None, pattern=r"^[a-fA-F0-9]{64}$")
    outcome_contract_id: str | None = None
    capability_candidates: list[str] = Field(default_factory=list)
    skill_ids: list[str] = Field(default_factory=list, max_length=3)
    agent_profile: str = "security-investigator"
    transition_id: str
    step_run_id: str | None = None
    plan_revision: int = Field(default=0, ge=0, le=2)
    step_generation: int = Field(default=0, ge=0)
    run_fence: int = Field(default=0, ge=0)
    step_fence: int = Field(default=0, ge=0)
    usage_reservation_id: str | None = None
    dispatch_permit_id: str | None = None
    work_contract_id: str | None = None
    work_contract_digest: str | None = Field(default=None, pattern=r"^[a-fA-F0-9]{64}$")
    lease_fence: int = Field(default=0, ge=0)
    lease_owner_id: str = "local-worker"
    attempt: int = Field(default=1, ge=1)
    max_tool_calls: int = Field(default=3, ge=1, le=3)
    approval_request_id: str | None = None
    budget_reservation: BudgetState


class StepPatch(BaseModel):
    step_id: str
    transition_id: str
    step_run_id: str | None = None
    plan_revision: int = Field(default=0, ge=0, le=2)
    step_generation: int = Field(default=0, ge=0)
    run_fence: int = Field(default=0, ge=0)
    step_fence: int = Field(default=0, ge=0)
    usage_reservation_id: str | None = None
    attempt: int = Field(default=1, ge=1)
    lease_fence: int = Field(default=0, ge=0)
    status: StepStatus
    findings: list[Finding] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    artifact_ids: list[str] = Field(default_factory=list)
    tool_invocation_ids: list[str] = Field(default_factory=list)
    actual_tool_name: str | None = None
    actual_tool_version: str | None = None
    actual_tool_calls: int = Field(default=0, ge=0)
    artifact_bytes: int = Field(default=0, ge=0)
    decision_summary: str = ""
    usage: ModelUsage = Field(default_factory=ModelUsage)
    observation: ToolResult | None = None
    typed_error: str | None = None
    claims: list[Claim] = Field(default_factory=list)
    evidence_links: list[EvidenceLink] = Field(default_factory=list)
    verification_requests: list[str] = Field(default_factory=list)
    context_usage: ContextBudget = Field(default_factory=ContextBudget)


class LeaseSummary(BaseModel):
    owner_id: str | None = None
    fence: int = Field(default=0, ge=0)
    lease_until: datetime | None = None
    heartbeat_at: datetime | None = None


class AgentState(BaseModel):
    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="before")
    @classmethod
    def upcast_public_schema(cls, value: Any) -> Any:
        """Upgrade durable v0.7 JSON state at the v0.8 runtime boundary.

        State rows are JSON documents rather than migration-managed columns.
        Keeping an old top-level/report version after recovery would create a
        mixed 1.6/1.7 object graph, so the upcast is deterministic and happens
        before validation for every persistence adapter.
        """

        if not isinstance(value, dict):
            return value
        payload = dict(value)
        payload["schema_version"] = SCHEMA_VERSION
        for field in (
            "raw_primary_receipt",
            "baseline_admission",
            "published_baseline",
            "sealed_admission",
            "report",
        ):
            nested = payload.get(field)
            if isinstance(nested, dict):
                nested = dict(nested)
                nested["schema_version"] = SCHEMA_VERSION
                if field == "sealed_admission" and isinstance(nested.get("report"), dict):
                    nested["report"] = {**nested["report"], "schema_version": SCHEMA_VERSION}
                payload[field] = nested
        for field in ("audit_units", "evidence_gap_tickets"):
            rows = payload.get(field)
            if isinstance(rows, list):
                payload[field] = [
                    {**item, "schema_version": SCHEMA_VERSION} if isinstance(item, dict) else item for item in rows
                ]
        return payload

    schema_version: str = SCHEMA_VERSION
    state_version: int = Field(default=1, ge=1)
    transition_counter: int = Field(default=0, ge=0)
    run_id: str
    parent_run_id: str | None = None
    fork_checkpoint_id: str | None = None
    fork_request_id: str | None = None
    fork_child_checkpoint_id: str | None = None
    fork_checkpoint_state_version: int | None = Field(default=None, ge=1)
    task: TaskRequest
    task_spec_ref: TaskSpecRef | None = None
    resolved_task_contract: ResolvedTaskContract | None = None
    obligation_status: list[TaskObligation] = Field(default_factory=list)
    evidence_compiler_receipt: EvidenceCompilerReceipt | None = None
    belief_state: BeliefState = Field(default_factory=BeliefState)
    answer_revisions: list[PublishedAnswerRevision] = Field(default_factory=list)
    parser_run_ids: list[str] = Field(default_factory=list)
    pending_clarification: ClarificationRequest | None = None
    clarifications: list[dict[str, Any]] = Field(default_factory=list)
    active_route: RouteRecord | None = None
    intent_analysis_id: str | None = None
    plan_contract_id: str | None = None
    team_plan_id: str | None = None
    active_evidence_request_ids: list[str] = Field(default_factory=list)
    completion_snapshot_id: str | None = None
    completion_receipt_id: str | None = None
    plan_revisions: list[PlanRevision] = Field(default_factory=list)
    replan_count: int = Field(default=0, ge=0, le=2)
    scenario: Scenario = Scenario.UNKNOWN
    status: RunStatus = RunStatus.PENDING
    workspace: str = ""
    input_artifacts: list[InputArtifact] = Field(default_factory=list)
    plan: list[PlanStep] = Field(default_factory=list)
    current_step_index: int = 0
    active_invocation_id: str | None = None
    observations: list[ToolResult] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    knowledge_hits: list[KnowledgeHit] = Field(default_factory=list)
    repository_index: RepositoryIndexRef | None = None
    context_items: list[ContextItemRef] = Field(default_factory=list)
    context_packs: list[ContextPackRef] = Field(default_factory=list)
    selected_skill_ids: list[str] = Field(default_factory=list)
    active_agent_profiles: list[str] = Field(default_factory=list)
    outcome_contracts: list[OutcomeContract] = Field(default_factory=list)
    claims: list[Claim] = Field(default_factory=list)
    evidence_links: list[EvidenceLink] = Field(default_factory=list)
    verification_results: list[VerificationResult] = Field(default_factory=list)
    contract_grades: dict[str, list[dict[str, Any]]] = Field(default_factory=dict)
    verification_rounds: int = Field(default=0, ge=0, le=2)
    completion_reasons: list[str] = Field(default_factory=list)
    active_grants: list[CapabilityGrant] = Field(default_factory=list)
    notebook: RunNotebook | None = None
    replay_bundle: ReplayBundleRef | None = None
    findings: list[Finding] = Field(default_factory=list)
    audit_kernel: str | None = None
    audit_units: list[AuditUnitResult] = Field(default_factory=list)
    audit_coverage: dict[str, Any] = Field(default_factory=dict)
    anchor_report_artifact_id: str | None = None
    anchor_report_digest: str | None = Field(default=None, pattern=r"^[a-fA-F0-9]{64}$")
    enhanced_report_artifact_id: str | None = None
    enhanced_report_digest: str | None = Field(default=None, pattern=r"^[a-fA-F0-9]{64}$")
    raw_primary_receipt: RawPrimaryReceipt | None = None
    baseline_admission: BaselineAdmission | None = None
    published_baseline: PublishedBaselineProjection | None = None
    sealed_admission: SealedAdmissionSnapshot | None = None
    evidence_gap_tickets: list[EvidenceGapTicket] = Field(default_factory=list)
    decisions: list[DecisionRecord] = Field(default_factory=list)
    pending_approval: ApprovalRequest | None = None
    pending_approvals: list[ApprovalRequest] = Field(default_factory=list)
    approvals: list[dict[str, Any]] = Field(default_factory=list)
    retry_counts: dict[str, int] = Field(default_factory=dict)
    step_runtime: dict[str, StepRuntime] = Field(default_factory=dict)
    processed_transition_ids: set[str] = Field(default_factory=set)
    lease: LeaseSummary = Field(default_factory=LeaseSummary)
    cancel_requested: bool = False
    budget: BudgetState = Field(default_factory=BudgetState)
    report: AgentReport | None = None
    last_error: str | None = None
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class LedgerEvent(BaseModel):
    schema_version: str = SCHEMA_VERSION
    event_id: str
    run_id: str
    sequence: int
    event_type: str
    timestamp: datetime
    actor: str
    dedupe_key: str
    payload: dict[str, Any]
    prev_hash: str
    hash: str


class RunSummary(BaseModel):
    schema_version: str = SCHEMA_VERSION
    run_id: str
    parent_run_id: str | None = None
    fork_checkpoint_id: str | None = None
    status: RunStatus
    scenario: Scenario
    current_step: int
    total_steps: int
    plan: list[PlanStep] = Field(default_factory=list)
    current_step_id: str | None = None
    budget: BudgetState = Field(default_factory=BudgetState)
    started_at: datetime | None = None
    updated_at: datetime | None = None
    latest_event_sequence: int = 0
    task_spec_ref: TaskSpecRef | None = None
    active_route: RouteRecord | None = None
    pending_clarification: ClarificationRequest | None = None
    pending_approval: ApprovalRequest | None = None
    last_error: str | None = None
    queue_status: QueueStatus = QueueStatus.QUEUED
    lease: LeaseSummary = Field(default_factory=LeaseSummary)
    active_step_ids: list[str] = Field(default_factory=list)
    cancel_requested: bool = False
    verified_claims: int = Field(default=0, ge=0)
    insufficient_claims: int = Field(default=0, ge=0)
    conflicted_claims: int = Field(default=0, ge=0)
    context_usage: ContextBudget = Field(default_factory=ContextBudget)
    active_approval_ids: list[str] = Field(default_factory=list)
    audit_kernel: str | None = None
    audit_coverage: dict[str, Any] = Field(default_factory=dict)
