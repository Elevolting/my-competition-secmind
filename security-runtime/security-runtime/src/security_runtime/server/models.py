from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator


class Settings(BaseModel):
    intent_timeout: int = Field(ge=5)
    reason_timeout: int = Field(ge=5)


class ResultItem(BaseModel):
    id: str | None = None
    output_key: str | None = Field(default=None, min_length=1, max_length=120)
    type: Literal["fact", "finding", "observation", "artifact"] = "fact"
    title: str = Field(min_length=1, max_length=240)
    summary: str = ""
    outcome: Literal["observed", "negative", "unverified"] = "observed"
    evidence_ids: list[str] = Field(default_factory=list)
    finding_id: str | None = None
    verification_status: Literal["candidate", "pending", "confirmed", "ruled_out", "insufficient"] | None = None


class StageRequest(BaseModel):
    worker: str = Field(min_length=1, max_length=200)
    attempt_id: str | None = None
    phase: str = Field(min_length=1, max_length=100)
    status: Literal["running", "approval", "completed", "failed", "cancelled", "timeout"]
    call_id: str | None = Field(default=None, max_length=200)


class Fact(BaseModel):
    id: str
    description: str
    title: str | None = None
    items: list[ResultItem] = Field(default_factory=list)


class Intent(BaseModel):
    id: str
    from_: list[str] = Field(alias="from")
    to: str | None = None
    description: str
    tool_name: str | None = None
    creator: str
    worker: str | None = None
    last_heartbeat_at: str | None = None
    created_at: str
    concluded_at: str | None = None
    attempt_id: str | None = None
    execution_status: str = "waiting"
    step_id: str | None = None
    depends_on: list[str] = Field(default_factory=list)
    required_outputs: dict[str, list[str]] = Field(default_factory=dict)
    validated_outputs: list[str] = Field(default_factory=list)
    blocked_reasons: list[str] = Field(default_factory=list)
    source_relations: dict[str, Literal["evidence", "process", "unknown"]] = Field(default_factory=dict)
    source_relation: str = "evidence"
    success_criteria: str | None = None
    title: str | None = None
    verification_target: str | None = None
    decision_id: str | None = None
    decision_summary: str | None = None

    model_config = {"populate_by_name": True}


class Hint(BaseModel):
    id: str
    content: str
    creator: str
    created_at: str


class ProjectReason(BaseModel):
    worker: str
    trigger: str
    started_at: str
    last_heartbeat_at: str


class ProjectMeta(BaseModel):
    id: str
    title: str
    status: Literal["active", "stopped", "completed"]
    bootstrap_enabled: bool
    dispatcher_enabled: bool = True
    created_at: str
    reason_attempt_id: str | None = None
    reason_decision_pending: bool = False
    reason: ProjectReason | None = None


class ProjectSummary(ProjectMeta):
    fact_count: int
    intent_count: int
    working_intent_count: int
    unclaimed_intent_count: int
    hint_count: int


class ProjectDetail(BaseModel):
    project: ProjectMeta
    facts: list[Fact]
    intents: list[Intent]
    hints: list[Hint]


class ProjectEvent(BaseModel):
    sequence: int
    event_id: str
    project_id: str
    intent_id: str | None = None
    attempt_id: str | None = None
    event_type: str
    worker: str | None = None
    timestamp: str
    payload: dict = Field(default_factory=dict)


class CreateHintInline(BaseModel):
    content: str
    creator: str

    @field_validator("content", "creator")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text


class CreateProjectRequest(BaseModel):
    title: str
    origin: str
    goal: str
    bootstrap_enabled: bool = True
    dispatcher_enabled: bool = True
    dispatcher_activation_token: str | None = Field(default=None, min_length=32, max_length=256)
    idempotency_key: str | None = Field(default=None, min_length=8, max_length=240)
    hints: list[CreateHintInline] | None = None

    @field_validator("title", "origin", "goal")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text


class CreateHintRequest(BaseModel):
    content: str
    creator: str

    @field_validator("content", "creator")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text


class CreateIntentRequest(BaseModel):
    from_: list[str] = Field(alias="from", min_length=1)
    description: str
    tool_name: str | None = None
    creator: str
    worker: str | None = None
    source_relations: dict[str, Literal["evidence", "process", "unknown"]] = Field(default_factory=dict)
    source_relation: Literal["evidence", "process", "unknown"] = "evidence"
    success_criteria: str | None = None
    title: str | None = Field(default=None, max_length=240)
    verification_target: str | None = Field(default=None, max_length=2000)

    model_config = {"populate_by_name": True}

    @field_validator("description", "creator", "worker", "tool_name", "title", "verification_target")
    @classmethod
    def validate_non_empty_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text

    @field_validator("from_")
    @classmethod
    def validate_fact_ids(cls, value: list[str]) -> list[str]:
        cleaned = []
        for item in value:
            text = item.strip()
            if not text:
                raise ValueError("fact ids must not be empty")
            cleaned.append(text)
        return cleaned


class HeartbeatRequest(BaseModel):
    worker: str
    attempt_id: str | None = None
    claim: bool = False
    outcome: Literal["waiting", "failed", "cancelled", "timeout"] = "waiting"
    reason: str | None = None

    @field_validator("worker")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text


class ReasonClaimRequest(BaseModel):
    worker: str
    trigger: str
    attempt_id: str | None = None

    @field_validator("worker", "trigger")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text


class ConcludeRequest(BaseModel):
    execution_status: Literal["completed", "failed", "cancelled", "timeout"] = "completed"
    worker: str
    attempt_id: str | None = None
    description: str
    title: str | None = None
    items: list[ResultItem] = Field(default_factory=list)

    @field_validator("title")
    @classmethod
    def validate_title(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not value:
            raise ValueError("title must not be empty")
        return value[:240]

    @field_validator("worker", "description")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text


class CompleteRequest(BaseModel):
    from_: list[str] = Field(alias="from", min_length=1)
    description: str
    worker: str

    model_config = {"populate_by_name": True}

    @field_validator("description", "worker")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text

    @field_validator("from_")
    @classmethod
    def validate_fact_ids(cls, value: list[str]) -> list[str]:
        cleaned = []
        for item in value:
            text = item.strip()
            if not text:
                raise ValueError("fact ids must not be empty")
            cleaned.append(text)
        return cleaned


class ConcludeResponse(BaseModel):
    fact: Fact
    intent: Intent


class UpdateProjectStatusRequest(BaseModel):
    status: Literal["active", "stopped"]


class ActivateDispatcherRequest(BaseModel):
    title: str
    # A token is required only while the project is awaiting activation.  An
    # already active project can be queried idempotently without resubmitting
    # the one-time credential.
    activation_token: str | None = Field(default=None, min_length=32, max_length=256)


class UpdateProjectTitleRequest(BaseModel):
    title: str

    @field_validator("title")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text


class ReopenRequest(BaseModel):
    description: str
    creator: str

    @field_validator("description", "creator")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text


class ReopenResponse(BaseModel):
    project: ProjectMeta
    fact: Fact
    intent: Intent


class PlanningIntentProposal(BaseModel):
    step_id: str | None = Field(default=None, min_length=1, max_length=120)
    depends_on: list[str] = Field(default_factory=list, max_length=30)
    required_outputs: dict[str, list[str]] = Field(default_factory=dict)
    from_: list[str] = Field(alias="from", min_length=1, max_length=30)
    description: str = Field(min_length=1, max_length=4000)
    title: str | None = Field(default=None, max_length=240)
    tool_name: str | None = Field(default=None, max_length=200)
    source_relations: dict[str, Literal["evidence", "process", "unknown"]] = Field(default_factory=dict)
    source_relation: Literal["evidence", "process", "unknown"] = "evidence"
    success_criteria: list[str] = Field(default_factory=list, max_length=12)
    verification_target: str | None = Field(default=None, max_length=2000)
    retry_intent_id: str | None = Field(default=None, max_length=200)

    model_config = {"populate_by_name": True}


class ApplyPlanningDecisionRequest(BaseModel):
    decision_id: str = Field(min_length=8, max_length=240)
    reason_attempt_id: str | None = None
    snapshot_hash: str = Field(min_length=8, max_length=128)
    trigger: str = Field(min_length=1, max_length=120)
    summary: str = Field(default="", max_length=4000)
    intents: list[PlanningIntentProposal] = Field(default_factory=list, max_length=12)
    validated_outputs: dict[str, list[str]] = Field(default_factory=dict)
    completion_validated: bool = False
    completion_fact_ids: list[str] = Field(default_factory=list, max_length=30)
    completion_reason: str | None = Field(default=None, max_length=2000)
    stop_reason: str | None = Field(default=None, max_length=2000)


class ApplyPlanningDecisionResponse(BaseModel):
    decision_id: str
    project_id: str
    status: Literal["created", "completed", "stopped", "replayed"]
    intent_ids: list[str] = Field(default_factory=list)
    summary: str = ""
    stop_reason: str | None = None
