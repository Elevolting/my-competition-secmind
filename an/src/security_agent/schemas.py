from __future__ import annotations

from datetime import UTC, datetime
from enum import IntEnum, StrEnum
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

from security_agent.budget_policy import MAX_MODEL_CALLS, MAX_RUNTIME_SECONDS, MAX_TOOL_CALLS

SCHEMA_VERSION = "1.0"


class Scenario(StrEnum):
    CODE_AUDIT = "code_audit"
    LOG_ANALYSIS = "log_analysis"
    INCIDENT_RESPONSE = "incident_response"
    PENETRATION_TEST = "penetration_test"
    REVERSE_TRIAGE = "reverse_triage"
    UNKNOWN = "unknown"


class RunStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    WAITING_APPROVAL = "waiting_approval"
    COMPLETED = "completed"
    PARTIAL = "partial"
    DENIED = "denied"
    FAILED = "failed"


class BatchStatus(StrEnum):
    PENDING = "pending"
    DISPATCHING = "dispatching"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL_FAILED = "partial_failed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class BatchTaskStatus(StrEnum):
    PENDING = "pending"
    BLOCKED = "blocked"
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    PARTIAL = "partial"
    FAILED = "failed"
    DENIED = "denied"
    CANCELLED = "cancelled"


class EvaluationMode(StrEnum):
    ANALYSIS = "analysis"
    BENCHMARK = "benchmark"


class EvaluationStatus(StrEnum):
    UPLOADED = "UPLOADED"
    INPUT_VALIDATING = "INPUT_VALIDATING"
    AGENT_QUEUED = "AGENT_QUEUED"
    AGENT_RUNNING = "AGENT_RUNNING"
    REPORT_READY = "REPORT_READY"
    SCORE_QUEUED = "SCORE_QUEUED"
    SCORING = "SCORING"
    SCORED = "SCORED"
    UNSCORABLE_NO_GOLD = "UNSCORABLE_NO_GOLD"
    INPUT_MISMATCH = "INPUT_MISMATCH"
    AGENT_FAILED = "AGENT_FAILED"
    SCORING_FAILED = "SCORING_FAILED"
    VERIFIER_REQUIRED = "VERIFIER_REQUIRED"


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


class AttachmentRef(BaseModel):
    ref: str = Field(min_length=1, description="Upload reference or input-root-relative path")
    name: str | None = None


class TaskRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = SCHEMA_VERSION
    name: str | None = Field(default=None, min_length=1, max_length=120)
    objective: str = Field(min_length=3, max_length=10_000)
    attachments: list[AttachmentRef] = Field(default_factory=list)
    target_scope: list[str] = Field(default_factory=list)
    constraints: list[str] = Field(default_factory=list)
    network_policy: Literal["none", "read_only_http", "scoped_file_post", "bounded_http", "session_http"] = "none"
    expected_outputs: list[str] = Field(default_factory=lambda: ["security_report"])
    autonomy_policy: Literal["graded", "approval_all", "automatic", "automatic_r3"] = "graded"
    analysis_backend: Literal["auto", "local", "secmind"] = "auto"
    question_bank_id: str | None = Field(default=None, pattern=r"^[0-9a-f-]{36}$")
    max_runtime_seconds: int | None = Field(default=None, ge=60, le=MAX_RUNTIME_SECONDS)
    max_tool_calls: int | None = Field(default=None, ge=1, le=MAX_TOOL_CALLS)
    max_model_calls: int | None = Field(default=None, ge=1, le=MAX_MODEL_CALLS)


class RunRetryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_id: str = Field(min_length=16, max_length=100, pattern=r"^[a-zA-Z0-9_-]+$")
    max_runtime_seconds: int | None = Field(default=None, ge=60, le=MAX_RUNTIME_SECONDS)
    max_tool_calls: int | None = Field(default=None, ge=1, le=MAX_TOOL_CALLS)
    max_model_calls: int | None = Field(default=None, ge=1, le=MAX_MODEL_CALLS)
    network_policy: Literal["none", "read_only_http", "scoped_file_post", "bounded_http", "session_http"] | None = None


class RunHintRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    content: str = Field(min_length=1, max_length=4000)
    creator: str = Field(default="web-operator", min_length=1, max_length=120)

    @field_validator("content", "creator")
    @classmethod
    def validate_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text


class ColdDigestCompactRequest(BaseModel):
    """Operator-triggered planner round for the durable cold digest view."""

    model_config = ConfigDict(extra="forbid")

    R: int = Field(default=6, ge=1, le=1000)
    K: int = Field(default=2, ge=2, le=1000)
    round_id: str | None = Field(default=None, min_length=1, max_length=200)


class QuestionBankInspectRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=120)
    attachments: list[AttachmentRef] = Field(min_length=1)
    analysis_mode: Literal["ai_assisted", "formatted"] = "ai_assisted"


class QuestionCandidateConfirmation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    candidate_id: str = Field(min_length=1, max_length=80)
    confirmed: bool = True
    name: str | None = Field(default=None, min_length=1, max_length=200)
    root: str = Field(min_length=1, max_length=2048)
    question_type: str | None = Field(default=None, min_length=1, max_length=40)


class QuestionBankConfirmRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    questions: list[QuestionCandidateConfirmation] = Field(min_length=1)


class BatchExecutionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    parallel: bool | None = None
    max_concurrency: int | None = Field(default=None, ge=1, le=64)


class BatchCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    question_bank_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    execution: BatchExecutionRequest = Field(default_factory=BatchExecutionRequest)


QuestionType = Literal[
    "web",
    "pwn",
    "reverse",
    "crypto",
    "forensics",
    "mobile",
    "blockchain",
    "ai_security",
    "code_audit",
    "misc",
    "unknown",
]

DirectoryRole = Literal[
    "wrapper",
    "container",
    "question_root",
    "internal",
    "ignore",
    "uncertain",
]


class DirectoryDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str = Field(min_length=1, max_length=2048)
    role: DirectoryRole
    confidence: float = Field(ge=0, le=1)
    name: str | None = Field(default=None, min_length=1, max_length=200)
    rationale_summary: str = Field(min_length=1, max_length=500)


class DirectoryScanProposal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decisions: list[DirectoryDecision] = Field(min_length=1, max_length=200)
    summary: str = Field(min_length=1, max_length=1000)


class QuestionClassification(BaseModel):
    model_config = ConfigDict(extra="forbid")

    candidate_id: str = Field(min_length=1, max_length=80)
    primary_type: QuestionType
    secondary_types: list[QuestionType] = Field(default_factory=list, max_length=3)
    confidence: float = Field(ge=0, le=1)
    evidence_paths: list[str] = Field(default_factory=list, max_length=20)
    rationale_summary: str = Field(min_length=1, max_length=500)
    needs_human_review: bool = False


class QuestionClassificationBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    classifications: list[QuestionClassification] = Field(min_length=1, max_length=50)
    summary: str = Field(min_length=1, max_length=1000)


class QuestionBoundaryProposal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    root: str = Field(min_length=1, max_length=2048)
    name: str = Field(min_length=1, max_length=200)
    question_type: QuestionType
    boundary_confidence: float = Field(ge=0, le=1)
    type_confidence: float = Field(ge=0, le=1)
    rationale_summary: str = Field(min_length=1, max_length=500)


class QuestionBankBoundaryProposal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    questions: list[QuestionBoundaryProposal] = Field(min_length=1, max_length=500)
    unresolved_paths: list[str] = Field(default_factory=list, max_length=500)
    summary: str = Field(min_length=1, max_length=1000)


class EvaluationCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: EvaluationMode = EvaluationMode.BENCHMARK
    name: str | None = Field(default=None, min_length=1, max_length=120)
    benchmark_task_id: str | None = Field(default=None, pattern=r"^T3S-[A-F0-9]{10}$")
    dataset_version: str = "3.0.0-2026.07"


class BenchmarkTaskSummary(BaseModel):
    task_id: str
    suite: str
    dataset_version: str
    prompt: str
    difficulty: str
    primary_domain: str
    scoring_mode: str
    input_file_count: int
    input_size_bytes: int
    input_manifest_sha256: str


class EvaluationJob(BaseModel):
    schema_version: str = "1.0"
    evaluation_id: str
    mode: EvaluationMode
    benchmark_task_id: str | None = None
    dataset_version: str
    run_id: str | None = None
    status: EvaluationStatus
    input_manifest_sha256: str | None = None
    submission_sha256: str | None = None
    score_available: bool = False
    report_available: bool = False
    report_status: str | None = None
    task_score: float | None = None
    error_code: str | None = None
    error_message: str | None = None
    dashboard_url: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ModelConfigUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    base_url: str = Field(min_length=8, max_length=2048)
    api_key: str | None = Field(default=None, min_length=8, max_length=4096)
    clear_api_key: bool = False
    planner_model: str | None = Field(default=None, min_length=1, max_length=256)
    worker_model: str | None = Field(default=None, min_length=1, max_length=256)
    fallback_model: str | None = Field(default=None, min_length=1, max_length=256)


class ModelConnectionTest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    base_url: str = Field(min_length=8, max_length=2048)
    api_key: str | None = Field(default=None, min_length=8, max_length=4096)
    planner_model: str | None = Field(default=None, min_length=1, max_length=256)
    worker_model: str | None = Field(default=None, min_length=1, max_length=256)
    fallback_model: str | None = Field(default=None, min_length=1, max_length=256)


class MCPServerUpsertRequest(BaseModel):
    """MCP connection configuration. Enable explicitly before discovery/calls."""

    model_config = ConfigDict(extra="forbid")

    server_id: str | None = Field(default=None, min_length=2, max_length=100, pattern=r"^[a-z0-9][a-z0-9_-]*$")
    enabled: bool = False
    command: str = Field(default="", max_length=2048)
    args: list[str] = Field(default_factory=list, max_length=100)
    name: str = Field(min_length=1, max_length=160)
    purpose: str = Field(min_length=1, max_length=500)
    category: str = Field(default="security", min_length=1, max_length=120)
    transport: Literal["streamable_http", "stdio", "sse", "display_only"] = "display_only"
    url: str = Field(default="", max_length=2048)
    icon: str = Field(default="safety", min_length=1, max_length=80)


class MCPToolUpsertRequest(BaseModel):
    """Presentation-only MCP tool metadata; never exposed to ToolBroker."""

    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=2, max_length=100, pattern=r"^[a-z0-9][a-z0-9_-]*$")
    display_name: str = Field(min_length=1, max_length=160)
    purpose: str = Field(min_length=1, max_length=500)
    input: str = Field(min_length=1, max_length=1000)
    returns: str = Field(min_length=1, max_length=1000)
    invocation_timing: str = Field(min_length=1, max_length=500)
    risk_level: Literal["R0", "R1", "R2", "R3"] = "R1"
    icon: str = Field(default="tool", min_length=1, max_length=80)


class ModelUsageQuotaUpdate(BaseModel):
    """Token quotas used for dashboard reporting (zero means report-only)."""

    model_config = ConfigDict(extra="forbid")

    hourly_tokens: int = Field(default=0, ge=0, le=10_000_000_000)
    daily_tokens: int = Field(default=0, ge=0, le=10_000_000_000)
    monthly_tokens: int = Field(default=0, ge=0, le=100_000_000_000)


class InputArtifact(BaseModel):
    artifact_id: str = Field(default_factory=lambda: str(uuid4()))
    original_name: str
    relative_path: str
    sha256: str
    size_bytes: int
    media_type: str = "application/octet-stream"


class PlanStep(BaseModel):
    model_config = ConfigDict(extra="forbid")

    step_id: str
    objective: str
    agent_role: str
    dependencies: list[str] = Field(default_factory=list)
    tool_candidates: list[str] = Field(default_factory=list)
    inputs: dict[str, Any] = Field(default_factory=dict)
    success_criteria: list[str] = Field(default_factory=list)
    risk_hint: RiskLevel = RiskLevel.R0
    max_attempts: int = Field(default=2, ge=1, le=5)
    tool_version: str | None = None


class PlanningIntent(BaseModel):
    """A bounded, user-visible direction returned for one planning round.

    This is deliberately smaller than ``PlanStep``.  Runtime owns execution
    attempts and tool leases; the workbench only records what should be
    explored and why it is connected to the current graph.
    """

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

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


class PlanningCallbackRequest(BaseModel):
    """Authenticated Runtime -> workbench planning callback payload."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = "1.1"
    run_id: str = Field(min_length=1, max_length=200)
    project_id: str = Field(min_length=1, max_length=200)
    trigger: str = Field(min_length=1, max_length=120)
    decision_id: str = Field(min_length=8, max_length=240)
    snapshot_hash: str = Field(min_length=8, max_length=128)
    goal: str = Field(min_length=1, max_length=10000)
    module_route: str = Field(min_length=1, max_length=80)
    target_scope: list[str] = Field(default_factory=list, max_length=100)
    facts: list[dict[str, Any]] = Field(default_factory=list, max_length=1000)
    intents: list[dict[str, Any]] = Field(default_factory=list, max_length=1000)
    hints: list[dict[str, Any]] = Field(default_factory=list, max_length=1000)
    tool_event_ids: list[str] = Field(default_factory=list, max_length=5000)
    budget: dict[str, Any] = Field(default_factory=dict)


class PlanningCallbackResponse(BaseModel):
    """Auditable planning output.  Hidden model reasoning is never included."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = "1.1"
    decision_id: str = Field(min_length=8, max_length=240)
    snapshot_hash: str = Field(min_length=8, max_length=128)
    summary: str = Field(default="", max_length=4000)
    intents: list[PlanningIntent] = Field(default_factory=list, max_length=12)
    validated_outputs: dict[str, list[str]] = Field(default_factory=dict)
    completion_requested: bool = False
    completion_validated: bool = False
    completion_reason: str | None = Field(default=None, max_length=2000)
    completion_fact_ids: list[str] = Field(default_factory=list, max_length=30)
    stop_reason: str | None = Field(default=None, max_length=2000)
    replayed: bool = False


class BudgetState(BaseModel):
    # Keep historical defaults when reading records without explicit budgets.
    # New runs are initialized from Settings and the task's selected budget.
    max_steps: int = 12
    max_tool_calls: int = 12
    max_model_calls: int = 20
    max_runtime_seconds: int = 600
    steps_used: int = 0
    tool_calls_used: int = 0
    model_calls_used: int = 0
    provider_requests_used: int = 0
    runtime_seconds_used: float = Field(default=0, ge=0)
    prompt_tokens_used: int = 0
    completion_tokens_used: int = 0
    cache_read_tokens_used: int = 0
    model_usage_recorded: bool = False


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


class ExperienceCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=2, max_length=240)
    summary: str = Field(min_length=3, max_length=4000)
    module_route: str = Field(default="code_audit", min_length=2, max_length=80)
    experience_kind: Literal["success_pattern", "failure_lesson", "operator_note"] = "operator_note"
    vulnerability_type: str | None = Field(default=None, max_length=160)
    tags: list[str] = Field(default_factory=list, max_length=20)
    conditions: list[str] = Field(default_factory=list, max_length=20)
    lessons: list[str] = Field(default_factory=list, max_length=30)
    steps: list[str] = Field(default_factory=list, max_length=30)
    limitations: list[str] = Field(default_factory=list, max_length=20)


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
    external: dict[str, Any] = Field(default_factory=dict)


class ApprovalResponse(BaseModel):
    decision: ApprovalDecision
    actor: str = "operator"
    reason: str = ""
    edited_parameters: dict[str, Any] | None = None

    @field_validator("edited_parameters")
    @classmethod
    def require_edited_parameters(cls, value: dict[str, Any] | None, info: Any) -> Any:
        if info.data.get("decision") == ApprovalDecision.EDIT and value is None:
            raise ValueError("edited_parameters is required for edit decisions")
        return value


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


class ToolContext(BaseModel):
    run_id: str
    step_id: str
    workspace: str
    allowed_paths: list[str]
    module_base_url: str | None = None
    external_execution: dict[str, Any] = Field(default_factory=dict)
    # Every task tool call is bound to the active blackboard intent.  The
    # callback is intentionally runtime-only and is never serialized into a
    # task snapshot.
    blackboard: dict[str, Any] = Field(default_factory=dict)
    blackboard_validator: Any = Field(default=None, exclude=True, repr=False)
    progress_callback: Any = Field(default=None, exclude=True, repr=False)
    analysis_backend: str = "local"
    module_auth_token: str = Field(default="", exclude=True, repr=False)
    task_constraints: list[str] = Field(default_factory=list)
    # Task context is carried to external adapters so a module can solve the
    # uploaded question instead of receiving only a bare target path/URL.
    task_objective: str = ""
    target_scope: list[str] = Field(default_factory=list)
    input_artifacts: list[InputArtifact] = Field(default_factory=list)
    mcp_generated_root: str | None = None
    # External modules such as Security Runtime execute asynchronously. The orchestrator
    # supplies these bounded polling settings to the verification gate.
    module_poll_interval_seconds: float = Field(default=3.0, ge=0.2, le=60.0)
    module_poll_timeout_seconds: float = Field(default=1800.0, ge=1.0, le=7200.0)


class ToolResult(BaseModel):
    status: ToolStatus
    data: dict[str, Any] = Field(default_factory=dict)
    summary: str = ""
    artifacts: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    duration_ms: int = 0
    error_code: str | None = None
    error_message: str | None = None


class AgentReport(BaseModel):
    run_id: str
    status: RunStatus
    executive_summary: str
    verified_outputs: list[str] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    decisions: list[DecisionRecord] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    confirmed_findings: list[Finding] = Field(default_factory=list)
    candidate_findings: list[Finding] = Field(default_factory=list)
    ruled_out_directions: list[str] = Field(default_factory=list)
    insufficient_evidence: list[str] = Field(default_factory=list)
    worker_reports: list[str] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class AgentState(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = SCHEMA_VERSION
    run_id: str
    task: TaskRequest
    scenario: Scenario = Scenario.UNKNOWN
    # Canonical module identifier.  Older persisted runs may still contain
    # ``audit``; API/UI projections normalize that legacy value to code_audit.
    module_route: str = "code_audit"
    routing: dict[str, Any] = Field(default_factory=dict)
    status: RunStatus = RunStatus.PENDING
    workspace: str = ""
    input_artifacts: list[InputArtifact] = Field(default_factory=list)
    knowledge_hits: list[KnowledgeHit] = Field(default_factory=list)
    plan: list[PlanStep] = Field(default_factory=list)
    current_step_index: int = 0
    observations: list[ToolResult] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    decisions: list[DecisionRecord] = Field(default_factory=list)
    pending_approval: ApprovalRequest | None = None
    approvals: list[dict[str, Any]] = Field(default_factory=list)
    retry_counts: dict[str, int] = Field(default_factory=dict)
    step_failures: dict[str, str] = Field(default_factory=dict)
    retry_of: str | None = None
    retry_context: dict[str, Any] = Field(default_factory=dict)
    budget: BudgetState = Field(default_factory=BudgetState)
    report: AgentReport | None = None
    last_error: str | None = None
    # Runtime state for an asynchronous external adapter (currently Security Runtime).
    external_execution: dict[str, Any] = Field(default_factory=dict)
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    # The SQL snapshot, rather than the in-memory LangGraph saver, owns recovery.
    resume_node: str | None = None
    active_node: str | None = None
    active_node_started_at: datetime | None = None


class LedgerEvent(BaseModel):
    schema_version: str = SCHEMA_VERSION
    event_id: str
    run_id: str
    sequence: int
    event_type: str
    timestamp: datetime
    actor: str
    payload: dict[str, Any]
    prev_hash: str
    hash: str


class RunSummary(BaseModel):
    schema_version: str = SCHEMA_VERSION
    run_id: str
    name: str | None = None
    status: RunStatus
    scenario: Scenario
    module_route: str = "code_audit"
    routing: dict[str, Any] = Field(default_factory=dict)
    current_step: int
    total_steps: int
    input_artifact_count: int = 0
    pending_approval: ApprovalRequest | None = None
    last_error: str | None = None
    stop_reason: str | None = None
    can_retry: bool = False
    retry_blocked_reason: str | None = None
    retry_of: str | None = None
    external_execution: dict[str, Any] = Field(default_factory=dict)
    blackboard: dict[str, Any] = Field(default_factory=dict)
    budget: BudgetState = Field(default_factory=BudgetState)
