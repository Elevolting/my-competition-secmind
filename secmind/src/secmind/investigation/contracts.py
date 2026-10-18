"""Strict, digest-sealed contracts for the trusted investigation kernel.

These Pydantic records cross planning, worker, verification, recovery, and
completion boundaries. Contract sealing uses canonical content digests so a
replayed object is compared by meaning rather than serialization order.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal, TypeVar
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from secmind.schemas import (
    Finding,
    ModelUsage,
    PlanStep,
    RiskLevel,
    RunStatus,
    StepStatus,
)

SCHEMA_VERSION_V15 = "1.5"
SHA256_PATTERN = r"^[a-f0-9]{64}$"


class StrictContract(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=False)

    schema_version: Literal["1.5"] = "1.5"


ContractT = TypeVar("ContractT", bound=StrictContract)


def canonical_content_digest(value: BaseModel | dict[str, Any], *, exclude: set[str] | None = None) -> str:
    """Hash stable business content while excluding volatile envelope metadata."""

    omitted = {
        "created_at",
        "updated_at",
        "issued_at",
        "decided_at",
        "settled_at",
        "lease_until",
        "owner_id",
        "content_digest",
    }
    omitted.update(exclude or set())
    payload = value.model_dump(mode="json", exclude=omitted) if isinstance(value, BaseModel) else value
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def seal_contract(
    contract_type: type[ContractT],
    /,
    *,
    digest_field: str = "content_digest",
    **values: Any,
) -> ContractT:
    """Build a contract whose digest is derived from its canonical business content."""

    placeholder = "0" * 64
    draft = contract_type.model_validate({**values, digest_field: placeholder})
    digest = canonical_content_digest(draft, exclude={digest_field})
    return draft.model_copy(update={digest_field: digest})


class StrategyLevel(StrEnum):
    QUICK = "quick"
    BALANCED = "balanced"
    DEEP = "deep"


class ReviewVerdict(StrEnum):
    APPROVE = "approve"
    REVISE = "revise"
    REJECT = "reject"


class HypothesisStatus(StrEnum):
    PROPOSED = "proposed"
    SUPPORTED = "supported"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"
    VERIFIED = "verified"


class EvidenceRequestStatus(StrEnum):
    OPEN = "open"
    CLAIMED = "claimed"
    SATISFIED = "satisfied"
    UNSATISFIABLE = "unsatisfiable"
    CANCELLED = "cancelled"


class ObligationStatus(StrEnum):
    OPEN = "open"
    SATISFIED = "satisfied"
    CONTRADICTED = "contradicted"
    UNVERIFIED = "unverified"
    WAIVED = "waived"
    CANCELLED = "cancelled"


class RecoveryAction(StrEnum):
    RESUME_CHECKPOINT = "resume_checkpoint"
    REQUEUE_SAFE_STEP = "requeue_safe_step"
    APPLY_CACHED_RESULT = "apply_cached_result"
    CANCEL_AND_REAP = "cancel_and_reap"
    REQUIRE_OPERATOR = "require_operator"


class RecoveryCommandStatus(StrEnum):
    PENDING = "pending"
    CLAIMED = "claimed"
    APPLIED = "applied"
    REJECTED = "rejected"
    RECOVERY_REQUIRED = "recovery_required"


class ReservationStatus(StrEnum):
    RESERVED = "reserved"
    PARTIALLY_HELD = "partially_held"
    SETTLED = "settled"
    # A provider/tool can report more additive usage than was reserved after
    # the external side effect has already happened.  The receipt remains an
    # accounting fact and must be terminal rather than rejected and left as an
    # orphaned RESERVED row.
    OVERSPENT = "overspent"
    # A late receipt can close a reservation that a recovery path previously
    # released or marked uncertain.  RECONCILED is terminal and auditable; it
    # is deliberately distinct from a normal in-lease settlement.
    RECONCILED = "reconciled"
    RELEASED = "released"
    RECOVERY_REQUIRED = "recovery_required"


class PermitStatus(StrEnum):
    ISSUED = "issued"
    CONSUMED = "consumed"
    REVOKED = "revoked"
    EXPIRED = "expired"


class ArtifactView(StrEnum):
    RAW_RESTRICTED = "raw_restricted"
    EXECUTION_RESTRICTED = "execution_restricted"
    OBSERVABLE = "observable"
    PUBLIC = "public"
    QUARANTINED = "quarantined"


class ArtifactDataClass(StrEnum):
    SOURCE = "source"
    CREDENTIAL = "credential"
    TOOL_INPUT = "tool_input"
    TOOL_OUTPUT = "tool_output"
    LOG = "log"
    REPORT = "report"
    MODEL_IO = "model_io"


class CompletionOutcome(StrEnum):
    COMPLETE = "complete"
    CONTINUE = "continue"
    SUPPLEMENT = "supplement"
    REPLAN = "replan"
    PARTIAL = "partial"
    RECOVERY_REQUIRED = "recovery_required"
    AWAITING_APPROVAL = "awaiting_approval"
    AWAITING_USER_DECISION = "awaiting_user_decision"
    DENIED = "denied"
    CANCELLED = "cancelled"


class SecurityIntentAnalysis(StrictContract):
    analysis_id: str = Field(default_factory=lambda: str(uuid4()))
    run_id: str
    task_spec_digest: str = Field(pattern=SHA256_PATTERN)
    intent_type: str
    objective_summary: str
    explicit_scope: list[str] = Field(default_factory=list)
    excluded_scope: list[str] = Field(default_factory=list)
    authorization_constraints: list[str] = Field(default_factory=list)
    ambiguities: list[str] = Field(default_factory=list)
    owner_decisions: list[str] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    risk_flags: list[str] = Field(default_factory=list)
    expected_deliverables: list[str] = Field(default_factory=list)
    recommended_strategy: StrategyLevel = StrategyLevel.BALANCED
    rationale_summary: str
    content_digest: str = Field(pattern=SHA256_PATTERN)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class PlanProposal(StrictContract):
    proposal_id: str = Field(default_factory=lambda: str(uuid4()))
    run_id: str
    parent_revision_id: str | None = None
    hypotheses: list[str] = Field(default_factory=list)
    proposed_steps: list[PlanStep] = Field(min_length=1)
    assumptions: list[str] = Field(default_factory=list)
    estimated_usage: ModelUsage = Field(default_factory=ModelUsage)
    expected_coverage: list[str] = Field(default_factory=list)
    stop_conditions: list[str] = Field(min_length=1)
    author_profile: str
    prompt_ref: str | None = None
    content_digest: str = Field(pattern=SHA256_PATTERN)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class PlanReview(StrictContract):
    review_id: str = Field(default_factory=lambda: str(uuid4()))
    run_id: str
    proposal_id: str
    verdict: ReviewVerdict
    scope_violations: list[str] = Field(default_factory=list)
    risk_gaps: list[str] = Field(default_factory=list)
    evidence_gaps: list[str] = Field(default_factory=list)
    budget_gaps: list[str] = Field(default_factory=list)
    dependency_errors: list[str] = Field(default_factory=list)
    fallback_gaps: list[str] = Field(default_factory=list)
    required_corrections: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    confidence: float = Field(default=1.0, ge=0, le=1)
    reviewer_profile: str
    content_digest: str = Field(pattern=SHA256_PATTERN)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class PlanContract(StrictContract):
    contract_id: str = Field(default_factory=lambda: str(uuid4()))
    run_id: str
    accepted_proposal_id: str
    revision: int = Field(default=0, ge=0, le=2)
    immutable_task_scope_digest: str = Field(pattern=SHA256_PATTERN)
    dag_digest: str = Field(pattern=SHA256_PATTERN)
    allowed_capabilities: list[str] = Field(min_length=1)
    allowed_tool_sets: dict[str, list[str]] = Field(default_factory=dict)
    outcome_contract_ids: list[str] = Field(default_factory=list)
    budget_envelope: dict[str, int | float] = Field(default_factory=dict)
    approval_requirements: list[str] = Field(default_factory=list)
    completion_policy: str
    catalog_digest: str = Field(pattern=SHA256_PATTERN)
    content_digest: str = Field(pattern=SHA256_PATTERN)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class AgentProfileV2(StrictContract):
    profile_id: str
    version: str
    role: str
    allowed_capabilities: list[str] = Field(min_length=1)
    allowed_action_kinds: list[str] = Field(min_length=1)
    forbidden_action_kinds: list[str] = Field(default_factory=list)
    maximum_risk: RiskLevel = RiskLevel.R1
    model_policy_id: str
    context_policy_id: str
    max_turns: int = Field(default=3, ge=1, le=3)
    max_tool_proposals: int = Field(default=2, ge=0, le=8)
    max_replans: int = Field(default=0, ge=0, le=2)
    can_propose_hypothesis: bool = True
    can_propose_replan: bool = False
    can_issue_critique: bool = False
    content_digest: str = Field(pattern=SHA256_PATTERN)


class SkillBinding(StrictContract):
    skill_id: str
    version: str
    digest: str = Field(pattern=SHA256_PATTERN)
    signer: str | None = None
    compatible_profiles: list[str] = Field(min_length=1)
    required_capabilities: list[str] = Field(default_factory=list)
    prompt_template_ref: str
    input_schema_ref: str
    output_schema_ref: str


class AgentWorkContract(StrictContract):
    contract_id: str = Field(default_factory=lambda: str(uuid4()))
    run_id: str
    step_id: str
    profile_id: str
    plan_revision: int = Field(default=0, ge=0, le=2)
    step_generation: int = Field(default=0, ge=0)
    delegation_id: str = Field(default_factory=lambda: str(uuid4()))
    attempt: int = Field(default=1, ge=1)
    task: str
    goal: str
    stop_conditions: list[str] = Field(min_length=1)
    required_evidence_types: list[str] = Field(min_length=1)
    capability: str
    immutable_scope: list[str] = Field(min_length=1)
    allowed_input_refs: list[str] = Field(default_factory=list)
    dependency_refs: list[str] = Field(default_factory=list)
    allowed_action_kinds: list[str] = Field(min_length=1)
    allowed_tool_sets: list[str] = Field(default_factory=list)
    skill_bindings: list[SkillBinding] = Field(default_factory=list)
    success_criteria: list[str] = Field(min_length=1)
    failure_policy: Literal["fail_fast", "continue", "skip_dependents"]
    budget_reservation_id: str
    outcome_contract_id: str
    run_fence: int = Field(ge=1)
    step_fence: int = Field(ge=1)
    transition_id: str
    content_digest: str = Field(pattern=SHA256_PATTERN)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class TeamMember(StrictContract):
    profile_id: str
    capability: str
    step_ids: list[str] = Field(min_length=1)
    skill_ids: list[str] = Field(default_factory=list)
    concurrency_key: str
    budget_units: int = Field(ge=0)
    purpose: str


class TeamPlan(StrictContract):
    team_plan_id: str = Field(default_factory=lambda: str(uuid4()))
    run_id: str
    plan_contract_id: str
    strategy: StrategyLevel
    members: list[TeamMember] = Field(min_length=1, max_length=4)
    max_parallel_specialists: int = Field(default=3, ge=1, le=4)
    uncovered_obligations: list[str] = Field(default_factory=list)
    rationale_summary: str
    content_digest: str = Field(pattern=SHA256_PATTERN)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @model_validator(mode="after")
    def require_unique_profiles_and_coverage(self) -> TeamPlan:
        keys = [(member.profile_id, member.capability, tuple(member.step_ids)) for member in self.members]
        if len(keys) != len(set(keys)):
            raise ValueError("team contains duplicate member assignments")
        if self.uncovered_obligations:
            raise ValueError("team cannot leave required obligations uncovered")
        return self


class ContextCapsule(StrictContract):
    capsule_id: str = Field(default_factory=lambda: str(uuid4()))
    run_id: str
    objective: str
    scope_digest: str = Field(pattern=SHA256_PATTERN)
    completed_obligations: list[str] = Field(default_factory=list)
    open_hypotheses: list[str] = Field(default_factory=list)
    rejected_hypotheses: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    evidence_requests: list[str] = Field(default_factory=list)
    critiques: list[str] = Field(default_factory=list)
    failed_attempt_summaries: list[str] = Field(default_factory=list)
    current_contract_ref: str
    budget_remaining: dict[str, int | float] = Field(default_factory=dict)
    continuation_reason: str
    content_digest: str = Field(pattern=SHA256_PATTERN)


class AgentThreadRef(StrictContract):
    thread_id: str = Field(default_factory=lambda: str(uuid4()))
    run_id: str
    root_step_id: str
    profile_id: str
    contract_digest: str = Field(pattern=SHA256_PATTERN)
    context_pack_digest: str = Field(pattern=SHA256_PATTERN)
    thread_version: int = Field(default=1, ge=1)
    continuation_generation: int = Field(default=0, ge=0)
    active_attempt_id: str | None = None
    expected_last_patch_digest: str = Field(pattern=SHA256_PATTERN)
    run_fence: int = Field(ge=1)
    expires_at: datetime
    status: Literal["active", "idle", "completed", "expired", "cancelled"] = "idle"
    content_digest: str = Field(pattern=SHA256_PATTERN)


class MessageKind(StrEnum):
    HYPOTHESIS_PROPOSED = "hypothesis.proposed"
    EVIDENCE_NEED_PROPOSED = "evidence.need_proposed"
    EVIDENCE_REQUESTED = "evidence.requested"
    EVIDENCE_SUPPLIED = "evidence.supplied"
    CRITIQUE_ISSUED = "critique.issued"
    CONTRADICTION_DETECTED = "contradiction.detected"
    REPLAN_PROPOSED = "replan.proposed"
    DELIVERABLE_SUBMITTED = "deliverable.submitted"
    VERIFICATION_COMPLETED = "verification.completed"


class CollaborationMessage(StrictContract):
    message_id: str = Field(default_factory=lambda: str(uuid4()))
    run_id: str
    sender_profile_id: str
    sender_delegation_id: str
    sender_thread_id: str
    sender_attempt: int = Field(ge=1)
    recipient_role: str
    resolved_recipient_id: str | None = None
    kind: MessageKind
    correlation_id: str
    causation_id: str | None = None
    plan_revision: int = Field(default=0, ge=0, le=2)
    step_generation: int = Field(default=0, ge=0)
    contract_digest: str = Field(pattern=SHA256_PATTERN)
    transition_id: str
    run_fence: int = Field(ge=1)
    payload_schema: str
    payload: dict[str, Any]
    payload_digest: str = Field(pattern=SHA256_PATTERN)
    dedupe_key: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime


class MessageReceipt(StrictContract):
    message_id: str
    delivery_attempt: int = Field(default=1, ge=1)
    reservation_owner: str
    delivery_fence: int = Field(ge=1)
    lease_until: datetime
    receipt_version: int = Field(default=1, ge=1)
    transport_status: Literal["created", "reserved", "delivered", "acked", "expired", "reclaimed"]
    processing_status: Literal["pending", "processing", "processed", "failed_retryable", "failed_final"]
    processed_transition_id: str | None = None
    processed_at: datetime | None = None


class Hypothesis(StrictContract):
    hypothesis_id: str = Field(default_factory=lambda: str(uuid4()))
    run_id: str
    subject_ref: str
    statement: str
    attack_path_summary: str | None = None
    preconditions: list[str] = Field(default_factory=list)
    expected_impact: str | None = None
    confidence: float = Field(default=0.5, ge=0, le=1)
    supporting_evidence_ids: list[str] = Field(default_factory=list)
    contradicting_evidence_ids: list[str] = Field(default_factory=list)
    status: HypothesisStatus = HypothesisStatus.PROPOSED
    producer: str
    fingerprint: str = Field(pattern=SHA256_PATTERN)
    content_digest: str = Field(pattern=SHA256_PATTERN)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class EvidenceNeedProposal(StrictContract):
    proposal_id: str = Field(default_factory=lambda: str(uuid4()))
    run_id: str
    hypothesis_id: str | None = None
    target_claim_id: str | None = None
    reason_code: str
    requested_evidence_types: list[str] = Field(min_length=1)
    rationale_summary: str
    producer_delegation_id: str
    content_digest: str = Field(pattern=SHA256_PATTERN)


class EvidenceRequest(StrictContract):
    request_id: str = Field(default_factory=lambda: str(uuid4()))
    run_id: str
    target_claim_id: str | None = None
    hypothesis_id: str | None = None
    reason_code: str
    requested_evidence_types: list[str] = Field(min_length=1)
    immutable_scope: list[str] = Field(min_length=1)
    allowed_capabilities: list[str] = Field(min_length=1)
    independence_requirement: int = Field(default=1, ge=1, le=3)
    success_criteria: list[str] = Field(min_length=1)
    priority: int = Field(default=50, ge=0, le=100)
    budget_ceiling: int = Field(default=1, ge=0)
    dedupe_key: str
    status: EvidenceRequestStatus = EvidenceRequestStatus.OPEN
    claimed_by_delegation_id: str | None = None
    claim_attempt: int | None = Field(default=None, ge=1)
    satisfied_by_evidence_ids: list[str] = Field(default_factory=list)
    verifier_receipt_id: str | None = None
    resolution_reason: str | None = None
    request_version: int = Field(default=1, ge=1)
    content_digest: str = Field(pattern=SHA256_PATTERN)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class Critique(StrictContract):
    critique_id: str = Field(default_factory=lambda: str(uuid4()))
    run_id: str
    target_type: str
    target_id: str
    verdict: str
    violated_invariants: list[str] = Field(default_factory=list)
    gaps: list[str] = Field(default_factory=list)
    contradictions: list[str] = Field(default_factory=list)
    requested_evidence_ids: list[str] = Field(default_factory=list)
    proposed_correction: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    confidence: float = Field(default=1.0, ge=0, le=1)
    critic_profile: str
    content_digest: str = Field(pattern=SHA256_PATTERN)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class SpecialistResult(StrictContract):
    result_id: str = Field(default_factory=lambda: str(uuid4()))
    run_id: str
    delegation_id: str
    attempt: int = Field(ge=1)
    step_id: str
    plan_revision: int = Field(default=0, ge=0, le=2)
    step_generation: int = Field(default=0, ge=0)
    contract_digest: str = Field(pattern=SHA256_PATTERN)
    run_fence: int = Field(ge=1)
    step_fence: int = Field(ge=1)
    status: StepStatus
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    artifact_ids: list[str] = Field(default_factory=list)
    evidence_need_proposals: list[EvidenceNeedProposal] = Field(default_factory=list)
    critiques: list[Critique] = Field(default_factory=list)
    replan_proposal_id: str | None = None
    decision_summary: str
    limitation_ids: list[str] = Field(default_factory=list)
    actual_invocation_ids: list[str] = Field(default_factory=list)
    progress_digest: str = Field(pattern=SHA256_PATTERN)
    continuation_handle: str | None = None
    typed_error: str | None = None


class RequirementObligation(StrictContract):
    obligation_id: str = Field(default_factory=lambda: str(uuid4()))
    run_id: str
    source_type: str
    source_ref: str
    requirement_summary: str
    immutable_scope: list[str] = Field(min_length=1)
    satisfaction_rule_id: str
    required_evidence_types: list[str] = Field(min_length=1)
    minimum_independence_level: int = Field(default=1, ge=1, le=3)
    status: ObligationStatus = ObligationStatus.OPEN
    satisfied_by_evidence_ids: list[str] = Field(default_factory=list)
    verifier_receipt_id: str | None = None
    waiver_approval_id: str | None = None
    obligation_version: int = Field(default=1, ge=1)
    content_digest: str = Field(pattern=SHA256_PATTERN)


class RunAuthority(StrictContract):
    run_id: str
    owner_id: str
    run_fence: int = Field(ge=1)
    lease_until: datetime
    claimed_state_version: int = Field(ge=1)
    claim_transition_id: str
    issued_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    authority_digest: str = Field(pattern=SHA256_PATTERN)


class RecoveryCommand(StrictContract):
    command_id: str = Field(default_factory=lambda: str(uuid4()))
    run_id: str
    assessment_id: str
    assessment_digest: str = Field(pattern=SHA256_PATTERN)
    action: RecoveryAction
    checkpoint_id: str | None = None
    checkpoint_state_version: int | None = Field(default=None, ge=0)
    expected_run_state_version: int = Field(ge=1)
    target_plan_revision: int = Field(default=0, ge=0, le=2)
    target_step_id: str | None = None
    target_generation: int | None = Field(default=None, ge=0)
    target_invocation_id: str | None = None
    issued_fence: int = Field(ge=1)
    preconditions: list[str] = Field(default_factory=list)
    postconditions: list[str] = Field(min_length=1)
    status: RecoveryCommandStatus = RecoveryCommandStatus.PENDING
    result_receipt_id: str | None = None
    command_digest: str = Field(pattern=SHA256_PATTERN)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class TransitionReceipt(StrictContract):
    transition_id: str
    run_id: str
    graph_node_id: str
    pre_state_version: int = Field(ge=1)
    pre_state_digest: str = Field(pattern=SHA256_PATTERN)
    post_state_version: int = Field(ge=1)
    post_state_digest: str = Field(pattern=SHA256_PATTERN)
    checkpoint_id: str | None = None
    checkpoint_state_version: int | None = Field(default=None, ge=0)
    plan_revision: int = Field(default=0, ge=0, le=2)
    step_generation: int | None = Field(default=None, ge=0)
    run_fence: int = Field(ge=1)
    event_type: str
    event_payload_digest: str = Field(pattern=SHA256_PATTERN)
    committed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    receipt_digest: str = Field(pattern=SHA256_PATTERN)


class NodeResultReceipt(StrictContract):
    node_result_id: str = Field(default_factory=lambda: str(uuid4()))
    transition_id: str
    producer_type: str
    deterministic_key: str
    result_ref: str
    result_digest: str = Field(pattern=SHA256_PATTERN)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class StepLeaseV15(StrictContract):
    step_run_id: str
    run_id: str
    step_id: str
    plan_revision: int = Field(default=0, ge=0, le=2)
    generation: int = Field(default=0, ge=0)
    attempt: int = Field(ge=1)
    owner_id: str
    run_fence: int = Field(ge=1)
    step_fence: int = Field(ge=1)
    lease_until: datetime
    reservation_ids: list[str] = Field(min_length=1)
    status: StepStatus
    version: int = Field(default=1, ge=1)


class DispatchPermit(StrictContract):
    permit_id: str = Field(default_factory=lambda: str(uuid4()))
    invocation_id: str
    run_id: str
    step_run_id: str
    run_fence: int = Field(ge=1)
    step_fence: int = Field(ge=1)
    input_digest: str = Field(pattern=SHA256_PATTERN)
    policy_decision_id: str
    approval_resolution_id: str | None = None
    expires_at: datetime
    nonce: str
    status: PermitStatus = PermitStatus.ISSUED


class ExecutionIdentity(StrictContract):
    invocation_id: str
    attempt: int = Field(ge=1)
    run_id: str
    step_run_id: str
    run_fence: int = Field(ge=1)
    step_fence: int = Field(ge=1)
    actual_tool_name: str
    actual_tool_version: str
    image_digest: str | None = None
    rule_bundle_digest: str | None = None
    advisory_digest: str | None = None
    input_digest: str = Field(pattern=SHA256_PATTERN)
    output_digest: str = Field(pattern=SHA256_PATTERN)
    artifact_ids: list[str] = Field(default_factory=list)
    started_at: datetime
    settled_at: datetime
    identity_digest: str = Field(pattern=SHA256_PATTERN)


class UsageReservation(StrictContract):
    reservation_id: str = Field(default_factory=lambda: str(uuid4()))
    run_id: str
    parent_reservation_id: str | None = None
    step_id: str | None = None
    delegation_id: str | None = None
    attempt: int = Field(default=1, ge=1)
    transition_id: str
    kind: Literal["run", "step", "tool", "model"]
    tool_calls: int = Field(default=0, ge=0)
    provider_requests: int = Field(default=0, ge=0)
    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    cost_units: float = Field(default=0, ge=0)
    wall_time_ms: int = Field(default=0, ge=0)
    artifact_bytes: int = Field(default=0, ge=0)
    status: ReservationStatus = ReservationStatus.RESERVED
    content_digest: str = Field(pattern=SHA256_PATTERN)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class UsageSettlement(StrictContract):
    settlement_id: str = Field(default_factory=lambda: str(uuid4()))
    reservation_id: str
    run_id: str
    tool_invocation_ids: list[str] = Field(default_factory=list)
    model_invocation_ids: list[str] = Field(default_factory=list)
    actual_tool_calls: int = Field(default=0, ge=0)
    provider_requests: int = Field(default=0, ge=0)
    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    cache_hit_input_tokens: int = Field(default=0, ge=0)
    cache_miss_input_tokens: int = Field(default=0, ge=0)
    cost_units: float = Field(default=0, ge=0)
    wall_time_ms: int = Field(default=0, ge=0)
    artifact_bytes: int = Field(default=0, ge=0)
    fallback_count: int = Field(default=0, ge=0)
    settled_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    receipt_digest: str = Field(pattern=SHA256_PATTERN)


class ArtifactSecurityLabel(StrictContract):
    artifact_id: str = Field(pattern=SHA256_PATTERN)
    owner_run_id: str
    owner_step_id: str | None = None
    owner_invocation_id: str | None = None
    view: ArtifactView
    data_class: ArtifactDataClass
    encryption_key_ref: str | None = None
    retention_policy_id: str
    allowed_purposes: list[str] = Field(min_length=1)
    created_by: str
    classification_version: int = Field(default=1, ge=1)
    content_sha256: str = Field(pattern=SHA256_PATTERN)
    size: int = Field(ge=0)
    media_type: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class SecureStateProjection(StrictContract):
    projection_id: str = Field(default_factory=lambda: str(uuid4()))
    source_ref: str
    run_id: str
    scrub_policy_version: str
    observable_ref: str
    removed_field_paths: list[str] = Field(default_factory=list)
    secret_fingerprints: list[str] = Field(default_factory=list)
    source_digest: str = Field(pattern=SHA256_PATTERN)
    observable_digest: str = Field(pattern=SHA256_PATTERN)
    scrub_receipt_digest: str = Field(pattern=SHA256_PATTERN)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class CompletionSnapshotV2(StrictContract):
    snapshot_id: str = Field(default_factory=lambda: str(uuid4()))
    run_id: str
    run_state_version: int = Field(ge=1)
    run_fence: int = Field(ge=1)
    quiet_epoch: int = Field(ge=1)
    active_sessions: list[str] = Field(default_factory=list)
    active_step_leases: list[str] = Field(default_factory=list)
    active_invocations: list[str] = Field(default_factory=list)
    unsettled_reservations: list[str] = Field(default_factory=list)
    pending_approvals: list[str] = Field(default_factory=list)
    pending_clarifications: list[str] = Field(default_factory=list)
    open_evidence_requests: list[str] = Field(default_factory=list)
    pending_replan: bool = False
    cancel_intent: bool = False
    unprojected_outbox_ordinals: list[int] = Field(default_factory=list)
    input_integrity: bool
    artifact_integrity: bool
    evidence_integrity: bool
    ledger_integrity: bool
    requirement_obligations: list[str] = Field(default_factory=list)
    outcome_grades: dict[str, str] = Field(default_factory=dict)
    report_claim_ids: list[str] = Field(default_factory=list)
    unscanned_scope: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    snapshot_digest: str = Field(pattern=SHA256_PATTERN)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def is_quiet(self) -> bool:
        return not any(
            (
                self.active_sessions,
                self.active_step_leases,
                self.active_invocations,
                self.unsettled_reservations,
                self.pending_approvals,
                self.pending_clarifications,
                self.open_evidence_requests,
                self.unprojected_outbox_ordinals,
                self.pending_replan,
                self.cancel_intent,
            )
        )


class CompletionReceipt(StrictContract):
    receipt_id: str = Field(default_factory=lambda: str(uuid4()))
    run_id: str
    snapshot_id: str
    decision: CompletionOutcome
    satisfied_obligation_ids: list[str] = Field(default_factory=list)
    unsatisfied_obligation_ids: list[str] = Field(default_factory=list)
    verification_receipt_ids: list[str] = Field(default_factory=list)
    report_ref: str | None = None
    gate_rule_version: str
    decided_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    receipt_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def complete_requires_no_unsatisfied_obligations(self) -> CompletionReceipt:
        if self.decision == CompletionOutcome.COMPLETE and self.unsatisfied_obligation_ids:
            raise ValueError("complete receipt cannot contain unsatisfied obligations")
        return self


def semantic_progress_digest(
    *,
    plan_revision: int,
    terminal_step_states: dict[str, RunStatus | StepStatus | str],
    verified_claim_ids: list[str],
    evidence_keys: list[str],
    satisfied_evidence_request_ids: list[str],
    unmet_obligation_ids: list[str],
) -> str:
    return canonical_content_digest(
        {
            "plan_revision": plan_revision,
            "terminal_step_states": sorted((key, str(value)) for key, value in terminal_step_states.items()),
            "verified_claim_ids": sorted(set(verified_claim_ids)),
            "evidence_keys": sorted(set(evidence_keys)),
            "satisfied_evidence_request_ids": sorted(set(satisfied_evidence_request_ids)),
            "unmet_obligation_ids": sorted(set(unmet_obligation_ids)),
        }
    )
