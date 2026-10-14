"""Typed, read-only projections of one durable SecMind run.

The ledger, coordinator, and checkpoint store remain authoritative.  This
module does not create a second persistence mechanism: it produces a bounded
operator view from a versioned :class:`~secmind.schemas.AgentState` and its
matching public summary.
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from secmind.schemas import (
    SCHEMA_VERSION,
    AgentState,
    ClaimStatus,
    LeaseSummary,
    PlanStep,
    QueueStatus,
    RunStatus,
    RunSummary,
    Scenario,
    StepRuntime,
    StepStatus,
    ToolStatus,
)
from secmind.task_context import require_resolved_task_contract

SESSION_PROJECTION_VERSION = "1.0"

SessionAction = Literal[
    "resolve_clarification",
    "resolve_approval",
    "wait_for_worker",
    "operator_recovery_required",
    "inspect_report_or_replay",
    "recover_incomplete_run",
]

_FINISHED_STATUSES = frozenset(
    {
        RunStatus.COMPLETED,
        RunStatus.PARTIAL,
        RunStatus.DENIED,
        RunStatus.FAILED,
        RunStatus.CANCELLED,
    }
)


class _SessionModel(BaseModel):
    """Immutable response component with an explicit unknown-field boundary."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class SessionConsistencyView(_SessionModel):
    stable: bool
    read_attempts: int = Field(ge=1, le=3)
    state_version: int = Field(ge=1)
    latest_event_sequence: int = Field(ge=0)
    queue_status: QueueStatus
    lease_owner_id: str | None = None
    lease_fence: int = Field(ge=0)
    vector_digest: str = Field(pattern=r"^[a-f0-9]{64}$")


class SessionResumeView(_SessionModel):
    can_resume: bool
    automatic_recovery_possible: bool
    requires_operator_input: bool
    recommended_action: SessionAction
    action_url: str | None = None
    state_version: int = Field(ge=1)
    latest_event_sequence: int = Field(ge=0)
    lease: LeaseSummary = Field(default_factory=LeaseSummary)


class SessionWorkspaceView(_SessionModel):
    workspace_reference_present: bool
    input_artifact_count: int = Field(ge=0)
    repository_index_recorded: bool
    replay_bundle_recorded: bool


class SessionMultiTaskView(_SessionModel):
    task_count: int = Field(ge=0)
    active_step_ids: list[str] = Field(default_factory=list)
    current_step_id: str | None = None
    status_counts: dict[str, int] = Field(default_factory=dict)
    plan_revision_count: int = Field(ge=0)
    replan_count: int = Field(ge=0)


class SessionCapabilityView(_SessionModel):
    selected_skill_ids: list[str] = Field(default_factory=list)
    context_pack_count: int = Field(ge=0)
    tool_observation_count: int = Field(ge=0)
    tool_invocation_count: int = Field(ge=0)
    verified_claims: int = Field(ge=0)
    insufficient_claims: int = Field(ge=0)
    conflicted_claims: int = Field(ge=0)


class SessionStepView(_SessionModel):
    step_id: str
    objective: str
    agent_role: str
    capability: str
    status: StepStatus
    dependencies: list[str] = Field(default_factory=list)
    concurrency_key: str
    tool_candidates: list[str] = Field(default_factory=list)
    selected_skill_ids: list[str] = Field(default_factory=list)
    context_requirements: dict[str, Any] = Field(default_factory=dict)
    runtime: StepRuntime | None = None
    tool_result_observed: bool
    tool_result_succeeded: bool
    evidence_ids: list[str] = Field(default_factory=list)
    integrated_evidence_ids: list[str] = Field(default_factory=list)
    verified_evidence_ids: list[str] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)
    admitted_finding_ids: list[str] = Field(default_factory=list)
    outcome_contract_id: str | None = None


class SessionPendingView(_SessionModel):
    clarification_request_id: str | None = None
    approval_request_ids: list[str] = Field(default_factory=list)


class SessionLinksView(_SessionModel):
    steps: str
    claims: str
    evidence_graph: str
    skills: str
    replay_bundle: str


class RunSessionSnapshot(_SessionModel):
    schema_version: str = SCHEMA_VERSION
    projection_version: str = SESSION_PROJECTION_VERSION
    snapshot_id: str = Field(pattern=r"^session-[a-f0-9]{64}$")
    observed_at: datetime
    session_id: str
    run_id: str
    state_version: int = Field(ge=1)
    status: RunStatus
    queue_status: QueueStatus
    scenario: Scenario
    objective: str
    interaction_mode: Literal["interactive", "unattended"]
    autonomy_policy: Literal["graded", "approval_all", "automatic"]
    started_at: datetime
    updated_at: datetime | None = None
    consistency: SessionConsistencyView
    resume: SessionResumeView
    workspace: SessionWorkspaceView
    multi_task: SessionMultiTaskView
    prompt_tool_skill: SessionCapabilityView
    tasks: list[SessionStepView] = Field(default_factory=list)
    pending: SessionPendingView
    links: SessionLinksView


def build_run_session_snapshot(
    state: AgentState,
    summary: RunSummary,
    *,
    stable: bool = True,
    read_attempts: int = 1,
    observed_at: datetime | None = None,
) -> RunSessionSnapshot:
    """Project one coherent run-state observation into the public read model."""

    if state.run_id != summary.run_id:
        raise ValueError("state and summary must belong to the same run")

    contract = require_resolved_task_contract(state)
    indexes = _projection_indexes(state)
    step_cards = [_step_card(state, step, indexes) for step in state.plan]
    status_counts = {status.value: 0 for status in StepStatus}
    for card in step_cards:
        status_counts[card.status.value] += 1

    pending_approval_ids = {item.request_id for item in state.pending_approvals}
    if state.pending_approval is not None:
        pending_approval_ids.add(state.pending_approval.request_id)
    approval_ids = sorted(pending_approval_ids)

    vector = {
        "run_id": state.run_id,
        "state_version": state.state_version,
        "status": summary.status.value,
        "queue_status": summary.queue_status.value,
        "latest_event_sequence": summary.latest_event_sequence,
        "lease": summary.lease.model_dump(mode="json"),
    }
    vector_digest = hashlib.sha256(
        json.dumps(vector, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()

    return RunSessionSnapshot(
        snapshot_id=f"session-{vector_digest}",
        observed_at=observed_at or datetime.now(UTC),
        session_id=state.run_id,
        run_id=state.run_id,
        state_version=state.state_version,
        status=summary.status,
        queue_status=summary.queue_status,
        scenario=state.scenario,
        objective=contract.objective,
        interaction_mode=contract.interaction_mode,
        autonomy_policy=contract.autonomy_policy,
        started_at=state.started_at,
        updated_at=summary.updated_at,
        consistency=SessionConsistencyView(
            stable=stable,
            read_attempts=read_attempts,
            state_version=state.state_version,
            latest_event_sequence=summary.latest_event_sequence,
            queue_status=summary.queue_status,
            lease_owner_id=summary.lease.owner_id,
            lease_fence=summary.lease.fence,
            vector_digest=vector_digest,
        ),
        resume=_resume_view(state, summary, approval_ids),
        workspace=SessionWorkspaceView(
            workspace_reference_present=bool(state.workspace),
            input_artifact_count=len(state.input_artifacts),
            repository_index_recorded=state.repository_index is not None,
            replay_bundle_recorded=state.replay_bundle is not None,
        ),
        multi_task=SessionMultiTaskView(
            task_count=len(step_cards),
            active_step_ids=list(summary.active_step_ids),
            current_step_id=summary.current_step_id,
            status_counts=status_counts,
            plan_revision_count=len(state.plan_revisions),
            replan_count=state.replan_count,
        ),
        prompt_tool_skill=SessionCapabilityView(
            selected_skill_ids=list(state.selected_skill_ids),
            context_pack_count=len(state.context_packs),
            tool_observation_count=len(state.observations),
            tool_invocation_count=sum(len(item.tool_invocation_ids) for item in state.step_runtime.values()),
            verified_claims=summary.verified_claims,
            insufficient_claims=summary.insufficient_claims,
            conflicted_claims=summary.conflicted_claims,
        ),
        tasks=step_cards,
        pending=SessionPendingView(
            clarification_request_id=(
                state.pending_clarification.request_id if state.pending_clarification is not None else None
            ),
            approval_request_ids=approval_ids,
        ),
        links=SessionLinksView(
            steps=f"/api/v1/runs/{state.run_id}/steps",
            claims=f"/api/v1/runs/{state.run_id}/claims",
            evidence_graph=f"/api/v1/runs/{state.run_id}/evidence-graph",
            skills=f"/api/v1/runs/{state.run_id}/skills",
            replay_bundle=f"/api/v1/runs/{state.run_id}/replay-bundle",
        ),
    )


def _resume_view(state: AgentState, summary: RunSummary, pending_approval_ids: list[str]) -> SessionResumeView:
    action_url: str | None = None
    if summary.status == RunStatus.RECOVERY_REQUIRED:
        action: SessionAction = "operator_recovery_required"
        can_resume = False
        automatic = False
        requires_input = True
        action_url = f"/api/v1/runs/{state.run_id}/recover"
    elif state.pending_clarification is not None:
        action = "resolve_clarification"
        can_resume = True
        automatic = False
        requires_input = True
        action_url = f"/api/v1/runs/{state.run_id}/clarifications/{state.pending_clarification.request_id}"
    elif pending_approval_ids:
        action = "resolve_approval"
        can_resume = True
        automatic = False
        requires_input = True
        if len(pending_approval_ids) == 1:
            action_url = f"/api/v1/runs/{state.run_id}/approvals/{pending_approval_ids[0]}"
        else:
            action_url = f"/api/v1/runs/{state.run_id}/approvals/batch"
    elif summary.status in {RunStatus.WAITING_APPROVAL, RunStatus.WAITING_CLARIFICATION}:
        # A parked status without its durable request cannot be resumed safely;
        # presenting it as an automatic queue wait would conceal state drift.
        action = "operator_recovery_required"
        can_resume = False
        automatic = False
        requires_input = True
        action_url = f"/api/v1/runs/{state.run_id}/recover"
    elif summary.status in _FINISHED_STATUSES:
        action = "inspect_report_or_replay"
        can_resume = False
        automatic = False
        requires_input = False
        action_url = f"/api/v1/runs/{state.run_id}/report"
    elif summary.queue_status in {QueueStatus.QUEUED, QueueStatus.LEASED, QueueStatus.RETRY, QueueStatus.WAITING}:
        action = "wait_for_worker"
        can_resume = True
        automatic = True
        requires_input = False
    else:
        action = "recover_incomplete_run"
        can_resume = True
        automatic = True
        requires_input = False
        action_url = f"/api/v1/runs/{state.run_id}/recover"
    return SessionResumeView(
        can_resume=can_resume,
        automatic_recovery_possible=automatic,
        requires_operator_input=requires_input,
        recommended_action=action,
        action_url=action_url,
        state_version=state.state_version,
        latest_event_sequence=summary.latest_event_sequence,
        lease=summary.lease,
    )


class _ProjectionIndexes:
    def __init__(self, state: AgentState) -> None:
        self.canonical_evidence_ids = {item.evidence_id for item in state.evidence}
        self.verified_evidence_ids = {
            evidence_id for result in state.verification_results for evidence_id in result.verified_evidence_ids
        }
        self.verified_evidence_ids.update(
            link.evidence_id for link in state.evidence_links if link.verifier_status == ClaimStatus.VERIFIED
        )
        self.finding_ids_by_evidence: dict[str, set[str]] = defaultdict(set)
        for finding in state.findings:
            for evidence_id in finding.evidence_ids:
                self.finding_ids_by_evidence[evidence_id].add(finding.finding_id)
        self.admitted_finding_ids = (
            set(state.sealed_admission.admitted_finding_ids) if state.sealed_admission is not None else set()
        )


def _projection_indexes(state: AgentState) -> _ProjectionIndexes:
    return _ProjectionIndexes(state)


def _step_card(state: AgentState, step: PlanStep, indexes: _ProjectionIndexes) -> SessionStepView:
    runtime = state.step_runtime.get(step.step_id)
    status = runtime.status if runtime is not None else StepStatus.PENDING
    observation_indexes = runtime.observation_indexes if runtime is not None else []
    observations = [state.observations[index] for index in observation_indexes if 0 <= index < len(state.observations)]
    evidence_ids = {evidence.evidence_id for observation in observations for evidence in observation.evidence}
    integrated_evidence_ids = evidence_ids.intersection(indexes.canonical_evidence_ids)
    verified_evidence_ids = integrated_evidence_ids.intersection(indexes.verified_evidence_ids)
    finding_ids = {
        finding_id
        for evidence_id in integrated_evidence_ids
        for finding_id in indexes.finding_ids_by_evidence[evidence_id]
    }
    return SessionStepView(
        step_id=step.step_id,
        objective=step.objective,
        agent_role=step.agent_role,
        capability=step.capability,
        status=status,
        dependencies=list(step.dependencies),
        concurrency_key=step.concurrency_key,
        tool_candidates=list(step.tool_candidates),
        selected_skill_ids=list(step.skill_ids),
        context_requirements=dict(step.context_requirements),
        runtime=runtime,
        tool_result_observed=bool(observations),
        tool_result_succeeded=any(item.status == ToolStatus.SUCCESS for item in observations),
        evidence_ids=sorted(evidence_ids),
        integrated_evidence_ids=sorted(integrated_evidence_ids),
        verified_evidence_ids=sorted(verified_evidence_ids),
        finding_ids=sorted(finding_ids),
        admitted_finding_ids=sorted(finding_ids.intersection(indexes.admitted_finding_ids)),
        outcome_contract_id=step.outcome_contract_id,
    )


__all__ = [
    "RunSessionSnapshot",
    "SESSION_PROJECTION_VERSION",
    "SessionAction",
    "build_run_session_snapshot",
]
