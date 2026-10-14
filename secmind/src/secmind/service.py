"""Application service and durable worker lifecycle.

``RunService`` is the API-facing use-case façade. ``RunWorker`` is the only
background component allowed to claim a run lease and advance the graph. SQL
details belong to the coordinator and unit-of-work modules, not this layer.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from collections import defaultdict
from collections.abc import AsyncIterator, Iterable
from contextlib import asynccontextmanager, suppress
from datetime import UTC, datetime
from typing import Any
from uuid import NAMESPACE_URL, uuid4, uuid5

import httpx
from langgraph.checkpoint.base.id import uuid6
from sqlalchemy import select
from sqlalchemy.orm import Session

from secmind.admission import AdmissionError, AdmissionService
from secmind.artifact_store import ContentAddressedArtifactStore
from secmind.coordinator import (
    ArtifactObjectRow,
    CoordinatorConflict,
    CoordinatorStore,
    ModelGatewayFailureRow,
    ModelInvocationRow,
    OutboxEventRow,
    RunJobRow,
    RunLease,
    StepRunRow,
)
from secmind.execution import ApprovalRow, ToolInvocationRow
from secmind.investigation.contracts import UsageReservation, seal_contract
from secmind.investigation.store import InvestigationStore
from secmind.ledger import ZERO_HASH, LedgerStore, canonical_json, redact
from secmind.metrics import (
    ACTIVE_RUNS,
    RUN_JOB_DURATION,
    RUN_JOB_FAILURES,
    RUN_JOBS_CLAIMED,
)
from secmind.orchestrator import SecMindOrchestrator
from secmind.primary_baseline import baseline_report, restore_published_baseline
from secmind.public_coverage import public_coverage_projection
from secmind.replay import (
    REQUIRED_REPLAY_ENTRIES,
    DeterministicReplayResult,
    ReplayEntry,
    ReplayError,
    ReplayManager,
    ReplayVerification,
)
from secmind.reporting import render_markdown, render_sarif
from secmind.resume_reconciler import (
    ApprovalView,
    ArtifactView,
    CheckpointView,
    ClarificationView,
    InvocationView,
    OutboxView,
    ReconciliationSnapshot,
    ResumeReconciler,
    RunJobView,
    RunnerResourceView,
    StepView,
)
from secmind.schemas import (
    SCHEMA_VERSION,
    AgentReport,
    AgentState,
    ApprovalResponse,
    BudgetState,
    ClaimStatus,
    ClarificationResponse,
    ContextBudget,
    InvocationStatus,
    LeaseSummary,
    LedgerEvent,
    QueueStatus,
    ReplayBundleRef,
    ResumeAction,
    ResumeAssessment,
    RetentionHold,
    RunStatus,
    RunSummary,
    SealedAdmissionSnapshot,
    StepStatus,
    TaskRequest,
    TaskSpec,
    ToolInputEnvelope,
)
from secmind.secret_scrubber import scrub_text, scrub_value
from secmind.session_projection import RunSessionSnapshot, build_run_session_snapshot
from secmind.task_context import require_resolved_task_contract
from secmind.task_specs import ClarificationRequestRow
from secmind.unit_of_work import ControlPlaneUnitOfWork

logger = logging.getLogger(__name__)

_REPLAYABLE_STATUSES = frozenset(
    {
        RunStatus.COMPLETED,
        RunStatus.PARTIAL,
        RunStatus.DENIED,
        RunStatus.FAILED,
        RunStatus.RECOVERY_REQUIRED,
        RunStatus.CANCELLED,
    }
)


def _aware_datetime(value: datetime | None) -> datetime | None:
    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=UTC)


def _checkpoint_view(value: Any | None) -> CheckpointView:
    """Read the durable AgentState version from the checkpoint payload itself."""

    if value is None:
        return CheckpointView(False)
    payload = getattr(value, "checkpoint", None)
    if not isinstance(payload, dict):
        return CheckpointView(True)
    raw_checkpoint_id = payload.get("id")
    checkpoint_id = str(raw_checkpoint_id) if raw_checkpoint_id is not None else None
    channel_values = payload.get("channel_values")
    raw_agent: Any = channel_values.get("agent") if isinstance(channel_values, dict) else None
    if isinstance(raw_agent, AgentState):
        state_version: Any = raw_agent.state_version
    elif isinstance(raw_agent, dict):
        nested = raw_agent.get("agent")
        state_payload = nested if isinstance(nested, dict) else raw_agent
        state_version = state_payload.get("state_version")
    else:
        state_version = None
    if isinstance(state_version, bool) or not isinstance(state_version, int) or state_version < 1:
        state_version = None
    return CheckpointView(True, state_version, checkpoint_id)


class EventHub:
    """Best-effort live notifications backed by the durable ledger for replay."""

    def __init__(self) -> None:
        self._subscribers: dict[str, set[asyncio.Queue[dict[str, Any]]]] = defaultdict(set)
        self._lock = asyncio.Lock()

    async def publish(self, event: dict[str, Any]) -> None:
        async with self._lock:
            subscribers = tuple(self._subscribers.get(str(event["run_id"]), ()))
        for queue in subscribers:
            if queue.full():
                while not queue.empty():
                    try:
                        queue.get_nowait()
                    except asyncio.QueueEmpty:
                        break
                queue.put_nowait(
                    {
                        "schema_version": SCHEMA_VERSION,
                        "run_id": str(event["run_id"]),
                        "event_type": "stream.gap",
                        "sequence": event.get("sequence"),
                    }
                )
            else:
                queue.put_nowait(event)

    @asynccontextmanager
    async def subscribe(self, run_id: str) -> AsyncIterator[asyncio.Queue[dict[str, Any]]]:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=500)
        async with self._lock:
            self._subscribers[run_id].add(queue)
        try:
            yield queue
        finally:
            async with self._lock:
                self._subscribers[run_id].discard(queue)


class RunService:
    """Expose run use cases without leaking orchestrator or database internals."""

    def __init__(
        self,
        orchestrator: SecMindOrchestrator,
        ledger: LedgerStore,
        event_hub: EventHub,
        coordinator: CoordinatorStore,
        artifact_store: ContentAddressedArtifactStore,
        unit_of_work: ControlPlaneUnitOfWork | None = None,
        replay_manager: ReplayManager | None = None,
        investigation_store: InvestigationStore | None = None,
    ) -> None:
        self.orchestrator = orchestrator
        self.ledger = ledger
        self.event_hub = event_hub
        self.coordinator = coordinator
        self.artifact_store = artifact_store
        self.unit_of_work = unit_of_work
        self.investigation_store = investigation_store
        self.replay_manager = replay_manager or ReplayManager(artifact_store, engine=coordinator.engine)
        self.worker = RunWorker(self)
        self._projector_stop = asyncio.Event()
        self._projector_task: asyncio.Task[None] | None = None

    async def startup(self) -> None:
        projector = self.orchestrator.outbox_projector
        if projector is not None and self._inline_projector_enabled() and self._projector_task is None:
            self._projector_stop.clear()
            self._projector_task = asyncio.create_task(
                projector.serve(self._projector_stop),
                name="secmind-outbox-projector",
            )
        if self.orchestrator.settings.runtime_role in {"embedded", "worker"}:
            await self.worker.start()

    def submit(self, task: TaskRequest) -> str:
        run_id = (
            str(uuid5(NAMESPACE_URL, f"secmind:client-request:{task.client_request_id}"))
            if task.client_request_id
            else str(uuid4())
        )
        existing = self.ledger.load_state(run_id)
        if existing is not None:
            if existing.task != task:
                raise RuntimeError("client_request_id was reused with a different task")
            return run_id
        state = AgentState(
            run_id=run_id,
            task=task,
            status=RunStatus.PENDING,
            budget=BudgetState(
                max_steps=self.orchestrator.settings.max_steps,
                max_tool_calls=self.orchestrator.settings.max_tool_calls,
                max_model_calls=self.orchestrator.settings.max_model_calls,
                max_provider_requests=self.orchestrator.settings.max_provider_requests,
                max_input_tokens=self.orchestrator.settings.max_input_tokens,
                max_output_tokens=self.orchestrator.settings.max_output_tokens,
                max_cost_units=self.orchestrator.settings.max_cost_units,
                max_runtime_seconds=self.orchestrator.settings.max_runtime_seconds,
            ),
        )
        if self.unit_of_work is not None:
            if (self.investigation_store is not None
                    and self.investigation_store.engine.url != self.unit_of_work.engine.url):
                raise RuntimeError("run submission requires one control-plane database")
            self.unit_of_work.submit_run(
                state,
                root_reservation=(self._root_budget_reservation(state)
                                  if self.investigation_store is not None else None),
            )
        else:
            self.ledger.save_state(state)
            self.ledger.append(run_id, "run.queued", {"objective": task.objective}, actor="api")
            self._reserve_root_budget(state)
            self.coordinator.enqueue_run(run_id)
        if self._inline_projector_enabled():
            projector = self.orchestrator.outbox_projector
            if projector is not None:
                for outbox_id in projector.claim_batch():
                    projector.project_claimed(outbox_id)
        self.worker.notify()
        return run_id

    def _reserve_root_budget(self, state: AgentState) -> None:
        if self.investigation_store is None:
            return
        self.investigation_store.reserve_usage(self._root_budget_reservation(state))

    @staticmethod
    def _root_budget_reservation(state: AgentState) -> UsageReservation:
        run_id = state.run_id
        return seal_contract(
            UsageReservation,
            reservation_id=str(uuid5(NAMESPACE_URL, f"secmind:budget:{run_id}:root")),
            run_id=run_id,
            transition_id=f"run:{run_id}:budget-root",
            kind="run",
            tool_calls=state.budget.max_tool_calls,
            provider_requests=state.budget.max_provider_requests,
            input_tokens=state.budget.max_input_tokens,
            output_tokens=state.budget.max_output_tokens,
            cost_units=state.budget.max_cost_units,
            wall_time_ms=state.budget.max_runtime_seconds * 1000,
            artifact_bytes=state.budget.max_tool_calls * 16 * 1024 * 1024,
        )

    def submit_approval(
        self,
        run_id: str,
        request_id: str,
        response: ApprovalResponse,
        *,
        actor: str = "local-operator",
    ) -> bool:
        _resolution_id, changed = self.submit_approval_resolution(
            run_id,
            request_id,
            response,
            actor=actor,
        )
        return changed

    def submit_clarification_resolution(
        self,
        run_id: str,
        request_id: str,
        response: ClarificationResponse,
    ) -> tuple[str, bool]:
        state = self.state(run_id)
        pending = state.pending_clarification
        if pending is not None and pending.request_id != request_id:
            raise RuntimeError("Clarification request is not active for this run")
        if pending is None:
            # A retry can arrive after the worker has already consumed the
            # resolution.  Only an existing resolved record may take this
            # path; never activate an orphaned or stale request.
            try:
                self.orchestrator.task_spec_repository.clarification_response(
                    request_id,
                    run_id=run_id,
                )
            except KeyError as exc:
                raise RuntimeError("Clarification request is not active for this run") from exc
        resolution_id, changed = self.orchestrator.task_spec_repository.resolve_clarification(
            request_id,
            response,
            run_id=run_id,
        )
        if pending is not None:
            # Healing is intentionally idempotent: if the process failed after
            # committing the resolution but before waking the queue, the same
            # response repairs the parked job.  A job already leased by a
            # worker is left untouched.
            self.coordinator.ensure_job_awake(run_id)
            self.worker.notify()
        return resolution_id, changed

    def task_spec(self, run_id: str) -> TaskSpec:
        self.state(run_id)
        return self.orchestrator.task_spec_repository.load_spec(run_id)

    def submit_approval_resolution(
        self,
        run_id: str,
        request_id: str,
        response: ApprovalResponse,
        *,
        actor: str = "local-operator",
    ) -> tuple[str | None, bool]:
        state = self.ledger.load_state(run_id)
        if state is None:
            raise KeyError(run_id)
        active_requests = {
            item.request_id: item
            for item in [
                *state.pending_approvals,
                *([state.pending_approval] if state.pending_approval is not None else []),
            ]
        }
        if active_requests and request_id not in active_requests:
            raise RuntimeError("A different approval request is active")
        pending = active_requests.get(request_id)
        if pending is None:
            return response.resolution_id, False
        if self.unit_of_work is not None:
            resolution_id, changed = self.unit_of_work.resolve_approval_and_wake(
                run_id=run_id,
                request_id=request_id,
                response=response,
                actor=actor,
                fence=state.lease.fence,
            )
            if not changed:
                return resolution_id, False
        else:
            resolution_id = self.orchestrator.broker.resolve_approval(
                request_id,
                response,
                actor=actor,
                run_id=run_id,
                fence=state.lease.fence,
            )
            effective_parameters = (
                response.edited_parameters if response.edited_parameters is not None else pending.parameters
            )
            try:
                self.orchestrator.broker.consume_approval(
                    request_id,
                    run_id=run_id,
                    step_id=pending.step_id,
                    tool_name=pending.tool_name,
                    parameters=effective_parameters,
                    fence=state.lease.fence,
                    resolution_id=resolution_id,
                )
            except Exception as exc:
                if "already consumed" not in str(exc):
                    raise
                return resolution_id, False
            self.coordinator.wake_job(run_id)
        self.worker.notify()
        return resolution_id, True

    def submit_approvals_batch(
        self,
        run_id: str,
        resolutions: list[tuple[str, ApprovalResponse]],
        *,
        actor: str = "local-operator",
    ) -> list[dict[str, Any]]:
        """Resolve a bounded set of currently-active approvals independently.

        Every item keeps the same idempotent, transactional resolution semantics
        as the single-approval endpoint. The result is per item so a duplicate
        retry cannot conceal a conflicting decision for another request.
        """

        state = self.ledger.load_state(run_id)
        if state is None:
            raise KeyError(run_id)
        active_ids = {
            item.request_id
            for item in [
                *state.pending_approvals,
                *([state.pending_approval] if state.pending_approval is not None else []),
            ]
        }
        requested_ids = {request_id for request_id, _response in resolutions}
        if len(requested_ids) != len(resolutions):
            raise RuntimeError("Batch contains duplicate approval request ids")
        unknown_ids = sorted(requested_ids - active_ids)
        if unknown_ids:
            raise RuntimeError(f"Approval request is not active: {', '.join(unknown_ids)}")
        results: list[dict[str, Any]] = []
        for request_id, response in resolutions:
            resolution_id, changed = self.submit_approval_resolution(
                run_id,
                request_id,
                response,
                actor=actor,
            )
            results.append(
                {
                    "request_id": request_id,
                    "resolution_id": resolution_id,
                    "resolution_status": "accepted" if changed else "already_resolved",
                }
            )
        return results

    async def cancel(self, run_id: str) -> None:
        self.state(run_id)
        active_invocations = self.orchestrator.broker.active_invocation_ids(run_id)
        self.coordinator.cancel_job(run_id)
        await self.orchestrator.project_outbox()
        runner_url = self.orchestrator.settings.sandbox_runner_url.rstrip("/")
        control_token = getattr(self.orchestrator.settings, "sandbox_control_token", "")
        if runner_url and control_token and active_invocations:
            async with httpx.AsyncClient(timeout=5) as client:
                await asyncio.gather(
                    *(
                        client.delete(
                            f"{runner_url}/internal/v1/invocations/{invocation_id}",
                            headers={"Authorization": f"Bearer {control_token}"},
                        )
                        for invocation_id in active_invocations
                    ),
                    return_exceptions=True,
                )

    async def recover(
        self,
        run_id: str,
        *,
        assessment_id: str,
        assessment_digest: str,
        actor: str = "operator",
        reaper_confirmed: bool = False,
    ) -> str:
        """Consume one still-current recovery assessment exactly once.

        Recovery never trusts a previously rendered action on its own.  It
        recollects every control plane, requires the digest to remain stable,
        then delegates the state CAS and assessment consumption to one database
        transaction.
        """

        if self.unit_of_work is None:
            raise RuntimeError("assessment-bound recovery requires the transactional control plane")
        requested = self.unit_of_work.load_resume_assessment(run_id, assessment_id)
        if requested.assessment_digest != assessment_digest:
            raise RuntimeError("recovery assessment digest does not match")
        existing_consumption = self.unit_of_work.resume_assessment_consumption(
            run_id,
            assessment_id,
            assessment_digest,
        )
        if existing_consumption is not None:
            return existing_consumption
        current = await self.recovery_assessment(run_id)
        if current.assessment_id != assessment_id or current.assessment_digest != assessment_digest:
            raise RuntimeError("recovery assessment is stale; collect a new assessment")
        if current.action == ResumeAction.REQUIRE_OPERATOR_RECOVERY:
            raise RuntimeError("assessment requires operator investigation and cannot resume the run")
        consumption_id = self.unit_of_work.consume_resume_assessment(
            current,
            actor=actor,
            reaper_confirmed=reaper_confirmed,
        )
        if current.action in {
            ResumeAction.RESUME_FROM_CHECKPOINT,
            ResumeAction.REQUEUE_SAFE_STEP,
            ResumeAction.RETURN_CACHED_RESULT,
        }:
            self.worker.notify()
        if self._inline_projector_enabled():
            await self.orchestrator.project_outbox()
        return consumption_id

    def state(self, run_id: str) -> AgentState:
        state = self.ledger.load_state(run_id)
        if state is None:
            raise KeyError(run_id)
        return state

    def public_report(self, run_id: str) -> AgentReport:
        """Return the validated terminal report, never the mutable work view."""

        return AdmissionService.public_report(self.state(run_id))

    def public_admission_snapshot(self, run_id: str) -> SealedAdmissionSnapshot:
        """Return a validated copy of the public terminal admission."""

        return AdmissionService.public_snapshot(self.state(run_id))

    def input_envelope(self, run_id: str, invocation_id: str) -> ToolInputEnvelope:
        self.state(run_id)
        if self.unit_of_work is None:
            raise KeyError(invocation_id)
        return self.unit_of_work.load_tool_input_envelope(run_id, invocation_id)

    def create_retention_hold(
        self,
        run_id: str,
        *,
        reason: str,
        expires_at: datetime,
        actor: str = "operator",
        client_request_id: str | None = None,
    ) -> RetentionHold:
        self.state(run_id)
        if self.unit_of_work is None:
            raise RuntimeError("retention governance requires the transactional control plane")
        hold_values: dict[str, Any] = {
            "run_id": run_id,
            "reason": reason,
            "expires_at": expires_at,
            "actor": actor,
        }
        if client_request_id is not None:
            hold_values["hold_id"] = str(
                uuid5(
                    NAMESPACE_URL,
                    f"secmind:retention-hold:{run_id}:{client_request_id}",
                )
            )
        hold = RetentionHold.model_validate(hold_values)
        self.unit_of_work.create_retention_hold(hold)
        if self._inline_projector_enabled() and self.orchestrator.outbox_projector is not None:
            for outbox_id in self.orchestrator.outbox_projector.claim_batch():
                self.orchestrator.outbox_projector.project_claimed(outbox_id)
        return hold

    def retention_holds(self, run_id: str) -> list[RetentionHold]:
        self.state(run_id)
        if self.unit_of_work is None:
            return []
        return self.unit_of_work.list_retention_holds(run_id)

    def latest_recovery_assessment(self, run_id: str) -> ResumeAssessment:
        self.state(run_id)
        if self.unit_of_work is None:
            raise RuntimeError("recovery assessment store is unavailable")
        try:
            return self.unit_of_work.latest_resume_assessment(run_id)
        except KeyError as exc:
            raise RuntimeError("no recovery assessment has been generated for this run") from exc

    async def recovery_assessment(self, run_id: str) -> ResumeAssessment:
        """Collect durable control-plane projections and make a pure recovery decision.

        Runner resources are never guessed. If the runner inventory cannot be
        collected, active or unknown invocations force operator recovery.
        """

        state = self.state(run_id)
        checkpoint = await self.orchestrator.checkpointer.aget_tuple(self.orchestrator._config(run_id))
        checkpoint_view = _checkpoint_view(checkpoint)
        applied_invocations = {item.invocation_id for item in state.observations if item.invocation_id is not None}
        manifest_by_name = {item.name: item for item in self.orchestrator.broker.registry.manifests()}
        with Session(self.coordinator.engine) as session:
            job = session.get(RunJobRow, run_id)
            if job is None:
                raise KeyError(run_id)
            step_rows = session.scalars(select(StepRunRow).where(StepRunRow.run_id == run_id)).all()
            invocation_rows = session.scalars(select(ToolInvocationRow).where(ToolInvocationRow.run_id == run_id)).all()
            approval_rows = session.scalars(select(ApprovalRow).where(ApprovalRow.run_id == run_id)).all()
            clarification_rows = session.scalars(
                select(ClarificationRequestRow).where(ClarificationRequestRow.run_id == run_id)
            ).all()
            outbox_rows = session.scalars(select(OutboxEventRow).where(OutboxEventRow.run_id == run_id)).all()

        plan_by_step = {item.step_id: item for item in state.plan}
        step_views: list[StepView] = []
        for row in step_rows:
            plan_step = plan_by_step.get(row.step_id)
            candidates = [] if plan_step is None else plan_step.tool_candidates
            idempotent = not candidates or all(
                manifest_by_name.get(tool) is not None and manifest_by_name[tool].idempotent for tool in candidates
            )
            step_views.append(
                StepView(
                    run_id=run_id,
                    step_id=row.step_id,
                    status=StepStatus(row.status),
                    fence=row.fence,
                    idempotent=idempotent,
                    lease_until=_aware_datetime(row.lease_until),
                    attempt=row.attempt,
                    run_fence=row.run_fence,
                )
            )
        steps = tuple(step_views)
        invocation_views: list[InvocationView] = []
        unknown_invocation_ids: list[str] = []
        for invocation_row in invocation_rows:
            try:
                invocation_status = InvocationStatus(invocation_row.status)
            except ValueError:
                unknown_invocation_ids.append(invocation_row.invocation_id)
                continue
            invocation_views.append(
                InvocationView(
                    run_id=run_id,
                    invocation_id=invocation_row.invocation_id,
                    step_id=invocation_row.step_id,
                    status=invocation_status,
                    fence=invocation_row.fence,
                    attempt=invocation_row.attempt,
                    idempotent=bool(
                        manifest_by_name.get(invocation_row.tool_name)
                        and manifest_by_name[invocation_row.tool_name].idempotent
                    ),
                    result_committed=invocation_row.result_json is not None,
                    applied_to_state=invocation_row.invocation_id in applied_invocations,
                    outcome_uncertain=invocation_row.status == InvocationStatus.RECOVERY_REQUIRED.value,
                    lease_until=_aware_datetime(invocation_row.lease_until),
                )
            )
        invocations = tuple(invocation_views)
        (
            runner_resources_collected,
            runner_resources,
        ) = await self._collect_runner_resources(run_id)
        artifact_ids = {item.artifact_ref for item in state.evidence if item.artifact_ref is not None} | {
            item.artifact_id for observation in state.observations for item in observation.artifacts
        }
        artifacts: list[ArtifactView] = []
        for artifact_id in sorted(artifact_ids):
            exists = False
            valid = False
            try:
                content = self.artifact_store.read(artifact_id)
                exists = True
                valid = hashlib.sha256(content).hexdigest() == artifact_id.lower()
            except (OSError, ValueError):
                pass
            artifacts.append(ArtifactView(run_id, artifact_id, exists, valid))
        ledger_valid = self.ledger.verify(run_id)
        snapshot = ReconciliationSnapshot(
            run_id=run_id,
            state_version=state.state_version,
            state_status=state.status,
            checkpoint=checkpoint_view,
            run_job=RunJobView(
                status=job.status,
                fence=job.fence,
                owner_id=job.owner_id,
                lease_until=_aware_datetime(job.lease_until),
            ),
            steps=steps,
            invocations=invocations,
            approvals=tuple(ApprovalView(run_id, row.request_id, row.status) for row in approval_rows),
            clarifications=tuple(ClarificationView(run_id, row.request_id, row.status) for row in clarification_rows),
            artifacts=tuple(artifacts),
            runner_resources=runner_resources,
            runner_resources_collected=runner_resources_collected,
            unknown_invocation_ids=tuple(sorted(unknown_invocation_ids)),
            outbox=OutboxView(
                pending_count=sum(
                    row.status in {"pending", "projecting"} and row.event_type != "recovery.assessed"
                    for row in outbox_rows
                ),
                failed_count=sum(
                    row.status in {"failed", "retry_wait", "dead_letter"} and row.event_type != "recovery.assessed"
                    for row in outbox_rows
                ),
                ledger_head_matches=ledger_valid,
            ),
            ledger_valid=ledger_valid,
            budget_consistent=(
                state.budget.steps_used <= state.budget.max_steps
                and state.budget.tool_calls_used <= state.budget.max_tool_calls
                and state.budget.model_calls_used <= state.budget.max_model_calls
            ),
            report_committed=AdmissionService.has_public_report(state),
            cancel_requested=state.cancel_requested,
        )
        result = ResumeReconciler().assess(snapshot)
        created_at = datetime.now(UTC)
        assessment = ResumeAssessment(
            assessment_id=str(uuid5(NAMESPACE_URL, f"secmind:resume:{result.assessment_digest}")),
            run_id=run_id,
            action=result.action,
            reason_codes=list(result.reason_codes),
            rationale_summary="; ".join(result.reason_codes),
            state_version=state.state_version,
            fence=result.fence,
            checkpoint_present=checkpoint is not None,
            checkpoint_state_version=result.checkpoint_state_version,
            checkpoint_id=result.checkpoint_id,
            control_digest=result.control_digest,
            runner_resources_collected=result.runner_resources_collected,
            step_ids=list(result.step_ids),
            invocation_ids=list(result.invocation_ids),
            stale_resources=[*result.runner_resource_ids, *result.stale_invocation_ids],
            assessment_digest=result.assessment_digest,
            created_at=created_at,
        )
        if self.unit_of_work is not None:
            self.unit_of_work.record_resume_assessment(assessment)
        return assessment

    async def _collect_runner_resources(self, run_id: str) -> tuple[bool, tuple[RunnerResourceView, ...]]:
        runner_url = self.orchestrator.settings.sandbox_runner_url.rstrip("/")
        control_token = getattr(self.orchestrator.settings, "sandbox_control_token", "")
        if not runner_url or not control_token:
            return False, ()
        try:
            async with httpx.AsyncClient(timeout=2) as client:
                response = await client.get(
                    f"{runner_url}/internal/v1/resources",
                    params={"run_id": run_id},
                    headers={"Authorization": f"Bearer {control_token}"},
                )
                response.raise_for_status()
            payload = response.json()
            raw_resources = payload.get("resources") if isinstance(payload, dict) else None
            if not isinstance(raw_resources, list) or len(raw_resources) > 10_000:
                return False, ()
            resources: list[RunnerResourceView] = []
            for item in raw_resources:
                if not isinstance(item, dict):
                    return False, ()
                resource_id = item.get("resource_id")
                invocation_id = item.get("invocation_id")
                fence = item.get("fence")
                active = item.get("active", True)
                resource_run_id = item.get("run_id")
                if (
                    not isinstance(resource_id, str)
                    or not isinstance(invocation_id, str)
                    or resource_run_id != run_id
                    or isinstance(fence, bool)
                    or not isinstance(fence, int)
                    or not isinstance(active, bool)
                ):
                    return False, ()
                resources.append(
                    RunnerResourceView(
                        run_id=run_id,
                        resource_id=resource_id,
                        invocation_id=invocation_id,
                        fence=fence,
                        active=active,
                    )
                )
            return True, tuple(resources)
        except (httpx.HTTPError, KeyError, TypeError, ValueError):
            return False, ()

    def build_replay_bundle(self, run_id: str) -> ReplayBundleRef:
        """Build an immutable replay bundle and CAS its reference into terminal state.

        Bundle persistence intentionally happens before the state CAS. A CAS loser may
        leave an unreferenced immutable object, but can never overwrite a newer run
        snapshot. A subsequent artifact reconciliation pass may remove such objects.
        """

        for attempt in range(3):
            state = self._replayable_state(run_id)
            if state.replay_bundle is not None:
                return state.replay_bundle
            ledger_events = self.ledger.events(run_id, limit=1_000_000)
            latest_event = self.ledger.latest_event(run_id)
            if latest_event is not None and (not ledger_events or ledger_events[-1].sequence != latest_event.sequence):
                raise ReplayError("ledger exceeds the replay export event limit")
            latest_hash = latest_event.hash if latest_event is not None else ZERO_HASH
            replay_ref = self.replay_manager.build(
                run_id=run_id,
                parent_run_id=state.parent_run_id,
                entries=self._build_replay_entries(state, ledger_events),
                ledger_head_hash=latest_hash,
            )
            candidate = state.model_copy(update={"replay_bundle": replay_ref})
            try:
                self.ledger.save_state_cas(candidate, expected_version=state.state_version)
            except RuntimeError as exc:
                current = self._replayable_state(run_id)
                if current.replay_bundle is not None:
                    return current.replay_bundle
                if attempt == 2:
                    raise CoordinatorConflict("replay reference compare-and-swap failed") from exc
                continue
            return replay_ref
        raise CoordinatorConflict("replay reference compare-and-swap failed")  # pragma: no cover

    def get_replay_bundle(self, run_id: str) -> ReplayBundleRef:
        state = self._replayable_state(run_id)
        if state.replay_bundle is None:
            raise ReplayError("replay bundle has not been built")
        return state.replay_bundle

    def verify_replay_bundle(self, run_id: str) -> ReplayVerification:
        return self.replay_manager.verify_only(self.get_replay_bundle(run_id))

    def deterministic_replay(self, run_id: str) -> DeterministicReplayResult:
        return self.replay_manager.deterministic_replay(self.get_replay_bundle(run_id))

    async def checkpoint_fork(
        self,
        parent_run_id: str,
        checkpoint_id: str,
        *,
        task: TaskRequest | None = None,
        actor: str = "operator",
        fork_request_id: str | None = None,
    ) -> AgentState:
        """Create a new queued run from one immutable LangGraph checkpoint.

        The checkpoint is copied under a fresh thread id before the child is
        queued.  This preserves the graph cursor and channel versions, while
        the child gets its own ledger, lease, budget accounting, and replay
        lineage.  A checkpoint with no next node cannot be forked because it
        would silently create a completed child with no executable cursor.
        """
        if not checkpoint_id or not actor:
            raise ValueError("checkpoint id and actor are required")
        if fork_request_id is not None and not 8 <= len(fork_request_id) <= 128:
            raise ValueError("fork request id must contain 8 to 128 characters")
        request_id = fork_request_id or str(uuid4())
        child_run_id = str(uuid5(NAMESPACE_URL, f"secmind:checkpoint-fork:{request_id}"))
        existing_child = self.ledger.load_state(child_run_id)
        if existing_child is not None:
            if (existing_child.parent_run_id != parent_run_id
                    or existing_child.fork_checkpoint_id != checkpoint_id
                    or existing_child.fork_request_id != request_id
                    or task is not None and existing_child.task != task):
                raise RuntimeError("fork request id was reused with different inputs")
            try:
                self.coordinator.job_status(child_run_id)
            except KeyError:
                pass
            else:
                return existing_child
        self.state(parent_run_id)
        checkpoint = await self.orchestrator.checkpointer.aget_tuple(
            {"configurable": {"thread_id": parent_run_id, "checkpoint_id": checkpoint_id}}
        )
        if checkpoint is None or getattr(checkpoint, "checkpoint", None) is None:
            raise RuntimeError("requested checkpoint was not found for the parent run")
        payload = dict(checkpoint.checkpoint)
        if payload.get("id") != checkpoint_id:
            raise RuntimeError("checkpoint identity does not match the requested id")
        snapshot = await self.orchestrator.graph.aget_state(checkpoint.config)
        if not snapshot.next:
            raise RuntimeError("terminal checkpoints cannot be forked")
        channel_values = payload.get("channel_values")
        if not isinstance(channel_values, dict) or not isinstance(channel_values.get("agent"), dict):
            raise RuntimeError("checkpoint does not contain a valid agent state")
        child_state = AgentState.model_validate(channel_values["agent"])
        if child_state.run_id != parent_run_id:
            raise RuntimeError("checkpoint agent state is bound to a different run")
        # Once a run has durable task contracts, artifacts, approvals or tool
        # receipts, copying only the graph checkpoint would leave references
        # into the parent's run-scoped stores. Reject that boundary until the
        # corresponding records can be cloned and rebound transactionally.
        if (
            child_state.task_spec_ref is not None
            or child_state.resolved_task_contract is not None
            or child_state.workspace
            or child_state.input_artifacts
            or child_state.plan
            or child_state.observations
            or child_state.pending_approval is not None
            or child_state.pending_approvals
            or child_state.pending_clarification is not None
            or child_state.active_invocation_id is not None
        ):
            raise RuntimeError("checkpoint contains run-scoped records that cannot yet be forked safely")
        if task is not None and task != child_state.task:
            raise RuntimeError("checkpoint fork input changes are not supported; create a new task instead")
        child_state = child_state.model_copy(update={
            "run_id": child_run_id,
            "parent_run_id": parent_run_id,
            "fork_checkpoint_id": checkpoint_id,
            "fork_request_id": request_id,
            "fork_child_checkpoint_id": str(uuid6(clock_seq=0)),
            "fork_checkpoint_state_version": child_state.state_version,
            "status": RunStatus.PENDING,
            "state_version": 1,
            "transition_counter": 0,
            "lease": LeaseSummary(),
            "cancel_requested": False,
            "replay_bundle": None,
            "report": None,
            "sealed_admission": None,
            "pending_approval": None,
            "pending_approvals": [],
            "pending_clarification": None,
            "last_error": None,
            "processed_transition_ids": set(),
            "active_invocation_id": None,
            "active_grants": [],
            "approvals": [],
            "retry_counts": {},
            "budget": BudgetState(
                max_steps=self.orchestrator.settings.max_steps,
                max_tool_calls=self.orchestrator.settings.max_tool_calls,
                max_model_calls=self.orchestrator.settings.max_model_calls,
                max_provider_requests=self.orchestrator.settings.max_provider_requests,
                max_input_tokens=self.orchestrator.settings.max_input_tokens,
                max_output_tokens=self.orchestrator.settings.max_output_tokens,
                max_cost_units=self.orchestrator.settings.max_cost_units,
                max_runtime_seconds=self.orchestrator.settings.max_runtime_seconds,
            ),
            "started_at": datetime.now(UTC),
        })
        child_state.step_runtime = {
            step_id: runtime.model_copy(update={
                "status": StepStatus.PENDING,
                "assigned_worker": None,
                "lease_fence": 0,
                "transition_id": None,
                "run_fence": 0,
                "step_fence": 0,
                "tool_invocation_ids": [],
            }) if runtime.status in {StepStatus.RUNNING, StepStatus.READY}
            else runtime
            for step_id, runtime in child_state.step_runtime.items()
        }
        uow = self.unit_of_work or ControlPlaneUnitOfWork(
            self.coordinator.engine, initialize_schema=False,
        )
        if (self.ledger.engine.url != uow.engine.url
                or self.coordinator.engine.url != uow.engine.url
                or (self.investigation_store is not None
                    and self.investigation_store.engine.url != uow.engine.url)):
            raise RuntimeError("checkpoint fork requires one control-plane database")
        prepared = uow.prepare_checkpoint_fork(child_state)
        if prepared.status != RunStatus.PENDING:
            try:
                self.coordinator.job_status(child_run_id)
            except KeyError as exc:
                raise RuntimeError("fork child has no claimable job") from exc
            return prepared
        if not prepared.fork_child_checkpoint_id:
            raise RuntimeError("prepared fork has no child checkpoint identity")
        child_state = prepared.model_copy(update={
            "status": RunStatus.RUNNING,
            "state_version": prepared.state_version + 1,
        })
        root_reservation = (
            self._root_budget_reservation(child_state)
            if self.investigation_store is not None else None
        )
        child_payload = dict(payload)
        child_payload["id"] = child_state.fork_child_checkpoint_id
        child_channels = dict(channel_values)
        child_channels["agent"] = child_state.model_dump(mode="json")
        child_payload["channel_values"] = child_channels
        parent_config = getattr(checkpoint, "config", {})
        parent_cfg = parent_config.get("configurable", {}) if isinstance(parent_config, dict) else {}
        child_config = {"configurable": {
            "thread_id": child_run_id,
            "checkpoint_ns": parent_cfg.get("checkpoint_ns", ""),
        }}
        child_checkpoint = await self.orchestrator.checkpointer.aget_tuple({
            "configurable": {**child_config["configurable"], "checkpoint_id": child_payload["id"]},
        })
        if child_checkpoint is not None:
            saved_channels = child_checkpoint.checkpoint.get("channel_values", {})
            if (child_checkpoint.checkpoint.get("id") != child_payload["id"]
                    or saved_channels.get("agent") != child_channels["agent"]
                    or child_checkpoint.metadata.get("parent_run_id") != parent_run_id
                    or child_checkpoint.metadata.get("parent_checkpoint_id") != checkpoint_id):
                raise RuntimeError("prepared child checkpoint does not match the fork request")
        else:
            await self.orchestrator.checkpointer.aput(
                child_config,
                child_payload,
                {
                    **checkpoint.metadata,
                    "source": "fork",
                    "parent_run_id": parent_run_id,
                    "parent_checkpoint_id": checkpoint_id,
                },
                dict(payload.get("channel_versions", {})),
            )
        # Pending writes were produced *after* the selected checkpoint. The
        # child reruns the checkpoint's next nodes under its own run identity.
        published = uow.submit_checkpoint_fork(
            child_state, parent_run_id=parent_run_id, checkpoint_id=checkpoint_id,
            actor=actor, root_reservation=root_reservation,
        )
        if not published:
            current = self.ledger.load_state(child_run_id)
            if current is None:
                raise RuntimeError("published fork child disappeared")
            return current
        self.worker.notify()
        return child_state

    # Short service names keep API integration independent of storage terminology.
    def build_replay(self, run_id: str) -> ReplayBundleRef:
        return self.build_replay_bundle(run_id)

    def get_replay(self, run_id: str) -> ReplayBundleRef:
        return self.get_replay_bundle(run_id)

    def verify_replay(self, run_id: str) -> ReplayVerification:
        return self.verify_replay_bundle(run_id)

    def _replayable_state(self, run_id: str) -> AgentState:
        state = self.state(run_id)
        if state.status not in _REPLAYABLE_STATUSES:
            raise RuntimeError("Replay bundles are available only for terminal runs")
        return state

    def _build_replay_entries(
        self,
        state: AgentState,
        ledger_events: list[LedgerEvent],
    ) -> list[ReplayEntry]:
        database = self._replay_database_snapshot(state.run_id)
        report = self._replay_report(state)
        plan_events = [
            {
                "sequence": event.sequence,
                "event_type": event.event_type,
                "payload": event.payload,
            }
            for event in ledger_events
            if event.event_type.startswith("plan.") or event.event_type.startswith("run.replanned")
        ]
        plan_events.append(
            {
                "revision": "terminal-state",
                "state_version": state.state_version,
                "plan": [step.model_dump(mode="json") for step in state.plan],
            }
        )
        ledger_rows: list[dict[str, Any]] = []
        for event in ledger_events:
            payload = event.model_dump(mode="json")
            if _scrub_replay_value(payload) != payload:
                raise ReplayError("ledger contains unredacted sensitive information")
            ledger_rows.append(payload)

        tool_artifacts = sorted(
            (
                artifact.model_dump(mode="json")
                for observation in state.observations
                for artifact in observation.artifacts
            ),
            key=lambda item: (str(item["artifact_id"]), str(item["sha256"])),
        )
        artifact_manifest = {
            "input_artifacts": sorted(
                (item.model_dump(mode="json") for item in state.input_artifacts),
                key=lambda item: (str(item["relative_path"]), str(item["sha256"])),
            ),
            "tool_artifacts": tool_artifacts,
            "evidence_artifact_refs": sorted(
                {evidence.artifact_ref for evidence in state.evidence if evidence.artifact_ref is not None}
            ),
            "objects": database["artifacts"],
        }
        approvals_and_grants = [
            *database["approvals"],
            *[
                {"record_type": "capability_grant", **grant.model_dump(mode="json")}
                for grant in sorted(state.active_grants, key=lambda item: item.grant_id)
            ],
        ]
        evidence_graph = [
            *[
                {"record_type": "evidence", **evidence.model_dump(mode="json")}
                for evidence in sorted(state.evidence, key=lambda item: item.evidence_id)
            ],
            *[
                {"record_type": "link", **link.model_dump(mode="json")}
                for link in sorted(state.evidence_links, key=lambda item: item.link_id)
            ],
            *[
                {"record_type": "verification", **result.model_dump(mode="json")}
                for result in sorted(state.verification_results, key=lambda item: item.claim_id)
            ],
        ]
        # Old sealed runs can predate ResolvedTaskContract.  Replay is a
        # read-only provenance operation, so preserve their artifacts without
        # reviving mutable TaskRequest fields as execution policy.
        resolved_task = require_resolved_task_contract(state) if state.resolved_task_contract is not None else None
        entries = {
            "input-inventory.json": _json_bytes(
                {
                    "run_id": state.run_id,
                    "attachments": [item.model_dump(mode="json") for item in state.task.attachments],
                    "input_artifacts": artifact_manifest["input_artifacts"],
                }
            ),
            "effective-policy.json": _json_bytes(
                {
                    "schema_version": state.schema_version,
                    "contract_status": "sealed" if resolved_task is not None else "legacy_unsealed",
                    "autonomy_policy": (resolved_task.autonomy_policy if resolved_task is not None else "unavailable"),
                    "target_scope": resolved_task.authorized_scope if resolved_task is not None else [],
                    "constraints": resolved_task.constraints if resolved_task is not None else [],
                    "cancel_requested": state.cancel_requested,
                }
            ),
            "selected-skills.json": _json_bytes(
                {
                    "selected_skill_ids": sorted(state.selected_skill_ids),
                    "external_skill_cards": sorted(
                        (
                            {
                                "skill_id": str(item.metadata["external_skill_id"]),
                                "catalog_digest": item.metadata.get("catalog_digest"),
                                "source_commit": item.metadata.get("source_commit"),
                                "source_path": item.metadata.get("source_path"),
                                "source_sha256": item.metadata.get("source_sha256"),
                                "executable": False,
                            }
                            for item in state.context_items
                            if item.metadata.get("external_skill_id")
                        ),
                        key=lambda item: item["skill_id"],
                    ),
                    "step_bindings": [
                        {
                            "step_id": step.step_id,
                            "signed_skill_ids": sorted(step.skill_ids),
                            "external_skill_card_ids": sorted(
                                step.context_requirements.get("external_skill_card_ids", [])
                            ),
                            "tool_candidates": sorted(step.tool_candidates),
                        }
                        for step in sorted(state.plan, key=lambda item: item.step_id)
                    ],
                    "active_agent_profiles": sorted(state.active_agent_profiles),
                }
            ),
            "repository-index-ref.json": _json_bytes(
                {} if state.repository_index is None else state.repository_index.model_dump(mode="json")
            ),
            "context-pack-manifest.jsonl": _jsonl_bytes(
                pack.model_dump(mode="json") for pack in sorted(state.context_packs, key=lambda item: item.pack_id)
            ),
            "plan-revisions.jsonl": _jsonl_bytes(plan_events),
            "outcome-contracts.jsonl": _jsonl_bytes(
                contract.model_dump(mode="json")
                for contract in sorted(
                    state.outcome_contracts,
                    key=lambda item: (item.step_id, item.contract_id),
                )
            ),
            "model-invocations.jsonl": _jsonl_bytes(database["models"]),
            "tool-invocations.jsonl": _jsonl_bytes(database["tools"]),
            "approvals-and-grants.jsonl": _jsonl_bytes(approvals_and_grants),
            "claims.jsonl": _jsonl_bytes(
                claim.model_dump(mode="json") for claim in sorted(state.claims, key=lambda item: item.claim_id)
            ),
            "evidence-graph.jsonl": _jsonl_bytes(evidence_graph),
            "artifact-manifest.json": _json_bytes(artifact_manifest),
            "ledger.jsonl": _jsonl_bytes(ledger_rows, scrub=False),
            "report.json": _json_bytes(report.model_dump(mode="json")),
            "report.md": _scrub_replay_string(render_markdown(report)).encode("utf-8"),
            "report.sarif": _json_bytes(render_sarif(report)),
        }
        if database["step_patches"]:
            entries["step-patches.jsonl"] = _jsonl_bytes(database["step_patches"])
        missing = REQUIRED_REPLAY_ENTRIES - set(entries)
        if missing:  # pragma: no cover - construction is intentionally exhaustive
            raise ReplayError(f"service replay projection is incomplete: {', '.join(sorted(missing))}")
        media_types = {
            "report.md": "text/markdown; charset=utf-8",
            "report.sarif": "application/sarif+json",
        }
        return [
            ReplayEntry(
                path=path,
                content=entries[path],
                media_type=media_types.get(
                    path,
                    "application/x-ndjson" if path.endswith(".jsonl") else "application/json",
                ),
            )
            for path in sorted(entries)
        ]

    def _replay_database_snapshot(self, run_id: str) -> dict[str, list[dict[str, Any]]]:
        with Session(self.coordinator.engine) as session:
            model_rows = list(
                session.scalars(
                    select(ModelInvocationRow)
                    .where(ModelInvocationRow.run_id == run_id)
                    .order_by(
                        ModelInvocationRow.created_at,
                        ModelInvocationRow.model_invocation_id,
                    )
                ).all()
            )
            failure_rows = list(
                session.scalars(
                    select(ModelGatewayFailureRow)
                    .where(ModelGatewayFailureRow.run_id == run_id)
                    .order_by(ModelGatewayFailureRow.created_at, ModelGatewayFailureRow.failure_id)
                ).all()
            )
            tool_rows = list(
                session.scalars(
                    select(ToolInvocationRow)
                    .where(ToolInvocationRow.run_id == run_id)
                    .order_by(ToolInvocationRow.created_at, ToolInvocationRow.invocation_id)
                ).all()
            )
            approval_rows = list(
                session.scalars(
                    select(ApprovalRow)
                    .where(ApprovalRow.run_id == run_id)
                    .order_by(ApprovalRow.created_at, ApprovalRow.request_id)
                ).all()
            )
            artifact_rows = list(
                session.scalars(
                    select(ArtifactObjectRow)
                    .where(ArtifactObjectRow.run_id == run_id)
                    .order_by(ArtifactObjectRow.created_at, ArtifactObjectRow.artifact_id)
                ).all()
            )
            step_rows = list(
                session.scalars(
                    select(StepRunRow)
                    .where(StepRunRow.run_id == run_id, StepRunRow.result_json.is_not(None))
                    .order_by(StepRunRow.step_id, StepRunRow.attempt, StepRunRow.step_run_id)
                ).all()
            )
            return {
                "models": [
                    {
                        "model_invocation_id": row.model_invocation_id,
                        "run_id": row.run_id,
                        "step_id": row.step_id,
                        "provider_request_id": row.provider_request_id,
                        "model_id": row.model_id,
                        "status": row.status,
                        "input_tokens": row.input_tokens,
                        "output_tokens": row.output_tokens,
                        "cache_hit_input_tokens": row.cache_hit_input_tokens,
                        "cache_miss_input_tokens": row.cache_miss_input_tokens,
                        "cost_microunits": row.cost_microunits,
                        "request_hash": row.request_hash,
                        "task_kind": row.task_kind,
                        "model_lane": row.model_lane,
                        "router_version": row.router_version,
                        "prompt_version": row.prompt_version,
                        "response_hash": row.response_hash,
                        "request_digest": row.request_digest,
                        "attempt_ordinal": row.attempt_ordinal,
                        "stage": row.stage,
                        "error_type": row.error_type,
                        "status_code": row.status_code,
                        "duration_ms": row.duration_ms,
                        "retryable": row.retryable,
                        "deadline_ms": row.deadline_ms,
                        "remaining_budget_ms": row.remaining_budget_ms,
                        "route": row.route,
                        "route_profile": row.route_profile,
                        "created_at": _isoformat(row.created_at),
                        "updated_at": _isoformat(row.updated_at),
                    }
                    for row in model_rows
                ],
                "model_gateway_failures": [
                    {
                        "failure_id": row.failure_id,
                        "run_id": row.run_id,
                        "logical_call_id": row.logical_call_id,
                        "error_type": row.error_type,
                        "stage": row.stage,
                        "message": row.message,
                        "status_code": row.status_code,
                        "retryable": row.retryable,
                        "request_digest": row.request_digest,
                        "route": row.route,
                        "route_profile": row.route_profile,
                        "model_id": row.model_id,
                        "prompt_version": row.prompt_version,
                        "deadline_ms": row.deadline_ms,
                        "remaining_budget_ms": row.remaining_budget_ms,
                        "fallback_status": row.fallback_status,
                        "attempts": _stored_json(row.attempts_json, "model gateway failure attempts"),
                        "created_at": _isoformat(row.created_at),
                        "updated_at": _isoformat(row.updated_at),
                    }
                    for row in failure_rows
                ],
                "tools": [
                    {
                        "invocation_id": row.invocation_id,
                        "run_id": row.run_id,
                        "step_id": row.step_id,
                        "tool_name": row.tool_name,
                        "tool_version": row.tool_version,
                        "idempotency_key": row.idempotency_key,
                        "parameters_hash": row.parameters_hash,
                        "attempt": row.attempt,
                        "status": row.status,
                        "owner_id": row.owner_id,
                        "fence": row.fence,
                        "grant_id": row.grant_id,
                        "result": _stored_json(row.result_json, "tool invocation result"),
                        "error": row.error,
                        "created_at": _isoformat(row.created_at),
                        "updated_at": _isoformat(row.updated_at),
                    }
                    for row in tool_rows
                ],
                "approvals": [
                    {
                        "record_type": "approval",
                        "request_id": row.request_id,
                        "run_id": row.run_id,
                        "step_id": row.step_id,
                        "tool_name": row.tool_name,
                        "parameters_hash": row.parameters_hash,
                        "request": _stored_json(row.request_json, "approval request"),
                        "status": row.status,
                        "decision": row.decision,
                        "effective_parameters_hash": row.effective_parameters_hash,
                        "response": _stored_json(row.response_json, "approval response"),
                        "actor": row.actor,
                        "resolution_id": row.resolution_id,
                        "consumed_at": _isoformat(row.consumed_at),
                        "fence": row.fence,
                        "created_at": _isoformat(row.created_at),
                        "resolved_at": _isoformat(row.resolved_at),
                    }
                    for row in approval_rows
                ],
                "artifacts": [
                    {
                        "artifact_id": row.artifact_id,
                        "sha256": row.artifact_id,
                        "run_id": row.run_id,
                        "invocation_id": row.invocation_id,
                        "size_bytes": row.size_bytes,
                        "media_type": row.media_type,
                        "created_at": _isoformat(row.created_at),
                    }
                    for row in artifact_rows
                ],
                "step_patches": [_required_stored_json(row.result_json, "step result") for row in step_rows],
            }

    @staticmethod
    def _replay_report(state: AgentState) -> AgentReport:
        try:
            report = AdmissionService.public_report(state)
        except AdmissionError as exc:
            raise ReplayError("replay requires a valid sealed admission snapshot") from exc
        return AgentReport.model_validate(_scrub_replay_value(report.model_dump(mode="json")))

    def list_summaries(
        self,
        *,
        statuses: set[RunStatus] | None = None,
        offset: int = 0,
        limit: int = 100,
    ) -> list[RunSummary]:
        states = self.ledger.list_states(statuses=statuses, offset=offset, limit=limit)
        return [self._summary_from_state(state) for state in states]

    def summary(self, run_id: str) -> RunSummary:
        return self._summary_from_state(self.state(run_id))

    def session_snapshot(self, run_id: str) -> RunSessionSnapshot:
        """Return a bounded, stabilized read model without creating new state.

        Agent state, coordinator lease, and ledger sequence live in separate
        durable records.  Two matching observations provide an honest
        consistency boundary for an operator read without locking an active
        worker.  A rapidly-changing run is still returned, but explicitly
        marked unstable so polling clients know to refresh.
        """

        previous_signature: tuple[Any, ...] | None = None
        state: AgentState | None = None
        summary: RunSummary | None = None
        for read_attempts in range(1, 4):
            state = self.state(run_id)
            summary = self._summary_from_state(state)
            signature = (
                state.state_version,
                summary.status,
                summary.queue_status,
                summary.latest_event_sequence,
                summary.lease.owner_id,
                summary.lease.fence,
            )
            if signature == previous_signature:
                return build_run_session_snapshot(
                    state,
                    summary,
                    stable=True,
                    read_attempts=read_attempts,
                )
            previous_signature = signature

        if state is None or summary is None:
            raise RuntimeError("session snapshot stabilization produced no observation")
        return build_run_session_snapshot(
            state,
            summary,
            stable=False,
            read_attempts=3,
        )

    def _summary_from_state(self, state: AgentState) -> RunSummary:
        run_id = state.run_id
        try:
            queue_state, coordinator_lease, queue_error = self.coordinator.job_snapshot(run_id)
        except KeyError:
            queue_state, coordinator_lease, queue_error = "completed", None, None
        queue_status = self._map_queue_status(queue_state)
        live_lease = (
            LeaseSummary(
                owner_id=coordinator_lease.owner_id,
                fence=coordinator_lease.fence,
                lease_until=coordinator_lease.lease_until,
            )
            if coordinator_lease is not None
            else state.lease
        )
        latest = self.ledger.latest_event(run_id)
        active_approval_ids = {item.request_id for item in state.pending_approvals}
        if state.pending_approval is not None:
            active_approval_ids.add(state.pending_approval.request_id)
        context_usage = max(
            (item.token_budget for item in state.context_packs),
            key=lambda item: item.used_tokens,
            default=ContextBudget(),
        )
        if state.budget.context_tokens_used > context_usage.used_tokens:
            context_usage = context_usage.model_copy(
                update={"used_tokens": min(context_usage.total_tokens, state.budget.context_tokens_used)}
            )
        current_step_id = (
            state.plan[state.current_step_index].step_id if state.current_step_index < len(state.plan) else None
        )
        # A verifier may choose the eventual terminal status one checkpoint
        # before the immutable Admission snapshot is sealed.  That internal
        # state is still in flight: exposing it as terminal lets clients race
        # the report/completion endpoints and observe a 409.  Publish the
        # terminal status only once its public report authority exists.
        public_status = state.status
        if state.status in {RunStatus.COMPLETED, RunStatus.PARTIAL} and state.sealed_admission is None:
            public_status = RunStatus.RUNNING
        return RunSummary(
            run_id=run_id,
            parent_run_id=state.parent_run_id,
            fork_checkpoint_id=state.fork_checkpoint_id,
            status=public_status,
            scenario=state.scenario,
            current_step=state.current_step_index,
            total_steps=len(state.plan),
            plan=state.plan,
            current_step_id=current_step_id,
            budget=state.budget,
            started_at=state.started_at,
            updated_at=latest.timestamp if latest else state.started_at,
            latest_event_sequence=latest.sequence if latest else 0,
            task_spec_ref=state.task_spec_ref,
            active_route=state.active_route,
            pending_clarification=state.pending_clarification,
            pending_approval=state.pending_approval,
            last_error=state.last_error or queue_error,
            queue_status=queue_status,
            lease=live_lease,
            active_step_ids=sorted(
                step_id for step_id, runtime in state.step_runtime.items() if runtime.status.value == "running"
            ),
            cancel_requested=state.cancel_requested,
            verified_claims=sum(item.status == ClaimStatus.VERIFIED for item in state.claims),
            insufficient_claims=sum(item.status == ClaimStatus.INSUFFICIENT for item in state.claims),
            conflicted_claims=sum(item.status == ClaimStatus.CONFLICTED for item in state.claims),
            context_usage=context_usage,
            active_approval_ids=sorted(active_approval_ids),
            audit_kernel=state.audit_kernel,
            audit_coverage=public_coverage_projection(state.audit_coverage),
        )

    async def recover_incomplete(self) -> None:
        for run_id in self.ledger.incomplete_run_ids():
            state = self.ledger.load_state(run_id)
            if state is not None and state.pending_clarification is not None:
                try:
                    self.orchestrator.task_spec_repository.clarification_response(
                        state.pending_clarification.request_id,
                        run_id=run_id,
                    )
                except KeyError:
                    pass
                else:
                    self.coordinator.ensure_job_awake(run_id)
                    continue
            try:
                self.coordinator.enqueue_run(run_id)
            except CoordinatorConflict:
                continue
        self.worker.notify()

    async def shutdown(self) -> None:
        await self.worker.stop()
        if self._projector_task is not None:
            self._projector_stop.set()
            await self._projector_task
            self._projector_task = None
        await self.orchestrator.broker.aclose()
        self.orchestrator.broker.close()
        if self.orchestrator.knowledge_store is not None:
            self.orchestrator.knowledge_store.close()
        self.ledger.close()
        self.coordinator.close()

    def _queue_status(self, run_id: str) -> QueueStatus:
        try:
            status, _ = self.coordinator.job_status(run_id)
        except KeyError:
            return QueueStatus.COMPLETE
        return self._map_queue_status(status)

    @staticmethod
    def _map_queue_status(status: str) -> QueueStatus:
        mapping = {
            "queued": QueueStatus.QUEUED,
            "leased": QueueStatus.LEASED,
            "waiting": QueueStatus.WAITING,
            "recovery_required": QueueStatus.WAITING,
            "retry": QueueStatus.RETRY,
            "completed": QueueStatus.COMPLETE,
            "cancelled": QueueStatus.CANCELLED,
        }
        return mapping.get(status, QueueStatus.QUEUED)

    def _inline_projector_enabled(self) -> bool:
        settings = self.orchestrator.settings
        if settings.env.lower() in {"production", "competition"}:
            return False
        if settings.runtime_role == "embedded":
            return True
        return settings.runtime_role == "api" and settings.database_url.startswith("sqlite")


def _scrub_replay_string(value: str) -> str:
    return scrub_text(value)


def _scrub_replay_value(value: Any) -> Any:
    """Recursively remove credential material without weakening deterministic output."""
    return scrub_value(value)


def _json_bytes(value: Any) -> bytes:
    return canonical_json(_scrub_replay_value(redact(value))).encode("utf-8")


def _jsonl_bytes(values: Iterable[Any], *, scrub: bool = True) -> bytes:
    rows: list[str] = []
    for value in values:
        safe = _scrub_replay_value(redact(value)) if scrub else value
        rows.append(canonical_json(safe))
    return ("\n".join(rows) + ("\n" if rows else "")).encode("utf-8")


def _stored_json(value: str | None, label: str) -> dict[str, Any] | None:
    if value is None:
        return None
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ReplayError(f"stored {label} is invalid JSON") from exc
    if not isinstance(parsed, dict):
        raise ReplayError(f"stored {label} must be a JSON object")
    return parsed


def _required_stored_json(value: str | None, label: str) -> dict[str, Any]:
    parsed = _stored_json(value, label)
    if parsed is None:
        raise ReplayError(f"stored {label} is missing")
    return parsed


def _isoformat(value: datetime | None) -> str | None:
    return None if value is None else value.isoformat()


class RunWorker:
    """Bounded durable worker that is the only component allowed to advance a run."""

    def __init__(self, service: RunService) -> None:
        self.service = service
        self.settings = service.orchestrator.settings
        self._task: asyncio.Task[None] | None = None
        self._wake = asyncio.Event()
        self._stopping = False

    async def start(self) -> None:
        if self._task is None:
            self._stopping = False
            self._task = asyncio.create_task(self._loop())

    def notify(self) -> None:
        self._wake.set()

    async def stop(self) -> None:
        self._stopping = True
        self._wake.set()
        if self._task is not None:
            await self._task
            self._task = None

    async def _loop(self) -> None:
        active: set[asyncio.Task[None]] = set()
        try:
            while not self._stopping:
                completed = {task for task in active if task.done()}
                if completed:
                    active.difference_update(completed)
                    await asyncio.gather(*completed)
                capacity = self.settings.worker_claim_limit - len(active)
                if capacity > 0:
                    leases = self.service.coordinator.claim_jobs(
                        self.settings.worker_id,
                        limit=capacity,
                        lease_seconds=self.settings.worker_lease_seconds,
                    )
                    if leases:
                        RUN_JOBS_CLAIMED.inc(len(leases))
                        active.update(
                            asyncio.create_task(self._run(lease), name=f"secmind-run-{lease.run_id}")
                            for lease in leases
                        )
                if active:
                    await asyncio.wait(
                        active,
                        timeout=self.settings.worker_poll_seconds,
                        return_when=asyncio.FIRST_COMPLETED,
                    )
                    continue
                self._wake.clear()
                try:
                    await asyncio.wait_for(self._wake.wait(), timeout=self.settings.worker_poll_seconds)
                except TimeoutError:
                    pass
        finally:
            if active:
                await asyncio.gather(*active)

    async def _run(self, lease: RunLease) -> None:
        started = time.monotonic()
        ACTIVE_RUNS.inc()
        heartbeat: asyncio.Task[None] | None = None
        try:
            state = self.service.ledger.load_state(lease.run_id)
            if state is None:
                self.service.coordinator.finish_job(
                    lease.run_id,
                    owner_id=lease.owner_id,
                    fence=lease.fence,
                    status="cancelled",
                )
                return
            state.lease = LeaseSummary(
                owner_id=lease.owner_id,
                fence=lease.fence,
                lease_until=lease.lease_until,
            )
            # Lease acquisition is queue control state, not an AgentState
            # transition.  Advancing RunRow here can place business state one
            # version ahead of its LangGraph checkpoint after a crash.
            self.service.coordinator.enqueue_outbox(
                lease.run_id,
                transition_id=f"run:{lease.run_id}:lease:{lease.fence}",
                event_type="run.leased",
                payload={"owner_id": lease.owner_id, "fence": lease.fence},
                actor="coordinator",
                lease_owner_id=lease.owner_id,
                lease_fence=lease.fence,
            )
            authority = (
                self.service.investigation_store.issue_authority(
                    lease.run_id,
                    owner_id=lease.owner_id,
                    run_fence=lease.fence,
                )
                if self.service.investigation_store is not None
                else None
            )
            heartbeat = asyncio.create_task(self._heartbeat(lease))
            advance = asyncio.create_task(self._advance(state, authority), name=f"secmind-run-{state.run_id}")
            done, _ = await asyncio.wait({advance, heartbeat}, return_when=asyncio.FIRST_COMPLETED)
            if heartbeat in done:
                advance.cancel()
                with suppress(asyncio.CancelledError):
                    await advance
                await heartbeat
                raise CoordinatorConflict("run heartbeat stopped without an error")
            completed = await advance
            if completed.status in {
                RunStatus.WAITING_APPROVAL,
                RunStatus.WAITING_CLARIFICATION,
            }:
                self.service.coordinator.park_job(
                    lease.run_id,
                    owner_id=lease.owner_id,
                    fence=lease.fence,
                    status="waiting",
                )
            elif completed.status == RunStatus.RECOVERY_REQUIRED:
                self.service.coordinator.park_job(
                    lease.run_id,
                    owner_id=lease.owner_id,
                    fence=lease.fence,
                    status="recovery_required",
                )
            else:
                terminal = "cancelled" if completed.cancel_requested else "completed"
                self.service.coordinator.finish_job(
                    lease.run_id,
                    owner_id=lease.owner_id,
                    fence=lease.fence,
                    status=terminal,
                )
        except Exception as exc:
            RUN_JOB_FAILURES.inc()
            delay = min(60, 2 ** min(lease.attempts, 6))
            safe_error = scrub_text(str(exc))[:500]
            logger.error(
                "run worker failed: %s",
                safe_error,
                extra={
                    "run_id": lease.run_id,
                    "fence": lease.fence,
                    "attempt": lease.attempts,
                    "error_type": type(exc).__name__,
                },
            )
            if lease.attempts >= self.settings.worker_max_attempts:
                current = self.service.ledger.load_state(lease.run_id)
                if current is None:
                    return
                current.status = RunStatus.RECOVERY_REQUIRED
                current.last_error = f"Worker retry budget exhausted: {type(exc).__name__}"
                self._materialize_recovery_report(current)
                current.lease = LeaseSummary(
                    owner_id=lease.owner_id,
                    fence=lease.fence,
                    lease_until=lease.lease_until,
                )
                try:
                    self.service.coordinator.commit_transition(
                        current,
                        expected_version=current.state_version,
                        owner_id=lease.owner_id,
                        fence=lease.fence,
                        transition_id=f"run:{lease.run_id}:recovery-required:{lease.fence}",
                        event_type="run.recovery_required",
                        payload={
                            "error_type": type(exc).__name__,
                            "attempts": lease.attempts,
                        },
                        actor="coordinator",
                    )
                    self.service.coordinator.park_job(
                        lease.run_id,
                        owner_id=lease.owner_id,
                        fence=lease.fence,
                        status="recovery_required",
                    )
                except CoordinatorConflict:
                    return
                return
            try:
                self.service.coordinator.enqueue_outbox(
                    lease.run_id,
                    transition_id=f"run:{lease.run_id}:worker-failure:{lease.fence}:{lease.attempts}",
                    event_type="run.worker_failed",
                    payload={
                        "error_type": type(exc).__name__,
                        "retry_in_seconds": delay,
                    },
                    actor="coordinator",
                    lease_owner_id=lease.owner_id,
                    lease_fence=lease.fence,
                )
            except CoordinatorConflict:
                return
            try:
                self.service.coordinator.retry_job(
                    lease.run_id,
                    owner_id=lease.owner_id,
                    fence=lease.fence,
                    delay_seconds=delay,
                    error=f"{type(exc).__name__}: {safe_error}"[:500],
                )
            except CoordinatorConflict:
                return
        finally:
            ACTIVE_RUNS.dec()
            RUN_JOB_DURATION.observe(time.monotonic() - started)
            if heartbeat is not None:
                heartbeat.cancel()
                with suppress(asyncio.CancelledError):
                    await heartbeat

    async def _advance(self, state: AgentState, authority: Any) -> AgentState:
        if state.status == RunStatus.PENDING:
            return await self.service.orchestrator.start(state.task, state.run_id, authority=authority)
        if state.status == RunStatus.WAITING_CLARIFICATION and state.pending_clarification is not None:
            clarification_response = self.service.orchestrator.task_spec_repository.clarification_response(
                state.pending_clarification.request_id,
                run_id=state.run_id,
            )
            return await self.service.orchestrator.resume_clarification(
                state.run_id,
                clarification_response,
                authority=authority,
            )
        if state.status == RunStatus.WAITING_APPROVAL and state.pending_approval is not None:
            approval_response = self.service.orchestrator.broker.approval_response(
                state.pending_approval.request_id,
                run_id=state.run_id,
            )
            return await self.service.orchestrator.resume(
                state.run_id,
                approval_response,
                authority=authority,
            )
        return await self.service.orchestrator.recover(state.run_id, authority=authority)

    def _materialize_recovery_report(self, state: AgentState) -> None:
        """Make retry exhaustion observable without inventing a successful result."""

        reason = state.last_error or "The run exhausted its bounded recovery budget."
        if state.sealed_admission is not None:
            # A completed admission is immutable. Recovery diagnostics remain
            # on run state/ledger and must never replace its public report.
            try:
                AdmissionService.restore_sealed_view(state)
            except AdmissionError as exc:
                state.report = None
                state.audit_coverage["sealed_admission_error"] = scrub_text(str(exc))[:500]
            state.audit_coverage["recovery_report_materialized"] = True
            return
        state.audit_coverage["recovery_report_materialized"] = True
        durable_baseline = baseline_report(state)
        coverage = dict(state.audit_coverage)
        coverage.update(
            {
                "recovery_report_materialized": True,
                "primary_preserved": durable_baseline is not None,
            }
        )
        state.audit_coverage = coverage
        state.report = AgentReport(
            run_id=state.run_id,
            status=RunStatus.RECOVERY_REQUIRED,
            executive_summary=(
                durable_baseline.executive_summary
                if durable_baseline is not None
                else "SecMind could not safely advance the run after bounded retries; available partial results are "
                "preserved for recovery."
            ),
            findings=list(durable_baseline.findings if durable_baseline is not None else state.findings),
            decisions=list(state.decisions),
            evidence=list(durable_baseline.evidence if durable_baseline is not None else state.evidence),
            limitations=list(
                dict.fromkeys(
                    [
                        *(durable_baseline.limitations if durable_baseline is not None else []),
                        *state.completion_reasons,
                        reason,
                    ]
                )
            ),
            coverage=coverage,
            audit_kernel=state.audit_kernel,
            audit_units=state.audit_units,
            claim_ids=(
                list(durable_baseline.claim_ids)
                if durable_baseline is not None
                else [claim.claim_id for claim in state.claims]
            ),
        )
        if state.published_baseline is not None:
            restore_published_baseline(state)
        try:
            AdmissionService.seal(
                state,
                state.report,
                artifact_store=self.service.artifact_store,
                capsule_store=self.service.orchestrator.capsule_store,
            )
        except AdmissionError as exc:
            # Recovery must still converge, but an unverifiable candidate is
            # never promoted to a public report.
            state.report = None
            state.audit_coverage["sealed_admission_error"] = scrub_text(str(exc))[:500]

    async def _heartbeat(self, lease: RunLease) -> None:
        interval = max(1.0, self.settings.worker_lease_seconds / 3)
        while True:
            await asyncio.sleep(interval)
            self.service.coordinator.heartbeat(
                lease.run_id,
                owner_id=lease.owner_id,
                fence=lease.fence,
                lease_seconds=self.settings.worker_lease_seconds,
            )
