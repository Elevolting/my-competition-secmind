"""Atomic writes for authoritative cognitive control-plane state.

This module deliberately keeps row mappings beside their transaction service:
reviewing a write method and its uniqueness/fencing constraints should not
require jumping between ORM and repository modules.
"""

from __future__ import annotations

import hashlib
import threading
from collections import OrderedDict
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import NAMESPACE_URL, uuid4, uuid5

from sqlalchemy import Boolean, DateTime, Float, Integer, String, Text, UniqueConstraint, or_, select, text, update
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

from secmind.coordinator import OutboxEventRow, RunJobRow
from secmind.execution import (
    ApprovalRow,
    ExecutionConflict,
    ToolInvocationRow,
    parameters_hash,
    stable_json,
)
from secmind.investigation.contracts import UsageReservation
from secmind.ledger import LedgerStore, RunRow, canonical_json, redact
from secmind.schemas import (
    AgentState,
    ApprovalDecision,
    ApprovalResponse,
    CapabilityGrant,
    DataView,
    HookEvent,
    HookResult,
    InvocationStatus,
    ResumeAction,
    ResumeAssessment,
    RetentionHold,
    RunStatus,
    ToolInputEnvelope,
    ToolResult,
)
from secmind.secret_scrubber import scrub_text
from secmind.task_context import require_resolved_task_contract


class CognitiveBase(DeclarativeBase):
    pass


class RepositoryIndexRow(CognitiveBase):
    __tablename__ = "repository_indexes"

    index_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(36), unique=True, index=True)
    artifact_id: Mapped[str] = mapped_column(String(64))
    digest: Mapped[str] = mapped_column(String(64))
    summary_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ContextItemRow(CognitiveBase):
    __tablename__ = "context_items"
    __table_args__ = (UniqueConstraint("run_id", "content_hash", "kind"),)

    context_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(36), index=True)
    kind: Mapped[str] = mapped_column(String(40), index=True)
    source: Mapped[str] = mapped_column(String(500))
    authority_level: Mapped[int] = mapped_column(Integer)
    taint: Mapped[str] = mapped_column(String(20))
    sensitivity: Mapped[str] = mapped_column(String(40))
    content_hash: Mapped[str] = mapped_column(String(64))
    token_estimate: Mapped[int] = mapped_column(Integer, default=0)
    artifact_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    metadata_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ContextPackRow(CognitiveBase):
    __tablename__ = "context_packs"
    __table_args__ = (UniqueConstraint("run_id", "pack_digest"),)

    pack_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(36), index=True)
    step_id: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    agent_profile: Mapped[str] = mapped_column(String(100))
    pack_digest: Mapped[str] = mapped_column(String(64))
    manifest_json: Mapped[str] = mapped_column(Text)
    token_budget: Mapped[int] = mapped_column(Integer)
    token_used: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class OutcomeContractRow(CognitiveBase):
    __tablename__ = "outcome_contracts"
    __table_args__ = (UniqueConstraint("run_id", "step_id"),)

    contract_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(36), index=True)
    step_id: Mapped[str] = mapped_column(String(100))
    contract_digest: Mapped[str] = mapped_column(String(64))
    contract_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ClaimRow(CognitiveBase):
    __tablename__ = "claims"

    claim_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(36), index=True)
    step_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    claim_type: Mapped[str] = mapped_column(String(100))
    subject_ref: Mapped[str] = mapped_column(String(500))
    status: Mapped[str] = mapped_column(String(30), index=True)
    severity: Mapped[str] = mapped_column(String(20))
    confidence: Mapped[float] = mapped_column(Float)
    producer: Mapped[str] = mapped_column(String(100))
    claim_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class EvidenceLinkRow(CognitiveBase):
    __tablename__ = "evidence_links"
    __table_args__ = (UniqueConstraint("claim_id", "evidence_id", "relation"),)

    link_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(36), index=True)
    claim_id: Mapped[str] = mapped_column(String(36), index=True)
    evidence_id: Mapped[str] = mapped_column(String(100))
    relation: Mapped[str] = mapped_column(String(30))
    weight: Mapped[float] = mapped_column(Float)
    verifier_status: Mapped[str] = mapped_column(String(30))
    grader_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class RunNotebookRow(CognitiveBase):
    __tablename__ = "run_notebooks"

    run_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    notebook_digest: Mapped[str] = mapped_column(String(64))
    notebook_json: Mapped[str] = mapped_column(Text)
    state_version: Mapped[int] = mapped_column(Integer)
    source_fence: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    source_transition_id: Mapped[str | None] = mapped_column(String(200), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ProjectionHeadRow(CognitiveBase):
    """Monotonic source cursor for all cognitive read-model projections.

    The normalized tables are intentionally rebuildable and historically used
    advisory locks only.  This head is the durable CAS guard that prevents a
    delayed worker from re-applying an older snapshot after a newer transition
    has already been projected.
    """

    __tablename__ = "projection_heads"

    run_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    source_state_version: Mapped[int] = mapped_column(Integer)
    source_fence: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    source_transition_id: Mapped[str] = mapped_column(String(200))
    outbox_receipt_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    projection_digest: Mapped[str] = mapped_column(String(64))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class CapabilityGrantRow(CognitiveBase):
    __tablename__ = "capability_grants"

    grant_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(36), index=True)
    actor: Mapped[str] = mapped_column(String(100))
    grant_digest: Mapped[str] = mapped_column(String(64), unique=True)
    grant_json: Mapped[str] = mapped_column(Text)
    max_uses: Mapped[int] = mapped_column(Integer)
    uses: Mapped[int] = mapped_column(Integer, default=0)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class HookExecutionRow(CognitiveBase):
    __tablename__ = "hook_executions"
    __table_args__ = (UniqueConstraint("hook_id", "event_id"),)

    execution_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(36), index=True)
    step_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    hook_id: Mapped[str] = mapped_column(String(100))
    event_id: Mapped[str] = mapped_column(String(36))
    status: Mapped[str] = mapped_column(String(30))
    input_hash: Mapped[str] = mapped_column(String(64))
    output_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    result_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ReplayBundleRow(CognitiveBase):
    __tablename__ = "replay_bundles"
    __table_args__ = (UniqueConstraint("run_id", "manifest_digest"),)

    replay_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(36), index=True)
    parent_run_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    artifact_id: Mapped[str] = mapped_column(String(64))
    manifest_digest: Mapped[str] = mapped_column(String(64))
    ledger_head_hash: Mapped[str] = mapped_column(String(64))
    ledger_head_signature: Mapped[str | None] = mapped_column(Text, nullable=True)
    mode: Mapped[str] = mapped_column(String(40))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ScenarioRouteRow(CognitiveBase):
    __tablename__ = "scenario_routes"

    route_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(36), index=True)
    scenario: Mapped[str] = mapped_column(String(50))
    strategy: Mapped[str | None] = mapped_column(String(30), nullable=True)
    route_digest: Mapped[str] = mapped_column(String(64))
    route_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class PlanRevisionRow(CognitiveBase):
    __tablename__ = "plan_revisions"
    __table_args__ = (UniqueConstraint("run_id", "revision"),)

    revision_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(36), index=True)
    revision: Mapped[int] = mapped_column(Integer)
    trigger: Mapped[str] = mapped_column(String(50))
    parent_plan_digest: Mapped[str] = mapped_column(String(64))
    plan_digest: Mapped[str] = mapped_column(String(64))
    revision_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class InputEnvelopeRow(CognitiveBase):
    __tablename__ = "input_envelopes"

    invocation_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(36), index=True)
    step_id: Mapped[str] = mapped_column(String(100))
    raw_digest: Mapped[str] = mapped_column(String(64))
    observable_digest: Mapped[str] = mapped_column(String(64))
    execution_digest: Mapped[str] = mapped_column(String(64))
    envelope_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class InputMutationRow(CognitiveBase):
    __tablename__ = "input_mutations"

    mutation_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    invocation_id: Mapped[str] = mapped_column(String(36), index=True)
    run_id: Mapped[str] = mapped_column(String(36), index=True)
    stage: Mapped[str] = mapped_column(String(30))
    field_path: Mapped[str] = mapped_column(String(500))
    parent_digest: Mapped[str] = mapped_column(String(64))
    new_digest: Mapped[str] = mapped_column(String(64))
    mutation_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class RetentionHoldRow(CognitiveBase):
    __tablename__ = "retention_holds"

    hold_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(36), index=True)
    actor: Mapped[str] = mapped_column(String(100))
    reason: Mapped[str] = mapped_column(String(1000))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class DataAccessEventRow(CognitiveBase):
    __tablename__ = "data_access_events"

    access_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(36), index=True)
    actor: Mapped[str] = mapped_column(String(100))
    view: Mapped[str] = mapped_column(String(30))
    resource_type: Mapped[str] = mapped_column(String(50))
    resource_id: Mapped[str] = mapped_column(String(100))
    purpose: Mapped[str] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ResumeAssessmentRow(CognitiveBase):
    __tablename__ = "resume_assessments"

    assessment_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(36), index=True)
    action: Mapped[str] = mapped_column(String(50))
    reason_code: Mapped[str] = mapped_column(String(100))
    state_version: Mapped[int] = mapped_column(Integer)
    fence: Mapped[int] = mapped_column(Integer)
    checkpoint_state_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    checkpoint_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    control_digest: Mapped[str] = mapped_column(String(64))
    runner_resources_collected: Mapped[bool] = mapped_column(Boolean)
    assessment_json: Mapped[str] = mapped_column(Text)
    consumption_id: Mapped[str | None] = mapped_column(String(36), nullable=True, unique=True)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    consumed_by: Mapped[str | None] = mapped_column(String(100), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class UnitOfWorkConflict(RuntimeError):
    pass


def _resume_assessment_projection_matches(
    row: ResumeAssessmentRow,
    assessment: ResumeAssessment,
) -> bool:
    return (
        row.run_id == assessment.run_id
        and row.action == assessment.action.value
        and row.reason_code == assessment.reason_codes[0]
        and row.state_version == assessment.state_version
        and row.fence == assessment.fence
        and row.checkpoint_state_version == assessment.checkpoint_state_version
        and row.checkpoint_id == assessment.checkpoint_id
        and row.control_digest == assessment.control_digest
        and row.runner_resources_collected == assessment.runner_resources_collected
    )


_RECOVERY_WAKE_ACTIONS = frozenset(
    {
        ResumeAction.RESUME_FROM_CHECKPOINT,
        ResumeAction.REQUEUE_SAFE_STEP,
        ResumeAction.RETURN_CACHED_RESULT,
        ResumeAction.FINALIZE_OUTBOX,
    }
)


def _input_mutation_binding(value: Any) -> dict[str, Any]:
    """Return only immutable authorization-relevant mutation fields.

    Mutation ids and timestamps are recording metadata generated after a hook
    decision.  They may be regenerated while replaying a transition, so they
    cannot participate in the logical input-binding comparison.
    """

    return {
        "stage": value.stage,
        "field_path": value.field_path,
        "previous_digest": value.previous_digest,
        "new_digest": value.new_digest,
        "actor": value.actor,
        "reason": value.reason,
        "policy_ids": list(value.policy_ids),
    }


def _input_envelope_binding(value: ToolInputEnvelope) -> dict[str, Any]:
    """Canonical security binding used to detect invocation-id reuse."""

    return {
        "invocation_id": value.invocation_id,
        "run_id": value.run_id,
        "step_id": value.step_id,
        "raw_input_ref": value.raw_input_ref,
        "observable_input": value.observable_input,
        "execution_input_ref": value.execution_input_ref,
        "raw_digest": value.raw_digest,
        "observable_digest": value.observable_digest,
        "execution_digest": value.execution_digest,
        "mutation_chain": [_input_mutation_binding(item) for item in value.mutation_chain],
        "scope_binding": list(value.scope_binding),
        "approval_binding": value.approval_binding,
    }


class ControlPlaneUnitOfWork:
    """One-database transaction boundary for authoritative control-plane state.

    Artifact bytes and LangGraph checkpoints remain separate resources. Artifacts are
    written immutably before this transaction; unreferenced objects are reconciled.
    Checkpoints are correlated by stable transition ids rather than falsely presented
    as part of a distributed transaction.
    """

    def __init__(self, engine: Engine, *, initialize_schema: bool = True) -> None:
        self.engine = engine
        self._lock = threading.RLock()
        self._projection_digests: OrderedDict[str, str] = OrderedDict()
        # A projection for a run that has not been submitted yet is a useful
        # local/read-model compatibility path.  Once a durable RunRow exists,
        # the cache is never authoritative: every call rechecks source version,
        # fence and receipt under the database CAS lock.
        self._legacy_projection_runs: set[str] = set()
        if initialize_schema:
            CognitiveBase.metadata.create_all(engine)

    def _database_lock(self, session: Session, key: str) -> None:
        if self.engine.dialect.name == "postgresql":
            # Every writer touching run/job/approval/invocation state shares
            # one per-run serialization domain with CoordinatorStore,
            # InvestigationStore and OutboxProjector.
            session.execute(
                text("SELECT pg_advisory_xact_lock(hashtext(:lock_key))"),
                {"lock_key": f"secmind:coordinator:{key}"},
            )
        elif self.engine.dialect.name == "sqlite":
            session.execute(text("BEGIN IMMEDIATE"))

    def submit_run(
        self, state: AgentState, *, root_reservation: UsageReservation | None = None,
    ) -> bool:
        self._validate_root_reservation(state, root_reservation)
        now = datetime.now(UTC)
        with self._lock, Session(self.engine) as session:
            self._database_lock(session, state.run_id)
            existing = session.get(RunRow, state.run_id)
            if existing is not None:
                stored = AgentState.model_validate_json(existing.state_json)
                if stored.task != state.task:
                    raise UnitOfWorkConflict("client_request_id was reused with a different task")
                return False
            self._stage_run_submission(session, state, now)
            self._stage_root_reservation(session, root_reservation, now)
            session.commit()
            return True

    @staticmethod
    def _stage_run_submission(session: Session, state: AgentState, now: datetime) -> None:
        state.state_version = 1
        session.add(RunRow(
            run_id=state.run_id, status=state.status.value,
            state_version=state.state_version, state_json=state.model_dump_json(),
            created_at=now, updated_at=now,
        ))
        ControlPlaneUnitOfWork._stage_job_submission(session, state, now)

    @staticmethod
    def _stage_job_submission(session: Session, state: AgentState, now: datetime) -> None:
        session.add(RunJobRow(
            run_id=state.run_id, status="queued", fence=0,
            next_attempt_at=now, attempts=0, created_at=now, updated_at=now,
        ))
        session.add(OutboxEventRow(
            outbox_id=str(uuid4()), run_id=state.run_id,
            transition_id=f"run:{state.run_id}:submitted",
            event_type="run.queued", actor="api",
            payload_json=canonical_json(redact({"objective": state.task.objective})),
            status="pending", created_at=now,
        ))

    @staticmethod
    def _validate_root_reservation(
        state: AgentState, reservation: UsageReservation | None,
    ) -> None:
        if reservation is not None and (
            reservation.run_id != state.run_id
            or reservation.kind != "run"
            or reservation.parent_reservation_id is not None
        ):
            raise ValueError("root reservation does not match the run")

    @staticmethod
    def _stage_root_reservation(
        session: Session, reservation: UsageReservation | None, now: datetime,
    ) -> None:
        if reservation is None:
            return
        # InvestigationStore imports task_specs, which imports CognitiveBase.
        from secmind.investigation.store import UsageReservationRow

        if session.get(UsageReservationRow, reservation.reservation_id) is not None:
            raise UnitOfWorkConflict("root reservation already exists")
        session.add(UsageReservationRow(
            reservation_id=reservation.reservation_id,
            run_id=reservation.run_id,
            parent_reservation_id=None,
            transition_id=reservation.transition_id,
            kind=reservation.kind,
            status=reservation.status.value,
            content_digest=reservation.content_digest,
            payload_json=reservation.model_dump_json(),
            created_at=reservation.created_at,
            updated_at=now,
        ))

    def prepare_checkpoint_fork(self, state: AgentState) -> AgentState:
        """Claim one fork request without exposing a claimable worker job."""
        if (state.status != RunStatus.PENDING or state.state_version != 1
                or not state.parent_run_id or not state.fork_checkpoint_id
                or not state.fork_request_id):
            raise ValueError("fork preparation requires a pending child with request lineage")
        now = datetime.now(UTC)
        with self._lock, Session(self.engine) as session:
            self._database_lock(session, state.run_id)
            if session.get(RunRow, state.parent_run_id) is None:
                raise UnitOfWorkConflict("fork parent run no longer exists")
            existing = session.get(RunRow, state.run_id)
            if existing is not None:
                stored = AgentState.model_validate_json(existing.state_json)
                if (stored.parent_run_id != state.parent_run_id
                        or stored.fork_checkpoint_id != state.fork_checkpoint_id
                        or stored.fork_request_id != state.fork_request_id
                        or stored.task != state.task):
                    raise UnitOfWorkConflict("fork request id was reused with different inputs")
                return stored
            session.add(RunRow(
                run_id=state.run_id, status=state.status.value,
                state_version=state.state_version, state_json=state.model_dump_json(),
                created_at=now, updated_at=now,
            ))
            session.commit()
            return state

    def submit_checkpoint_fork(
        self,
        state: AgentState,
        *,
        parent_run_id: str,
        checkpoint_id: str,
        actor: str,
        root_reservation: UsageReservation | None,
    ) -> bool:
        """Publish a fork's run, budget, audit lineage and queue in one commit."""
        if state.parent_run_id != parent_run_id or state.fork_checkpoint_id != checkpoint_id:
            raise ValueError("fork state does not match its parent checkpoint")
        self._validate_root_reservation(state, root_reservation)
        now = datetime.now(UTC)
        with self._lock, Session(self.engine) as session:
            self._database_lock(session, state.run_id)
            if self.engine.dialect.name == "postgresql":
                # LedgerStore.append uses this same per-run lock, so its parent
                # hash chain cannot advance while we calculate the fork event.
                session.execute(text("SELECT pg_advisory_xact_lock(hashtext(:lock_key))"),
                                {"lock_key": f"secmind:run:{parent_run_id}"})
            if session.get(RunRow, parent_run_id) is None:
                raise UnitOfWorkConflict("fork parent run no longer exists")
            row = session.get(RunRow, state.run_id)
            if row is None:
                raise UnitOfWorkConflict("fork child was not prepared")
            stored = AgentState.model_validate_json(row.state_json)
            if (stored.parent_run_id != parent_run_id
                    or stored.fork_checkpoint_id != checkpoint_id
                    or stored.fork_request_id != state.fork_request_id
                    or stored.task != state.task):
                raise UnitOfWorkConflict("prepared fork does not match the child")
            if session.get(RunJobRow, state.run_id) is not None:
                return False
            if (stored.status != RunStatus.PENDING or state.status != RunStatus.RUNNING
                    or state.state_version != stored.state_version + 1):
                raise UnitOfWorkConflict("fork child is not ready for publication")
            row.status = state.status.value
            row.state_version = state.state_version
            row.state_json = state.model_dump_json()
            row.updated_at = now
            self._stage_job_submission(session, state, now)
            self._stage_root_reservation(session, root_reservation, now)
            LedgerStore.append_in_session(session, state.run_id, "run.checkpoint_forked", {
                "parent_run_id": parent_run_id, "checkpoint_id": checkpoint_id, "actor": actor,
            }, actor=actor, dedupe_key=f"run:{state.run_id}:forked")
            LedgerStore.append_in_session(session, parent_run_id, "run.checkpoint_forked", {
                "child_run_id": state.run_id, "checkpoint_id": checkpoint_id, "actor": actor,
            }, actor=actor, dedupe_key=f"run:{parent_run_id}:fork:{state.run_id}")
            session.commit()
            return True

    def persist_cognitive_projection(
        self,
        state: AgentState,
        *,
        source_state_version: int | None = None,
        expected_source_state_version: int | None = None,
        source_fence: int | None = None,
        fence: int | None = None,
        source_transition_id: str | None = None,
        transition_id: str | None = None,
        outbox_receipt_id: str | None = None,
        receipt_id: str | None = None,
    ) -> None:
        """Idempotently project authoritative RunRow state into query tables.

        RunRow plus its transition outbox remains the atomic source of truth. These
        normalized rows are rebuildable read models and therefore never pretend to
        share a transaction with artifact bytes or LangGraph checkpoints.
        """

        if (
            source_state_version is not None
            and expected_source_state_version is not None
            and int(source_state_version) != int(expected_source_state_version)
        ):
            raise UnitOfWorkConflict("projection source state version aliases disagree")
        requested_source_version = int(
            source_state_version
            if source_state_version is not None
            else expected_source_state_version
            if expected_source_state_version is not None
            else state.state_version
        )
        if requested_source_version != int(state.state_version):
            raise UnitOfWorkConflict("projection source state version does not match the state snapshot")

        if source_fence is not None and fence is not None and int(source_fence) != int(fence):
            raise UnitOfWorkConflict("projection source fence aliases disagree")
        requested_fence = int(
            source_fence if source_fence is not None else fence if fence is not None else state.lease.fence
        )
        if requested_fence != int(state.lease.fence):
            raise UnitOfWorkConflict("projection source fence does not match the state snapshot")

        explicit_transition = source_transition_id is not None or transition_id is not None
        if source_transition_id is not None and transition_id is not None and source_transition_id != transition_id:
            raise UnitOfWorkConflict("projection source transition aliases disagree")
        requested_transition = source_transition_id or transition_id
        source_transition = requested_transition or self._projection_transition_id(state)

        if outbox_receipt_id is not None and receipt_id is not None and outbox_receipt_id != receipt_id:
            raise UnitOfWorkConflict("projection outbox receipt aliases disagree")
        requested_receipt = outbox_receipt_id or receipt_id
        projection_digest = self._projection_digest(
            state,
            source_transition_id=source_transition,
            outbox_receipt_id=requested_receipt,
        )
        source_fence = requested_fence
        now = datetime.now(UTC)
        with self._lock, Session(self.engine) as session:
            if (
                state.run_id in self._legacy_projection_runs
                and self._projection_digests.get(state.run_id) == projection_digest
            ):
                return
            self._database_lock(session, state.run_id)
            run = session.get(RunRow, state.run_id, with_for_update=True)
            job = session.get(RunJobRow, state.run_id, with_for_update=True)
            durable_source = run is not None
            if run is not None:
                if job is None:
                    raise UnitOfWorkConflict("projection source run has no durable run job")
                if run.state_version > requested_source_version:
                    # A delayed read-model message is acknowledged only after
                    # the authoritative row has been checked under the lock.
                    session.rollback()
                    return
                if run.state_version < requested_source_version:
                    raise UnitOfWorkConflict("projection source state version is ahead of the durable run")
                if job.fence > requested_fence:
                    session.rollback()
                    return
                if job.fence < requested_fence:
                    raise UnitOfWorkConflict("projection source fence is ahead of the durable run job")

            receipt_row: OutboxEventRow | None = None
            if requested_receipt is not None:
                receipt_row = session.get(OutboxEventRow, requested_receipt, with_for_update=True)
                if receipt_row is None or receipt_row.run_id != state.run_id:
                    raise UnitOfWorkConflict("projection outbox receipt is not bound to the run")
                if explicit_transition and receipt_row.transition_id != source_transition:
                    raise UnitOfWorkConflict("projection outbox receipt does not match the source transition")
                source_transition = receipt_row.transition_id
            elif explicit_transition:
                receipt_row = session.scalars(
                    select(OutboxEventRow)
                    .where(
                        OutboxEventRow.run_id == state.run_id,
                        OutboxEventRow.transition_id == source_transition,
                    )
                    .with_for_update()
                ).first()
                if receipt_row is None:
                    raise UnitOfWorkConflict("projection source transition has no outbox receipt")
                requested_receipt = receipt_row.outbox_id
                projection_digest = self._projection_digest(
                    state,
                    source_transition_id=source_transition,
                    outbox_receipt_id=requested_receipt,
                )
            # Resolving a receipt can also resolve the authoritative transition
            # id.  Recompute after either branch so the durable digest always
            # covers the exact source identity written to ProjectionHeadRow.
            projection_digest = self._projection_digest(
                state,
                source_transition_id=source_transition,
                outbox_receipt_id=requested_receipt,
            )
            head = session.get(ProjectionHeadRow, state.run_id, with_for_update=True)
            if head is not None:
                if state.state_version < head.source_state_version or source_fence < head.source_fence:
                    # A delayed worker may still call this method after its
                    # lease was reclaimed.  It is safe to acknowledge an old
                    # read-model message, but never to merge it.
                    session.rollback()
                    return
                if state.state_version == head.source_state_version:
                    if (
                        source_transition == head.source_transition_id
                        and requested_receipt == head.outbox_receipt_id
                        and projection_digest == head.projection_digest
                    ):
                        if source_fence > head.source_fence:
                            head.source_fence = source_fence
                            head.updated_at = now
                            session.commit()
                        else:
                            session.rollback()
                        return
                    # Keep the established identity wording in the exception so
                    # callers can distinguish a source-version conflict from a
                    # normal row identity conflict without silently overwriting
                    # either route or plan data.
                    raise UnitOfWorkConflict(
                        "projection state version conflict: scenario route identity/"
                        "plan revision/source revision differs"
                    )
            if state.active_route is not None:
                route = state.active_route
                if route.run_id != state.run_id:
                    raise UnitOfWorkConflict("active route belongs to a different run")
                route_json = canonical_json(route.model_dump(mode="json"))
                existing_route = session.get(ScenarioRouteRow, route.route_id)
                if existing_route is not None:
                    if existing_route.run_id != state.run_id or existing_route.route_json != route_json:
                        raise UnitOfWorkConflict("scenario route identity was reused with different content")
                else:
                    session.add(
                        ScenarioRouteRow(
                            route_id=route.route_id,
                            run_id=state.run_id,
                            scenario=route.scenario.value,
                            strategy=(route.selected_strategy.value if route.selected_strategy is not None else None),
                            route_digest=route.route_digest,
                            route_json=route_json,
                            created_at=route.created_at,
                        )
                    )
            for revision in state.plan_revisions:
                if revision.run_id != state.run_id:
                    raise UnitOfWorkConflict("plan revision belongs to a different run")
                revision_json = canonical_json(revision.model_dump(mode="json"))
                existing_by_id = session.get(PlanRevisionRow, revision.revision_id)
                existing_by_number = session.scalar(
                    select(PlanRevisionRow).where(
                        PlanRevisionRow.run_id == state.run_id,
                        PlanRevisionRow.revision == revision.revision,
                    )
                )
                if existing_by_id is not None and existing_by_number is not None:
                    if existing_by_id.revision_id != existing_by_number.revision_id:
                        raise UnitOfWorkConflict("plan revision identity conflicts with its run revision")
                existing_revision = existing_by_id or existing_by_number
                if existing_revision is not None:
                    if (
                        existing_revision.revision_id != revision.revision_id
                        or existing_revision.run_id != state.run_id
                        or existing_revision.revision_json != revision_json
                    ):
                        raise UnitOfWorkConflict("plan revision was reused with different content")
                else:
                    session.add(
                        PlanRevisionRow(
                            revision_id=revision.revision_id,
                            run_id=state.run_id,
                            revision=revision.revision,
                            trigger=revision.trigger.value,
                            parent_plan_digest=revision.parent_plan_digest,
                            plan_digest=revision.plan_digest,
                            revision_json=revision_json,
                            created_at=revision.created_at,
                        )
                    )
            if state.repository_index is not None:
                reference = state.repository_index
                session.merge(
                    RepositoryIndexRow(
                        index_id=reference.index_id,
                        run_id=state.run_id,
                        artifact_id=reference.artifact_id,
                        digest=reference.digest,
                        summary_json=canonical_json(reference.model_dump(mode="json")),
                        created_at=reference.created_at,
                    )
                )
            for item in state.context_items:
                session.merge(
                    ContextItemRow(
                        context_id=item.context_id,
                        run_id=state.run_id,
                        kind=item.kind,
                        source=item.source,
                        authority_level=int(item.authority_level),
                        taint=item.taint.value,
                        sensitivity=item.sensitivity.value,
                        content_hash=item.content_hash,
                        token_estimate=item.token_estimate,
                        artifact_id=item.artifact_id,
                        metadata_json=canonical_json(redact(item.metadata)),
                        created_at=item.freshness,
                    )
                )
            for pack in state.context_packs:
                session.merge(
                    ContextPackRow(
                        pack_id=pack.pack_id,
                        run_id=state.run_id,
                        step_id=pack.step_id,
                        agent_profile=pack.agent_profile,
                        pack_digest=pack.pack_digest,
                        manifest_json=canonical_json(pack.model_dump(mode="json")),
                        token_budget=pack.token_budget.total_tokens,
                        token_used=pack.token_budget.used_tokens,
                        created_at=pack.created_at,
                    )
                )
            for contract in state.outcome_contracts:
                session.merge(
                    OutcomeContractRow(
                        contract_id=contract.contract_id,
                        run_id=state.run_id,
                        step_id=contract.step_id,
                        contract_digest=contract.contract_digest,
                        contract_json=canonical_json(contract.model_dump(mode="json")),
                        created_at=now,
                    )
                )
            for claim in state.claims:
                session.merge(
                    ClaimRow(
                        claim_id=claim.claim_id,
                        run_id=state.run_id,
                        step_id=claim.producer,
                        claim_type=claim.claim_type,
                        subject_ref=claim.subject_ref,
                        status=claim.status.value,
                        severity=claim.severity,
                        confidence=claim.confidence,
                        producer=claim.producer,
                        claim_json=canonical_json(claim.model_dump(mode="json")),
                        created_at=now,
                        updated_at=now,
                    )
                )
            for link in state.evidence_links:
                session.merge(
                    EvidenceLinkRow(
                        link_id=link.link_id,
                        run_id=state.run_id,
                        claim_id=link.claim_id,
                        evidence_id=link.evidence_id,
                        relation=link.relation.value,
                        weight=link.weight,
                        verifier_status=link.verifier_status.value,
                        grader_id=link.grader_id,
                        created_at=now,
                    )
                )
            if state.notebook is not None:
                session.merge(
                    RunNotebookRow(
                        run_id=state.run_id,
                        notebook_digest=state.notebook.notebook_digest,
                        notebook_json=canonical_json(state.notebook.model_dump(mode="json")),
                        state_version=state.state_version,
                        source_fence=source_fence,
                        source_transition_id=source_transition,
                        updated_at=now,
                    )
                )
            if head is None:
                session.add(
                    ProjectionHeadRow(
                        run_id=state.run_id,
                        source_state_version=state.state_version,
                        source_fence=source_fence,
                        source_transition_id=source_transition,
                        outbox_receipt_id=requested_receipt,
                        projection_digest=projection_digest,
                        updated_at=now,
                    )
                )
            else:
                head.source_state_version = state.state_version
                head.source_fence = source_fence
                head.source_transition_id = source_transition
                head.outbox_receipt_id = requested_receipt
                head.projection_digest = projection_digest
                head.updated_at = now
            session.commit()
            self._projection_digests[state.run_id] = projection_digest
            if durable_source:
                self._legacy_projection_runs.discard(state.run_id)
            else:
                self._legacy_projection_runs.add(state.run_id)
            self._projection_digests.move_to_end(state.run_id)
            if len(self._projection_digests) > 1_024:
                self._projection_digests.popitem(last=False)

    @staticmethod
    def _projection_digest(
        state: AgentState,
        *,
        source_transition_id: str | None = None,
        outbox_receipt_id: str | None = None,
    ) -> str:
        """Hash only rebuildable query projections, not the full run cursor.

        Most graph checkpoints change status, budget, or routing metadata while
        leaving every normalized read model untouched.  Skipping those repeated
        merge/query loops removes substantial database traffic without changing
        the authoritative RunRow or LangGraph checkpoint semantics.
        """

        projected = state.model_dump(
            mode="json",
            include={
                "state_version",
                "active_route",
                "plan_revisions",
                "repository_index",
                "context_items",
                "context_packs",
                "outcome_contracts",
                "claims",
                "evidence_links",
                "notebook",
            },
        )
        # Bind the source revision and receipt identity, but not volatile
        # heartbeat/fence timestamps.  A fence advance for the same semantic
        # snapshot is a separate CAS field on ProjectionHeadRow.
        projected["source_transition_id"] = source_transition_id or ControlPlaneUnitOfWork._projection_transition_id(
            state
        )
        projected["outbox_receipt_id"] = outbox_receipt_id
        return hashlib.sha256(canonical_json(projected).encode()).hexdigest()

    @staticmethod
    def _projection_transition_id(state: AgentState) -> str:
        """Return a stable source identity for projection CAS.

        The authoritative coordinator transition id is carried by the outbox
        receipt in production.  AgentState does not expose that id directly,
        so the fallback identity binds the run, state version and transition
        counter until a receipt-backed projector supplies the stronger value.
        """

        return f"state:{state.run_id}:{state.state_version}:{state.transition_counter}"

    def record_tool_input_envelope(self, envelope: ToolInputEnvelope) -> bool:
        """Persist one immutable tool-input binding and its mutation chain.

        The operation is idempotent for a semantically identical transition.
        Reusing an invocation id with any different input, scope, approval, or
        mutation provenance is rejected before the tool can be claimed.
        """

        envelope_json = canonical_json(envelope.model_dump(mode="json"))
        with self._lock, Session(self.engine) as session:
            self._database_lock(session, envelope.run_id)
            if session.get(RunRow, envelope.run_id) is None:
                raise UnitOfWorkConflict("input envelope references an unknown run")
            existing = session.get(InputEnvelopeRow, envelope.invocation_id)
            if existing is not None:
                try:
                    stored = ToolInputEnvelope.model_validate_json(existing.envelope_json)
                except ValueError as exc:
                    raise UnitOfWorkConflict("stored input envelope is invalid") from exc
                if _input_envelope_binding(stored) != _input_envelope_binding(envelope):
                    raise UnitOfWorkConflict("invocation input envelope binding conflict")
                mutation_rows = session.scalars(
                    select(InputMutationRow).where(
                        InputMutationRow.invocation_id == envelope.invocation_id,
                    )
                ).all()
                stored_mutations = {item.mutation_id: item for item in stored.mutation_chain}
                if len(mutation_rows) != len(stored_mutations):
                    raise UnitOfWorkConflict("stored input mutation chain is incomplete")
                for row in mutation_rows:
                    mutation = stored_mutations.get(row.mutation_id)
                    if mutation is None:
                        raise UnitOfWorkConflict("stored input mutation chain is inconsistent")
                    mutation_json = canonical_json(mutation.model_dump(mode="json"))
                    if (
                        row.run_id != stored.run_id
                        or row.stage != mutation.stage
                        or row.field_path != mutation.field_path
                        or row.parent_digest != mutation.previous_digest
                        or row.new_digest != mutation.new_digest
                        or row.mutation_json != mutation_json
                    ):
                        raise UnitOfWorkConflict("stored input mutation chain is inconsistent")
                return False

            mutation_ids: set[str] = set()
            for mutation in envelope.mutation_chain:
                identity_reused = mutation.mutation_id in mutation_ids
                identity_reused = identity_reused or session.get(InputMutationRow, mutation.mutation_id) is not None
                if identity_reused:
                    raise UnitOfWorkConflict("input mutation identity was reused")
                mutation_ids.add(mutation.mutation_id)
            session.add(
                InputEnvelopeRow(
                    invocation_id=envelope.invocation_id,
                    run_id=envelope.run_id,
                    step_id=envelope.step_id,
                    raw_digest=envelope.raw_digest,
                    observable_digest=envelope.observable_digest,
                    execution_digest=envelope.execution_digest,
                    envelope_json=envelope_json,
                    created_at=envelope.created_at,
                )
            )
            for mutation in envelope.mutation_chain:
                session.add(
                    InputMutationRow(
                        mutation_id=mutation.mutation_id,
                        invocation_id=envelope.invocation_id,
                        run_id=envelope.run_id,
                        stage=mutation.stage,
                        field_path=mutation.field_path,
                        parent_digest=mutation.previous_digest,
                        new_digest=mutation.new_digest,
                        mutation_json=canonical_json(mutation.model_dump(mode="json")),
                        created_at=mutation.created_at,
                    )
                )
            session.commit()
            return True

    def load_tool_input_envelope(self, run_id: str, invocation_id: str) -> ToolInputEnvelope:
        """Load the observable provenance record without exposing execution arguments.

        The run binding is checked explicitly so an invocation id cannot be used as
        a cross-run oracle by the operator API.
        """

        with Session(self.engine) as session:
            row = session.get(InputEnvelopeRow, invocation_id)
            if row is None or row.run_id != run_id:
                raise KeyError(invocation_id)
            try:
                envelope = ToolInputEnvelope.model_validate_json(row.envelope_json)
            except ValueError as exc:
                raise UnitOfWorkConflict("stored input envelope is invalid") from exc
            if envelope.run_id != run_id or envelope.invocation_id != invocation_id:
                raise UnitOfWorkConflict("stored input envelope binding is inconsistent")
            return envelope

    def create_retention_hold(self, hold: RetentionHold) -> bool:
        """Atomically persist a bounded hold and its auditable outbox event."""

        if hold.expires_at.tzinfo is None or hold.expires_at <= datetime.now(UTC):
            raise UnitOfWorkConflict("retention hold expiry must be in the future")
        with self._lock, Session(self.engine) as session:
            self._database_lock(session, hold.run_id)
            if session.get(RunRow, hold.run_id) is None:
                raise KeyError(hold.run_id)
            existing = session.get(RetentionHoldRow, hold.hold_id)
            if existing is not None:
                stored = RetentionHold(
                    hold_id=existing.hold_id,
                    run_id=existing.run_id,
                    reason=existing.reason,
                    expires_at=(
                        existing.expires_at
                        if existing.expires_at.tzinfo is not None
                        else existing.expires_at.replace(tzinfo=UTC)
                    ),
                    actor=existing.actor,
                    created_at=(
                        existing.created_at
                        if existing.created_at.tzinfo is not None
                        else existing.created_at.replace(tzinfo=UTC)
                    ),
                )
                if stored.model_dump(exclude={"created_at"}) != hold.model_dump(exclude={"created_at"}):
                    raise UnitOfWorkConflict("retention hold identity was reused")
                return False
            session.add(
                RetentionHoldRow(
                    hold_id=hold.hold_id,
                    run_id=hold.run_id,
                    actor=hold.actor,
                    reason=hold.reason,
                    expires_at=hold.expires_at,
                    created_at=hold.created_at,
                )
            )
            session.add(
                OutboxEventRow(
                    outbox_id=str(uuid4()),
                    run_id=hold.run_id,
                    transition_id=f"retention:{hold.hold_id}:created",
                    event_type="retention.hold_created",
                    actor=hold.actor,
                    payload_json=canonical_json(
                        {
                            "hold_id": hold.hold_id,
                            "expires_at": hold.expires_at.isoformat(),
                            "reason": redact(hold.reason),
                        }
                    ),
                    status="pending",
                    created_at=hold.created_at,
                )
            )
            session.commit()
            return True

    def list_retention_holds(self, run_id: str) -> list[RetentionHold]:
        with Session(self.engine) as session:
            if session.get(RunRow, run_id) is None:
                raise KeyError(run_id)
            rows = session.scalars(
                select(RetentionHoldRow)
                .where(RetentionHoldRow.run_id == run_id)
                .order_by(RetentionHoldRow.created_at, RetentionHoldRow.hold_id)
            ).all()
            return [
                RetentionHold(
                    hold_id=row.hold_id,
                    run_id=row.run_id,
                    reason=row.reason,
                    expires_at=(
                        row.expires_at if row.expires_at.tzinfo is not None else row.expires_at.replace(tzinfo=UTC)
                    ),
                    actor=row.actor,
                    created_at=(
                        row.created_at if row.created_at.tzinfo is not None else row.created_at.replace(tzinfo=UTC)
                    ),
                )
                for row in rows
            ]

    def record_data_access_event(
        self,
        *,
        run_id: str,
        actor: str,
        view: DataView,
        resource_type: str,
        resource_id: str,
        purpose: str,
        decision: str,
        reason_code: str,
    ) -> str:
        """Persist an append-only, scrubbed record for an access decision.

        The v0.5 migration intentionally keeps this projection compact.  The
        decision and reason are encoded before the operator-supplied purpose so
        even a truncated value remains unambiguous and safe to review.
        """

        if decision not in {"allowed", "denied"}:
            raise ValueError("invalid data access decision")
        if (
            not actor
            or len(actor) > 100
            or any(ord(character) < 32 or ord(character) == 127 for character in actor)
            or not resource_type
            or len(resource_type) > 50
            or any(ord(character) < 32 or ord(character) == 127 for character in resource_type)
        ):
            raise ValueError("invalid data access actor or resource type")
        if (
            not resource_id
            or len(resource_id) > 100
            or any(ord(character) < 32 or ord(character) == 127 for character in resource_id)
            or not reason_code
            or len(reason_code) > 100
            or any(ord(character) < 32 or ord(character) == 127 for character in reason_code)
        ):
            raise ValueError("invalid data access resource or reason")
        safe_purpose = " ".join(scrub_text(purpose[:2000]).split()) or "unspecified"
        audit_purpose = (f"decision={decision};reason={reason_code};purpose={safe_purpose}")[:500]
        access_id = str(uuid4())
        now = datetime.now(UTC)
        with self._lock, Session(self.engine) as session:
            self._database_lock(session, run_id)
            if session.get(RunRow, run_id) is None:
                raise KeyError(run_id)
            session.add(
                DataAccessEventRow(
                    access_id=access_id,
                    run_id=run_id,
                    actor=actor,
                    view=view.value,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    purpose=audit_purpose,
                    created_at=now,
                )
            )
            session.add(
                OutboxEventRow(
                    outbox_id=str(uuid4()),
                    run_id=run_id,
                    transition_id=f"data-access:{access_id}",
                    event_type="data.access_decision",
                    actor=actor,
                    payload_json=canonical_json(
                        {
                            "access_id": access_id,
                            "decision": decision,
                            "purpose": safe_purpose,
                            "reason_code": reason_code,
                            "resource_id": resource_id,
                            "resource_type": resource_type,
                            "view": view.value,
                        }
                    ),
                    status="pending",
                    created_at=now,
                )
            )
            session.commit()
        return access_id

    def record_resume_assessment(self, assessment: ResumeAssessment) -> bool:
        payload = canonical_json(assessment.model_dump(mode="json"))
        with self._lock, Session(self.engine) as session:
            self._database_lock(session, assessment.run_id)
            if session.get(RunRow, assessment.run_id) is None:
                raise KeyError(assessment.run_id)
            existing = session.get(ResumeAssessmentRow, assessment.assessment_id)
            if existing is not None:
                try:
                    stored = ResumeAssessment.model_validate_json(existing.assessment_json)
                except ValueError as exc:
                    raise UnitOfWorkConflict("stored resume assessment is invalid") from exc
                if not _resume_assessment_projection_matches(existing, stored):
                    raise UnitOfWorkConflict("stored resume assessment projection is inconsistent")
                if stored.model_dump(exclude={"created_at"}) != assessment.model_dump(exclude={"created_at"}):
                    raise UnitOfWorkConflict("resume assessment identity was reused")
                return False
            session.add(
                ResumeAssessmentRow(
                    assessment_id=assessment.assessment_id,
                    run_id=assessment.run_id,
                    action=assessment.action.value,
                    reason_code=assessment.reason_codes[0],
                    state_version=assessment.state_version,
                    fence=assessment.fence,
                    checkpoint_state_version=assessment.checkpoint_state_version,
                    checkpoint_id=assessment.checkpoint_id,
                    control_digest=assessment.control_digest,
                    runner_resources_collected=assessment.runner_resources_collected,
                    assessment_json=payload,
                    created_at=assessment.created_at,
                )
            )
            session.add(
                OutboxEventRow(
                    outbox_id=str(uuid4()),
                    run_id=assessment.run_id,
                    transition_id=f"resume-assessment:{assessment.assessment_digest}",
                    event_type="recovery.assessed",
                    actor="system",
                    payload_json=canonical_json(
                        {
                            "action": assessment.action.value,
                            "assessment_digest": assessment.assessment_digest,
                            "reason_codes": assessment.reason_codes,
                        }
                    ),
                    status="pending",
                    created_at=assessment.created_at,
                )
            )
            session.commit()
            return True

    def load_resume_assessment(self, run_id: str, assessment_id: str) -> ResumeAssessment:
        with Session(self.engine) as session:
            row = session.get(ResumeAssessmentRow, assessment_id)
            if row is None or row.run_id != run_id:
                raise KeyError(assessment_id)
            try:
                assessment = ResumeAssessment.model_validate_json(row.assessment_json)
            except ValueError as exc:
                raise UnitOfWorkConflict("stored resume assessment is invalid") from exc
            if not _resume_assessment_projection_matches(row, assessment):
                raise UnitOfWorkConflict("stored resume assessment projection is inconsistent")
            return assessment

    def latest_resume_assessment(self, run_id: str) -> ResumeAssessment:
        with Session(self.engine) as session:
            row = session.scalars(
                select(ResumeAssessmentRow)
                .where(ResumeAssessmentRow.run_id == run_id)
                .order_by(ResumeAssessmentRow.created_at.desc(), ResumeAssessmentRow.assessment_id.desc())
                .limit(1)
            ).first()
            if row is None:
                raise KeyError(run_id)
            try:
                assessment = ResumeAssessment.model_validate_json(row.assessment_json)
            except ValueError as exc:
                raise UnitOfWorkConflict("stored resume assessment is invalid") from exc
            if not _resume_assessment_projection_matches(row, assessment):
                raise UnitOfWorkConflict("stored resume assessment projection is inconsistent")
            return assessment

    def resume_assessment_consumption(
        self,
        run_id: str,
        assessment_id: str,
        assessment_digest: str,
    ) -> str | None:
        with Session(self.engine) as session:
            row = session.get(ResumeAssessmentRow, assessment_id)
            if row is None or row.run_id != run_id:
                raise KeyError(assessment_id)
            try:
                stored = ResumeAssessment.model_validate_json(row.assessment_json)
            except ValueError as exc:
                raise UnitOfWorkConflict("stored resume assessment is invalid") from exc
            if not _resume_assessment_projection_matches(row, stored):
                raise UnitOfWorkConflict("stored resume assessment projection is inconsistent")
            if stored.assessment_digest != assessment_digest:
                raise UnitOfWorkConflict("resume assessment digest does not match")
            if (row.consumed_at is None) != (row.consumption_id is None):
                raise UnitOfWorkConflict("resume assessment consumption record is incomplete")
            return row.consumption_id

    def consume_resume_assessment(
        self,
        assessment: ResumeAssessment,
        *,
        actor: str,
        reaper_confirmed: bool = False,
    ) -> str:
        """CAS one freshly revalidated assessment into one recovery transition.

        Assessment consumption, RunRow state CAS, run-job transition and outbox
        publication share the same database transaction.  A stale checkpoint,
        fence or control summary therefore cannot wake a run, and a consumed
        assessment can never trigger a second transition.
        """

        if not actor:
            raise ValueError("recovery actor is required")
        now = datetime.now(UTC)
        with self._lock, Session(self.engine) as session:
            self._database_lock(session, assessment.run_id)
            row = session.scalars(
                select(ResumeAssessmentRow)
                .where(ResumeAssessmentRow.assessment_id == assessment.assessment_id)
                .with_for_update()
            ).first()
            if row is None or row.run_id != assessment.run_id:
                raise KeyError(assessment.assessment_id)
            try:
                stored = ResumeAssessment.model_validate_json(row.assessment_json)
            except ValueError as exc:
                raise UnitOfWorkConflict("stored resume assessment is invalid") from exc
            if not _resume_assessment_projection_matches(row, stored):
                raise UnitOfWorkConflict("stored resume assessment projection is inconsistent")
            if stored.model_dump(exclude={"created_at"}) != assessment.model_dump(exclude={"created_at"}):
                raise UnitOfWorkConflict("resume assessment is stale or does not match durable control state")
            if stored.control_digest == "0" * 64:
                raise UnitOfWorkConflict("resume assessment has no bound control summary")
            if (row.consumed_at is None) != (row.consumption_id is None):
                raise UnitOfWorkConflict("resume assessment consumption record is incomplete")
            if row.consumed_at is not None:
                if row.consumption_id is None:  # pragma: no cover - narrowed by invariant above
                    raise UnitOfWorkConflict("resume assessment consumption record is incomplete")
                return row.consumption_id

            action = stored.action
            if action == ResumeAction.REQUIRE_OPERATOR_RECOVERY:
                raise UnitOfWorkConflict("operator-recovery assessment cannot resume a run")
            is_cancel = action == ResumeAction.CANCEL_AND_REAP
            is_finalize_outbox = action == ResumeAction.FINALIZE_OUTBOX
            if action not in _RECOVERY_WAKE_ACTIONS and not is_cancel:
                raise UnitOfWorkConflict(f"resume action is not executable: {action.value}")
            if action == ResumeAction.RESUME_FROM_CHECKPOINT and (
                not stored.checkpoint_present or stored.checkpoint_state_version is None
            ):
                raise UnitOfWorkConflict("checkpoint resume action has no bound checkpoint version")
            if is_cancel and (not reaper_confirmed or not stored.runner_resources_collected):
                raise UnitOfWorkConflict("cancel-and-reap requires confirmed runner resource collection and reaping")

            run = session.get(RunRow, assessment.run_id, with_for_update=True)
            job = session.get(RunJobRow, assessment.run_id, with_for_update=True)
            if run is None or job is None:
                raise UnitOfWorkConflict("resume assessment references an incomplete run")
            if run.state_version != stored.state_version:
                raise UnitOfWorkConflict("run state changed after resume assessment")
            if job.fence != stored.fence:
                raise UnitOfWorkConflict("run fence changed after resume assessment")
            if job.status == "leased":
                raise UnitOfWorkConflict("leased run cannot be recovered concurrently")

            state = AgentState.model_validate_json(run.state_json)
            if state.state_version != stored.state_version:
                raise UnitOfWorkConflict("run snapshot version disagrees with durable version")
            candidate = state.model_copy(deep=True)
            semantic_change = is_cancel
            if is_finalize_outbox:
                # FINALIZE_OUTBOX is an operator-authorized recovery retry, not
                # a silent success.  It atomically releases failed/dead-letter
                # leases into a fresh retry generation and emits a receipt in
                # the same transaction as assessment consumption.  A later
                # projector still decides whether the event can be committed.
                outbox_rows = session.scalars(
                    select(OutboxEventRow)
                    .where(
                        OutboxEventRow.run_id == assessment.run_id,
                        OutboxEventRow.status.in_(["failed", "dead_letter", "retry_wait"]),
                        # FINALIZE_OUTBOX repairs an external/transient cause.
                        # Deterministic payload and dedupe failures require an
                        # explicit operator quarantine+skip receipt instead of
                        # reopening an immutable bad intent indefinitely.
                        or_(
                            OutboxEventRow.failure_class.is_(None),
                            ~OutboxEventRow.failure_class.in_(("payload_conflict", "payload_invalid")),
                        ),
                    )
                    .with_for_update()
                ).all()
                for outbox in outbox_rows:
                    payload_digest = (
                        outbox.payload_digest or hashlib.sha256(outbox.payload_json.encode("utf-8")).hexdigest()
                    )
                    resolution_digest = hashlib.sha256(
                        canonical_json(
                            {
                                "outbox_id": outbox.outbox_id,
                                "payload_digest": payload_digest,
                                "assessment_digest": stored.assessment_digest,
                                "actor": actor,
                            }
                        ).encode("utf-8")
                    ).hexdigest()
                    retry_transition_id = f"outbox-retry:{outbox.outbox_id}:{resolution_digest[:32]}"
                    retry_receipt = session.scalars(
                        select(OutboxEventRow).where(
                            OutboxEventRow.run_id == assessment.run_id,
                            OutboxEventRow.transition_id == retry_transition_id,
                        )
                    ).first()
                    if retry_receipt is None:
                        session.add(
                            OutboxEventRow(
                                outbox_id=str(uuid4()),
                                run_id=assessment.run_id,
                                transition_id=retry_transition_id,
                                transition_ordinal=outbox.transition_ordinal,
                                subsequence=outbox.subsequence + 1,
                                event_type="outbox.retry_authorized",
                                actor=actor,
                                payload_json=canonical_json(
                                    {
                                        "outbox_id": outbox.outbox_id,
                                        "payload_digest": payload_digest,
                                        "assessment_digest": stored.assessment_digest,
                                        "resolution_digest": resolution_digest,
                                    }
                                ),
                                status="pending",
                                created_at=now,
                            )
                        )
                    outbox.payload_digest = payload_digest
                    outbox.status = "retry_wait"
                    outbox.owner_id = None
                    outbox.lease_until = None
                    outbox.next_attempt_at = now
                    outbox.dead_lettered_at = None
                    outbox.failure_class = "operator_retry"
                    # An explicit operator retry opens a new bounded attempt
                    # generation.  It cannot inherit an exhausted automatic
                    # retry count and spin forever.
                    outbox.attempts = 0
                if job.status not in {"completed", "cancelled"}:
                    job.status = "queued"
                    job.last_error = None
            if is_cancel:
                job.fence += 1
                job.status = "cancelled"
                job.last_error = "cancelled after confirmed recovery reaper"
                candidate.cancel_requested = True
                candidate.status = RunStatus.CANCELLED
                candidate.last_error = "Run was cancelled after confirmed recovery reaping"
                session.execute(
                    update(ToolInvocationRow)
                    .where(
                        ToolInvocationRow.run_id == assessment.run_id,
                        ToolInvocationRow.status == InvocationStatus.RUNNING.value,
                    )
                    .values(
                        status=InvocationStatus.CANCELLED.value,
                        error="cancelled after confirmed recovery reaper",
                        lease_until=None,
                        updated_at=now,
                    )
                )
            elif not is_finalize_outbox:
                if job.status in {"completed", "cancelled"}:
                    raise UnitOfWorkConflict("terminal run job cannot be recovered")
                # A checkpoint-bound recovery is a queue wake, not a new graph
                # transition.  Mutating RunRow here would move business state
                # ahead of the checkpoint that is about to resume.  A
                # checkpoint-less run only needs a semantic update when it is
                # not already restartable from PENDING.
                if not stored.checkpoint_present and candidate.status != RunStatus.PENDING:
                    candidate.status = RunStatus.PENDING
                    candidate.last_error = None
                    semantic_change = True
                job.status = "queued"
                job.last_error = None
                job.next_attempt_at = now
            job.wake_requested = False
            job.owner_id = None
            job.lease_until = None
            job.updated_at = now
            if semantic_change:
                candidate.lease.owner_id = None
                candidate.lease.fence = job.fence
                candidate.lease.lease_until = None
                next_version = stored.state_version + 1
                candidate.state_version = next_version
                result = session.execute(
                    update(RunRow)
                    .where(
                        RunRow.run_id == assessment.run_id,
                        RunRow.state_version == stored.state_version,
                    )
                    .values(
                        status=candidate.status.value,
                        state_version=next_version,
                        state_json=candidate.model_dump_json(),
                        updated_at=now,
                    )
                )
                if getattr(result, "rowcount", 0) != 1:
                    raise UnitOfWorkConflict("run state compare-and-swap failed")

            consumption_id = str(uuid5(NAMESPACE_URL, f"secmind:resume-consumption:{stored.assessment_digest}"))
            row.consumption_id = consumption_id
            row.consumed_at = now
            row.consumed_by = actor
            session.add(
                OutboxEventRow(
                    outbox_id=str(uuid4()),
                    run_id=assessment.run_id,
                    transition_id=f"resume-consumption:{consumption_id}",
                    event_type="recovery.consumed",
                    actor=actor,
                    payload_json=canonical_json(
                        {
                            "action": action.value,
                            "assessment_digest": stored.assessment_digest,
                            "consumption_id": consumption_id,
                            "control_digest": stored.control_digest,
                        }
                    ),
                    status="pending",
                    created_at=now,
                )
            )
            session.commit()
            return consumption_id

    def record_hook_executions(self, event: HookEvent, results: list[HookResult]) -> None:
        """Persist signed hook decisions idempotently for independent audit."""

        with self._lock, Session(self.engine) as session:
            self._database_lock(session, event.run_id)
            for result in results:
                existing = session.scalar(
                    select(HookExecutionRow).where(
                        HookExecutionRow.hook_id == result.hook_id,
                        HookExecutionRow.event_id == result.event_id,
                    )
                )
                stable_result = result.model_copy(update={"duration_ms": 0})
                payload = canonical_json(redact(stable_result.model_dump(mode="json")))
                if existing is not None:
                    if existing.result_json != payload:
                        raise UnitOfWorkConflict("hook execution dedupe payload mismatch")
                    continue
                execution_id = str(uuid5(NAMESPACE_URL, f"secmind:hook-execution:{result.hook_id}:{result.event_id}"))
                session.add(
                    HookExecutionRow(
                        execution_id=execution_id,
                        run_id=event.run_id,
                        step_id=event.step_id,
                        hook_id=result.hook_id,
                        event_id=result.event_id,
                        status=result.decision.value,
                        input_hash=result.input_hash,
                        output_hash=result.output_hash,
                        result_json=payload,
                        created_at=event.created_at,
                    )
                )
            session.commit()

    def resolve_approval_and_wake(
        self,
        *,
        run_id: str,
        request_id: str,
        response: ApprovalResponse,
        actor: str,
        fence: int,
        grant_ttl_seconds: int = 600,
    ) -> tuple[str, bool]:
        """Resolve, grant/deny, consume, wake and emit an outbox event atomically."""

        now = datetime.now(UTC)
        serialized = stable_json(response.model_dump(mode="json"))
        with self._lock, Session(self.engine) as session:
            self._database_lock(session, run_id)
            approval = session.scalars(
                select(ApprovalRow).where(ApprovalRow.request_id == request_id).with_for_update()
            ).first()
            if approval is None:
                raise KeyError(request_id)
            if approval.run_id != run_id:
                raise ExecutionConflict("approval request belongs to a different run")
            run = session.get(RunRow, run_id)
            job = session.get(RunJobRow, run_id, with_for_update=True)
            if run is None or job is None:
                raise UnitOfWorkConflict("approval references an incomplete run")
            state = AgentState.model_validate_json(run.state_json)
            active_request = next(
                (
                    item
                    for item in [
                        *state.pending_approvals,
                        *([state.pending_approval] if state.pending_approval is not None else []),
                    ]
                    if item.request_id == request_id
                ),
                None,
            )
            if active_request is None:
                raise ExecutionConflict("approval is not the active request for this run")
            if approval.status == "consumed":
                if approval.response_json != serialized or approval.resolution_id is None:
                    raise ExecutionConflict("approval request was already resolved differently")
                return approval.resolution_id, False
            if approval.status not in {"pending", "resolved", "resolved_unconsumed"}:
                raise ExecutionConflict("approval is not resolvable")
            if approval.response_json is not None and approval.response_json != serialized:
                raise ExecutionConflict("approval request was already resolved differently")
            effective_parameters = (
                response.edited_parameters
                if response.decision == ApprovalDecision.EDIT and response.edited_parameters is not None
                else active_request.parameters
            )
            resolution_id = approval.resolution_id or response.resolution_id or str(uuid4())
            approval.status = "consumed"
            approval.decision = response.decision.value
            approval.effective_parameters_hash = parameters_hash(effective_parameters)
            approval.response_json = serialized
            approval.actor = actor
            approval.resolution_id = resolution_id
            approval.fence = max(fence, approval.fence)
            approval.resolved_at = approval.resolved_at or now
            approval.consumed_at = now

            grant_id: str | None = None
            if response.decision in {ApprovalDecision.APPROVE, ApprovalDecision.EDIT}:
                # The mutable TaskRequest is retained for request provenance only.
                # Approval grants are an execution authority, so their scope must
                # come from the run-bound sealed contract.  Failing closed here
                # also prevents a caller from widening ``state.task.target_scope``
                # between contract compilation and approval resolution.
                resolved_contract = require_resolved_task_contract(state)
                authorized_scope = list(resolved_contract.authorized_scope)
                task_constraints = list(resolved_contract.constraints)
                expires_at = now + timedelta(seconds=max(1, grant_ttl_seconds))
                grant_payload: dict[str, Any] = {
                    "run_id": run_id,
                    "actor": actor,
                    "allowed_actions": ["execute"],
                    "allowed_tools": [approval.tool_name],
                    "target_scope": authorized_scope,
                    "parameter_constraints": {
                        "parameters_hash": parameters_hash(effective_parameters),
                        "task_constraints": task_constraints,
                    },
                    "network_constraints": [],
                    "max_uses": 1,
                    "expires_at": expires_at.isoformat(),
                    "resolution_id": resolution_id,
                }
                grant_digest = hashlib.sha256(canonical_json(grant_payload).encode()).hexdigest()
                grant_id = str(uuid4())
                grant = CapabilityGrant(
                    grant_id=grant_id,
                    run_id=run_id,
                    actor=actor,
                    allowed_actions=["execute"],
                    allowed_tools=[approval.tool_name],
                    target_scope=authorized_scope,
                    parameter_constraints={
                        "parameters_hash": parameters_hash(effective_parameters),
                        "task_constraints": task_constraints,
                    },
                    max_uses=1,
                    expires_at=expires_at,
                    grant_digest=grant_digest,
                )
                session.add(
                    CapabilityGrantRow(
                        grant_id=grant_id,
                        run_id=run_id,
                        actor=actor,
                        grant_digest=grant_digest,
                        grant_json=grant.model_dump_json(),
                        max_uses=1,
                        uses=0,
                        expires_at=expires_at,
                        created_at=now,
                    )
                )

            if job.status in {"completed", "cancelled"}:
                raise UnitOfWorkConflict("terminal run cannot be woken by approval")
            job.status = "queued"
            job.owner_id = None
            job.lease_until = None
            job.next_attempt_at = now
            job.updated_at = now
            transition_id = f"approval:{request_id}:resolution:{resolution_id}"
            session.add(
                OutboxEventRow(
                    outbox_id=str(uuid4()),
                    run_id=run_id,
                    transition_id=transition_id,
                    event_type="approval.resolved",
                    actor=actor,
                    payload_json=canonical_json(
                        redact(
                            {
                                "request_id": request_id,
                                "resolution_id": resolution_id,
                                "decision": response.decision.value,
                                "grant_id": grant_id,
                            }
                        )
                    ),
                    status="pending",
                    created_at=now,
                )
            )
            session.commit()
            return resolution_id, True

    def grants_for_run(self, run_id: str, *, now: datetime | None = None) -> list[CapabilityGrant]:
        checked_at = now or datetime.now(UTC)
        with Session(self.engine) as session:
            rows = session.scalars(
                select(CapabilityGrantRow).where(
                    CapabilityGrantRow.run_id == run_id,
                    CapabilityGrantRow.revoked_at.is_(None),
                    CapabilityGrantRow.expires_at > checked_at,
                    CapabilityGrantRow.uses < CapabilityGrantRow.max_uses,
                )
            ).all()
            return [
                CapabilityGrant.model_validate_json(row.grant_json).model_copy(
                    update={"uses": row.uses, "revoked_at": row.revoked_at}
                )
                for row in rows
            ]

    def grant_bound_to_invocation(self, run_id: str, idempotency_key: str) -> CapabilityGrant | None:
        """Return the original grant only for replay of the same logical invocation."""

        with Session(self.engine) as session:
            invocation = session.scalars(
                select(ToolInvocationRow)
                .where(
                    ToolInvocationRow.run_id == run_id,
                    ToolInvocationRow.idempotency_key == idempotency_key,
                )
                .with_for_update()
            ).first()
            if invocation is None or invocation.grant_id is None:
                return None
            row = session.get(CapabilityGrantRow, invocation.grant_id)
            if row is None or row.revoked_at is not None:
                return None
            grant = CapabilityGrant.model_validate_json(row.grant_json)
            return grant.model_copy(update={"uses": 0, "revoked_at": row.revoked_at})

    def cached_tool_result(
        self,
        *,
        run_id: str,
        idempotency_key: str,
        tool_name: str,
        tool_version: str,
        parameters: dict[str, Any],
    ) -> ToolResult | None:
        with Session(self.engine) as session:
            row = session.scalars(
                select(ToolInvocationRow).where(
                    ToolInvocationRow.run_id == run_id,
                    ToolInvocationRow.idempotency_key == idempotency_key,
                )
            ).first()
            if row is None:
                return None
            if (
                row.parameters_hash != parameters_hash(parameters)
                or row.tool_name != tool_name
                or row.tool_version != tool_version
            ):
                raise ExecutionConflict("idempotency key was reused with different tool input")
            if row.status == InvocationStatus.COMPLETED.value and row.result_json:
                return ToolResult.model_validate_json(row.result_json)
            return None

    def claim_tool_invocation(
        self,
        *,
        invocation_id: str,
        run_id: str,
        step_id: str,
        tool_name: str,
        tool_version: str,
        idempotency_key: str,
        parameters: dict[str, Any],
        idempotent: bool,
        lease_seconds: int,
        owner_id: str,
        fence: int,
        grant_id: str | None,
        grant_required: bool,
    ) -> tuple[InvocationStatus, ToolResult | None, int]:
        """Claim an invocation and consume a grant in the same DB transaction."""

        now = datetime.now(UTC)
        digest = parameters_hash(parameters)
        with self._lock, Session(self.engine) as session:
            self._database_lock(session, run_id)
            job = session.get(RunJobRow, run_id, with_for_update=True)
            lease_until = None if job is None else job.lease_until
            if lease_until is not None and lease_until.tzinfo is None:
                lease_until = lease_until.replace(tzinfo=UTC)
            if (
                job is None
                or job.status != "leased"
                or job.owner_id != owner_id
                or job.fence != fence
                or lease_until is None
                or lease_until <= now
            ):
                raise UnitOfWorkConflict("run lease is absent, expired, or fenced")
            invocation = session.scalars(
                select(ToolInvocationRow)
                .where(
                    ToolInvocationRow.run_id == run_id,
                    ToolInvocationRow.idempotency_key == idempotency_key,
                )
                .with_for_update()
            ).first()
            if invocation is not None:
                if (
                    invocation.parameters_hash != digest
                    or invocation.tool_name != tool_name
                    or invocation.tool_version != tool_version
                ):
                    raise ExecutionConflict("idempotency key was reused with different tool input")
                if invocation.status == InvocationStatus.COMPLETED.value and invocation.result_json:
                    return (
                        InvocationStatus.COMPLETED,
                        ToolResult.model_validate_json(invocation.result_json),
                        invocation.attempt,
                    )
                current_lease = invocation.lease_until
                if current_lease is not None and current_lease.tzinfo is None:
                    current_lease = current_lease.replace(tzinfo=UTC)
                if (
                    invocation.status == InvocationStatus.RUNNING.value
                    and invocation.fence == fence
                    and current_lease is not None
                    and current_lease > now
                ):
                    return InvocationStatus.PENDING, None, invocation.attempt
                if not idempotent:
                    invocation.status = InvocationStatus.RECOVERY_REQUIRED.value
                    invocation.updated_at = now
                    session.commit()
                    return InvocationStatus.RECOVERY_REQUIRED, None, invocation.attempt
                if grant_required and invocation.grant_id is None:
                    raise ExecutionConflict("R2 invocation has no durable capability grant binding")
                invocation.invocation_id = invocation_id
                invocation.status = InvocationStatus.RUNNING.value
                invocation.attempt += 1
                invocation.lease_until = now + timedelta(seconds=lease_seconds)
                invocation.owner_id = owner_id
                invocation.fence = fence
                invocation.heartbeat_at = now
                invocation.updated_at = now
                session.commit()
                return InvocationStatus.RUNNING, None, invocation.attempt

            if grant_required:
                if grant_id is None:
                    raise ExecutionConflict("R2 invocation requires a capability grant")
                grant_row = session.scalars(
                    select(CapabilityGrantRow).where(CapabilityGrantRow.grant_id == grant_id).with_for_update()
                ).first()
                if grant_row is None:
                    raise ExecutionConflict("capability grant does not exist")
                expires_at = grant_row.expires_at
                if expires_at.tzinfo is None:
                    expires_at = expires_at.replace(tzinfo=UTC)
                grant = CapabilityGrant.model_validate_json(grant_row.grant_json)
                if (
                    grant_row.run_id != run_id
                    or grant_row.revoked_at is not None
                    or expires_at <= now
                    or grant_row.uses >= grant_row.max_uses
                    or tool_name not in grant.allowed_tools
                    or "execute" not in grant.allowed_actions
                    or grant.parameter_constraints.get("parameters_hash") != digest
                ):
                    raise ExecutionConflict("capability grant is expired, consumed, revoked, or out of scope")
                grant_row.uses += 1

            session.add(
                ToolInvocationRow(
                    invocation_id=invocation_id,
                    run_id=run_id,
                    step_id=step_id,
                    tool_name=tool_name,
                    tool_version=tool_version,
                    idempotency_key=idempotency_key,
                    parameters_hash=digest,
                    attempt=1,
                    status=InvocationStatus.RUNNING.value,
                    lease_until=now + timedelta(seconds=lease_seconds),
                    owner_id=owner_id,
                    fence=fence,
                    heartbeat_at=now,
                    grant_id=grant_id,
                    created_at=now,
                    updated_at=now,
                )
            )
            session.add(
                OutboxEventRow(
                    outbox_id=str(uuid4()),
                    run_id=run_id,
                    transition_id=f"tool:{idempotency_key}:started",
                    event_type="tool.started",
                    actor="tool-broker",
                    payload_json=canonical_json(
                        {
                            "tool": tool_name,
                            "version": tool_version,
                            "invocation_id": invocation_id,
                            "grant_id": grant_id,
                        }
                    ),
                    status="pending",
                    created_at=now,
                )
            )
            session.commit()
            return InvocationStatus.RUNNING, None, 1
