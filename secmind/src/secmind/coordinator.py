"""PostgreSQL-backed run coordination and durable scheduling records.

This module owns run/step leases, monotonically increasing fences, model usage,
artifact ownership, and the transactional outbox. A caller may advance a run
only while its lease and fence still match the authoritative database row.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from sqlalchemy import (
    Boolean,
    DateTime,
    Integer,
    String,
    Text,
    UniqueConstraint,
    and_,
    create_engine,
    event,
    func,
    or_,
    select,
    text,
    update,
)
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column
from sqlalchemy.pool import StaticPool

from secmind.execution import ExecutionBase, StaleFenceError, ToolInvocationRow
from secmind.ledger import Base, RunRow, canonical_json, redact
from secmind.model_policy import MODEL_CATALOG
from secmind.model_router import MODEL_ROUTER_VERSION, ModelLane, ModelTaskKind
from secmind.schemas import AgentState, InvocationStatus, RunStatus, StepStatus, ToolResult


class CoordinatorConflict(RuntimeError):
    """A durable transition lost a lease, fence, or compare-and-swap race."""


class CoordinatorBase(DeclarativeBase):
    pass


class RunJobRow(CoordinatorBase):
    __tablename__ = "run_jobs"

    run_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    status: Mapped[str] = mapped_column(String(30), index=True, default="queued")
    owner_id: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    fence: Mapped[int] = mapped_column(Integer, default=0)
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    wake_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    next_attempt_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class StepRunRow(CoordinatorBase):
    __tablename__ = "step_runs"
    __table_args__ = (UniqueConstraint("run_id", "step_id", "attempt"),)

    step_run_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(36), index=True)
    step_id: Mapped[str] = mapped_column(String(100))
    attempt: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(30), index=True)
    transition_id: Mapped[str] = mapped_column(String(200))
    fence: Mapped[int] = mapped_column(Integer)
    run_fence: Mapped[int] = mapped_column(Integer, default=0)
    plan_revision: Mapped[int] = mapped_column(Integer, default=0)
    generation: Mapped[int] = mapped_column(Integer, default=0)
    version: Mapped[int] = mapped_column(Integer, default=1)
    owner_id: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    context_pack_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    outcome_contract_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    reservation_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    dispatch_permit_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    dependency_outputs_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    result_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ModelInvocationRow(CoordinatorBase):
    __tablename__ = "model_invocations"

    model_invocation_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(36), index=True)
    step_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    provider_request_id: Mapped[str | None] = mapped_column(String(200), nullable=True)
    model_id: Mapped[str] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(String(30), index=True)
    input_tokens: Mapped[int] = mapped_column(Integer, default=0)
    output_tokens: Mapped[int] = mapped_column(Integer, default=0)
    cache_hit_input_tokens: Mapped[int] = mapped_column(Integer, default=0)
    cache_miss_input_tokens: Mapped[int] = mapped_column(Integer, default=0)
    cost_microunits: Mapped[int] = mapped_column(Integer, default=0)
    request_hash: Mapped[str] = mapped_column(String(64))
    task_kind: Mapped[str] = mapped_column(String(50), default="legacy_unknown", server_default="legacy_unknown")
    model_lane: Mapped[str] = mapped_column(String(30), default="legacy_unknown", server_default="legacy_unknown")
    router_version: Mapped[str] = mapped_column(String(100), default="legacy_unknown", server_default="legacy_unknown")
    prompt_version: Mapped[str] = mapped_column(String(256), default="legacy_unknown", server_default="legacy_unknown")
    prompt_artifact_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    prompt_selection_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    logical_call_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    parent_logical_call_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    prompt_optimizer_attempt_id: Mapped[str | None] = mapped_column(String(160), nullable=True, index=True)
    prompt_lineage_reason: Mapped[str] = mapped_column(
        String(80), default="legacy_unbound_prompt", server_default="legacy_unbound_prompt"
    )
    lineage_stage: Mapped[str] = mapped_column(String(32), default="legacy", server_default="legacy")
    response_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    request_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    attempt_ordinal: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    stage: Mapped[str] = mapped_column(String(64), default="provider", server_default="provider")
    error_type: Mapped[str | None] = mapped_column(String(80), nullable=True)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    retryable: Mapped[bool] = mapped_column(Boolean, default=False, server_default="0")
    deadline_ms: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    remaining_budget_ms: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    route: Mapped[str] = mapped_column(String(120), default="legacy_unknown", server_default="legacy_unknown")
    route_profile: Mapped[str] = mapped_column(String(64), default="legacy_unknown", server_default="legacy_unknown")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ModelGatewayFailureRow(CoordinatorBase):
    __tablename__ = "model_gateway_failures"

    failure_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(36), index=True)
    logical_call_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    error_type: Mapped[str] = mapped_column(String(80))
    stage: Mapped[str] = mapped_column(String(64))
    message: Mapped[str] = mapped_column(Text)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    retryable: Mapped[bool] = mapped_column(Boolean, default=False, server_default="0")
    request_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    route: Mapped[str] = mapped_column(String(120))
    route_profile: Mapped[str] = mapped_column(String(64))
    model_id: Mapped[str] = mapped_column(String(200), default="", server_default="")
    prompt_version: Mapped[str] = mapped_column(String(256), default="", server_default="")
    deadline_ms: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    remaining_budget_ms: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    fallback_status: Mapped[str] = mapped_column(String(32))
    attempts_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class OutboxEventRow(CoordinatorBase):
    __tablename__ = "outbox_events"
    __table_args__ = (UniqueConstraint("run_id", "transition_id"),)

    outbox_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(36), index=True)
    transition_id: Mapped[str] = mapped_column(String(200))
    transition_ordinal: Mapped[int] = mapped_column(Integer, default=0, index=True)
    subsequence: Mapped[int] = mapped_column(Integer, default=0)
    event_type: Mapped[str] = mapped_column(String(100), index=True)
    actor: Mapped[str] = mapped_column(String(100))
    payload_json: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(20), index=True, default="pending")
    owner_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    # ``payload_digest`` binds the durable outbox intent at enqueue time.  The
    # field is nullable for databases created before v0.8.4; the projector
    # backfills it for such rows before accepting a projection.
    payload_digest: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    # ``next_attempt_at`` makes a failed lease retryable without a hot loop.
    # ``None`` is deliberately accepted for legacy rows and treated as ready.
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    failure_class: Mapped[str | None] = mapped_column(String(64), nullable=True)
    dead_lettered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Operator-authorized quarantine is a terminal, auditable resolution for a
    # deterministic payload/dedupe failure.  The raw payload remains immutable
    # for forensic replay; only its digest is copied into the skip receipt.
    quarantine_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    quarantined_by: Mapped[str | None] = mapped_column(String(100), nullable=True)
    quarantined_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    skip_receipt_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    skip_receipt_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    projected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


@event.listens_for(OutboxEventRow, "before_insert")
def _bind_outbox_payload(_mapper: Any, _connection: Any, target: OutboxEventRow) -> None:
    """Populate immutable outbox metadata for every producer.

    Outbox rows are constructed in several stores.  A mapper hook keeps the
    payload binding uniform without requiring every producer to remember the
    new fields.  Existing rows remain nullable and are handled by the
    projector's legacy path.
    """

    if target.payload_digest is None:
        target.payload_digest = hashlib.sha256(target.payload_json.encode("utf-8")).hexdigest()
    if target.next_attempt_at is None:
        target.next_attempt_at = target.created_at or datetime.now(UTC)


class ArtifactObjectRow(CoordinatorBase):
    __tablename__ = "artifact_objects"

    artifact_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(36), index=True)
    invocation_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    storage_ref: Mapped[str] = mapped_column(String(300), unique=True)
    size_bytes: Mapped[int] = mapped_column(Integer)
    media_type: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ArtifactOwnerRow(CoordinatorBase):
    __tablename__ = "artifact_owners"

    run_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    artifact_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    invocation_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    producer_step_id: Mapped[str] = mapped_column(String(100))
    output_name: Mapped[str] = mapped_column(String(100))
    sha256: Mapped[str] = mapped_column(String(64))
    size_bytes: Mapped[int] = mapped_column(Integer)
    media_type: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


@dataclass(frozen=True)
class RunLease:
    run_id: str
    owner_id: str
    fence: int
    lease_until: datetime
    attempts: int


@dataclass(frozen=True)
class StepLease:
    run_id: str
    step_id: str
    attempt: int
    owner_id: str
    fence: int
    lease_until: datetime
    transition_id: str
    step_run_id: str = ""
    run_fence: int = 0
    plan_revision: int = 0
    generation: int = 0
    reservation_id: str | None = None
    dispatch_permit_id: str | None = None


@dataclass(frozen=True)
class OutboxEvent:
    outbox_id: str
    run_id: str
    transition_id: str
    event_type: str
    actor: str
    payload_json: str


def _aware(value: datetime | None) -> datetime | None:
    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=UTC)


class CoordinatorStore:
    """PostgreSQL-compatible durable queue and fenced transition control plane."""

    def __init__(
        self,
        database_url: str | None = None,
        *,
        engine: Engine | None = None,
        initialize_schema: bool = True,
    ) -> None:
        self._owns_engine = engine is None
        if engine is None:
            if database_url is None:
                raise ValueError("database_url or engine is required")
            kwargs: dict[str, Any] = {}
            if database_url.startswith("sqlite"):
                kwargs["connect_args"] = {"check_same_thread": False}
                if database_url.endswith(":memory:"):
                    kwargs["poolclass"] = StaticPool
            engine = create_engine(database_url, future=True, **kwargs)
        self.engine = engine
        self._lock = threading.RLock()
        if initialize_schema:
            # Test/development convenience only. Production passes False and verifies Alembic head.
            Base.metadata.create_all(self.engine)
            ExecutionBase.metadata.create_all(self.engine)
            CoordinatorBase.metadata.create_all(self.engine)

    def _database_lock(self, session: Session, run_id: str) -> None:
        if self.engine.dialect.name == "postgresql":
            session.execute(
                text("SELECT pg_advisory_xact_lock(hashtext(:lock_key))"),
                {"lock_key": f"secmind:coordinator:{run_id}"},
            )
        elif self.engine.dialect.name == "sqlite":
            # SQLite has no row locks; acquire its single writer reservation before reading.
            session.execute(text("BEGIN IMMEDIATE"))

    def enqueue_run(self, run_id: str, *, next_attempt_at: datetime | None = None) -> None:
        now = datetime.now(UTC)
        with self._lock, Session(self.engine) as session:
            self._database_lock(session, run_id)
            row = session.get(RunJobRow, run_id)
            if row is not None:
                if row.status in {"completed", "cancelled"}:
                    raise CoordinatorConflict("terminal run job cannot be enqueued again")
                return
            session.add(
                RunJobRow(
                    run_id=run_id,
                    status="queued",
                    fence=0,
                    next_attempt_at=next_attempt_at or now,
                    attempts=0,
                    created_at=now,
                    updated_at=now,
                )
            )
            session.commit()

    def claim_jobs(
        self,
        owner_id: str,
        *,
        limit: int = 1,
        lease_seconds: int = 30,
        now: datetime | None = None,
    ) -> list[RunLease]:
        if not owner_id or limit < 1 or lease_seconds < 1:
            raise ValueError("owner_id, positive limit and positive lease_seconds are required")
        claimed_at = now or datetime.now(UTC)
        with self._lock, Session(self.engine) as session:
            self._database_lock(session, "queue")
            eligible = and_(
                RunJobRow.next_attempt_at <= claimed_at,
                or_(
                    RunJobRow.status.in_(["queued", "retry"]),
                    and_(RunJobRow.status == "leased", RunJobRow.lease_until <= claimed_at),
                ),
            )
            query = (
                select(RunJobRow).where(eligible).order_by(RunJobRow.next_attempt_at, RunJobRow.created_at).limit(limit)
            )
            if self.engine.dialect.name == "postgresql":
                query = query.with_for_update(skip_locked=True)
            rows = list(session.scalars(query).all())
            leases: list[RunLease] = []
            for row in rows:
                previous_status = row.status
                row.status = "leased"
                row.owner_id = owner_id
                row.wake_requested = False
                row.fence += 1
                # attempts is the consecutive failure/crash sequence used by
                # RunWorker's retry budget. A normal parked -> queued wake is
                # progress, so it must not consume that budget.
                row.attempts = row.attempts + 1 if previous_status in {"retry", "leased"} else 1
                row.heartbeat_at = claimed_at
                row.lease_until = claimed_at + timedelta(seconds=lease_seconds)
                row.updated_at = claimed_at
                leases.append(
                    RunLease(
                        run_id=row.run_id,
                        owner_id=owner_id,
                        fence=row.fence,
                        lease_until=row.lease_until,
                        attempts=row.attempts,
                    )
                )
            session.commit()
            return leases

    def heartbeat(
        self,
        run_id: str,
        *,
        owner_id: str,
        fence: int,
        lease_seconds: int = 30,
        now: datetime | None = None,
    ) -> RunLease:
        heartbeat_at = now or datetime.now(UTC)
        with self._lock, Session(self.engine) as session:
            self._database_lock(session, run_id)
            row = session.get(RunJobRow, run_id)
            self._require_lease(row, owner_id=owner_id, fence=fence, now=heartbeat_at)
            if row is None:  # pragma: no cover - established by _require_lease
                raise CoordinatorConflict("run lease disappeared")
            row.heartbeat_at = heartbeat_at
            row.lease_until = heartbeat_at + timedelta(seconds=lease_seconds)
            row.updated_at = heartbeat_at
            session.commit()
            lease_until = _aware(row.lease_until)
            if lease_until is None:  # pragma: no cover - established by _require_lease
                raise CoordinatorConflict("run lease has no expiry")
            return RunLease(row.run_id, owner_id, fence, lease_until, row.attempts)

    def finish_job(self, run_id: str, *, owner_id: str, fence: int, status: str = "completed") -> None:
        if status not in {"completed", "cancelled"}:
            raise ValueError("finish status must be completed or cancelled")
        now = datetime.now(UTC)
        with self._lock, Session(self.engine) as session:
            self._database_lock(session, run_id)
            row = session.get(RunJobRow, run_id)
            self._require_lease(row, owner_id=owner_id, fence=fence, now=now)
            if row is None:  # pragma: no cover - established by _require_lease
                raise CoordinatorConflict("run lease disappeared")
            row.status = status
            row.wake_requested = False
            row.lease_until = None
            row.owner_id = None
            row.last_error = None
            row.updated_at = now
            session.commit()

    def retry_job(
        self,
        run_id: str,
        *,
        owner_id: str,
        fence: int,
        delay_seconds: int,
        error: str,
    ) -> None:
        now = datetime.now(UTC)
        with self._lock, Session(self.engine) as session:
            self._database_lock(session, run_id)
            row = session.get(RunJobRow, run_id)
            self._require_lease(row, owner_id=owner_id, fence=fence, now=now)
            if row is None:  # pragma: no cover - established by _require_lease
                raise CoordinatorConflict("run lease disappeared")
            row.status = "retry"
            row.wake_requested = False
            row.owner_id = None
            row.lease_until = None
            row.next_attempt_at = now + timedelta(seconds=max(0, delay_seconds))
            row.last_error = error
            row.updated_at = now
            session.commit()

    def park_job(self, run_id: str, *, owner_id: str, fence: int, status: str = "waiting") -> None:
        if status not in {"waiting", "recovery_required"}:
            raise ValueError("park status must be waiting or recovery_required")
        now = datetime.now(UTC)
        with self._lock, Session(self.engine) as session:
            self._database_lock(session, run_id)
            row = session.get(RunJobRow, run_id)
            self._require_lease(row, owner_id=owner_id, fence=fence, now=now)
            if row is None:  # pragma: no cover - established by _require_lease
                raise CoordinatorConflict("run lease disappeared")
            if row.wake_requested:
                row.status = "queued"
                row.next_attempt_at = now
            else:
                row.status = status
            row.wake_requested = False
            row.owner_id = None
            row.lease_until = None
            row.updated_at = now
            session.commit()

    def wake_job(self, run_id: str) -> None:
        now = datetime.now(UTC)
        with self._lock, Session(self.engine) as session:
            self._database_lock(session, run_id)
            row = session.get(RunJobRow, run_id)
            if row is None:
                raise KeyError(run_id)
            if row.status in {"completed", "cancelled"}:
                raise CoordinatorConflict("terminal run job cannot be woken")
            row.status = "queued"
            row.owner_id = None
            row.lease_until = None
            row.next_attempt_at = now
            row.updated_at = now
            session.commit()

    def ensure_job_awake(self, run_id: str) -> bool:
        """Idempotently make a parked/retrying job claimable without revoking a live lease."""

        now = datetime.now(UTC)
        with self._lock, Session(self.engine) as session:
            self._database_lock(session, run_id)
            row = session.get(RunJobRow, run_id)
            if row is None:
                raise KeyError(run_id)
            if row.status == "leased":
                row.wake_requested = True
                row.updated_at = now
                session.commit()
                return False
            if row.status in {"queued", "completed", "cancelled"}:
                return False
            if row.status not in {"waiting", "retry", "recovery_required"}:
                raise CoordinatorConflict(f"run job cannot be woken from {row.status}")
            row.status = "queued"
            row.wake_requested = False
            row.owner_id = None
            row.lease_until = None
            row.next_attempt_at = now
            row.updated_at = now
            session.commit()
            return True

    def cancel_job(self, run_id: str) -> None:
        now = datetime.now(UTC)
        with self._lock, Session(self.engine) as session:
            self._database_lock(session, run_id)
            row = session.get(RunJobRow, run_id)
            if row is None:
                raise KeyError(run_id)
            if row.status == "completed":
                raise CoordinatorConflict("completed run job cannot be cancelled")
            row.fence += 1
            row.status = "cancelled"
            row.wake_requested = False
            row.owner_id = None
            row.lease_until = None
            row.last_error = "cancelled by operator"
            row.updated_at = now
            run = session.get(RunRow, run_id)
            if run is not None:
                state = AgentState.model_validate_json(run.state_json)
                state.cancel_requested = True
                state.status = RunStatus.CANCELLED
                state.last_error = "Run was cancelled by the operator"
                state.lease.owner_id = None
                state.lease.fence = row.fence
                state.lease.lease_until = None
                state.state_version = run.state_version + 1
                run.status = state.status.value
                run.state_version = state.state_version
                run.state_json = state.model_dump_json()
                run.updated_at = now
            session.execute(
                update(ToolInvocationRow)
                .where(
                    ToolInvocationRow.run_id == run_id,
                    ToolInvocationRow.status == InvocationStatus.RUNNING.value,
                )
                .values(
                    status=InvocationStatus.CANCELLED.value,
                    error="cancelled by operator",
                    lease_until=None,
                    updated_at=now,
                )
            )
            transition_id = f"run:{run_id}:cancel:{row.fence}"
            if (
                session.scalars(
                    select(OutboxEventRow).where(
                        OutboxEventRow.run_id == run_id,
                        OutboxEventRow.transition_id == transition_id,
                    )
                ).first()
                is None
            ):
                session.add(
                    OutboxEventRow(
                        outbox_id=str(uuid4()),
                        run_id=run_id,
                        transition_id=transition_id,
                        event_type="run.cancelled",
                        actor="operator",
                        payload_json=canonical_json({"reason": "cancelled by operator"}),
                        status="pending",
                        created_at=now,
                    )
                )
            session.commit()

    def job_status(self, run_id: str) -> tuple[str, RunLease | None]:
        status, lease, _error = self.job_snapshot(run_id)
        return status, lease

    def job_snapshot(self, run_id: str) -> tuple[str, RunLease | None, str | None]:
        """Return the live queue projection without touching semantic run state."""

        with Session(self.engine) as session:
            row = session.get(RunJobRow, run_id)
            if row is None:
                raise KeyError(run_id)
            lease = None
            lease_until = _aware(row.lease_until)
            if row.owner_id is not None and lease_until is not None:
                lease = RunLease(row.run_id, row.owner_id, row.fence, lease_until, row.attempts)
            return row.status, lease, row.last_error

    def assert_lease(self, run_id: str, *, owner_id: str, fence: int, now: datetime | None = None) -> None:
        with Session(self.engine) as session:
            self._require_lease(
                session.get(RunJobRow, run_id),
                owner_id=owner_id,
                fence=fence,
                now=now or datetime.now(UTC),
            )

    @staticmethod
    def _require_lease(row: RunJobRow | None, *, owner_id: str, fence: int, now: datetime) -> None:
        lease_until = _aware(None if row is None else row.lease_until)
        if (
            row is None
            or row.status != "leased"
            or row.owner_id != owner_id
            or row.fence != fence
            or lease_until is None
            or lease_until <= now
        ):
            raise CoordinatorConflict("run lease is absent, expired, or fenced")

    def commit_transition(
        self,
        state: AgentState,
        *,
        expected_version: int,
        owner_id: str,
        fence: int,
        transition_id: str,
        event_type: str,
        payload: dict[str, Any],
        actor: str = "orchestrator",
    ) -> int:
        """Atomically CAS the run snapshot and enqueue its externally visible event."""
        now = datetime.now(UTC)
        safe_payload = canonical_json(redact(payload))
        with self._lock, Session(self.engine) as session:
            self._database_lock(session, state.run_id)
            self._require_lease(session.get(RunJobRow, state.run_id), owner_id=owner_id, fence=fence, now=now)
            existing = session.scalars(
                select(OutboxEventRow).where(
                    OutboxEventRow.run_id == state.run_id,
                    OutboxEventRow.transition_id == transition_id,
                )
            ).first()
            if existing is not None:
                if (
                    existing.event_type != event_type
                    or existing.actor != actor
                    or existing.payload_json != safe_payload
                ):
                    raise CoordinatorConflict("transition id was reused with different event content")
                run = session.get(RunRow, state.run_id)
                if run is None:
                    raise CoordinatorConflict("transition exists without durable run state")
                state.state_version = run.state_version
                return run.state_version

            next_version = expected_version + 1
            candidate = state.model_copy(update={"state_version": next_version})
            result = session.execute(
                update(RunRow)
                .where(RunRow.run_id == state.run_id, RunRow.state_version == expected_version)
                .values(
                    status=state.status.value,
                    state_version=next_version,
                    state_json=candidate.model_dump_json(),
                    updated_at=now,
                )
            )
            if getattr(result, "rowcount", 0) != 1:
                session.rollback()
                raise CoordinatorConflict("run state compare-and-swap failed")
            session.add(
                OutboxEventRow(
                    outbox_id=str(uuid4()),
                    run_id=state.run_id,
                    transition_id=transition_id,
                    event_type=event_type,
                    actor=actor,
                    payload_json=safe_payload,
                    status="pending",
                    created_at=now,
                )
            )
            session.commit()
            state.state_version = next_version
            return next_version

    def enqueue_outbox(
        self,
        run_id: str,
        *,
        transition_id: str,
        event_type: str,
        payload: dict[str, Any],
        actor: str = "system",
        lease_owner_id: str | None = None,
        lease_fence: int | None = None,
    ) -> str:
        if (lease_owner_id is None) != (lease_fence is None):
            raise ValueError("lease owner and fence must be supplied together")
        safe_payload = canonical_json(redact(payload))
        with self._lock, Session(self.engine) as session:
            self._database_lock(session, run_id)
            if lease_owner_id is not None and lease_fence is not None:
                self._require_lease(
                    session.get(RunJobRow, run_id, with_for_update=True),
                    owner_id=lease_owner_id,
                    fence=lease_fence,
                    now=datetime.now(UTC),
                )
            existing = session.scalars(
                select(OutboxEventRow).where(
                    OutboxEventRow.run_id == run_id,
                    OutboxEventRow.transition_id == transition_id,
                )
            ).first()
            if existing is not None:
                if (existing.event_type, existing.actor, existing.payload_json) != (event_type, actor, safe_payload):
                    raise CoordinatorConflict("transition id was reused with different event content")
                return existing.outbox_id
            outbox_id = str(uuid4())
            session.add(
                OutboxEventRow(
                    outbox_id=outbox_id,
                    run_id=run_id,
                    transition_id=transition_id,
                    event_type=event_type,
                    actor=actor,
                    payload_json=safe_payload,
                    status="pending",
                    created_at=datetime.now(UTC),
                )
            )
            session.commit()
            return outbox_id

    def record_model_attempts(self, run_id: str, attempts: list[Any]) -> None:
        now = datetime.now(UTC)
        with self._lock, Session(self.engine) as session:
            self._database_lock(session, run_id)
            anchor_ordinal = int(
                session.scalar(
                    select(func.max(OutboxEventRow.transition_ordinal)).where(OutboxEventRow.run_id == run_id)
                )
                or 0
            )
            next_subsequence = int(
                session.scalar(
                    select(func.max(OutboxEventRow.subsequence)).where(
                        OutboxEventRow.run_id == run_id,
                        OutboxEventRow.transition_ordinal == anchor_ordinal,
                    )
                )
                or 0
            )
            for attempt in sorted(attempts, key=lambda item: (item.sequence, item.provider_request_id)):
                provider_request_id = attempt.provider_request_id
                if (
                    not isinstance(provider_request_id, str)
                    or not provider_request_id
                    or len(provider_request_id) > 180
                    or any(ord(character) < 32 or ord(character) == 127 for character in provider_request_id)
                ):
                    raise CoordinatorConflict("provider request id is invalid")
                request_hash = attempt.provider_request_sha256
                if len(request_hash) != 64 or any(character not in "0123456789abcdef" for character in request_hash):
                    raise CoordinatorConflict("provider attempt request hash is not a canonical SHA-256 digest")
                request_digest = getattr(attempt, "request_digest", request_hash)
                if request_digest != request_hash:
                    raise CoordinatorConflict("provider attempt request digest does not match request hash")
                attempt_ordinal = max(1, int(getattr(attempt, "ordinal", 0) or 0))
                stage = getattr(attempt, "stage", "provider") or "provider"
                error_type = getattr(attempt, "error_type", None)
                status_code = getattr(attempt, "status_code", None)
                duration_ms = max(0, int(getattr(attempt, "duration_ms", 0) or 0))
                retryable = bool(getattr(attempt, "retryable", False))
                deadline_ms = max(0, int(getattr(attempt, "deadline_ms", 0) or 0))
                remaining_budget_ms = max(0, int(getattr(attempt, "remaining_budget_ms", 0) or 0))
                route = getattr(attempt, "route", "legacy_unknown") or "legacy_unknown"
                route_profile = getattr(attempt, "route_profile", "legacy_unknown") or "legacy_unknown"
                if status_code is not None and not 100 <= int(status_code) <= 599:
                    raise CoordinatorConflict("provider attempt status code is invalid")
                if (
                    not isinstance(stage, str)
                    or not stage
                    or len(stage) > 64
                    or (error_type is not None and (not isinstance(error_type, str) or len(error_type) > 80))
                    or not isinstance(route, str)
                    or not route
                    or len(route) > 120
                    or not isinstance(route_profile, str)
                    or not route_profile
                    or len(route_profile) > 64
                    or any(
                        ord(character) < 32 or ord(character) == 127
                        for value in (stage, error_type or "", route, route_profile)
                        for character in value
                    )
                ):
                    raise CoordinatorConflict("provider attempt diagnostic metadata is invalid")
                allowed_task_kinds = {item.value for item in ModelTaskKind} | {"embedding"}
                allowed_lanes = {item.value for item in ModelLane} | {"embedding"}
                if (
                    not isinstance(attempt.task_kind, str)
                    or not attempt.task_kind
                    or len(attempt.task_kind) > 50
                    or not isinstance(attempt.lane, str)
                    or not attempt.lane
                    or len(attempt.lane) > 30
                    or not isinstance(attempt.router_version, str)
                    or not attempt.router_version
                    or len(attempt.router_version) > 100
                    or any(
                        ord(character) < 32 or ord(character) == 127
                        for value in (attempt.task_kind, attempt.lane, attempt.router_version)
                        for character in value
                    )
                ):
                    raise CoordinatorConflict("provider attempt route identity is incomplete")
                if attempt.task_kind not in allowed_task_kinds or attempt.lane not in allowed_lanes:
                    raise CoordinatorConflict("provider attempt route identity is not reviewed")
                if attempt.router_version != MODEL_ROUTER_VERSION:
                    raise CoordinatorConflict("provider attempt router version is not reviewed")
                if attempt.task_kind == "embedding":
                    if attempt.lane != "embedding":
                        raise CoordinatorConflict("embedding attempt has an invalid route lane")
                elif attempt.lane == "embedding":
                    raise CoordinatorConflict("chat attempt cannot use the embedding route lane")
                reasoning_tasks = {
                    ModelTaskKind.PLANNING.value,
                    ModelTaskKind.PRIMARY_REVIEW.value,
                    ModelTaskKind.REASONING.value,
                    ModelTaskKind.VERIFICATION.value,
                }
                lightweight_tasks = {
                    ModelTaskKind.CRITIC_REVIEW.value,
                    ModelTaskKind.PROMPT_OPTIMIZATION.value,
                    ModelTaskKind.CLASSIFICATION.value,
                    ModelTaskKind.SUMMARIZATION.value,
                    ModelTaskKind.EXTRACTION.value,
                }
                if attempt.task_kind in reasoning_tasks and attempt.lane != ModelLane.REASONING.value:
                    raise CoordinatorConflict("reasoning task has an invalid route lane")
                if attempt.task_kind in lightweight_tasks and attempt.lane != ModelLane.LIGHTWEIGHT.value:
                    raise CoordinatorConflict("lightweight task has an invalid route lane")
                model = MODEL_CATALOG.get(attempt.model_id)
                expected_capability = "embedding" if attempt.task_kind == "embedding" else "chat"
                if model is None or expected_capability not in model.capabilities:
                    raise CoordinatorConflict("provider attempt model is not reviewed for its endpoint")
                if (
                    not isinstance(attempt.prompt_version, str)
                    or not attempt.prompt_version
                    or attempt.prompt_version == "legacy_unknown"
                    or len(attempt.prompt_version) > 256
                    or any(ord(character) < 32 or ord(character) == 127 for character in attempt.prompt_version)
                ):
                    raise CoordinatorConflict("provider attempt prompt version is invalid")
                prompt_artifact_id = getattr(attempt, "prompt_artifact_id", None)
                prompt_selection_digest = getattr(attempt, "prompt_selection_digest", None)
                logical_call_id = getattr(attempt, "logical_call_id", None)
                if logical_call_id is None or logical_call_id == "":
                    logical_call_id = f"legacy:{run_id}:{provider_request_id}"
                parent_logical_call_id = getattr(attempt, "parent_logical_call_id", None) or logical_call_id
                prompt_optimizer_attempt_id = getattr(attempt, "prompt_optimizer_attempt_id", None)
                prompt_lineage_reason = getattr(attempt, "prompt_lineage_reason", None) or (
                    "legacy_embedding" if attempt.task_kind == "embedding" else "legacy_unbound_prompt"
                )
                if attempt.task_kind == "embedding" and prompt_lineage_reason == "legacy_unbound_prompt":
                    prompt_lineage_reason = "legacy_embedding"
                lineage_stage = getattr(attempt, "lineage_stage", None) or "legacy"
                if prompt_selection_digest is None or prompt_selection_digest == "":
                    prompt_selection_digest = hashlib.sha256(
                        canonical_json(
                            {
                                "lineage": "legacy_unbound_prompt",
                                "run_id": run_id,
                                "prompt_version": attempt.prompt_version,
                                "task_kind": attempt.task_kind,
                            }
                        ).encode("utf-8")
                    ).hexdigest()
                for name, value, max_length in (
                    ("prompt artifact id", prompt_artifact_id, 64),
                    ("prompt selection digest", prompt_selection_digest, 64),
                ):
                    if value is not None and (
                        not isinstance(value, str)
                        or len(value) != max_length
                        or any(character not in "0123456789abcdef" for character in value)
                    ):
                        raise CoordinatorConflict(f"provider attempt {name} is not a canonical SHA-256 digest")
                for name, value, max_length in (
                    ("logical call id", logical_call_id, 128),
                    ("parent logical call id", parent_logical_call_id, 128),
                    ("prompt optimizer attempt id", prompt_optimizer_attempt_id, 160),
                    ("prompt lineage reason", prompt_lineage_reason, 80),
                    ("lineage stage", lineage_stage, 32),
                ):
                    if value is not None and (
                        not isinstance(value, str)
                        or not value
                        or len(value) > max_length
                        or any(ord(character) < 32 or ord(character) == 127 for character in value)
                    ):
                        raise CoordinatorConflict(f"provider attempt {name} is invalid")
                if not prompt_lineage_reason[0].islower() or any(
                    character not in "abcdefghijklmnopqrstuvwxyz0123456789._:-" for character in prompt_lineage_reason
                ):
                    raise CoordinatorConflict("provider attempt prompt lineage reason is not typed")
                for name, value in (
                    ("logical call id", logical_call_id),
                    ("parent logical call id", parent_logical_call_id),
                    ("prompt optimizer attempt id", prompt_optimizer_attempt_id),
                ):
                    if value is not None and (
                        not value[0].isalnum()
                        or any(
                            character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:-"
                            for character in value
                        )
                    ):
                        raise CoordinatorConflict(f"provider attempt {name} is not a safe lineage identity")
                response_hash = attempt.response_sha256
                if response_hash is not None and (
                    len(response_hash) != 64 or any(character not in "0123456789abcdef" for character in response_hash)
                ):
                    raise CoordinatorConflict("provider attempt response hash is not a canonical SHA-256 digest")
                if attempt.run_id != run_id:
                    raise CoordinatorConflict("provider attempt belongs to another run")
                cost_microunits = max(0, int(round(attempt.usage.cost_units * 1_000_000)))
                event_transition_id = f"model-attempt:{provider_request_id}"
                event_payload = canonical_json(
                    redact(
                        {
                            "provider_request_id": provider_request_id,
                            "logical_call_id": logical_call_id,
                            "model_id": attempt.model_id,
                            "endpoint": attempt.endpoint,
                            "attempt_sequence": attempt.sequence,
                            "attempt_ordinal": attempt_ordinal,
                            "stage": stage,
                            "duration_ms": attempt.duration_ms,
                            "status_code": attempt.status_code,
                            "succeeded": attempt.succeeded,
                            "retryable": attempt.retryable,
                            "deadline_ms": deadline_ms,
                            "remaining_budget_ms": remaining_budget_ms,
                            "error_type": attempt.error_type,
                            "request_hash": request_hash,
                            "request_digest": request_digest,
                            "task_kind": attempt.task_kind,
                            "lane": attempt.lane,
                            "route": route,
                            "route_profile": route_profile,
                            "router_version": attempt.router_version,
                            "prompt_version": attempt.prompt_version,
                            "prompt_artifact_id": prompt_artifact_id,
                            "prompt_selection_digest": prompt_selection_digest,
                            "parent_logical_call_id": parent_logical_call_id,
                            "prompt_optimizer_attempt_id": prompt_optimizer_attempt_id,
                            "prompt_lineage_reason": prompt_lineage_reason,
                            "lineage_stage": lineage_stage,
                            "response_hash": response_hash,
                            "usage": attempt.usage.model_dump(mode="json"),
                            "provider_reported_usage": attempt.provider_reported_usage.model_dump(mode="json"),
                            "unknown_usage": attempt.unknown_usage,
                        }
                    )
                )
                existing = session.scalars(
                    select(ModelInvocationRow).where(ModelInvocationRow.provider_request_id == provider_request_id)
                ).first()
                if existing is not None:
                    if (
                        existing.run_id,
                        existing.request_hash,
                        existing.task_kind,
                        existing.model_lane,
                        existing.router_version,
                        existing.prompt_version,
                        existing.prompt_artifact_id,
                        existing.prompt_selection_digest,
                        existing.logical_call_id,
                        existing.parent_logical_call_id,
                        existing.prompt_optimizer_attempt_id,
                        existing.prompt_lineage_reason,
                        existing.lineage_stage,
                        existing.model_id,
                        existing.status,
                        existing.input_tokens,
                        existing.output_tokens,
                        existing.cache_hit_input_tokens,
                        existing.cache_miss_input_tokens,
                        existing.cost_microunits,
                        existing.response_hash,
                        existing.request_digest,
                        existing.attempt_ordinal,
                        existing.stage,
                        existing.error_type,
                        existing.status_code,
                        existing.duration_ms,
                        existing.retryable,
                        existing.deadline_ms,
                        existing.remaining_budget_ms,
                        existing.route,
                        existing.route_profile,
                    ) != (
                        run_id,
                        request_hash,
                        attempt.task_kind,
                        attempt.lane,
                        attempt.router_version,
                        attempt.prompt_version,
                        prompt_artifact_id,
                        prompt_selection_digest,
                        logical_call_id,
                        parent_logical_call_id,
                        prompt_optimizer_attempt_id,
                        prompt_lineage_reason,
                        lineage_stage,
                        attempt.model_id,
                        "completed" if attempt.succeeded else "failed",
                        attempt.usage.input_tokens,
                        attempt.usage.output_tokens,
                        attempt.usage.cache_hit_input_tokens,
                        attempt.usage.cache_miss_input_tokens,
                        cost_microunits,
                        response_hash,
                        request_digest,
                        attempt_ordinal,
                        stage,
                        error_type,
                        status_code,
                        duration_ms,
                        retryable,
                        deadline_ms,
                        remaining_budget_ms,
                        route,
                        route_profile,
                    ):
                        raise CoordinatorConflict("provider request id was reused with different audit metadata")
                else:
                    session.add(
                        ModelInvocationRow(
                            model_invocation_id=str(uuid4()),
                            run_id=run_id,
                            provider_request_id=provider_request_id,
                            model_id=attempt.model_id,
                            status="completed" if attempt.succeeded else "failed",
                            input_tokens=attempt.usage.input_tokens,
                            output_tokens=attempt.usage.output_tokens,
                            cache_hit_input_tokens=attempt.usage.cache_hit_input_tokens,
                            cache_miss_input_tokens=attempt.usage.cache_miss_input_tokens,
                            # ``ModelUsage.cost_units`` is the provider-independent
                            # budget currency. Persist it at micro-unit precision.
                            cost_microunits=cost_microunits,
                            request_hash=request_hash,
                            task_kind=attempt.task_kind,
                            model_lane=attempt.lane,
                            router_version=attempt.router_version,
                            prompt_version=attempt.prompt_version,
                            prompt_artifact_id=prompt_artifact_id,
                            prompt_selection_digest=prompt_selection_digest,
                            logical_call_id=logical_call_id,
                            parent_logical_call_id=parent_logical_call_id,
                            prompt_optimizer_attempt_id=prompt_optimizer_attempt_id,
                            prompt_lineage_reason=prompt_lineage_reason,
                            lineage_stage=lineage_stage,
                            response_hash=response_hash,
                            request_digest=request_digest,
                            attempt_ordinal=attempt_ordinal,
                            stage=stage,
                            error_type=error_type,
                            status_code=status_code,
                            duration_ms=duration_ms,
                            retryable=retryable,
                            deadline_ms=deadline_ms,
                            remaining_budget_ms=remaining_budget_ms,
                            route=route,
                            route_profile=route_profile,
                            created_at=now,
                            updated_at=now,
                        )
                    )
                existing_event = session.scalars(
                    select(OutboxEventRow).where(
                        OutboxEventRow.run_id == run_id,
                        OutboxEventRow.transition_id == event_transition_id,
                    )
                ).first()
                if existing_event is not None:
                    # Older immutable events predate provenance. Preserve their
                    # identity on replay instead of conflicting after upgrade.
                    previous_payload = json.loads(existing_event.payload_json)
                    comparison_payload = json.loads(event_payload)
                    for provenance_field in ("provider_reported_usage", "unknown_usage"):
                        if provenance_field not in previous_payload:
                            comparison_payload.pop(provenance_field, None)
                    if (
                        existing_event.event_type,
                        existing_event.actor,
                        existing_event.payload_json,
                    ) != ("model.attempt_recorded", "model_gateway", canonical_json(comparison_payload)):
                        raise CoordinatorConflict("model attempt audit event conflicts with durable metadata")
                else:
                    next_subsequence += 1
                    session.add(
                        OutboxEventRow(
                            outbox_id=str(uuid4()),
                            run_id=run_id,
                            transition_id=event_transition_id,
                            transition_ordinal=anchor_ordinal,
                            subsequence=next_subsequence,
                            event_type="model.attempt_recorded",
                            actor="model_gateway",
                            payload_json=event_payload,
                            status="pending",
                            created_at=now,
                        )
                    )
            session.commit()

    def record_model_failure(self, run_id: str, failure: Any) -> None:
        """Persist one sanitized gateway failure envelope idempotently."""

        if hasattr(failure, "model_dump"):
            payload = failure.model_dump(mode="json")
        elif isinstance(failure, dict):
            payload = dict(failure)
        else:
            raise CoordinatorConflict("model gateway failure has no serializable contract")
        failure_id = payload.get("failure_id")
        if (
            not isinstance(failure_id, str)
            or len(failure_id) != 64
            or any(character not in "0123456789abcdef" for character in failure_id)
        ):
            raise CoordinatorConflict("model gateway failure id is not a canonical SHA-256 digest")
        safe_payload = redact(payload)
        attempts_json = canonical_json(safe_payload.get("attempts", []))
        event_payload = canonical_json({"failure": safe_payload})
        now = datetime.now(UTC)
        with self._lock, Session(self.engine) as session:
            self._database_lock(session, run_id)
            existing = session.get(ModelGatewayFailureRow, failure_id)
            row_values = {
                "run_id": run_id,
                "logical_call_id": safe_payload.get("logical_call_id"),
                "error_type": safe_payload.get("error_type", "gateway"),
                "stage": safe_payload.get("stage", "gateway"),
                "message": safe_payload.get("message", "Model gateway failed"),
                "status_code": safe_payload.get("status_code"),
                "retryable": bool(safe_payload.get("retryable", False)),
                "request_digest": safe_payload.get("request_digest"),
                "route": safe_payload.get("route", "general:lightweight"),
                "route_profile": safe_payload.get("route_profile", "primary-strong"),
                "model_id": safe_payload.get("model_id", ""),
                "prompt_version": safe_payload.get("prompt_version", ""),
                "deadline_ms": max(0, int(safe_payload.get("deadline_ms", 0) or 0)),
                "remaining_budget_ms": max(0, int(safe_payload.get("remaining_budget_ms", 0) or 0)),
                "fallback_status": safe_payload.get("fallback_status", "not_attempted"),
                "attempts_json": attempts_json,
            }
            if existing is not None:
                existing_values = {
                    "run_id": existing.run_id,
                    "logical_call_id": existing.logical_call_id,
                    "error_type": existing.error_type,
                    "stage": existing.stage,
                    "message": existing.message,
                    "status_code": existing.status_code,
                    "retryable": existing.retryable,
                    "request_digest": existing.request_digest,
                    "route": existing.route,
                    "route_profile": existing.route_profile,
                    "model_id": existing.model_id,
                    "prompt_version": existing.prompt_version,
                    "deadline_ms": existing.deadline_ms,
                    "remaining_budget_ms": existing.remaining_budget_ms,
                    "fallback_status": existing.fallback_status,
                    "attempts_json": existing.attempts_json,
                }
                if existing_values != row_values:
                    raise CoordinatorConflict("model gateway failure id was reused with different metadata")
            else:
                session.add(
                    ModelGatewayFailureRow(
                        failure_id=failure_id,
                        **row_values,
                        created_at=now,
                        updated_at=now,
                    )
                )
            transition_id = f"model-gateway-failure:{failure_id}"
            existing_event = session.scalars(
                select(OutboxEventRow).where(
                    OutboxEventRow.run_id == run_id,
                    OutboxEventRow.transition_id == transition_id,
                )
            ).first()
            if existing_event is not None:
                if (
                    existing_event.event_type,
                    existing_event.actor,
                    existing_event.payload_json,
                ) != ("model.gateway_failure_recorded", "model_gateway", event_payload):
                    raise CoordinatorConflict("model gateway failure event conflicts with durable metadata")
            else:
                anchor_ordinal = int(
                    session.scalar(
                        select(func.max(OutboxEventRow.transition_ordinal)).where(OutboxEventRow.run_id == run_id)
                    )
                    or 0
                )
                next_subsequence = int(
                    session.scalar(
                        select(func.max(OutboxEventRow.subsequence)).where(
                            OutboxEventRow.run_id == run_id,
                            OutboxEventRow.transition_ordinal == anchor_ordinal,
                        )
                    )
                    or 0
                )
                session.add(
                    OutboxEventRow(
                        outbox_id=str(uuid4()),
                        run_id=run_id,
                        transition_id=transition_id,
                        transition_ordinal=anchor_ordinal,
                        subsequence=next_subsequence + 1,
                        event_type="model.gateway_failure_recorded",
                        actor="model_gateway",
                        payload_json=event_payload,
                        status="pending",
                        created_at=now,
                    )
                )
            session.commit()

    def complete_tool_invocation(
        self,
        *,
        run_id: str,
        idempotency_key: str,
        invocation_id: str,
        attempt: int,
        owner_id: str,
        fence: int,
        result: ToolResult,
        transition_id: str,
        event_type: str,
        payload: dict[str, Any],
    ) -> None:
        self._finish_tool_invocation(
            run_id=run_id,
            idempotency_key=idempotency_key,
            invocation_id=invocation_id,
            attempt=attempt,
            owner_id=owner_id,
            fence=fence,
            result=result,
            error=None,
            transition_id=transition_id,
            event_type=event_type,
            payload=payload,
        )

    def claim_step(
        self,
        *,
        run_id: str,
        step_id: str,
        owner_id: str,
        run_fence: int,
        transition_id: str,
        context_pack_id: str | None = None,
        outcome_contract_id: str | None = None,
        plan_revision: int = 0,
        generation: int = 0,
        reservation_id: str | None = None,
        dispatch_permit_id: str | None = None,
        idempotent: bool = True,
        lease_seconds: int = 30,
        now: datetime | None = None,
    ) -> StepLease:
        """Claim one step under a valid run lease and issue an independent fence."""

        claimed_at = now or datetime.now(UTC)
        with self._lock, Session(self.engine) as session:
            self._database_lock(session, run_id)
            self._require_lease(session.get(RunJobRow, run_id), owner_id=owner_id, fence=run_fence, now=claimed_at)
            row = session.scalars(
                select(StepRunRow)
                .where(StepRunRow.run_id == run_id, StepRunRow.step_id == step_id)
                .order_by(StepRunRow.attempt.desc())
                .limit(1)
            ).first()
            if row is not None:
                lease_until = _aware(row.lease_until)
                if row.status == StepStatus.SUCCEEDED.value:
                    raise CoordinatorConflict("completed step cannot be claimed")
                if row.status == StepStatus.RUNNING.value and row.run_fence != run_fence and not idempotent:
                    raise CoordinatorConflict("stale non-idempotent step requires operator recovery")
                if (
                    row.status == StepStatus.RUNNING.value
                    and row.run_fence == run_fence
                    and lease_until
                    and lease_until > claimed_at
                ):
                    if (
                        row.transition_id == transition_id
                        and row.owner_id == owner_id
                        and row.run_fence == run_fence
                        and row.plan_revision == plan_revision
                        and row.generation == generation
                    ):
                        return StepLease(
                            run_id=run_id,
                            step_id=step_id,
                            attempt=row.attempt,
                            owner_id=owner_id,
                            fence=row.fence,
                            lease_until=lease_until,
                            transition_id=transition_id,
                            step_run_id=row.step_run_id,
                            run_fence=run_fence,
                            plan_revision=plan_revision,
                            generation=generation,
                            reservation_id=row.reservation_id,
                            dispatch_permit_id=row.dispatch_permit_id,
                        )
                    raise CoordinatorConflict("step is already leased")
                attempt = row.attempt + 1
                step_fence = row.fence + 1
                row.status = StepStatus.FAILED.value
                row.lease_until = None
                row.updated_at = claimed_at
            else:
                attempt = 1
                step_fence = 1
            lease_until = claimed_at + timedelta(seconds=lease_seconds)
            step_run_id = str(uuid4())
            claimed = StepRunRow(
                step_run_id=step_run_id,
                run_id=run_id,
                step_id=step_id,
                attempt=attempt,
                status=StepStatus.RUNNING.value,
                transition_id=transition_id,
                fence=step_fence,
                run_fence=run_fence,
                plan_revision=plan_revision,
                generation=generation,
                version=1,
                owner_id=owner_id,
                lease_until=lease_until,
                heartbeat_at=claimed_at,
                context_pack_id=context_pack_id,
                outcome_contract_id=outcome_contract_id,
                reservation_id=reservation_id,
                dispatch_permit_id=dispatch_permit_id,
                created_at=claimed_at,
                updated_at=claimed_at,
            )
            session.add(claimed)
            session.add(
                OutboxEventRow(
                    outbox_id=str(uuid4()),
                    run_id=run_id,
                    transition_id=f"{transition_id}:claimed:{step_fence}",
                    event_type="step.claimed",
                    actor="coordinator",
                    payload_json=canonical_json(
                        {"step_id": step_id, "attempt": attempt, "fence": step_fence, "owner_id": owner_id}
                    ),
                    status="pending",
                    created_at=claimed_at,
                )
            )
            session.commit()
            return StepLease(
                run_id=run_id,
                step_id=step_id,
                attempt=attempt,
                owner_id=owner_id,
                fence=step_fence,
                lease_until=lease_until,
                transition_id=transition_id,
                step_run_id=step_run_id,
                run_fence=run_fence,
                plan_revision=plan_revision,
                generation=generation,
                reservation_id=reservation_id,
                dispatch_permit_id=dispatch_permit_id,
            )

    def heartbeat_step(
        self,
        lease: StepLease,
        *,
        lease_seconds: int = 30,
        now: datetime | None = None,
    ) -> StepLease:
        heartbeat_at = now or datetime.now(UTC)
        with self._lock, Session(self.engine) as session:
            self._database_lock(session, lease.run_id)
            row = session.scalars(
                select(StepRunRow).where(
                    StepRunRow.run_id == lease.run_id,
                    StepRunRow.step_id == lease.step_id,
                    StepRunRow.attempt == lease.attempt,
                )
            ).one()
            if lease.run_fence:
                self._require_lease(
                    session.get(RunJobRow, lease.run_id),
                    owner_id=lease.owner_id,
                    fence=lease.run_fence,
                    now=heartbeat_at,
                )
            self._require_step_lease(row, lease, heartbeat_at)
            row.heartbeat_at = heartbeat_at
            row.lease_until = heartbeat_at + timedelta(seconds=lease_seconds)
            row.updated_at = heartbeat_at
            session.commit()
            return StepLease(
                **{
                    **lease.__dict__,
                    "lease_until": row.lease_until,
                }
            )

    def complete_step(
        self,
        lease: StepLease,
        *,
        status: StepStatus,
        result: dict[str, Any],
        dependency_outputs: dict[str, Any],
    ) -> None:
        if status not in {StepStatus.SUCCEEDED, StepStatus.FAILED, StepStatus.SKIPPED, StepStatus.CANCELLED}:
            raise ValueError("step completion requires a terminal status")
        now = datetime.now(UTC)
        transition_id = f"{lease.transition_id}:completed:{lease.fence}"
        payload = {
            "step_id": lease.step_id,
            "attempt": lease.attempt,
            "fence": lease.fence,
            "status": status.value,
            "dependency_outputs": dependency_outputs,
        }
        with self._lock, Session(self.engine) as session:
            self._database_lock(session, lease.run_id)
            if lease.run_fence:
                self._require_lease(
                    session.get(RunJobRow, lease.run_id),
                    owner_id=lease.owner_id,
                    fence=lease.run_fence,
                    now=now,
                )
            row = session.scalars(
                select(StepRunRow).where(
                    StepRunRow.run_id == lease.run_id,
                    StepRunRow.step_id == lease.step_id,
                    StepRunRow.attempt == lease.attempt,
                )
            ).one()
            result_json = canonical_json(redact(result))
            dependency_json = canonical_json(dependency_outputs)
            if row.status in {
                StepStatus.SUCCEEDED.value,
                StepStatus.FAILED.value,
                StepStatus.SKIPPED.value,
                StepStatus.CANCELLED.value,
            }:
                if (
                    row.status == status.value
                    and row.result_json == result_json
                    and row.dependency_outputs_json == dependency_json
                ):
                    return
                raise CoordinatorConflict("step completion replay conflicts with its durable result")
            self._require_step_lease(row, lease, now)
            row.status = status.value
            row.result_json = result_json
            row.dependency_outputs_json = dependency_json
            row.lease_until = None
            row.updated_at = now
            session.add(
                OutboxEventRow(
                    outbox_id=str(uuid4()),
                    run_id=lease.run_id,
                    transition_id=transition_id,
                    event_type="step.completed",
                    actor="coordinator",
                    payload_json=canonical_json(payload),
                    status="pending",
                    created_at=now,
                )
            )
            session.commit()

    @staticmethod
    def _require_step_lease(row: StepRunRow, lease: StepLease, now: datetime) -> None:
        lease_until = _aware(row.lease_until)
        if (
            row.status != StepStatus.RUNNING.value
            or row.owner_id != lease.owner_id
            or row.fence != lease.fence
            or (lease.run_fence != 0 and row.run_fence != lease.run_fence)
            or row.attempt != lease.attempt
            or lease_until is None
            or lease_until <= now
        ):
            raise CoordinatorConflict("step lease is absent, expired, or fenced")

    def fail_tool_invocation(
        self,
        *,
        run_id: str,
        idempotency_key: str,
        invocation_id: str,
        attempt: int,
        owner_id: str,
        fence: int,
        error: str,
        transition_id: str,
        event_type: str,
        payload: dict[str, Any],
    ) -> None:
        self._finish_tool_invocation(
            run_id=run_id,
            idempotency_key=idempotency_key,
            invocation_id=invocation_id,
            attempt=attempt,
            owner_id=owner_id,
            fence=fence,
            result=None,
            error=error,
            transition_id=transition_id,
            event_type=event_type,
            payload=payload,
        )

    def _finish_tool_invocation(
        self,
        *,
        run_id: str,
        idempotency_key: str,
        invocation_id: str,
        attempt: int,
        owner_id: str,
        fence: int,
        result: ToolResult | None,
        error: str | None,
        transition_id: str,
        event_type: str,
        payload: dict[str, Any],
    ) -> None:
        now = datetime.now(UTC)
        safe_payload = canonical_json(redact(payload))
        with self._lock, Session(self.engine) as session:
            self._database_lock(session, run_id)
            self._require_lease(
                session.get(RunJobRow, run_id, with_for_update=True),
                owner_id=owner_id,
                fence=fence,
                now=now,
            )
            row = session.scalars(
                select(ToolInvocationRow)
                .where(
                    ToolInvocationRow.run_id == run_id,
                    ToolInvocationRow.idempotency_key == idempotency_key,
                )
                .with_for_update()
            ).one()
            if (
                row.status != InvocationStatus.RUNNING.value
                or row.invocation_id != invocation_id
                or row.attempt != attempt
                or row.fence != fence
            ):
                raise StaleFenceError("tool completion was produced by a stale invocation")
            existing = session.scalars(
                select(OutboxEventRow).where(
                    OutboxEventRow.run_id == run_id,
                    OutboxEventRow.transition_id == transition_id,
                )
            ).first()
            if existing is not None and (
                existing.event_type != event_type
                or existing.actor != "tool-broker"
                or existing.payload_json != safe_payload
            ):
                raise CoordinatorConflict("tool transition id was reused with different event content")
            row.status = InvocationStatus.COMPLETED.value if result is not None else InvocationStatus.FAILED.value
            row.result_json = result.model_dump_json() if result is not None else None
            row.error = error
            row.lease_until = None
            row.updated_at = now
            if result is not None:
                for artifact_index, artifact in enumerate(result.artifacts):
                    existing_artifact = session.get(ArtifactObjectRow, artifact.artifact_id)
                    if existing_artifact is None:
                        session.add(
                            ArtifactObjectRow(
                                artifact_id=artifact.artifact_id,
                                run_id=run_id,
                                invocation_id=invocation_id,
                                storage_ref=f"sha256/{artifact.artifact_id[:2]}/{artifact.artifact_id}",
                                size_bytes=artifact.size_bytes,
                                media_type=artifact.media_type,
                                created_at=now,
                            )
                        )
                    elif (
                        existing_artifact.size_bytes != artifact.size_bytes
                        or existing_artifact.media_type != artifact.media_type
                    ):
                        raise CoordinatorConflict("artifact id was reused with different metadata")
                    owner = session.get(ArtifactOwnerRow, {"run_id": run_id, "artifact_id": artifact.artifact_id})
                    if owner is None:
                        session.add(
                            ArtifactOwnerRow(
                                run_id=run_id,
                                artifact_id=artifact.artifact_id,
                                invocation_id=invocation_id,
                                producer_step_id=row.step_id,
                                output_name=(
                                    "cyclonedx_sbom"
                                    if row.tool_name == "syft_sbom"
                                    and artifact.media_type != "application/vnd.secmind.evidence+json"
                                    else f"artifact_{artifact_index}"
                                ),
                                sha256=artifact.sha256,
                                size_bytes=artifact.size_bytes,
                                media_type=artifact.media_type,
                                created_at=now,
                            )
                        )
            if existing is None:
                session.add(
                    OutboxEventRow(
                        outbox_id=str(uuid4()),
                        run_id=run_id,
                        transition_id=transition_id,
                        event_type=event_type,
                        actor="tool-broker",
                        payload_json=safe_payload,
                        status="pending",
                        created_at=now,
                    )
                )
            session.commit()

    def pending_outbox(self, *, limit: int = 100) -> list[OutboxEvent]:
        with Session(self.engine) as session:
            rows = session.scalars(
                select(OutboxEventRow)
                .where(OutboxEventRow.status.in_(["pending", "retry_wait", "failed"]))
                .order_by(OutboxEventRow.created_at, OutboxEventRow.outbox_id)
                .limit(limit)
            ).all()
            return [
                OutboxEvent(row.outbox_id, row.run_id, row.transition_id, row.event_type, row.actor, row.payload_json)
                for row in rows
            ]

    def mark_outbox_projected(self, outbox_id: str) -> None:
        with self._lock, Session(self.engine) as session:
            row = session.get(OutboxEventRow, outbox_id)
            if row is None:
                raise KeyError(outbox_id)
            if row.status == "projected":
                return
            if row.status == "quarantined":
                # The skip receipt, rather than a transition ledger event, is
                # the terminal projection for this row.
                return
            if row.status == "dead_letter":
                raise CoordinatorConflict("dead-letter outbox event requires an explicit resolution")
            row.status = "projected"
            row.projected_at = datetime.now(UTC)
            row.owner_id = None
            row.lease_until = None
            session.commit()

    def retry_outbox(
        self,
        outbox_id: str,
        *,
        actor: str,
        reason: str,
        expected_payload_digest: str | None = None,
        now: datetime | None = None,
    ) -> bool:
        """Authorize one durable retry of a failed/dead-letter outbox row.

        The operation is fenced by the run advisory lock and binds the retry to
        the original payload digest.  A retry receipt is itself an outbox
        event, so an operator action is auditable and replayable without
        editing rows by hand.  ``False`` means the row was already projected.
        """

        if not actor or not reason.strip():
            raise ValueError("operator and retry reason are required")
        retried_at = now or datetime.now(UTC)
        with self._lock, Session(self.engine) as session:
            row = session.get(OutboxEventRow, outbox_id)
            if row is None:
                raise KeyError(outbox_id)
            self._database_lock(session, row.run_id)
            row = session.scalars(
                select(OutboxEventRow).where(OutboxEventRow.outbox_id == outbox_id).with_for_update()
            ).first()
            if row is None:  # pragma: no cover - row was checked before locking
                raise KeyError(outbox_id)
            if row.status == "projected":
                return False
            if row.status not in {"failed", "dead_letter", "retry_wait"}:
                raise CoordinatorConflict(f"outbox row is not retryable: {row.status}")
            payload_digest = row.payload_digest or hashlib.sha256(row.payload_json.encode("utf-8")).hexdigest()
            if expected_payload_digest is not None and expected_payload_digest != payload_digest:
                raise CoordinatorConflict("outbox retry payload digest conflict")
            row.payload_digest = payload_digest
            row.status = "retry_wait"
            row.owner_id = None
            row.lease_until = None
            row.attempts = 0
            row.next_attempt_at = retried_at
            row.failure_class = "operator_retry"
            row.dead_lettered_at = None
            resolution_digest = hashlib.sha256(
                canonical_json(
                    {
                        "outbox_id": outbox_id,
                        "payload_digest": payload_digest,
                        "actor": actor,
                        "reason": reason,
                    }
                ).encode("utf-8")
            ).hexdigest()
            transition_id = f"outbox-retry:{outbox_id}:{resolution_digest[:32]}"
            existing = session.scalars(
                select(OutboxEventRow).where(
                    OutboxEventRow.run_id == row.run_id,
                    OutboxEventRow.transition_id == transition_id,
                )
            ).first()
            if existing is None:
                session.add(
                    OutboxEventRow(
                        outbox_id=str(uuid4()),
                        run_id=row.run_id,
                        transition_id=transition_id,
                        transition_ordinal=row.transition_ordinal,
                        subsequence=row.subsequence + 1,
                        event_type="outbox.retry_authorized",
                        actor=actor,
                        payload_json=canonical_json(
                            redact(
                                {
                                    "outbox_id": outbox_id,
                                    "payload_digest": payload_digest,
                                    "reason": reason,
                                    "resolution_digest": resolution_digest,
                                }
                            )
                        ),
                        status="pending",
                        created_at=retried_at,
                    )
                )
            session.commit()
            return True

    def quarantine_outbox(
        self,
        outbox_id: str,
        *,
        operator_id: str | None = None,
        operator: str | None = None,
        actor: str | None = None,
        reason: str,
        authorization: str | None = None,
        authorization_ref: str | None = None,
        now: datetime | None = None,
    ) -> Any:
        """Create an operator-authorized quarantine/skip receipt.

        The implementation lives with the projector because it must append the
        metadata-only receipt and advance the hash chain in the same transaction
        as the outbox terminal state.  This thin entry point keeps the durable
        coordinator API convenient for recovery callers while avoiding a module
        import cycle at import time.
        """

        from secmind.outbox_projector import OutboxProjector

        effective_operator = operator_id or operator or actor
        return OutboxProjector(self.engine, owner_id=f"operator:{effective_operator or 'unknown'}").quarantine_and_skip(
            outbox_id,
            operator_id=effective_operator,
            reason=reason,
            authorization=authorization or authorization_ref,
            now=now,
        )

    quarantine_and_skip = quarantine_outbox
    skip_outbox = quarantine_outbox

    def active_step_lease_ids(self, run_id: str) -> list[str]:
        """Read the durable active-work set used by the v0.6 quiet gate."""

        with Session(self.engine) as session:
            job = session.get(RunJobRow, run_id)
            if job is None:
                return []
            now = datetime.now(UTC)
            rows = session.scalars(
                select(StepRunRow)
                .where(
                    StepRunRow.run_id == run_id,
                    StepRunRow.status == StepStatus.RUNNING.value,
                    StepRunRow.run_fence == job.fence,
                    StepRunRow.lease_until.is_not(None),
                    StepRunRow.lease_until > now,
                )
                .order_by(StepRunRow.step_run_id)
            ).all()
            return [row.step_run_id for row in rows]

    def pending_outbox_ordinals(self, run_id: str) -> list[int]:
        """Return causal ordinals not durably projected to the ledger.

        ``projecting`` is only a lease, and retry/dead-letter rows are audit
        gaps.  They therefore keep the quiet-completion gate closed just like
        a pending row; readiness degradation must not be mistaken for causal
        completion.  A quarantined row is terminal only when its durable skip
        receipt is present.
        """

        with Session(self.engine) as session:
            quarantined_with_receipt = and_(
                OutboxEventRow.status == "quarantined",
                OutboxEventRow.skip_receipt_id.is_not(None),
            )
            rows = session.scalars(
                select(OutboxEventRow)
                .where(
                    OutboxEventRow.run_id == run_id,
                    and_(OutboxEventRow.status != "projected", ~quarantined_with_receipt),
                )
                .order_by(OutboxEventRow.transition_ordinal, OutboxEventRow.subsequence, OutboxEventRow.outbox_id)
            ).all()
            # Legacy/non-transition producers use ordinal zero. Preserve one
            # sentinel so any such event still prevents a false quiet state.
            return sorted(set(row.transition_ordinal for row in rows))

    def close(self) -> None:
        if self._owns_engine:
            self.engine.dispose()
