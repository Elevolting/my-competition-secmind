from __future__ import annotations

import hashlib
import json
import threading
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from sqlalchemy import DateTime, Integer, String, Text, UniqueConstraint, create_engine, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column
from sqlalchemy.pool import StaticPool

from secmind.schemas import (
    ApprovalDecision,
    ApprovalRequest,
    ApprovalResponse,
    InvocationStatus,
    ToolResult,
)


class ExecutionConflict(RuntimeError):
    """The requested transition conflicts with an already durable transition."""


class StaleFenceError(ExecutionConflict):
    """A former worker attempted to commit after ownership moved elsewhere."""


class ExecutionBase(DeclarativeBase):
    pass


class ToolInvocationRow(ExecutionBase):
    __tablename__ = "tool_invocations"
    __table_args__ = (UniqueConstraint("run_id", "idempotency_key"),)

    invocation_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(36), index=True)
    step_id: Mapped[str] = mapped_column(String(100))
    tool_name: Mapped[str] = mapped_column(String(100))
    tool_version: Mapped[str] = mapped_column(String(100))
    idempotency_key: Mapped[str] = mapped_column(String(200))
    parameters_hash: Mapped[str] = mapped_column(String(64))
    attempt: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(30), index=True)
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    owner_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    fence: Mapped[int] = mapped_column(Integer, default=0)
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    grant_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    result_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ApprovalRow(ExecutionBase):
    __tablename__ = "approvals"

    request_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(36), index=True)
    step_id: Mapped[str] = mapped_column(String(100))
    tool_name: Mapped[str] = mapped_column(String(100))
    parameters_hash: Mapped[str] = mapped_column(String(64))
    request_json: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(20), index=True, default="pending")
    decision: Mapped[str | None] = mapped_column(String(20), nullable=True)
    effective_parameters_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    response_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    actor: Mapped[str | None] = mapped_column(String(100), nullable=True)
    resolution_id: Mapped[str | None] = mapped_column(String(36), nullable=True, unique=True)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    fence: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


def stable_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def parameters_hash(parameters: dict[str, Any]) -> str:
    return hashlib.sha256(stable_json(parameters).encode()).hexdigest()


class ExecutionStore:
    """Durable, concurrency-safe ownership of approvals and tool side effects."""

    def __init__(
        self,
        database_url: str | None = None,
        *,
        engine: Engine | None = None,
        initialize_schema: bool = True,
    ) -> None:
        self._owns_engine = engine is None
        if engine is None:
            database_url = database_url or "sqlite+pysqlite:///:memory:"
            kwargs: dict[str, Any] = {}
            if database_url.startswith("sqlite"):
                kwargs = {
                    "connect_args": {"check_same_thread": False, "timeout": 30},
                    "poolclass": StaticPool,
                }
            engine = create_engine(database_url, future=True, **kwargs)
        self.engine = engine
        self._lock = threading.RLock()
        if initialize_schema:
            ExecutionBase.metadata.create_all(self.engine)

    def _database_lock(self, session: Session, key: str) -> None:
        if self.engine.dialect.name == "postgresql":
            session.execute(
                text("SELECT pg_advisory_xact_lock(hashtext(:lock_key))"),
                {"lock_key": f"secmind:execution:{key}"},
            )
        elif self.engine.dialect.name == "sqlite":
            # A file-backed SQLite database is used by local development and tests.
            # BEGIN IMMEDIATE serializes the read/decide/write approval transition
            # across independent ExecutionStore instances, not only this object's lock.
            session.execute(text("BEGIN IMMEDIATE"))

    def register_approval(self, request: ApprovalRequest) -> None:
        with self._lock, Session(self.engine) as session:
            self._database_lock(session, request.request_id)
            existing = session.get(ApprovalRow, request.request_id)
            serialized = request.model_dump_json()
            digest = parameters_hash(request.parameters)
            if existing is not None:
                if existing.request_json != serialized:
                    raise ExecutionConflict("approval request_id is already used by a different request")
                return
            now = datetime.now(UTC)
            session.add(
                ApprovalRow(
                    request_id=request.request_id,
                    run_id=request.run_id,
                    step_id=request.step_id,
                    tool_name=request.tool_name,
                    parameters_hash=digest,
                    request_json=serialized,
                    status="pending",
                    created_at=now,
                )
            )
            session.commit()

    def resolve_approval(
        self,
        request_id: str,
        response: ApprovalResponse,
        *,
        actor: str = "local-operator",
        run_id: str | None = None,
        fence: int = 0,
    ) -> str:
        """Resolve once. Identical retries succeed; conflicting retries fail."""
        with self._lock, Session(self.engine) as session:
            self._database_lock(session, request_id)
            row = session.scalars(
                select(ApprovalRow).where(ApprovalRow.request_id == request_id).with_for_update()
            ).first()
            if row is None:
                raise KeyError(f"Unknown approval request: {request_id}")
            if run_id is not None and row.run_id != run_id:
                raise ExecutionConflict("approval request belongs to a different run")
            response_payload = response.model_dump(mode="json")
            serialized = stable_json(response_payload)
            if row.status in {"resolved", "resolved_unconsumed", "consumed"}:
                if row.response_json == serialized:
                    if row.resolution_id is None:
                        raise ExecutionConflict("resolved approval has no resolution id")
                    return row.resolution_id
                raise ExecutionConflict("approval request was already resolved differently")
            request = ApprovalRequest.model_validate_json(row.request_json)
            effective = response.edited_parameters if response.decision == ApprovalDecision.EDIT else request.parameters
            row.status = "resolved_unconsumed"
            row.decision = response.decision.value
            row.effective_parameters_hash = parameters_hash(effective or {})
            row.response_json = serialized
            row.actor = actor
            row.resolution_id = response.resolution_id or str(uuid4())
            row.fence = fence
            row.resolved_at = datetime.now(UTC)
            session.commit()
            return row.resolution_id

    def consume_approval(
        self,
        request_id: str,
        *,
        run_id: str,
        step_id: str,
        tool_name: str,
        parameters: dict[str, Any],
        fence: int,
        resolution_id: str | None = None,
    ) -> str:
        """Consume a resolved approval exactly once for its bound run and input."""
        with self._lock, Session(self.engine) as session:
            self._database_lock(session, request_id)
            row = session.scalars(
                select(ApprovalRow).where(ApprovalRow.request_id == request_id).with_for_update()
            ).first()
            if row is None:
                raise KeyError(f"Unknown approval request: {request_id}")
            if row.run_id != run_id or row.step_id != step_id or row.tool_name != tool_name:
                raise ExecutionConflict("approval does not belong to this run step")
            if row.effective_parameters_hash != parameters_hash(parameters):
                raise ExecutionConflict("approval parameters changed after resolution")
            if row.decision not in {ApprovalDecision.APPROVE.value, ApprovalDecision.EDIT.value}:
                raise ExecutionConflict("approval decision does not authorize execution")
            if resolution_id is not None and row.resolution_id != resolution_id:
                raise ExecutionConflict("approval resolution does not match")
            if row.status == "consumed":
                raise ExecutionConflict("approval resolution was already consumed")
            if row.status not in {"resolved", "resolved_unconsumed"}:
                raise ExecutionConflict("approval has not been resolved")
            if fence < row.fence:
                raise StaleFenceError("approval fence is stale")
            row.status = "consumed"
            row.fence = fence
            row.consumed_at = datetime.now(UTC)
            session.commit()
            if row.resolution_id is None:  # pragma: no cover - assigned above
                raise ExecutionConflict("resolved approval has no resolution id")
            return row.resolution_id

    def approval_response(self, request_id: str, *, run_id: str) -> ApprovalResponse:
        with Session(self.engine) as session:
            row = session.get(ApprovalRow, request_id)
            if row is None:
                raise KeyError(f"Unknown approval request: {request_id}")
            if row.run_id != run_id:
                raise ExecutionConflict("approval request belongs to a different run")
            if row.status not in {"resolved", "resolved_unconsumed", "consumed"} or not row.response_json:
                raise ExecutionConflict("approval request has not been resolved")
            return ApprovalResponse.model_validate_json(row.response_json)

    def approval_authorizes(
        self,
        request_id: str,
        *,
        run_id: str,
        step_id: str,
        tool_name: str,
        parameters: dict[str, Any],
    ) -> bool:
        with Session(self.engine) as session:
            self._database_lock(session, request_id)
            row = session.get(ApprovalRow, request_id)
            if row is None or row.status not in {"resolved", "resolved_unconsumed", "consumed"}:
                return False
            return bool(
                row.run_id == run_id
                and row.step_id == step_id
                and row.tool_name == tool_name
                and row.decision in {ApprovalDecision.APPROVE.value, ApprovalDecision.EDIT.value}
                and row.effective_parameters_hash == parameters_hash(parameters)
            )

    def claim_invocation(
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
        owner_id: str = "local-worker",
        fence: int = 0,
    ) -> tuple[InvocationStatus, ToolResult | None]:
        now = datetime.now(UTC)
        digest = parameters_hash(parameters)
        with self._lock, Session(self.engine) as session:
            self._database_lock(session, f"{run_id}:{idempotency_key}")
            row = session.scalars(
                select(ToolInvocationRow).where(
                    ToolInvocationRow.run_id == run_id,
                    ToolInvocationRow.idempotency_key == idempotency_key,
                )
            ).first()
            if row is None:
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
                        created_at=now,
                        updated_at=now,
                    )
                )
                session.commit()
                return InvocationStatus.RUNNING, None
            if row.parameters_hash != digest or row.tool_name != tool_name or row.tool_version != tool_version:
                raise ExecutionConflict("idempotency key was reused with different tool input")
            if row.status == InvocationStatus.COMPLETED.value and row.result_json:
                return InvocationStatus.COMPLETED, ToolResult.model_validate_json(row.result_json)
            lease_until = row.lease_until
            if lease_until is not None and lease_until.tzinfo is None:
                lease_until = lease_until.replace(tzinfo=UTC)
            if row.status == InvocationStatus.RUNNING.value and lease_until and lease_until > now:
                return InvocationStatus.PENDING, None
            if not idempotent:
                row.status = InvocationStatus.RECOVERY_REQUIRED.value
                row.updated_at = now
                session.commit()
                return InvocationStatus.RECOVERY_REQUIRED, None
            row.invocation_id = invocation_id
            row.status = InvocationStatus.RUNNING.value
            row.attempt += 1
            row.lease_until = now + timedelta(seconds=lease_seconds)
            row.owner_id = owner_id
            row.fence = fence
            row.heartbeat_at = now
            row.updated_at = now
            session.commit()
            return InvocationStatus.RUNNING, None

    def complete_invocation(
        self,
        run_id: str,
        idempotency_key: str,
        result: ToolResult,
        *,
        invocation_id: str | None = None,
        attempt: int | None = None,
        fence: int | None = None,
    ) -> None:
        with self._lock, Session(self.engine) as session:
            self._database_lock(session, f"{run_id}:{idempotency_key}")
            row = session.scalars(
                select(ToolInvocationRow).where(
                    ToolInvocationRow.run_id == run_id,
                    ToolInvocationRow.idempotency_key == idempotency_key,
                )
            ).one()
            self._assert_invocation_owner(row, invocation_id=invocation_id, attempt=attempt, fence=fence)
            row.result_json = result.model_dump_json()
            row.status = InvocationStatus.COMPLETED.value
            row.lease_until = None
            row.updated_at = datetime.now(UTC)
            session.commit()

    def fail_invocation(
        self,
        run_id: str,
        idempotency_key: str,
        error: str,
        *,
        invocation_id: str | None = None,
        attempt: int | None = None,
        fence: int | None = None,
    ) -> None:
        with self._lock, Session(self.engine) as session:
            self._database_lock(session, f"{run_id}:{idempotency_key}")
            row = session.scalars(
                select(ToolInvocationRow).where(
                    ToolInvocationRow.run_id == run_id,
                    ToolInvocationRow.idempotency_key == idempotency_key,
                )
            ).one()
            self._assert_invocation_owner(row, invocation_id=invocation_id, attempt=attempt, fence=fence)
            row.status = InvocationStatus.FAILED.value
            row.error = error
            row.lease_until = None
            row.updated_at = datetime.now(UTC)
            session.commit()

    def invocation_attempt(
        self,
        run_id: str,
        idempotency_key: str,
        *,
        invocation_id: str,
        fence: int,
    ) -> int:
        with Session(self.engine) as session:
            row = session.scalars(
                select(ToolInvocationRow).where(
                    ToolInvocationRow.run_id == run_id,
                    ToolInvocationRow.idempotency_key == idempotency_key,
                )
            ).one()
            self._assert_invocation_owner(row, invocation_id=invocation_id, attempt=None, fence=fence)
            return row.attempt

    def heartbeat_invocation(
        self,
        run_id: str,
        idempotency_key: str,
        *,
        owner_id: str,
        invocation_id: str,
        attempt: int,
        fence: int,
        lease_seconds: int,
    ) -> None:
        now = datetime.now(UTC)
        with self._lock, Session(self.engine) as session:
            self._database_lock(session, f"{run_id}:{idempotency_key}")
            row = session.scalars(
                select(ToolInvocationRow).where(
                    ToolInvocationRow.run_id == run_id,
                    ToolInvocationRow.idempotency_key == idempotency_key,
                )
            ).one()
            self._assert_invocation_owner(row, invocation_id=invocation_id, attempt=attempt, fence=fence)
            if row.owner_id != owner_id:
                raise StaleFenceError("invocation owner is stale")
            now = datetime.now(UTC)
            row.heartbeat_at = now
            row.lease_until = now + timedelta(seconds=lease_seconds)
            row.updated_at = now
            session.commit()

    def active_invocation_ids(self, run_id: str) -> list[str]:
        with Session(self.engine) as session:
            return list(
                session.scalars(
                    select(ToolInvocationRow.invocation_id).where(
                        ToolInvocationRow.run_id == run_id,
                        ToolInvocationRow.status == InvocationStatus.RUNNING.value,
                    )
                ).all()
            )

    @staticmethod
    def _assert_invocation_owner(
        row: ToolInvocationRow,
        *,
        invocation_id: str | None,
        attempt: int | None,
        fence: int | None,
    ) -> None:
        if row.status != InvocationStatus.RUNNING.value:
            raise StaleFenceError("invocation is no longer running")
        if invocation_id is not None and row.invocation_id != invocation_id:
            raise StaleFenceError("invocation id is stale")
        if attempt is not None and row.attempt != attempt:
            raise StaleFenceError("invocation attempt is stale")
        if fence is not None and row.fence != fence:
            raise StaleFenceError("invocation fence is stale")

    def close(self) -> None:
        if self._owns_engine:
            self.engine.dispose()
