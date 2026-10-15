"""Durable investigation objects, receipts, mailboxes, and usage accounting.

The store is independent from LangGraph checkpoints. It persists the evidence
and authority records used to prove what happened even when a graph node is
replayed after a crash.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ValidationError
from sqlalchemy import (
    DateTime,
    Integer,
    String,
    Text,
    UniqueConstraint,
    create_engine,
    func,
    select,
    text,
    update,
)
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column
from sqlalchemy.pool import StaticPool

from secmind.coordinator import OutboxEventRow, RunJobRow, StepRunRow
from secmind.execution import ApprovalRow, ToolInvocationRow
from secmind.investigation.contracts import (
    AgentWorkContract,
    ArtifactSecurityLabel,
    CollaborationMessage,
    CompletionOutcome,
    CompletionReceipt,
    CompletionSnapshotV2,
    DispatchPermit,
    ExecutionIdentity,
    MessageReceipt,
    NodeResultReceipt,
    PermitStatus,
    RecoveryCommand,
    RecoveryCommandStatus,
    RequirementObligation,
    ReservationStatus,
    RunAuthority,
    SecureStateProjection,
    TransitionReceipt,
    UsageReservation,
    UsageSettlement,
    canonical_content_digest,
    seal_contract,
)
from secmind.investigation.team import (
    COORDINATOR_ROLE,
    MailboxAuthorizationError,
    MailboxError,
    TypedMailbox,
)
from secmind.ledger import Base, RunRow, assert_run_archive_writable, canonical_json, redact
from secmind.schemas import AgentState, InvocationStatus, ModelUsage, StepStatus
from secmind.task_specs import ClarificationRequestRow


class InvestigationConflict(RuntimeError):
    """A v0.6 contract failed an idempotency, authority, or CAS invariant."""


class InvestigationAccessDenied(PermissionError):
    """A classified object is not available for the requested run and purpose."""


class InvestigationBase(DeclarativeBase):
    pass


class InvestigationObjectRow(InvestigationBase):
    __tablename__ = "investigation_objects"
    __table_args__ = (UniqueConstraint("run_id", "object_type", "logical_key", "version"),)

    object_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(36), index=True)
    object_type: Mapped[str] = mapped_column(String(80), index=True)
    logical_key: Mapped[str] = mapped_column(String(200))
    version: Mapped[int] = mapped_column(Integer, default=1)
    content_digest: Mapped[str] = mapped_column(String(64))
    payload_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class RecoveryCommandRow(InvestigationBase):
    __tablename__ = "recovery_commands"
    __table_args__ = (UniqueConstraint("run_id", "command_digest"),)

    command_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(36), index=True)
    action: Mapped[str] = mapped_column(String(40))
    status: Mapped[str] = mapped_column(String(30), index=True)
    issued_fence: Mapped[int] = mapped_column(Integer)
    command_digest: Mapped[str] = mapped_column(String(64))
    payload_json: Mapped[str] = mapped_column(Text)
    owner_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    result_receipt_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class TransitionReceiptRow(InvestigationBase):
    __tablename__ = "transition_receipts"
    __table_args__ = (UniqueConstraint("run_id", "transition_ordinal"),)

    transition_id: Mapped[str] = mapped_column(String(200), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(36), index=True)
    graph_node_id: Mapped[str] = mapped_column(String(100))
    pre_state_version: Mapped[int] = mapped_column(Integer)
    pre_state_digest: Mapped[str] = mapped_column(String(64))
    post_state_version: Mapped[int] = mapped_column(Integer)
    post_state_digest: Mapped[str] = mapped_column(String(64))
    post_state_json: Mapped[str] = mapped_column(Text)
    run_fence: Mapped[int] = mapped_column(Integer)
    transition_ordinal: Mapped[int] = mapped_column(Integer)
    event_type: Mapped[str] = mapped_column(String(100))
    event_payload_digest: Mapped[str] = mapped_column(String(64))
    receipt_digest: Mapped[str] = mapped_column(String(64))
    payload_json: Mapped[str] = mapped_column(Text)
    committed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class NodeResultReceiptRow(InvestigationBase):
    __tablename__ = "node_result_receipts"
    __table_args__ = (UniqueConstraint("transition_id", "deterministic_key"),)

    node_result_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    transition_id: Mapped[str] = mapped_column(String(200), index=True)
    producer_type: Mapped[str] = mapped_column(String(80))
    deterministic_key: Mapped[str] = mapped_column(String(200))
    result_ref: Mapped[str] = mapped_column(String(300))
    result_digest: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class UsageReservationRow(InvestigationBase):
    __tablename__ = "usage_reservations"

    reservation_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(36), index=True)
    parent_reservation_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    transition_id: Mapped[str] = mapped_column(String(200))
    kind: Mapped[str] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(30), index=True)
    content_digest: Mapped[str] = mapped_column(String(64))
    payload_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class UsageSettlementRow(InvestigationBase):
    __tablename__ = "usage_settlements"

    settlement_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    reservation_id: Mapped[str] = mapped_column(String(36), unique=True, index=True)
    run_id: Mapped[str] = mapped_column(String(36), index=True)
    receipt_digest: Mapped[str] = mapped_column(String(64))
    payload_json: Mapped[str] = mapped_column(Text)
    settled_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class DispatchPermitRow(InvestigationBase):
    __tablename__ = "dispatch_permits"
    __table_args__ = (UniqueConstraint("invocation_id", "nonce"),)

    permit_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    invocation_id: Mapped[str] = mapped_column(String(36), index=True)
    run_id: Mapped[str] = mapped_column(String(36), index=True)
    step_run_id: Mapped[str] = mapped_column(String(36), index=True)
    run_fence: Mapped[int] = mapped_column(Integer)
    step_fence: Mapped[int] = mapped_column(Integer)
    input_digest: Mapped[str] = mapped_column(String(64))
    nonce: Mapped[str] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(String(20), index=True)
    payload_json: Mapped[str] = mapped_column(Text)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ExecutionIdentityRow(InvestigationBase):
    __tablename__ = "execution_identities"
    __table_args__ = (UniqueConstraint("invocation_id", "attempt"),)

    identity_digest: Mapped[str] = mapped_column(String(64), primary_key=True)
    invocation_id: Mapped[str] = mapped_column(String(36), index=True)
    attempt: Mapped[int] = mapped_column(Integer)
    run_id: Mapped[str] = mapped_column(String(36), index=True)
    step_run_id: Mapped[str] = mapped_column(String(36))
    run_fence: Mapped[int] = mapped_column(Integer)
    step_fence: Mapped[int] = mapped_column(Integer)
    payload_json: Mapped[str] = mapped_column(Text)
    settled_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ArtifactSecurityLabelRow(InvestigationBase):
    __tablename__ = "artifact_security_labels"
    __table_args__ = (UniqueConstraint("artifact_id", "owner_run_id", "classification_version"),)

    label_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    artifact_id: Mapped[str] = mapped_column(String(64), index=True)
    owner_run_id: Mapped[str] = mapped_column(String(36), index=True)
    owner_step_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    owner_invocation_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    view: Mapped[str] = mapped_column(String(30), index=True)
    data_class: Mapped[str] = mapped_column(String(30))
    allowed_purposes_json: Mapped[str] = mapped_column(Text)
    retention_policy_id: Mapped[str] = mapped_column(String(100))
    classification_version: Mapped[int] = mapped_column(Integer)
    content_sha256: Mapped[str] = mapped_column(String(64))
    payload_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class SecureStateProjectionRow(InvestigationBase):
    __tablename__ = "secure_state_projections"

    projection_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    source_ref: Mapped[str] = mapped_column(String(300), unique=True)
    run_id: Mapped[str] = mapped_column(String(36), index=True)
    source_digest: Mapped[str] = mapped_column(String(64))
    observable_digest: Mapped[str] = mapped_column(String(64))
    scrub_receipt_digest: Mapped[str] = mapped_column(String(64))
    payload_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class CompletionSnapshotRow(InvestigationBase):
    __tablename__ = "completion_snapshots"
    __table_args__ = (UniqueConstraint("run_id", "run_state_version", "quiet_epoch"),)

    snapshot_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(36), index=True)
    run_state_version: Mapped[int] = mapped_column(Integer)
    run_fence: Mapped[int] = mapped_column(Integer)
    quiet_epoch: Mapped[int] = mapped_column(Integer)
    snapshot_digest: Mapped[str] = mapped_column(String(64))
    is_quiet: Mapped[int] = mapped_column(Integer, default=0)
    payload_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class CompletionReceiptRow(InvestigationBase):
    __tablename__ = "completion_receipts"
    __table_args__ = (UniqueConstraint("run_id", "snapshot_id"),)

    receipt_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(36), index=True)
    snapshot_id: Mapped[str] = mapped_column(String(36), index=True)
    decision: Mapped[str] = mapped_column(String(40))
    receipt_digest: Mapped[str] = mapped_column(String(64))
    payload_json: Mapped[str] = mapped_column(Text)
    decided_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class InvestigationMessageRow(InvestigationBase):
    __tablename__ = "investigation_messages"
    __table_args__ = (UniqueConstraint("run_id", "dedupe_key"),)

    message_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(36), index=True)
    recipient_role: Mapped[str] = mapped_column(String(100), index=True)
    kind: Mapped[str] = mapped_column(String(60))
    dedupe_key: Mapped[str] = mapped_column(String(200))
    payload_digest: Mapped[str] = mapped_column(String(64))
    payload_json: Mapped[str] = mapped_column(Text)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class MessageReceiptRow(InvestigationBase):
    __tablename__ = "message_receipts"

    message_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    delivery_attempt: Mapped[int] = mapped_column(Integer)
    reservation_owner: Mapped[str] = mapped_column(String(100))
    delivery_fence: Mapped[int] = mapped_column(Integer)
    lease_until: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    receipt_version: Mapped[int] = mapped_column(Integer)
    transport_status: Mapped[str] = mapped_column(String(20))
    processing_status: Mapped[str] = mapped_column(String(30))
    processed_transition_id: Mapped[str | None] = mapped_column(String(200), nullable=True)
    payload_json: Mapped[str] = mapped_column(Text)
    processed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


@dataclass(frozen=True)
class TransitionCommit:
    state: AgentState
    receipt: TransitionReceipt
    replayed: bool


_USAGE_FIELDS = (
    "tool_calls",
    "provider_requests",
    "input_tokens",
    "output_tokens",
    "cost_units",
    "artifact_bytes",
)

_SETTLEMENT_TERMINAL_STATUSES = frozenset(
    {
        ReservationStatus.SETTLED.value,
        ReservationStatus.OVERSPENT.value,
        ReservationStatus.RECONCILED.value,
    }
)


def _digest_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def _aware(value: datetime | None) -> datetime | None:
    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=UTC)


class InvestigationStore:
    """Transactional investigation truth store.

    Checkpoints are deliberately not consulted here. Every mutating method
    enforces its own idempotency, fencing, or compare-and-swap condition.
    """

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
        self._typed_mailbox = TypedMailbox()
        if initialize_schema:
            InvestigationBase.metadata.create_all(engine)
            # ``run_archive_freezes`` belongs to the shared ledger metadata,
            # but InvestigationStore is also used standalone in tests and
            # local services. Ensure the shared ledger tables exist on this
            # engine before its write guards query the freeze row.
            Base.metadata.create_all(engine)

    def close(self) -> None:
        if self._owns_engine:
            self.engine.dispose()

    def _database_lock(self, session: Session, run_id: str) -> None:
        if self.engine.dialect.name == "postgresql":
            # Share the Coordinator lock namespace. Completion snapshots can
            # then recheck outbox quiescence in the same transaction without a
            # concurrent control-plane transition inserting a new event after
            # the check.
            session.execute(
                text("SELECT pg_advisory_xact_lock(hashtext(:key))"),
                {"key": f"secmind:coordinator:{run_id}"},
            )
        elif self.engine.dialect.name == "sqlite":
            session.execute(text("BEGIN IMMEDIATE"))

    @staticmethod
    def _require_authority(session: Session, authority: RunAuthority, *, now: datetime) -> RunJobRow:
        row = session.get(RunJobRow, authority.run_id)
        lease_until = _aware(None if row is None else row.lease_until)
        if (
            row is None
            or row.status != "leased"
            or row.owner_id != authority.owner_id
            or row.fence != authority.run_fence
            or lease_until is None
            or lease_until <= now
        ):
            raise InvestigationConflict("current database lease does not match RunAuthority")
        return row

    def issue_authority(self, run_id: str, *, owner_id: str, run_fence: int) -> RunAuthority:
        now = datetime.now(UTC)
        with self._lock, Session(self.engine) as session:
            self._database_lock(session, run_id)
            assert_run_archive_writable(session, run_id)
            job = session.get(RunJobRow, run_id)
            run = session.get(RunRow, run_id)
            lease_until = _aware(None if job is None else job.lease_until)
            if (
                job is None
                or run is None
                or job.status != "leased"
                or job.owner_id != owner_id
                or job.fence != run_fence
                or lease_until is None
                or lease_until <= now
            ):
                raise InvestigationConflict("cannot issue authority without a current durable lease")
            return seal_contract(
                RunAuthority,
                digest_field="authority_digest",
                run_id=run_id,
                owner_id=owner_id,
                run_fence=run_fence,
                lease_until=lease_until,
                claimed_state_version=run.state_version,
                claim_transition_id=f"run:{run_id}:claim:{run_fence}",
                issued_at=now,
            )

    @staticmethod
    def _put_object_in_session(
        session: Session,
        contract: BaseModel,
        *,
        run_id: str,
        object_type: str,
        object_id: str,
        logical_key: str,
        version: int,
        content_digest: str | None,
    ) -> str:
        payload_json = contract.model_dump_json()
        digest = content_digest or canonical_content_digest(contract)
        existing = session.get(InvestigationObjectRow, object_id)
        if existing is not None:
            if existing.content_digest != digest:
                raise InvestigationConflict("investigation object id was reused with different content")
            return object_id
        same_key = session.scalars(
            select(InvestigationObjectRow).where(
                InvestigationObjectRow.run_id == run_id,
                InvestigationObjectRow.object_type == object_type,
                InvestigationObjectRow.logical_key == logical_key,
                InvestigationObjectRow.version == version,
            )
        ).first()
        if same_key is not None:
            if same_key.content_digest != digest:
                raise InvestigationConflict("logical object version was reused with different content")
            return same_key.object_id
        session.add(
            InvestigationObjectRow(
                object_id=object_id,
                run_id=run_id,
                object_type=object_type,
                logical_key=logical_key,
                version=version,
                content_digest=digest,
                payload_json=payload_json,
                created_at=datetime.now(UTC),
            )
        )
        return object_id

    def put_object(
        self,
        contract: BaseModel,
        *,
        run_id: str,
        object_type: str,
        object_id: str,
        logical_key: str,
        version: int = 1,
        content_digest: str | None = None,
    ) -> str:
        with self._lock, Session(self.engine) as session:
            self._database_lock(session, run_id)
            assert_run_archive_writable(session, run_id)
            result = self._put_object_in_session(
                session,
                contract,
                run_id=run_id,
                object_type=object_type,
                object_id=object_id,
                logical_key=logical_key,
                version=version,
                content_digest=content_digest,
            )
            session.commit()
            return result

    def put_object_fenced(
        self,
        contract: BaseModel,
        *,
        authority: RunAuthority,
        run_id: str,
        object_type: str,
        object_id: str,
        logical_key: str,
        version: int = 1,
        content_digest: str | None = None,
    ) -> str:
        """Commit an append-only object only for the current run owner.

        Long model calls can outlive a worker lease.  This variant closes the
        stale-owner window for v0.7 audit receipts by checking the run fence in
        the same transaction that stores the immutable object.
        """

        if run_id != authority.run_id:
            raise InvestigationConflict("object and authority belong to different runs")
        with self._lock, Session(self.engine) as session:
            self._database_lock(session, run_id)
            assert_run_archive_writable(session, run_id)
            self._require_authority(session, authority, now=datetime.now(UTC))
            result = self._put_object_in_session(
                session,
                contract,
                run_id=run_id,
                object_type=object_type,
                object_id=object_id,
                logical_key=logical_key,
                version=version,
                content_digest=content_digest,
            )
            session.commit()
            return result

    def list_objects(self, run_id: str, object_type: str) -> list[dict[str, Any]]:
        with Session(self.engine) as session:
            rows = session.scalars(
                select(InvestigationObjectRow)
                .where(
                    InvestigationObjectRow.run_id == run_id,
                    InvestigationObjectRow.object_type == object_type,
                )
                .order_by(InvestigationObjectRow.version, InvestigationObjectRow.created_at)
            ).all()
            return [json.loads(row.payload_json) for row in rows]

    def authorize_work_contract(
        self,
        contract_id: str,
        *,
        run_id: str,
        step_id: str,
        run_fence: int,
        step_fence: int,
        tool_name: str,
        content_digest: str,
    ) -> AgentWorkContract:
        with Session(self.engine) as session:
            row = session.get(InvestigationObjectRow, contract_id)
            if row is None or row.run_id != run_id or row.object_type != "agent_work_contract":
                raise InvestigationAccessDenied("agent work contract is missing or belongs to another run")
            contract = AgentWorkContract.model_validate_json(row.payload_json)
            if (
                row.content_digest != content_digest
                or contract.content_digest != content_digest
                or contract.step_id != step_id
                or contract.run_fence != run_fence
                or contract.step_fence != step_fence
                or tool_name not in contract.allowed_tool_sets
            ):
                raise InvestigationAccessDenied("agent work contract binding does not authorize this invocation")
            return contract

    def commit_transition(
        self,
        state: AgentState,
        *,
        authority: RunAuthority,
        transition_id: str,
        graph_node_id: str,
        event_type: str,
        event_payload: dict[str, Any],
        actor: str = "orchestrator",
        node_result: NodeResultReceipt | None = None,
        checkpoint_id: str | None = None,
        checkpoint_state_version: int | None = None,
        plan_revision: int = 0,
        step_generation: int | None = None,
        completion_snapshot: CompletionSnapshotV2 | None = None,
        completion_receipt: CompletionReceipt | None = None,
        completion_obligations: tuple[RequirementObligation, ...] = (),
    ) -> TransitionCommit:
        """CAS state + causal outbox, optionally with the completion authority bundle."""

        now = datetime.now(UTC)
        safe_payload = redact(event_payload)
        payload_json = canonical_json(safe_payload)
        payload_digest = _digest_json(safe_payload)
        with self._lock, Session(self.engine) as session:
            self._database_lock(session, state.run_id)
            assert_run_archive_writable(session, state.run_id)
            if state.run_id != authority.run_id:
                raise InvestigationConflict("state and authority belong to different runs")
            self._require_authority(session, authority, now=now)
            existing = session.get(TransitionReceiptRow, transition_id)
            if existing is not None:
                if (
                    existing.run_id != state.run_id
                    or existing.graph_node_id != graph_node_id
                    or existing.event_type != event_type
                    or existing.event_payload_digest != payload_digest
                ):
                    raise InvestigationConflict("transition replay content does not match its durable receipt")
                replay_state = AgentState.model_validate_json(existing.post_state_json)
                # A semantic transition survives worker replacement.  The
                # historical receipt keeps the original fence, while the state
                # returned to the resumed graph is rebound to the currently
                # validated authority so no old owner regains write access.
                if existing.run_fence != authority.run_fence:
                    replay_state.lease.owner_id = authority.owner_id
                    replay_state.lease.fence = authority.run_fence
                    replay_state.lease.lease_until = authority.lease_until
                receipt = TransitionReceipt.model_validate_json(existing.payload_json)
                return TransitionCommit(state=replay_state, receipt=receipt, replayed=True)

            run = session.get(RunRow, state.run_id)
            if run is None or run.state_version != state.state_version:
                raise InvestigationConflict("transition pre-state version is stale")
            pre_payload = json.loads(run.state_json)
            pre_digest = _digest_json(pre_payload)

            if (completion_snapshot is None) != (completion_receipt is None):
                raise InvestigationConflict("completion snapshot and receipt must be committed together")
            if completion_snapshot is not None and completion_receipt is not None:
                if (
                    state.completion_snapshot_id != completion_snapshot.snapshot_id
                    or state.completion_receipt_id != completion_receipt.receipt_id
                    or completion_snapshot.run_id != state.run_id
                    or completion_receipt.run_id != state.run_id
                ):
                    raise InvestigationConflict("terminal state is not bound to its completion authority bundle")
                for obligation in completion_obligations:
                    self._put_object_in_session(
                        session,
                        obligation,
                        run_id=state.run_id,
                        object_type="requirement_obligation",
                        object_id=obligation.obligation_id,
                        logical_key=obligation.source_ref,
                        version=1,
                        content_digest=obligation.content_digest,
                    )
                self._stage_completion_snapshot(session, completion_snapshot, authority)
                self._stage_completion_receipt(session, completion_receipt, authority)

            post_version = run.state_version + 1
            post_state = state.model_copy(update={"state_version": post_version})
            post_json = post_state.model_dump_json()
            post_digest = _digest_json(json.loads(post_json))
            ordinal = session.scalar(
                select(func.max(TransitionReceiptRow.transition_ordinal)).where(
                    TransitionReceiptRow.run_id == state.run_id
                )
            )
            transition_ordinal = int(ordinal or 0) + 1
            receipt = seal_contract(
                TransitionReceipt,
                digest_field="receipt_digest",
                transition_id=transition_id,
                run_id=state.run_id,
                graph_node_id=graph_node_id,
                pre_state_version=run.state_version,
                pre_state_digest=pre_digest,
                post_state_version=post_version,
                post_state_digest=post_digest,
                checkpoint_id=checkpoint_id,
                checkpoint_state_version=checkpoint_state_version,
                plan_revision=plan_revision,
                step_generation=step_generation,
                run_fence=authority.run_fence,
                event_type=event_type,
                event_payload_digest=payload_digest,
                committed_at=now,
            )
            cas = session.execute(
                update(RunRow)
                .where(
                    RunRow.run_id == state.run_id,
                    RunRow.state_version == run.state_version,
                )
                .values(
                    state_version=post_version,
                    state_json=post_json,
                    status=post_state.status.value,
                    updated_at=now,
                )
            )
            if getattr(cas, "rowcount", 0) != 1:
                raise InvestigationConflict("transition state compare-and-swap failed")
            session.add(
                TransitionReceiptRow(
                    transition_id=transition_id,
                    run_id=state.run_id,
                    graph_node_id=graph_node_id,
                    pre_state_version=run.state_version,
                    pre_state_digest=pre_digest,
                    post_state_version=post_version,
                    post_state_digest=post_digest,
                    post_state_json=post_json,
                    run_fence=authority.run_fence,
                    transition_ordinal=transition_ordinal,
                    event_type=event_type,
                    event_payload_digest=payload_digest,
                    receipt_digest=receipt.receipt_digest,
                    payload_json=receipt.model_dump_json(),
                    committed_at=now,
                )
            )
            session.add(
                OutboxEventRow(
                    outbox_id=str(uuid4()),
                    run_id=state.run_id,
                    transition_id=transition_id,
                    transition_ordinal=transition_ordinal,
                    subsequence=0,
                    event_type=event_type,
                    actor=actor,
                    payload_json=payload_json,
                    status="pending",
                    created_at=now,
                )
            )
            if node_result is not None:
                if node_result.transition_id != transition_id:
                    raise InvestigationConflict("node result is bound to another transition")
                session.add(
                    NodeResultReceiptRow(
                        node_result_id=node_result.node_result_id,
                        transition_id=transition_id,
                        producer_type=node_result.producer_type,
                        deterministic_key=node_result.deterministic_key,
                        result_ref=node_result.result_ref,
                        result_digest=node_result.result_digest,
                        created_at=node_result.created_at,
                    )
                )
            session.commit()
            return TransitionCommit(state=post_state, receipt=receipt, replayed=False)

    def reserve_usage(self, reservation: UsageReservation) -> UsageReservation:
        with self._lock, Session(self.engine) as session:
            self._database_lock(session, reservation.run_id)
            assert_run_archive_writable(session, reservation.run_id)
            existing = session.get(UsageReservationRow, reservation.reservation_id)
            if existing is not None:
                if existing.content_digest != reservation.content_digest:
                    raise InvestigationConflict("reservation id was reused with different content")
                return UsageReservation.model_validate_json(existing.payload_json)
            if reservation.parent_reservation_id is not None:
                parent_row = session.get(UsageReservationRow, reservation.parent_reservation_id)
                if parent_row is None or parent_row.run_id != reservation.run_id:
                    raise InvestigationConflict("usage reservation parent is missing or belongs to another run")
                parent = UsageReservation.model_validate_json(parent_row.payload_json)
                siblings = session.scalars(
                    select(UsageReservationRow).where(
                        UsageReservationRow.parent_reservation_id == parent.reservation_id,
                        UsageReservationRow.status != ReservationStatus.RELEASED.value,
                    )
                ).all()
                settled_ids = [row.reservation_id for row in siblings if row.status in _SETTLEMENT_TERMINAL_STATUSES]
                settlement_by_reservation = {
                    row.reservation_id: row
                    for row in session.scalars(
                        select(UsageSettlementRow).where(UsageSettlementRow.reservation_id.in_(settled_ids))
                    ).all()
                }
                totals = {name: 0.0 for name in _USAGE_FIELDS}
                for row in siblings:
                    child = UsageReservation.model_validate_json(row.payload_json)
                    settled_row = settlement_by_reservation.get(child.reservation_id)
                    settled = (
                        UsageSettlement.model_validate_json(settled_row.payload_json)
                        if settled_row is not None
                        else None
                    )
                    for name in _USAGE_FIELDS:
                        actual_name = "actual_tool_calls" if name == "tool_calls" else name
                        totals[name] += float(
                            getattr(settled, actual_name) if settled is not None else getattr(child, name)
                        )
                for name in _USAGE_FIELDS:
                    if totals[name] + float(getattr(reservation, name)) > float(getattr(parent, name)):
                        raise InvestigationConflict(f"usage reservation would oversell parent {name}")
            now = datetime.now(UTC)
            session.add(
                UsageReservationRow(
                    reservation_id=reservation.reservation_id,
                    run_id=reservation.run_id,
                    parent_reservation_id=reservation.parent_reservation_id,
                    transition_id=reservation.transition_id,
                    kind=reservation.kind,
                    status=reservation.status.value,
                    content_digest=reservation.content_digest,
                    payload_json=reservation.model_dump_json(),
                    created_at=reservation.created_at,
                    updated_at=now,
                )
            )
            session.commit()
            return reservation

    def settle_usage(self, settlement: UsageSettlement) -> UsageSettlement:
        with self._lock, Session(self.engine) as session:
            self._database_lock(session, settlement.run_id)
            assert_run_archive_writable(session, settlement.run_id)
            reservation_row = session.get(UsageReservationRow, settlement.reservation_id)
            if reservation_row is None or reservation_row.run_id != settlement.run_id:
                raise InvestigationConflict("settlement has no matching reservation")
            reservation = UsageReservation.model_validate_json(reservation_row.payload_json)
            existing = session.scalars(
                select(UsageSettlementRow).where(UsageSettlementRow.reservation_id == settlement.reservation_id)
            ).first()
            if existing is not None:
                stored = UsageSettlement.model_validate_json(existing.payload_json)
                # ``settlement_id`` and ``settled_at`` identify the write attempt,
                # not the billed usage.  A LangGraph node may be replayed after the
                # first transaction committed, so compare the immutable accounting
                # facts and return the original receipt when they are identical.
                # Any change to the actual usage remains a hard conflict.
                semantic_fields = (
                    "reservation_id",
                    "run_id",
                    "tool_invocation_ids",
                    "model_invocation_ids",
                    "actual_tool_calls",
                    "provider_requests",
                    "input_tokens",
                    "output_tokens",
                    "cache_hit_input_tokens",
                    "cache_miss_input_tokens",
                    "cost_units",
                    "wall_time_ms",
                    "artifact_bytes",
                    "fallback_count",
                )
                if any(getattr(stored, name) != getattr(settlement, name) for name in semantic_fields):
                    raise InvestigationConflict("reservation was settled with conflicting usage")
                return stored
            # Wall-clock duration is diagnostic usage, not an additive budget:
            # parallel requests overlap and an HTTP client's phase timeout is
            # not an absolute run deadline.  The actual duration is preserved
            # in the immutable settlement receipt but can never reject a paid
            # response or leave its reservation active.
            additive_actuals = {
                "tool_calls": settlement.actual_tool_calls,
                "provider_requests": settlement.provider_requests,
                "input_tokens": settlement.input_tokens,
                "output_tokens": settlement.output_tokens,
                "cost_units": settlement.cost_units,
                "artifact_bytes": settlement.artifact_bytes,
            }
            overspent = any(
                float(actual) > float(getattr(reservation, name)) for name, actual in additive_actuals.items()
            )
            session.add(
                UsageSettlementRow(
                    settlement_id=settlement.settlement_id,
                    reservation_id=settlement.reservation_id,
                    run_id=settlement.run_id,
                    receipt_digest=settlement.receipt_digest,
                    payload_json=settlement.model_dump_json(),
                    settled_at=settlement.settled_at,
                )
            )
            if overspent:
                reservation_row.status = ReservationStatus.OVERSPENT.value
            elif reservation_row.status in {
                ReservationStatus.RELEASED.value,
                ReservationStatus.RECOVERY_REQUIRED.value,
            }:
                reservation_row.status = ReservationStatus.RECONCILED.value
            else:
                reservation_row.status = ReservationStatus.SETTLED.value
            reservation_row.updated_at = settlement.settled_at
            session.commit()
            return settlement

    def release_usage(self, reservation_id: str, *, run_id: str) -> None:
        with self._lock, Session(self.engine) as session:
            self._database_lock(session, run_id)
            assert_run_archive_writable(session, run_id)
            row = session.get(UsageReservationRow, reservation_id)
            if row is None or row.run_id != run_id:
                raise InvestigationConflict("usage reservation does not exist for this run")
            if row.status in _SETTLEMENT_TERMINAL_STATUSES:
                raise InvestigationConflict("settled usage cannot be released")
            row.status = ReservationStatus.RELEASED.value
            row.updated_at = datetime.now(UTC)
            session.commit()

    def unsettled_reservation_ids(self, run_id: str, *, include_run_envelope: bool = False) -> list[str]:
        """Return durable, non-terminal reservations that can still create work."""

        with Session(self.engine) as session:
            statement = select(UsageReservationRow).where(
                UsageReservationRow.run_id == run_id,
                UsageReservationRow.status == ReservationStatus.RESERVED.value,
            )
            if not include_run_envelope:
                statement = statement.where(UsageReservationRow.kind != "run")
            rows = session.scalars(statement.order_by(UsageReservationRow.reservation_id)).all()
            return [row.reservation_id for row in rows]

    def settled_provider_usage(self, run_id: str) -> ModelUsage:
        """Aggregate actual provider usage from per-request durable receipts.

        Model step envelopes also have settlements, so summing every model
        reservation would double count the same provider work.  Per-request
        reservations are identified by their root-budget parent and are the
        crash-safe accounting source when the model-attempt projection has not
        yet reached a graph checkpoint.
        """

        with Session(self.engine) as session:
            payloads = session.scalars(
                select(UsageSettlementRow.payload_json)
                .join(
                    UsageReservationRow,
                    UsageReservationRow.reservation_id == UsageSettlementRow.reservation_id,
                )
                .where(
                    UsageSettlementRow.run_id == run_id,
                    UsageReservationRow.kind == "model",
                    UsageReservationRow.parent_reservation_id.is_not(None),
                )
                .order_by(UsageSettlementRow.settled_at, UsageSettlementRow.settlement_id)
            ).all()
        usage = ModelUsage()
        for payload in payloads:
            settlement = UsageSettlement.model_validate_json(payload)
            usage.provider_requests += settlement.provider_requests
            usage.input_tokens += settlement.input_tokens
            usage.output_tokens += settlement.output_tokens
            usage.cache_hit_input_tokens += settlement.cache_hit_input_tokens
            usage.cache_miss_input_tokens += settlement.cache_miss_input_tokens
            usage.cost_units += settlement.cost_units
        return usage

    def issue_dispatch_permit(self, permit: DispatchPermit, authority: RunAuthority) -> DispatchPermit:
        now = datetime.now(UTC)
        if permit.run_id != authority.run_id or permit.run_fence != authority.run_fence:
            raise InvestigationConflict("dispatch permit is outside current run authority")
        permit_expires_at = _aware(permit.expires_at)
        if permit_expires_at is None or permit_expires_at <= now:
            raise InvestigationConflict("dispatch permit must be issued with a future expiry")
        with self._lock, Session(self.engine) as session:
            self._database_lock(session, permit.run_id)
            assert_run_archive_writable(session, permit.run_id)
            self._require_authority(session, authority, now=now)
            step = session.get(StepRunRow, permit.step_run_id)
            step_lease_until = _aware(None if step is None else step.lease_until)
            if (
                step is None
                or step.run_id != permit.run_id
                or step.run_fence != permit.run_fence
                or step.fence != permit.step_fence
                or step.owner_id != authority.owner_id
                or step.status != "running"
                or step_lease_until is None
                or step_lease_until <= now
            ):
                raise InvestigationConflict("dispatch permit has no current fenced step lease")
            if step.reservation_id is not None:
                reservation = session.get(UsageReservationRow, step.reservation_id)
                if (
                    reservation is None
                    or reservation.run_id != permit.run_id
                    or reservation.status != ReservationStatus.RESERVED.value
                ):
                    raise InvestigationConflict("dispatch permit has no active usage reservation")
            existing = session.get(DispatchPermitRow, permit.permit_id)
            if existing is not None:
                if existing.payload_json != permit.model_dump_json():
                    raise InvestigationConflict("dispatch permit id was reused with different content")
                return permit
            session.add(
                DispatchPermitRow(
                    permit_id=permit.permit_id,
                    invocation_id=permit.invocation_id,
                    run_id=permit.run_id,
                    step_run_id=permit.step_run_id,
                    run_fence=permit.run_fence,
                    step_fence=permit.step_fence,
                    input_digest=permit.input_digest,
                    nonce=permit.nonce,
                    status=permit.status.value,
                    payload_json=permit.model_dump_json(),
                    expires_at=permit.expires_at,
                    created_at=now,
                )
            )
            session.commit()
            return permit

    def consume_dispatch_permit(
        self,
        permit_id: str,
        *,
        invocation_id: str,
        input_digest: str,
        run_fence: int,
        step_fence: int,
    ) -> DispatchPermit:
        now = datetime.now(UTC)
        with self._lock, Session(self.engine) as session:
            self._database_lock(session, "dispatch-permit")
            row = session.get(DispatchPermitRow, permit_id)
            if row is None:
                raise InvestigationConflict("dispatch permit does not exist")
            assert_run_archive_writable(session, row.run_id)
            if row.status != PermitStatus.ISSUED.value:
                raise InvestigationConflict("dispatch permit is not consumable")
            expires_at = _aware(row.expires_at)
            if expires_at is None or expires_at <= now:
                row.status = PermitStatus.EXPIRED.value
                session.commit()
                raise InvestigationConflict("dispatch permit expired")
            if (
                row.invocation_id != invocation_id
                or row.input_digest != input_digest
                or row.run_fence != run_fence
                or row.step_fence != step_fence
            ):
                raise InvestigationConflict("dispatch permit binding mismatch")
            job = session.get(RunJobRow, row.run_id)
            step = session.get(StepRunRow, row.step_run_id)
            job_lease_until = _aware(None if job is None else job.lease_until)
            step_lease_until = _aware(None if step is None else step.lease_until)
            if (
                job is None
                or job.status != "leased"
                or job.fence != row.run_fence
                or job_lease_until is None
                or job_lease_until <= now
                or step is None
                or step.run_id != row.run_id
                or step.run_fence != row.run_fence
                or step.fence != row.step_fence
                or step.owner_id != job.owner_id
                or step.status != "running"
                or step_lease_until is None
                or step_lease_until <= now
            ):
                raise InvestigationConflict("dispatch permit authority or step lease is no longer current")
            if step.reservation_id is not None:
                reservation = session.get(UsageReservationRow, step.reservation_id)
                if reservation is None or reservation.status != ReservationStatus.RESERVED.value:
                    raise InvestigationConflict("dispatch permit usage reservation is no longer active")
            row.status = PermitStatus.CONSUMED.value
            row.consumed_at = now
            session.commit()
            return DispatchPermit.model_validate_json(row.payload_json).model_copy(
                update={"status": PermitStatus.CONSUMED}
            )

    def revoke_dispatch_permits(self, run_id: str, *, run_fence: int) -> int:
        with self._lock, Session(self.engine) as session:
            self._database_lock(session, run_id)
            assert_run_archive_writable(session, run_id)
            result = session.execute(
                update(DispatchPermitRow)
                .where(
                    DispatchPermitRow.run_id == run_id,
                    DispatchPermitRow.run_fence == run_fence,
                    DispatchPermitRow.status == PermitStatus.ISSUED.value,
                )
                .values(status=PermitStatus.REVOKED.value)
            )
            session.commit()
            return int(getattr(result, "rowcount", 0) or 0)

    def record_execution_identity(self, identity: ExecutionIdentity) -> ExecutionIdentity:
        with self._lock, Session(self.engine) as session:
            self._database_lock(session, identity.run_id)
            assert_run_archive_writable(session, identity.run_id)
            now = datetime.now(UTC)
            job = session.get(RunJobRow, identity.run_id)
            step = session.get(StepRunRow, identity.step_run_id)
            job_lease = _aware(None if job is None else job.lease_until)
            step_lease = _aware(None if step is None else step.lease_until)
            if (
                job is None
                or job.status != "leased"
                or job.fence != identity.run_fence
                or job_lease is None
                or job_lease <= now
                or step is None
                or step.run_id != identity.run_id
                or step.run_fence != identity.run_fence
                or step.fence != identity.step_fence
                or step.status != "running"
                or step_lease is None
                or step_lease <= now
            ):
                raise InvestigationConflict("execution identity authority is stale or incomplete")
            existing = session.scalars(
                select(ExecutionIdentityRow).where(
                    ExecutionIdentityRow.invocation_id == identity.invocation_id,
                    ExecutionIdentityRow.attempt == identity.attempt,
                )
            ).first()
            if existing is not None:
                if (
                    existing.identity_digest != identity.identity_digest
                    or existing.payload_json != identity.model_dump_json()
                ):
                    raise InvestigationConflict("execution identity conflicts with the settled invocation")
                return identity
            session.add(
                ExecutionIdentityRow(
                    identity_digest=identity.identity_digest,
                    invocation_id=identity.invocation_id,
                    attempt=identity.attempt,
                    run_id=identity.run_id,
                    step_run_id=identity.step_run_id,
                    run_fence=identity.run_fence,
                    step_fence=identity.step_fence,
                    payload_json=identity.model_dump_json(),
                    settled_at=identity.settled_at,
                )
            )
            session.commit()
            return identity

    def execution_identity(self, invocation_id: str, *, run_id: str) -> ExecutionIdentity | None:
        with Session(self.engine) as session:
            row = session.scalars(
                select(ExecutionIdentityRow)
                .where(
                    ExecutionIdentityRow.invocation_id == invocation_id,
                    ExecutionIdentityRow.run_id == run_id,
                )
                .order_by(ExecutionIdentityRow.attempt.desc())
                .limit(1)
            ).first()
            return None if row is None else ExecutionIdentity.model_validate_json(row.payload_json)

    def label_artifact(self, label: ArtifactSecurityLabel) -> ArtifactSecurityLabel:
        with self._lock, Session(self.engine) as session:
            self._database_lock(session, label.owner_run_id)
            assert_run_archive_writable(session, label.owner_run_id)
            existing = session.scalars(
                select(ArtifactSecurityLabelRow).where(
                    ArtifactSecurityLabelRow.artifact_id == label.artifact_id,
                    ArtifactSecurityLabelRow.owner_run_id == label.owner_run_id,
                    ArtifactSecurityLabelRow.classification_version == label.classification_version,
                )
            ).first()
            if existing is not None:
                stored = ArtifactSecurityLabel.model_validate_json(existing.payload_json)
                security_binding = (
                    "view",
                    "data_class",
                    "retention_policy_id",
                    "allowed_purposes",
                    "content_sha256",
                    "size",
                    "media_type",
                )
                if any(getattr(stored, field) != getattr(label, field) for field in security_binding):
                    raise InvestigationConflict("artifact classification version conflicts")
                return stored
            session.add(
                ArtifactSecurityLabelRow(
                    label_id=str(uuid4()),
                    artifact_id=label.artifact_id,
                    owner_run_id=label.owner_run_id,
                    owner_step_id=label.owner_step_id,
                    owner_invocation_id=label.owner_invocation_id,
                    view=label.view.value,
                    data_class=label.data_class.value,
                    allowed_purposes_json=canonical_json(label.allowed_purposes),
                    retention_policy_id=label.retention_policy_id,
                    classification_version=label.classification_version,
                    content_sha256=label.content_sha256,
                    payload_json=label.model_dump_json(),
                    created_at=label.created_at,
                )
            )
            session.commit()
            return label

    def authorize_artifact(self, artifact_id: str, *, run_id: str, purpose: str) -> ArtifactSecurityLabel:
        with Session(self.engine) as session:
            row = session.scalars(
                select(ArtifactSecurityLabelRow)
                .where(
                    ArtifactSecurityLabelRow.artifact_id == artifact_id,
                    ArtifactSecurityLabelRow.owner_run_id == run_id,
                )
                .order_by(ArtifactSecurityLabelRow.classification_version.desc())
                .limit(1)
            ).first()
            if row is None:
                raise InvestigationAccessDenied("artifact has no current run-bound security label")
            label = ArtifactSecurityLabel.model_validate_json(row.payload_json)
            if purpose not in label.allowed_purposes or label.view.value == "quarantined":
                raise InvestigationAccessDenied("artifact is not authorized for this purpose")
            return label

    def record_secure_projection(self, projection: SecureStateProjection) -> SecureStateProjection:
        with self._lock, Session(self.engine) as session:
            self._database_lock(session, projection.run_id)
            assert_run_archive_writable(session, projection.run_id)
            existing = session.scalars(
                select(SecureStateProjectionRow).where(SecureStateProjectionRow.source_ref == projection.source_ref)
            ).first()
            if existing is not None:
                if existing.payload_json != projection.model_dump_json():
                    raise InvestigationConflict("secure projection source was reused with different content")
                return projection
            session.add(
                SecureStateProjectionRow(
                    projection_id=projection.projection_id,
                    source_ref=projection.source_ref,
                    run_id=projection.run_id,
                    source_digest=projection.source_digest,
                    observable_digest=projection.observable_digest,
                    scrub_receipt_digest=projection.scrub_receipt_digest,
                    payload_json=projection.model_dump_json(),
                    created_at=projection.created_at,
                )
            )
            session.commit()
            return projection

    @staticmethod
    def _stage_completion_snapshot(
        session: Session,
        snapshot: CompletionSnapshotV2,
        authority: RunAuthority,
    ) -> CompletionSnapshotV2:
        run = session.get(RunRow, snapshot.run_id)
        if (
            authority.run_id != snapshot.run_id
            or authority.run_fence != snapshot.run_fence
            or run is None
            or run.state_version != snapshot.run_state_version
        ):
            raise InvestigationConflict("completion snapshot is outside current run authority")
        expected_digest = canonical_content_digest(snapshot, exclude={"snapshot_digest"})
        if snapshot.snapshot_digest != expected_digest:
            raise InvestigationConflict("completion snapshot digest is invalid")
        now = datetime.now(UTC)
        actual_steps = sorted(
            session.scalars(
                select(StepRunRow.step_run_id).where(
                    StepRunRow.run_id == snapshot.run_id,
                    StepRunRow.status == StepStatus.RUNNING.value,
                    StepRunRow.run_fence == authority.run_fence,
                    StepRunRow.lease_until.is_not(None),
                    StepRunRow.lease_until > now,
                )
            ).all()
        )
        actual_invocations = sorted(
            session.scalars(
                select(ToolInvocationRow.invocation_id).where(
                    ToolInvocationRow.run_id == snapshot.run_id,
                    ToolInvocationRow.status == InvocationStatus.RUNNING.value,
                )
            ).all()
        )
        actual_reservations = sorted(
            session.scalars(
                select(UsageReservationRow.reservation_id).where(
                    UsageReservationRow.run_id == snapshot.run_id,
                    UsageReservationRow.status == ReservationStatus.RESERVED.value,
                    UsageReservationRow.kind != "run",
                )
            ).all()
        )
        actual_approvals = sorted(
            session.scalars(
                select(ApprovalRow.request_id).where(
                    ApprovalRow.run_id == snapshot.run_id,
                    ApprovalRow.status != "consumed",
                )
            ).all()
        )
        actual_clarifications = sorted(
            session.scalars(
                select(ClarificationRequestRow.request_id).where(
                    ClarificationRequestRow.run_id == snapshot.run_id,
                    ClarificationRequestRow.status != "consumed",
                )
            ).all()
        )
        expected_control = (
            sorted(set(snapshot.active_step_leases)),
            sorted(set(snapshot.active_invocations)),
            sorted(set(snapshot.unsettled_reservations)),
            sorted(set(snapshot.pending_approvals)),
            sorted(set(snapshot.pending_clarifications)),
        )
        if (
            actual_steps,
            actual_invocations,
            actual_reservations,
            actual_approvals,
            actual_clarifications,
        ) != (expected_control):
            raise InvestigationConflict("completion snapshot does not match durable control-plane quiescence")
        actual_unprojected = sorted(
            {
                row.transition_ordinal
                for row in session.scalars(
                    select(OutboxEventRow).where(
                        OutboxEventRow.run_id == snapshot.run_id,
                        OutboxEventRow.status != "projected",
                    )
                ).all()
            }
        )
        if actual_unprojected != sorted(set(snapshot.unprojected_outbox_ordinals)):
            raise InvestigationConflict("completion snapshot does not match durable outbox quiescence")
        existing = session.scalars(
            select(CompletionSnapshotRow).where(
                CompletionSnapshotRow.run_id == snapshot.run_id,
                CompletionSnapshotRow.run_state_version == snapshot.run_state_version,
                CompletionSnapshotRow.quiet_epoch == snapshot.quiet_epoch,
            )
        ).first()
        if existing is not None:
            if existing.snapshot_digest != snapshot.snapshot_digest:
                raise InvestigationConflict("completion snapshot epoch conflicts")
            return CompletionSnapshotV2.model_validate_json(existing.payload_json)
        session.add(
            CompletionSnapshotRow(
                snapshot_id=snapshot.snapshot_id,
                run_id=snapshot.run_id,
                run_state_version=snapshot.run_state_version,
                run_fence=snapshot.run_fence,
                quiet_epoch=snapshot.quiet_epoch,
                snapshot_digest=snapshot.snapshot_digest,
                is_quiet=1 if snapshot.is_quiet() else 0,
                payload_json=snapshot.model_dump_json(),
                created_at=snapshot.created_at,
            )
        )
        session.flush()
        return snapshot

    @staticmethod
    def _stage_completion_receipt(
        session: Session,
        receipt: CompletionReceipt,
        authority: RunAuthority,
    ) -> CompletionReceipt:
        snapshot_row = session.get(CompletionSnapshotRow, receipt.snapshot_id)
        if snapshot_row is None or snapshot_row.run_id != receipt.run_id:
            raise InvestigationConflict("completion receipt has no matching snapshot")
        snapshot = CompletionSnapshotV2.model_validate_json(snapshot_row.payload_json)
        if snapshot.run_fence != authority.run_fence:
            raise InvestigationConflict("completion receipt fence does not match current authority")
        expected_digest = canonical_content_digest(receipt, exclude={"receipt_digest"})
        if receipt.receipt_digest != expected_digest:
            raise InvestigationConflict("completion receipt digest is invalid")
        required = set(snapshot.requirement_obligations)
        satisfied = set(receipt.satisfied_obligation_ids)
        unsatisfied = set(receipt.unsatisfied_obligation_ids)
        if satisfied & unsatisfied or satisfied | unsatisfied != required:
            raise InvestigationConflict("completion receipt does not exactly cover snapshot obligations")
        if receipt.decision == CompletionOutcome.COMPLETE:
            integrity = (
                snapshot.input_integrity
                and snapshot.artifact_integrity
                and snapshot.evidence_integrity
                and snapshot.ledger_integrity
            )
            if not snapshot.is_quiet() or not integrity or not required or unsatisfied:
                failed_gates = [
                    *(["quiet"] if not snapshot.is_quiet() else []),
                    *(["integrity"] if not integrity else []),
                    *(["requirements"] if not required else []),
                    *(["obligations"] if unsatisfied else []),
                ]
                raise InvestigationConflict(
                    "complete requires a quiet, integrity-verified snapshot; failed gates: " + ", ".join(failed_gates)
                )
            obligation_rows = session.scalars(
                select(InvestigationObjectRow).where(
                    InvestigationObjectRow.run_id == receipt.run_id,
                    InvestigationObjectRow.object_type == "requirement_obligation",
                    InvestigationObjectRow.object_id.in_(required),
                )
            ).all()
            if len(obligation_rows) != len(required):
                raise InvestigationConflict("complete references an unknown requirement obligation")
            verifier_receipts = {
                item.verifier_receipt_id
                for row in obligation_rows
                for item in [RequirementObligation.model_validate_json(row.payload_json)]
                if item.verifier_receipt_id is not None
            }
            if verifier_receipts != set(receipt.verification_receipt_ids):
                raise InvestigationConflict("complete does not bind the exact verifier receipt set")
        existing = session.scalars(
            select(CompletionReceiptRow).where(
                CompletionReceiptRow.run_id == receipt.run_id,
                CompletionReceiptRow.snapshot_id == receipt.snapshot_id,
            )
        ).first()
        if existing is not None:
            if existing.receipt_digest != receipt.receipt_digest:
                raise InvestigationConflict("completion snapshot already has a conflicting decision")
            return CompletionReceipt.model_validate_json(existing.payload_json)
        session.add(
            CompletionReceiptRow(
                receipt_id=receipt.receipt_id,
                run_id=receipt.run_id,
                snapshot_id=receipt.snapshot_id,
                decision=receipt.decision.value,
                receipt_digest=receipt.receipt_digest,
                payload_json=receipt.model_dump_json(),
                decided_at=receipt.decided_at,
            )
        )
        return receipt

    def record_completion_snapshot(
        self,
        snapshot: CompletionSnapshotV2,
        authority: RunAuthority,
    ) -> CompletionSnapshotV2:
        with self._lock, Session(self.engine) as session:
            self._database_lock(session, snapshot.run_id)
            assert_run_archive_writable(session, snapshot.run_id)
            self._require_authority(session, authority, now=datetime.now(UTC))
            result = self._stage_completion_snapshot(session, snapshot, authority)
            session.commit()
            return result

    def record_completion_receipt(
        self,
        receipt: CompletionReceipt,
        authority: RunAuthority,
    ) -> CompletionReceipt:
        with self._lock, Session(self.engine) as session:
            self._database_lock(session, receipt.run_id)
            assert_run_archive_writable(session, receipt.run_id)
            self._require_authority(session, authority, now=datetime.now(UTC))
            result = self._stage_completion_receipt(session, receipt, authority)
            session.commit()
            return result

    def create_recovery_command(self, command: RecoveryCommand) -> RecoveryCommand:
        now = datetime.now(UTC)
        with self._lock, Session(self.engine) as session:
            self._database_lock(session, command.run_id)
            assert_run_archive_writable(session, command.run_id)
            existing = session.scalars(
                select(RecoveryCommandRow).where(
                    RecoveryCommandRow.run_id == command.run_id,
                    RecoveryCommandRow.command_digest == command.command_digest,
                )
            ).first()
            if existing is not None:
                return RecoveryCommand.model_validate_json(existing.payload_json)
            session.add(
                RecoveryCommandRow(
                    command_id=command.command_id,
                    run_id=command.run_id,
                    action=command.action.value,
                    status=command.status.value,
                    issued_fence=command.issued_fence,
                    command_digest=command.command_digest,
                    payload_json=command.model_dump_json(),
                    created_at=command.created_at,
                    updated_at=now,
                )
            )
            session.commit()
            return command

    def claim_recovery_command(self, command_id: str, authority: RunAuthority) -> RecoveryCommand:
        now = datetime.now(UTC)
        with self._lock, Session(self.engine) as session:
            self._database_lock(session, authority.run_id)
            assert_run_archive_writable(session, authority.run_id)
            self._require_authority(session, authority, now=now)
            row = session.get(RecoveryCommandRow, command_id)
            if (
                row is None
                or row.run_id != authority.run_id
                or row.issued_fence != authority.run_fence
                or row.status != RecoveryCommandStatus.PENDING.value
            ):
                raise InvestigationConflict("recovery command is missing, stale, or already consumed")
            row.status = RecoveryCommandStatus.CLAIMED.value
            row.owner_id = authority.owner_id
            row.updated_at = now
            session.commit()
            return RecoveryCommand.model_validate_json(row.payload_json).model_copy(
                update={"status": RecoveryCommandStatus.CLAIMED}
            )

    def complete_recovery_command(
        self,
        command_id: str,
        authority: RunAuthority,
        *,
        result_receipt_id: str,
        applied: bool,
    ) -> None:
        now = datetime.now(UTC)
        with self._lock, Session(self.engine) as session:
            self._database_lock(session, authority.run_id)
            assert_run_archive_writable(session, authority.run_id)
            self._require_authority(session, authority, now=now)
            row = session.get(RecoveryCommandRow, command_id)
            if (
                row is None
                or row.status != RecoveryCommandStatus.CLAIMED.value
                or row.owner_id != authority.owner_id
                or row.issued_fence != authority.run_fence
            ):
                raise InvestigationConflict("recovery command completion lost authority")
            row.status = (
                RecoveryCommandStatus.APPLIED.value if applied else RecoveryCommandStatus.RECOVERY_REQUIRED.value
            )
            row.result_receipt_id = result_receipt_id
            row.updated_at = now
            session.commit()

    def _validate_durable_message(
        self,
        message: CollaborationMessage,
        authority: RunAuthority,
        *,
        now: datetime,
        recipient_role: str = COORDINATOR_ROLE,
    ) -> None:
        if message.run_id != authority.run_id or message.run_fence != authority.run_fence:
            raise InvestigationAccessDenied("message is outside current run authority")
        if recipient_role != COORDINATOR_ROLE or message.recipient_role != recipient_role:
            raise InvestigationAccessDenied("durable mailbox only routes through the coordinator")
        if message.resolved_recipient_id not in {None, authority.owner_id}:
            raise InvestigationAccessDenied("message is addressed to another mailbox owner")
        if not all(
            (
                message.sender_profile_id,
                message.sender_delegation_id,
                message.sender_thread_id,
                message.correlation_id,
                message.transition_id,
                message.dedupe_key,
            )
        ):
            raise InvestigationConflict("message routing identity is incomplete")
        expires_at = _aware(message.expires_at)
        created_at = _aware(message.created_at)
        if expires_at is None or created_at is None or expires_at <= now or created_at >= expires_at:
            raise InvestigationConflict("message expiry is invalid or no longer current")
        try:
            self._typed_mailbox.as_peer_data(message)
        except MailboxAuthorizationError as exc:
            raise InvestigationAccessDenied(str(exc)) from exc
        except (MailboxError, ValidationError, ValueError) as exc:
            raise InvestigationConflict(f"message contract is invalid: {exc}") from exc

    @staticmethod
    def _message_from_row(row: InvestigationMessageRow) -> CollaborationMessage:
        try:
            message = CollaborationMessage.model_validate_json(row.payload_json)
        except ValidationError as exc:
            raise InvestigationConflict("stored mailbox message is invalid") from exc
        if (
            row.message_id != message.message_id
            or row.run_id != message.run_id
            or row.recipient_role != message.recipient_role
            or row.kind != message.kind.value
            or row.dedupe_key != message.dedupe_key
            or row.payload_digest != message.payload_digest
            or _aware(row.expires_at) != _aware(message.expires_at)
            or _aware(row.created_at) != _aware(message.created_at)
        ):
            raise InvestigationConflict("stored mailbox envelope does not match its indexed routing fields")
        return message

    def publish_message(
        self,
        message: CollaborationMessage,
        authority: RunAuthority,
    ) -> CollaborationMessage:
        now = datetime.now(UTC)
        with self._lock, Session(self.engine) as session:
            self._database_lock(session, authority.run_id)
            assert_run_archive_writable(session, authority.run_id)
            self._require_authority(session, authority, now=now)
            self._validate_durable_message(message, authority, now=now)
            existing_id = session.get(InvestigationMessageRow, message.message_id)
            if existing_id is not None and existing_id.payload_json != message.model_dump_json():
                raise InvestigationConflict("message id was reused with different content")
            existing = session.scalars(
                select(InvestigationMessageRow).where(
                    InvestigationMessageRow.run_id == message.run_id,
                    InvestigationMessageRow.dedupe_key == message.dedupe_key,
                )
            ).first()
            if existing is not None:
                if (
                    existing.payload_digest != message.payload_digest
                    or existing.payload_json != message.model_dump_json()
                ):
                    raise InvestigationConflict("message dedupe key was reused with different payload")
                return CollaborationMessage.model_validate_json(existing.payload_json)
            session.add(
                InvestigationMessageRow(
                    message_id=message.message_id,
                    run_id=message.run_id,
                    recipient_role=message.recipient_role,
                    kind=message.kind.value,
                    dedupe_key=message.dedupe_key,
                    payload_digest=message.payload_digest,
                    payload_json=message.model_dump_json(),
                    expires_at=message.expires_at,
                    created_at=message.created_at,
                )
            )
            session.commit()
            return message

    def reserve_messages(
        self,
        run_id: str,
        *,
        recipient_role: str,
        owner_id: str,
        authority: RunAuthority,
        limit: int = 20,
        lease_seconds: int = 30,
    ) -> list[MessageReceipt]:
        if limit < 1 or limit > 100:
            raise ValueError("message reservation limit must be between 1 and 100")
        if lease_seconds < 1:
            raise ValueError("message reservation lease must be positive")
        if run_id != authority.run_id:
            raise InvestigationAccessDenied("cross-run mailbox reservation rejected")
        if recipient_role != COORDINATOR_ROLE:
            raise InvestigationAccessDenied("only the coordinator mailbox may reserve messages")
        if owner_id != authority.owner_id:
            raise InvestigationAccessDenied("reservation owner is not the current run owner")
        now = datetime.now(UTC)
        receipts: list[MessageReceipt] = []
        with self._lock, Session(self.engine) as session:
            self._database_lock(session, run_id)
            assert_run_archive_writable(session, run_id)
            self._require_authority(session, authority, now=now)
            messages = session.scalars(
                select(InvestigationMessageRow)
                .where(
                    InvestigationMessageRow.run_id == run_id,
                    InvestigationMessageRow.recipient_role == recipient_role,
                    InvestigationMessageRow.expires_at > now,
                )
                .order_by(InvestigationMessageRow.created_at)
                .limit(limit * 2)
            ).all()
            for message in messages:
                durable_message = self._message_from_row(message)
                self._validate_durable_message(
                    durable_message,
                    authority,
                    now=now,
                    recipient_role=recipient_role,
                )
                row = session.get(MessageReceiptRow, message.message_id)
                if row is not None and row.processing_status == "processed":
                    continue
                if row is not None:
                    lease_until = _aware(row.lease_until)
                    if lease_until is not None and lease_until > now:
                        continue
                attempt = 1 if row is None else row.delivery_attempt + 1
                fence = 1 if row is None else row.delivery_fence + 1
                receipt = MessageReceipt(
                    message_id=message.message_id,
                    delivery_attempt=attempt,
                    reservation_owner=owner_id,
                    delivery_fence=fence,
                    lease_until=now + timedelta(seconds=lease_seconds),
                    receipt_version=1 if row is None else row.receipt_version + 1,
                    transport_status="reserved",
                    processing_status="processing",
                )
                if row is None:
                    session.add(
                        MessageReceiptRow(
                            message_id=message.message_id,
                            delivery_attempt=attempt,
                            reservation_owner=owner_id,
                            delivery_fence=fence,
                            lease_until=receipt.lease_until,
                            receipt_version=receipt.receipt_version,
                            transport_status=receipt.transport_status,
                            processing_status=receipt.processing_status,
                            payload_json=receipt.model_dump_json(),
                        )
                    )
                else:
                    row.delivery_attempt = attempt
                    row.reservation_owner = owner_id
                    row.delivery_fence = fence
                    row.lease_until = receipt.lease_until
                    row.receipt_version = receipt.receipt_version
                    row.transport_status = receipt.transport_status
                    row.processing_status = receipt.processing_status
                    row.payload_json = receipt.model_dump_json()
                receipts.append(receipt)
                if len(receipts) >= limit:
                    break
            session.commit()
        return receipts

    def acknowledge_message(
        self,
        receipt: MessageReceipt,
        *,
        transition_id: str,
        recipient_role: str,
        authority: RunAuthority,
    ) -> MessageReceipt:
        if not transition_id:
            raise ValueError("message acknowledgement transition id is required")
        if recipient_role != COORDINATOR_ROLE:
            raise InvestigationAccessDenied("only the coordinator mailbox may acknowledge messages")
        if receipt.reservation_owner != authority.owner_id:
            raise InvestigationAccessDenied("message receipt belongs to another reservation owner")
        now = datetime.now(UTC)
        with self._lock, Session(self.engine) as session:
            self._database_lock(session, authority.run_id)
            assert_run_archive_writable(session, authority.run_id)
            self._require_authority(session, authority, now=now)
            message_row = session.get(InvestigationMessageRow, receipt.message_id)
            if message_row is None:
                raise InvestigationConflict("message acknowledgement has no durable message")
            message = self._message_from_row(message_row)
            self._validate_durable_message(
                message,
                authority,
                now=now,
                recipient_role=recipient_role,
            )
            row = session.get(MessageReceiptRow, receipt.message_id)
            lease_until = _aware(None if row is None else row.lease_until)
            if row is not None and row.processing_status == "processed":
                if (
                    row.reservation_owner != receipt.reservation_owner
                    or row.delivery_fence != receipt.delivery_fence
                    or row.processed_transition_id != transition_id
                ):
                    raise InvestigationConflict("message was acknowledged by a different owner or transition")
                return MessageReceipt.model_validate_json(row.payload_json)
            if (
                row is None
                or row.reservation_owner != receipt.reservation_owner
                or row.delivery_fence != receipt.delivery_fence
                or lease_until is None
                or lease_until <= now
                or row.processing_status != "processing"
            ):
                raise InvestigationConflict("message acknowledgement lost its delivery fence")
            current = MessageReceipt.model_validate_json(row.payload_json)
            if current != receipt:
                raise InvestigationConflict("message acknowledgement receipt does not match durable delivery")
            row.transport_status = "acked"
            row.processing_status = "processed"
            row.processed_transition_id = transition_id
            row.processed_at = now
            row.receipt_version += 1
            completed = current.model_copy(
                update={
                    "receipt_version": row.receipt_version,
                    "transport_status": "acked",
                    "processing_status": "processed",
                    "processed_transition_id": transition_id,
                    "processed_at": now,
                }
            )
            row.payload_json = completed.model_dump_json()
            session.commit()
            return completed
