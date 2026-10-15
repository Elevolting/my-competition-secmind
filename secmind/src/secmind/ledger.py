from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from sqlalchemy import DateTime, Integer, String, Text, UniqueConstraint, create_engine, select, text, update
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

from secmind.schemas import AgentState, LedgerEvent, RunStatus
from secmind.secret_scrubber import redact

ZERO_HASH = "0" * 64


class LedgerDedupeConflict(RuntimeError):
    pass


class LedgerFrozenError(RuntimeError):
    """Raised when a write arrives after an archive freeze boundary."""


@dataclass(frozen=True)
class ArchiveFreeze:
    run_id: str
    freeze_id: str
    status: str
    state_version: int
    latest_event_sequence: int
    ledger_head_hash: str
    artifact_snapshot_digest: str | None
    frozen_at: datetime


class Base(DeclarativeBase):
    pass


class EventRow(Base):
    __tablename__ = "ledger_events"
    __table_args__ = (
        UniqueConstraint("run_id", "sequence"),
        UniqueConstraint("run_id", "dedupe_key"),
    )

    event_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(36), index=True)
    sequence: Mapped[int] = mapped_column(Integer)
    event_type: Mapped[str] = mapped_column(String(100), index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    actor: Mapped[str] = mapped_column(String(100))
    dedupe_key: Mapped[str] = mapped_column(String(200))
    payload_json: Mapped[str] = mapped_column(Text)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))


class RunRow(Base):
    __tablename__ = "runs"

    run_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    status: Mapped[str] = mapped_column(String(30), index=True)
    state_version: Mapped[int] = mapped_column(Integer, default=1)
    state_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class RunFreezeRow(Base):
    __tablename__ = "run_archive_freezes"

    run_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    freeze_id: Mapped[str] = mapped_column(String(200), unique=True, index=True)
    status: Mapped[str] = mapped_column(String(20), index=True)
    state_version: Mapped[int] = mapped_column(Integer)
    latest_event_sequence: Mapped[int] = mapped_column(Integer)
    ledger_head_hash: Mapped[str] = mapped_column(String(64))
    artifact_snapshot_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    frozen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


def assert_run_archive_writable(session: Session, run_id: str) -> None:
    """Reject durable writes while a run is pending or sealed for archive."""

    freeze = session.get(RunFreezeRow, run_id)
    if freeze is not None and freeze.status in {"pending", "complete"}:
        raise LedgerFrozenError(f"run is frozen for archive: {run_id}")


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


class LedgerStore:
    """Append-only hash-chained event store plus persisted run snapshots."""

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
            connect_args = {"check_same_thread": False} if database_url.startswith("sqlite") else {}
            engine = create_engine(database_url, future=True, connect_args=connect_args)
        self.engine = engine
        self._locks: dict[str, threading.RLock] = {}
        self._locks_guard = threading.Lock()
        if initialize_schema:
            Base.metadata.create_all(self.engine)

    def _lock_for(self, run_id: str) -> threading.RLock:
        with self._locks_guard:
            return self._locks.setdefault(run_id, threading.RLock())

    def _database_lock(self, session: Session, run_id: str) -> None:
        if self.engine.dialect.name == "postgresql":
            session.execute(
                text("SELECT pg_advisory_xact_lock(hashtext(:lock_key))"),
                {"lock_key": f"secmind:run:{run_id}"},
            )

    def append(
        self,
        run_id: str,
        event_type: str,
        payload: dict[str, Any],
        actor: str = "system",
        dedupe_key: str | None = None,
    ) -> LedgerEvent:
        with self._lock_for(run_id), Session(self.engine) as session:
            self._database_lock(session, run_id)
            row = self.append_in_session(session, run_id, event_type, payload, actor, dedupe_key)
            session.commit()
            return self._to_event(row)

    @staticmethod
    def append_in_session(
        session: Session,
        run_id: str,
        event_type: str,
        payload: dict[str, Any],
        actor: str = "system",
        dedupe_key: str | None = None,
    ) -> EventRow:
        """Stage a ledger event inside a caller-held per-run database lock."""
        freeze = session.get(RunFreezeRow, run_id)
        if freeze is not None and freeze.status in {"pending", "complete"}:
            raise LedgerFrozenError(f"run is frozen for archive: {run_id}")
        safe_payload = redact(payload)
        effective_dedupe_key = dedupe_key or f"event:{uuid4()}"
        existing = session.scalars(
            select(EventRow).where(
                EventRow.run_id == run_id,
                EventRow.dedupe_key == effective_dedupe_key,
            )
        ).first()
        if existing is not None:
            if (
                existing.event_type != event_type
                or existing.actor != actor
                or existing.payload_json != canonical_json(safe_payload)
            ):
                raise LedgerDedupeConflict("ledger dedupe key was reused with different event content")
            return existing
        previous = session.scalars(
            select(EventRow).where(EventRow.run_id == run_id).order_by(EventRow.sequence.desc()).limit(1)
        ).first()
        sequence = 1 if previous is None else previous.sequence + 1
        prev_hash = ZERO_HASH if previous is None else previous.hash
        timestamp = datetime.now(UTC)
        event_id = str(uuid4())
        digest_input = {
            "event_id": event_id,
            "run_id": run_id,
            "sequence": sequence,
            "event_type": event_type,
            "timestamp": timestamp.isoformat(),
            "actor": actor,
            "dedupe_key": effective_dedupe_key,
            "payload": safe_payload,
            "prev_hash": prev_hash,
        }
        digest = hashlib.sha256(canonical_json(digest_input).encode()).hexdigest()
        row = EventRow(
            event_id=event_id,
            run_id=run_id,
            sequence=sequence,
            event_type=event_type,
            timestamp=timestamp,
            actor=actor,
            dedupe_key=effective_dedupe_key,
            payload_json=canonical_json(safe_payload),
            prev_hash=prev_hash,
            hash=digest,
        )
        session.add(row)
        session.flush()
        return row

    def events(self, run_id: str, after_sequence: int = 0, limit: int = 1000) -> list[LedgerEvent]:
        with Session(self.engine) as session:
            rows = session.scalars(
                select(EventRow)
                .where(EventRow.run_id == run_id, EventRow.sequence > after_sequence)
                .order_by(EventRow.sequence)
                .limit(limit)
            ).all()
            return [self._to_event(row) for row in rows]

    def latest_event(self, run_id: str) -> LedgerEvent | None:
        with Session(self.engine) as session:
            row = session.scalars(
                select(EventRow).where(EventRow.run_id == run_id).order_by(EventRow.sequence.desc()).limit(1)
            ).first()
            return None if row is None else self._to_event(row)

    def verify(self, run_id: str) -> bool:
        previous = ZERO_HASH
        for event in self.events(run_id, limit=1_000_000):
            if event.prev_hash != previous:
                return False
            digest_input = {
                "event_id": event.event_id,
                "run_id": event.run_id,
                "sequence": event.sequence,
                "event_type": event.event_type,
                "timestamp": event.timestamp.isoformat(),
                "actor": event.actor,
                "dedupe_key": event.dedupe_key,
                "payload": event.payload,
                "prev_hash": event.prev_hash,
            }
            expected = hashlib.sha256(canonical_json(digest_input).encode()).hexdigest()
            if expected != event.hash:
                return False
            previous = event.hash
        return True

    def save_state(self, state: AgentState) -> None:
        now = datetime.now(UTC)
        with self._lock_for(state.run_id), Session(self.engine) as session:
            self._database_lock(session, state.run_id)
            self._assert_writable(session, state.run_id)
            row = session.get(RunRow, state.run_id)
            if row is None:
                state.state_version = max(1, state.state_version)
                state_json = state.model_dump_json()
                row = RunRow(
                    run_id=state.run_id,
                    status=state.status.value,
                    state_version=state.state_version,
                    state_json=state_json,
                    created_at=now,
                    updated_at=now,
                )
                session.add(row)
            else:
                stored = AgentState.model_validate_json(row.state_json)
                state.state_version = max(state.state_version, stored.state_version, row.state_version) + 1
                state_json = state.model_dump_json()
                row.status = state.status.value
                row.state_version = state.state_version
                row.state_json = state_json
                row.updated_at = now
            session.commit()

    def save_state_cas(self, state: AgentState, *, expected_version: int) -> int:
        """Persist a state only when the durable version still matches the caller's view.

        This is the state-side fencing primitive used by the v0.3 coordinator.  It
        deliberately fails closed instead of silently merging two worker snapshots.
        """
        if expected_version < 0:
            raise ValueError("expected_version must be non-negative")
        now = datetime.now(UTC)
        next_version = expected_version + 1
        candidate = state.model_copy(update={"state_version": next_version})
        serialized = candidate.model_dump_json()
        with self._lock_for(state.run_id), Session(self.engine) as session:
            self._database_lock(session, state.run_id)
            self._assert_writable(session, state.run_id)
            if expected_version == 0:
                if session.get(RunRow, state.run_id) is not None:
                    raise RuntimeError("run state version conflict")
                session.add(
                    RunRow(
                        run_id=state.run_id,
                        status=state.status.value,
                        state_version=next_version,
                        state_json=serialized,
                        created_at=now,
                        updated_at=now,
                    )
                )
                session.commit()
                state.state_version = next_version
                return next_version
            result = session.execute(
                update(RunRow)
                .where(RunRow.run_id == state.run_id, RunRow.state_version == expected_version)
                .values(
                    status=state.status.value,
                    state_version=next_version,
                    state_json=serialized,
                    updated_at=now,
                )
            )
            if getattr(result, "rowcount", 0) != 1:
                session.rollback()
                raise RuntimeError("run state version conflict")
            session.commit()
            state.state_version = next_version
            return next_version

    def begin_archive_freeze(self, run_id: str, *, freeze_id: str | None = None) -> ArchiveFreeze:
        """Create a durable write fence at the current ledger boundary."""

        now = datetime.now(UTC)
        effective_freeze_id = freeze_id or f"freeze-{run_id}-{uuid4()}"
        terminal_statuses = {
            RunStatus.COMPLETED.value,
            RunStatus.PARTIAL.value,
            RunStatus.DENIED.value,
            RunStatus.FAILED.value,
            RunStatus.RECOVERY_REQUIRED.value,
            RunStatus.CANCELLED.value,
        }
        with self._lock_for(run_id), Session(self.engine) as session:
            self._database_lock(session, run_id)
            run = session.get(RunRow, run_id)
            if run is None:
                raise LedgerDedupeConflict(f"run state does not exist: {run_id}")
            if run.status not in terminal_statuses:
                raise LedgerDedupeConflict(f"run is not archivable: {run_id}")
            existing = session.get(RunFreezeRow, run_id)
            if existing is not None and existing.status in {"pending", "complete"}:
                raise LedgerDedupeConflict(f"run already has an active archive freeze: {run_id}")
            event = self.append_in_session(
                session,
                run_id,
                "archive.freeze_started",
                {"freeze_id": effective_freeze_id, "state_version": run.state_version},
                actor="archive",
                dedupe_key=f"archive-freeze:{effective_freeze_id}:started",
            )
            if existing is not None:
                session.delete(existing)
                session.flush()
            freeze = RunFreezeRow(
                run_id=run_id,
                freeze_id=effective_freeze_id,
                status="pending",
                state_version=run.state_version,
                latest_event_sequence=event.sequence,
                ledger_head_hash=event.hash,
                artifact_snapshot_digest=None,
                frozen_at=now,
            )
            session.add(freeze)
            session.commit()
            return self._to_freeze(freeze)

    def complete_archive_freeze(
        self,
        run_id: str,
        *,
        freeze_id: str,
        artifact_snapshot_digest: str,
    ) -> ArchiveFreeze:
        if len(artifact_snapshot_digest) != 64 or any(
            char not in "0123456789abcdef" for char in artifact_snapshot_digest
        ):
            raise ValueError("artifact_snapshot_digest must be a lowercase SHA-256 digest")
        with self._lock_for(run_id), Session(self.engine) as session:
            self._database_lock(session, run_id)
            row = session.get(RunFreezeRow, run_id)
            if row is None or row.freeze_id != freeze_id or row.status != "pending":
                raise LedgerDedupeConflict(f"archive freeze is not pending: {run_id}")
            latest = session.scalars(
                select(EventRow).where(EventRow.run_id == run_id).order_by(EventRow.sequence.desc()).limit(1)
            ).first()
            if latest is None or latest.sequence != row.latest_event_sequence or latest.hash != row.ledger_head_hash:
                raise LedgerDedupeConflict("ledger changed during archive freeze")
            row.status = "complete"
            row.artifact_snapshot_digest = artifact_snapshot_digest
            session.commit()
            return self._to_freeze(row)

    def abort_archive_freeze(self, run_id: str, *, freeze_id: str) -> None:
        with self._lock_for(run_id), Session(self.engine) as session:
            self._database_lock(session, run_id)
            row = session.get(RunFreezeRow, run_id)
            if row is not None and row.freeze_id == freeze_id and row.status in {"pending", "complete"}:
                row.status = "aborted"
                session.commit()

    def archive_freeze(self, run_id: str) -> ArchiveFreeze | None:
        with Session(self.engine) as session:
            row = session.get(RunFreezeRow, run_id)
            return None if row is None else self._to_freeze(row)

    @staticmethod
    def _assert_writable(session: Session, run_id: str) -> None:
        assert_run_archive_writable(session, run_id)

    def load_state(self, run_id: str) -> AgentState | None:
        with Session(self.engine) as session:
            row = session.get(RunRow, run_id)
            return None if row is None else AgentState.model_validate_json(row.state_json)

    def incomplete_run_ids(self) -> list[str]:
        terminal = {
            RunStatus.COMPLETED.value,
            RunStatus.PARTIAL.value,
            RunStatus.DENIED.value,
            RunStatus.FAILED.value,
            RunStatus.RECOVERY_REQUIRED.value,
            RunStatus.CANCELLED.value,
        }
        with Session(self.engine) as session:
            return list(session.scalars(select(RunRow.run_id).where(RunRow.status.not_in(terminal))).all())

    def list_states(
        self,
        *,
        statuses: set[RunStatus] | None = None,
        offset: int = 0,
        limit: int = 100,
    ) -> list[AgentState]:
        query = select(RunRow).order_by(RunRow.created_at.desc(), RunRow.run_id).offset(offset).limit(limit)
        if statuses:
            query = query.where(RunRow.status.in_([status.value for status in statuses]))
        with Session(self.engine) as session:
            return [AgentState.model_validate_json(row.state_json) for row in session.scalars(query).all()]

    def export_jsonl(self, run_id: str, destination: Path) -> Path:
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("w", encoding="utf-8", newline="\n") as output:
            for event in self.events(run_id, limit=1_000_000):
                output.write(event.model_dump_json() + "\n")
        return destination

    def close(self) -> None:
        if self._owns_engine:
            self.engine.dispose()

    @staticmethod
    def _to_event(row: EventRow) -> LedgerEvent:
        return LedgerEvent(
            event_id=row.event_id,
            run_id=row.run_id,
            sequence=row.sequence,
            event_type=row.event_type,
            timestamp=row.timestamp.replace(tzinfo=row.timestamp.tzinfo or UTC),
            actor=row.actor,
            dedupe_key=row.dedupe_key,
            payload=json.loads(row.payload_json),
            prev_hash=row.prev_hash,
            hash=row.hash,
        )

    @staticmethod
    def _to_freeze(row: RunFreezeRow) -> ArchiveFreeze:
        return ArchiveFreeze(
            run_id=row.run_id,
            freeze_id=row.freeze_id,
            status=row.status,
            state_version=row.state_version,
            latest_event_sequence=row.latest_event_sequence,
            ledger_head_hash=row.ledger_head_hash,
            artifact_snapshot_digest=row.artifact_snapshot_digest,
            frozen_at=row.frozen_at.replace(tzinfo=row.frozen_at.tzinfo or UTC),
        )
