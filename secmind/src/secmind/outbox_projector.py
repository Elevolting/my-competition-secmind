from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import logging
import re
from collections.abc import Awaitable, Callable
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol
from uuid import uuid4

from sqlalchemy import and_, exists, or_, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, aliased

from secmind.coordinator import CoordinatorStore, OutboxEventRow
from secmind.ledger import (
    ZERO_HASH,
    EventRow,
    LedgerDedupeConflict,
    canonical_json,
    redact,
)
from secmind.schemas import LedgerEvent

OUTBOX_WAKE_CHANNEL = "secmind_outbox_pending"
LEDGER_WAKE_CHANNEL = "secmind_ledger_events"
_CHANNEL = re.compile(r"^[a-z][a-z0-9_]{0,62}$")
logger = logging.getLogger(__name__)


class OutboxProjectionError(RuntimeError):
    pass


class OutboxOperatorAuthorizationError(OutboxProjectionError):
    """A quarantine/skip request lacks a valid operator authorization."""


class NotificationWakeup(Protocol):
    async def wait(self, timeout_seconds: float) -> bool: ...

    async def close(self) -> None: ...


class PollingWakeup:
    """Safety-poll wakeup used when PostgreSQL notifications are unavailable."""

    async def wait(self, timeout_seconds: float) -> bool:
        await asyncio.sleep(timeout_seconds)
        return False

    async def close(self) -> None:
        return None


class LocalNotificationWakeup:
    """In-process notification helper; the signal carries no authoritative data."""

    def __init__(self) -> None:
        self._event = asyncio.Event()

    def signal(self) -> None:
        self._event.set()

    async def wait(self, timeout_seconds: float) -> bool:
        try:
            await asyncio.wait_for(self._event.wait(), timeout_seconds)
        except TimeoutError:
            return False
        self._event.clear()
        return True

    async def close(self) -> None:
        self._event.set()


class PostgresNotificationWakeup:
    """LISTEN adapter used only to wake the durable database projector scan."""

    def __init__(self, connection_url: str, *, channel: str = OUTBOX_WAKE_CHANNEL) -> None:
        if not _CHANNEL.fullmatch(channel):
            raise ValueError("invalid PostgreSQL notification channel")
        self.connection_url = connection_url
        self.channel = channel
        self._connection: Any | None = None
        self._listener_task: asyncio.Task[None] | None = None
        self._event = asyncio.Event()

    async def start(self) -> None:
        if self._connection is not None:
            return
        from psycopg import AsyncConnection

        self._connection = await AsyncConnection.connect(self.connection_url, autocommit=True)
        await self._connection.execute(f"LISTEN {self.channel}")
        self._listener_task = asyncio.create_task(self._listen(), name="secmind-postgres-notify-listener")

    async def _listen(self) -> None:
        connection = self._connection
        if connection is None:
            raise RuntimeError("PostgreSQL notification listener was not started")
        async for _notification in connection.notifies():
            # Notification payloads are deliberately ignored. PostgreSQL remains
            # the source of truth and every wakeup triggers a fresh leased scan.
            self._event.set()

    async def wait(self, timeout_seconds: float) -> bool:
        await self.start()
        try:
            await asyncio.wait_for(self._event.wait(), timeout_seconds)
        except TimeoutError:
            return False
        self._event.clear()
        return True

    async def close(self) -> None:
        task = self._listener_task
        self._listener_task = None
        if task is not None:
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task
        connection = self._connection
        self._connection = None
        if connection is not None:
            await connection.close()


class OutboxProjector:
    """Lease and project outbox events to the hash ledger atomically.

    Ledger insertion and ``outbox_events.status=projected`` are committed by one
    database transaction. LISTEN/NOTIFY only shortens latency; the projector
    always performs bounded safety polling so lost notifications cannot lose an
    event.
    """

    def __init__(
        self,
        engine: Engine,
        *,
        owner_id: str,
        lease_seconds: int = 30,
        poll_interval_seconds: float = 1.0,
        batch_size: int = 100,
        max_attempts: int = 10,
        retry_backoff_seconds: float = 1.0,
        max_retry_backoff_seconds: float = 60.0,
        wakeup: NotificationWakeup | None = None,
        on_projected: Callable[[LedgerEvent], Awaitable[None] | None] | None = None,
        fault_injector: Callable[[str], None] | None = None,
    ) -> None:
        if (
            not owner_id
            or lease_seconds < 1
            or poll_interval_seconds <= 0
            or batch_size < 1
            or max_attempts < 1
            or retry_backoff_seconds < 0
            or max_retry_backoff_seconds < retry_backoff_seconds
        ):
            raise ValueError("invalid outbox projector configuration")
        self.engine = engine
        self.owner_id = owner_id
        self.lease_seconds = lease_seconds
        self.poll_interval_seconds = poll_interval_seconds
        self.batch_size = batch_size
        self.max_attempts = max_attempts
        self.retry_backoff_seconds = retry_backoff_seconds
        self.max_retry_backoff_seconds = max_retry_backoff_seconds
        self.wakeup = wakeup or PollingWakeup()
        self.on_projected = on_projected
        self.fault_injector = fault_injector

    def claim_batch(self, *, run_id: str | None = None, now: datetime | None = None) -> list[str]:
        claimed_at = now or datetime.now(UTC)
        with Session(self.engine) as session:
            self._begin_write(session)
            # A legacy database may contain ``failed`` rows created before the
            # retry/dead-letter states existed.  Any failed or expired lease at
            # the attempt ceiling is normalized to dead-letter before
            # selection; rows below it remain recoverable and use the same
            # backoff gate as retry_wait.
            legacy_terminal = session.scalars(
                select(OutboxEventRow).where(
                    OutboxEventRow.attempts >= self.max_attempts,
                    or_(
                        OutboxEventRow.status == "failed",
                        and_(
                            OutboxEventRow.status == "projecting",
                            OutboxEventRow.lease_until <= claimed_at,
                        ),
                    ),
                )
            ).all()
            for row in legacy_terminal:
                row.status = "dead_letter"
                row.dead_lettered_at = claimed_at
                row.failure_class = row.failure_class or "lease_attempt_limit"
                row.owner_id = None
                row.lease_until = None
            if legacy_terminal:
                session.flush()
            ready_at = or_(OutboxEventRow.next_attempt_at.is_(None), OutboxEventRow.next_attempt_at <= claimed_at)
            eligible = and_(
                OutboxEventRow.attempts < self.max_attempts,
                ready_at,
                or_(
                    OutboxEventRow.status == "pending",
                    OutboxEventRow.status == "retry_wait",
                    # ``failed`` is retained as a compatibility state for
                    # rows written by an older binary.  New failures use
                    # retry_wait and dead_letter explicitly.
                    OutboxEventRow.status == "failed",
                    and_(
                        OutboxEventRow.status == "projecting",
                        OutboxEventRow.lease_until <= claimed_at,
                    ),
                ),
            )
            earlier = aliased(OutboxEventRow)
            causally_earlier = or_(
                earlier.transition_ordinal < OutboxEventRow.transition_ordinal,
                and_(
                    earlier.transition_ordinal == OutboxEventRow.transition_ordinal,
                    earlier.subsequence < OutboxEventRow.subsequence,
                ),
                and_(
                    earlier.transition_ordinal == OutboxEventRow.transition_ordinal,
                    earlier.subsequence == OutboxEventRow.subsequence,
                    earlier.created_at < OutboxEventRow.created_at,
                ),
                and_(
                    earlier.transition_ordinal == OutboxEventRow.transition_ordinal,
                    earlier.subsequence == OutboxEventRow.subsequence,
                    earlier.created_at == OutboxEventRow.created_at,
                    earlier.outbox_id < OutboxEventRow.outbox_id,
                ),
            )
            is_causal_head = ~exists(
                select(earlier.outbox_id).where(
                    earlier.run_id == OutboxEventRow.run_id,
                    or_(
                        earlier.status.not_in(("projected", "quarantined")),
                        and_(
                            earlier.status == "quarantined",
                            earlier.skip_receipt_id.is_(None),
                        ),
                    ),
                    causally_earlier,
                )
            ).correlate(OutboxEventRow)
            filters = [eligible, is_causal_head]
            if run_id is not None:
                filters.append(OutboxEventRow.run_id == run_id)
            query = (
                select(OutboxEventRow)
                .where(*filters)
                .order_by(
                    OutboxEventRow.run_id,
                    OutboxEventRow.transition_ordinal,
                    OutboxEventRow.subsequence,
                    OutboxEventRow.created_at,
                    OutboxEventRow.outbox_id,
                )
                .limit(self.batch_size)
            )
            if self.engine.dialect.name == "postgresql":
                query = query.with_for_update(skip_locked=True)
            rows = list(session.scalars(query).all())
            for row in rows:
                row.status = "projecting"
                row.owner_id = self.owner_id
                row.lease_until = claimed_at + timedelta(seconds=self.lease_seconds)
                row.attempts += 1
                row.last_error = None
                row.failure_class = None
                row.next_attempt_at = None
            session.commit()
            return [row.outbox_id for row in rows]

    def quarantine_and_skip(
        self,
        outbox_id: str,
        *,
        operator_id: str | None = None,
        operator: str | None = None,
        actor: str | None = None,
        reason: str,
        authorization: Any | None = None,
        authorization_ref: str | None = None,
        now: datetime | None = None,
    ) -> LedgerEvent:
        """Atomically quarantine one permanent outbox failure and append a skip.

        A malformed payload or a deterministic ledger dedupe conflict cannot be
        repaired by spinning the retry queue.  An operator may instead authorize
        a metadata-only ``outbox.skipped`` ledger receipt.  The receipt advances
        the hash chain without parsing or copying the bad payload, and the
        ``quarantined`` row becomes a causal terminal only after that receipt is
        durable in the same transaction.
        """

        effective_operator = operator_id or operator or actor
        if not isinstance(effective_operator, str) or not effective_operator.strip():
            raise OutboxOperatorAuthorizationError("operator identity is required to quarantine an outbox event")
        normalized_operator = effective_operator.strip()
        if not isinstance(reason, str) or not reason.strip():
            raise OutboxOperatorAuthorizationError("operator quarantine reason is required")
        normalized_reason = reason.strip()
        receipt_at = now or datetime.now(UTC)
        if receipt_at.tzinfo is None:
            receipt_at = receipt_at.replace(tzinfo=UTC)
        effective_authorization = authorization_ref or authorization
        if isinstance(effective_authorization, str):
            effective_authorization = effective_authorization.strip() or None

        with Session(self.engine) as session:
            self._begin_write(session)
            row = session.scalars(
                select(OutboxEventRow).where(OutboxEventRow.outbox_id == outbox_id).with_for_update()
            ).first()
            if row is None:
                raise KeyError(outbox_id)
            self._lock_run(session, row.run_id)
            # Re-lock after acquiring the run serialization domain.  This keeps
            # the row and ledger-head decision on one authoritative snapshot.
            row = session.scalars(
                select(OutboxEventRow).where(OutboxEventRow.outbox_id == outbox_id).with_for_update()
            ).first()
            if row is None:  # pragma: no cover - row was checked above
                raise KeyError(outbox_id)

            if row.status == "projected":
                raise OutboxOperatorAuthorizationError("projected outbox event cannot be quarantined")
            if row.status == "quarantined":
                if not row.skip_receipt_id:
                    raise OutboxProjectionError("quarantined outbox row has no skip receipt")
                receipt = session.get(EventRow, row.skip_receipt_id)
                if (
                    receipt is None
                    or receipt.run_id != row.run_id
                    or receipt.event_type != "outbox.skipped"
                    or row.skip_receipt_digest not in {None, receipt.hash}
                ):
                    raise OutboxProjectionError("quarantined outbox row skip receipt is missing")
                return _event_from_row(receipt)
            if row.status == "projecting" and row.lease_until is not None and _aware(row.lease_until) > receipt_at:
                raise OutboxOperatorAuthorizationError("active outbox projector lease must expire before quarantine")
            if row.status not in {"pending", "retry_wait", "failed", "dead_letter", "projecting"}:
                raise OutboxOperatorAuthorizationError(f"outbox event cannot be quarantined from state {row.status}")
            if row.status != "dead_letter" and row.failure_class not in {"payload_conflict", "payload_invalid"}:
                raise OutboxOperatorAuthorizationError(
                    "only a permanent payload/dedupe failure may be quarantined before dead-lettering"
                )

            earlier = aliased(OutboxEventRow)
            causally_earlier = or_(
                earlier.transition_ordinal < row.transition_ordinal,
                and_(
                    earlier.transition_ordinal == row.transition_ordinal,
                    earlier.subsequence < row.subsequence,
                ),
                and_(
                    earlier.transition_ordinal == row.transition_ordinal,
                    earlier.subsequence == row.subsequence,
                    earlier.created_at < row.created_at,
                ),
                and_(
                    earlier.transition_ordinal == row.transition_ordinal,
                    earlier.subsequence == row.subsequence,
                    earlier.created_at == row.created_at,
                    earlier.outbox_id < row.outbox_id,
                ),
            )
            unresolved = or_(
                earlier.status.not_in(("projected", "quarantined")),
                and_(earlier.status == "quarantined", earlier.skip_receipt_id.is_(None)),
            )
            blocked = session.scalars(
                select(earlier.outbox_id)
                .where(earlier.run_id == row.run_id, unresolved, causally_earlier)
                .order_by(earlier.transition_ordinal, earlier.subsequence, earlier.created_at, earlier.outbox_id)
                .limit(1)
            ).first()
            if blocked is not None:
                raise OutboxOperatorAuthorizationError(
                    f"causal predecessor {blocked} must be projected or skipped first"
                )

            payload_digest = row.payload_digest or hashlib.sha256(row.payload_json.encode("utf-8")).hexdigest()
            safe_receipt_payload = redact(
                {
                    "receipt_type": "outbox_skip",
                    "outbox_id": row.outbox_id,
                    "run_id": row.run_id,
                    "transition_id": row.transition_id,
                    "event_type": row.event_type,
                    "payload_digest": payload_digest,
                    "operator_id": normalized_operator,
                    "reason": normalized_reason,
                    "authorization_ref": effective_authorization,
                }
            )
            dedupe_key = f"outbox-skip:{row.outbox_id}"
            existing = session.scalars(
                select(EventRow).where(EventRow.run_id == row.run_id, EventRow.dedupe_key == dedupe_key)
            ).first()
            if existing is not None:
                if (
                    existing.event_type != "outbox.skipped"
                    or existing.actor != normalized_operator
                    or existing.payload_json != canonical_json(safe_receipt_payload)
                ):
                    raise LedgerDedupeConflict("outbox skip receipt conflicts with an existing ledger event")
                receipt = existing
            else:
                previous = session.scalars(
                    select(EventRow).where(EventRow.run_id == row.run_id).order_by(EventRow.sequence.desc()).limit(1)
                ).first()
                sequence = 1 if previous is None else previous.sequence + 1
                prev_hash = ZERO_HASH if previous is None else previous.hash
                event_id = str(uuid4())
                digest_input = {
                    "event_id": event_id,
                    "run_id": row.run_id,
                    "sequence": sequence,
                    "event_type": "outbox.skipped",
                    "timestamp": receipt_at.isoformat(),
                    "actor": normalized_operator,
                    "dedupe_key": dedupe_key,
                    "payload": safe_receipt_payload,
                    "prev_hash": prev_hash,
                }
                event_hash = hashlib.sha256(canonical_json(digest_input).encode()).hexdigest()
                receipt = EventRow(
                    event_id=event_id,
                    run_id=row.run_id,
                    sequence=sequence,
                    event_type="outbox.skipped",
                    timestamp=receipt_at,
                    actor=normalized_operator,
                    dedupe_key=dedupe_key,
                    payload_json=canonical_json(safe_receipt_payload),
                    prev_hash=prev_hash,
                    hash=event_hash,
                )
                session.add(receipt)
                session.flush()

            if self.fault_injector is not None:
                self.fault_injector("after-skip-receipt-before-outbox")

            row.payload_digest = payload_digest
            row.status = "quarantined"
            row.owner_id = None
            row.lease_until = None
            row.next_attempt_at = None
            row.failure_class = "operator_quarantine"
            row.dead_lettered_at = row.dead_lettered_at or receipt_at
            row.last_error = None
            row.quarantine_reason = normalized_reason
            row.quarantined_by = normalized_operator
            row.quarantined_at = receipt_at
            row.skip_receipt_id = receipt.event_id
            row.skip_receipt_digest = receipt.hash
            if self.engine.dialect.name == "postgresql":
                notification = canonical_json({"run_id": row.run_id, "sequence": receipt.sequence})
                session.execute(
                    text("SELECT pg_notify(:channel, :payload)"),
                    {"channel": LEDGER_WAKE_CHANNEL, "payload": notification},
                )
            session.commit()
            return _event_from_row(receipt)

    # Descriptive aliases are kept for recovery integrations that call the
    # operation by its terminal-state or receipt terminology.
    quarantine_outbox = quarantine_and_skip
    skip_outbox = quarantine_and_skip

    def retry_failed(
        self,
        outbox_id: str,
        *,
        operator_id: str | None = None,
        operator: str | None = None,
        actor: str | None = None,
        reason: str,
        expected_payload_digest: str | None = None,
        now: datetime | None = None,
    ) -> bool:
        """Authorize a bounded retry after an external cause is repaired."""

        effective_operator = operator_id or operator or actor
        if not isinstance(effective_operator, str) or not effective_operator.strip():
            raise OutboxOperatorAuthorizationError("operator identity is required to retry an outbox event")
        return CoordinatorStore(engine=self.engine, initialize_schema=False).retry_outbox(
            outbox_id,
            actor=effective_operator.strip(),
            reason=reason,
            expected_payload_digest=expected_payload_digest,
            now=now,
        )

    retry_failed_outbox = retry_failed
    finalize_failed = retry_failed

    def project_claimed(self, outbox_id: str, *, now: datetime | None = None) -> LedgerEvent:
        projected_at = now or datetime.now(UTC)
        with Session(self.engine) as session:
            self._begin_write(session)
            row = session.scalars(
                select(OutboxEventRow).where(OutboxEventRow.outbox_id == outbox_id).with_for_update()
            ).first()
            if row is None:
                raise KeyError(outbox_id)
            if row.status == "projected":
                existing = session.scalars(
                    select(EventRow).where(
                        EventRow.run_id == row.run_id,
                        EventRow.dedupe_key == f"transition:{row.transition_id}",
                    )
                ).first()
                if existing is None:
                    raise OutboxProjectionError("projected outbox row has no ledger event")
                return _event_from_row(existing)
            if row.status == "quarantined":
                if not row.skip_receipt_id:
                    raise OutboxProjectionError("quarantined outbox row has no skip receipt")
                receipt = session.get(EventRow, row.skip_receipt_id)
                if (
                    receipt is None
                    or receipt.run_id != row.run_id
                    or receipt.event_type != "outbox.skipped"
                    or row.skip_receipt_digest not in {None, receipt.hash}
                ):
                    raise OutboxProjectionError("quarantined outbox row skip receipt is missing")
                return _event_from_row(receipt)
            if row.status != "projecting" or row.owner_id != self.owner_id:
                raise OutboxProjectionError("outbox event is not leased by this projector")
            lease_until = row.lease_until
            if lease_until is None or _aware(lease_until) <= projected_at:
                raise OutboxProjectionError("outbox projector lease expired")
            self._lock_run(session, row.run_id)
            payload_digest = hashlib.sha256(row.payload_json.encode("utf-8")).hexdigest()
            if row.payload_digest is None:
                # Safe compatibility path for rows created before the digest
                # column existed.  New rows are bound by the mapper hook at
                # enqueue time, so later payload mutation is a hard conflict.
                row.payload_digest = payload_digest
            elif row.payload_digest != payload_digest:
                raise OutboxProjectionError("outbox payload digest conflict: JSON object payload changed")
            dedupe_key = f"transition:{row.transition_id}"
            safe_payload = redact(_object_payload(row.payload_json))
            safe_json = canonical_json(safe_payload)
            existing = session.scalars(
                select(EventRow).where(EventRow.run_id == row.run_id, EventRow.dedupe_key == dedupe_key)
            ).first()
            if existing is not None:
                if (
                    existing.event_type != row.event_type
                    or existing.actor != row.actor
                    or existing.payload_json != safe_json
                ):
                    raise LedgerDedupeConflict("outbox transition conflicts with an existing ledger event")
                event = _event_from_row(existing)
            else:
                previous = session.scalars(
                    select(EventRow).where(EventRow.run_id == row.run_id).order_by(EventRow.sequence.desc()).limit(1)
                ).first()
                sequence = 1 if previous is None else previous.sequence + 1
                prev_hash = ZERO_HASH if previous is None else previous.hash
                event_id = str(uuid4())
                digest_input = {
                    "event_id": event_id,
                    "run_id": row.run_id,
                    "sequence": sequence,
                    "event_type": row.event_type,
                    "timestamp": projected_at.isoformat(),
                    "actor": row.actor,
                    "dedupe_key": dedupe_key,
                    "payload": safe_payload,
                    "prev_hash": prev_hash,
                }
                event_hash = hashlib.sha256(canonical_json(digest_input).encode()).hexdigest()
                event_row = EventRow(
                    event_id=event_id,
                    run_id=row.run_id,
                    sequence=sequence,
                    event_type=row.event_type,
                    timestamp=projected_at,
                    actor=row.actor,
                    dedupe_key=dedupe_key,
                    payload_json=safe_json,
                    prev_hash=prev_hash,
                    hash=event_hash,
                )
                session.add(event_row)
                event = _event_from_row(event_row)
            if self.fault_injector is not None:
                self.fault_injector("after-ledger-before-outbox")
            row.status = "projected"
            row.projected_at = projected_at
            row.owner_id = None
            row.lease_until = None
            row.last_error = None
            if self.engine.dialect.name == "postgresql":
                notification = canonical_json({"run_id": row.run_id, "sequence": event.sequence})
                session.execute(
                    text("SELECT pg_notify(:channel, :payload)"),
                    {"channel": LEDGER_WAKE_CHANNEL, "payload": notification},
                )
            session.commit()
            return event

    async def project_available(self, *, run_id: str | None = None) -> list[LedgerEvent]:
        projected: list[LedgerEvent] = []
        for outbox_id in self.claim_batch(run_id=run_id):
            try:
                event = self.project_claimed(outbox_id)
            except Exception as exc:
                self._release_failure(outbox_id, exc)
                continue
            projected.append(event)
            if self.on_projected is not None:
                try:
                    result = self.on_projected(event)
                    if inspect.isawaitable(result):
                        await result
                except Exception as exc:
                    # Delivery is advisory. WebSocket/API consumers recover from
                    # the durable ledger by sequence and must not make projection fail.
                    logger.warning("projected event callback failed", extra={"error_type": type(exc).__name__})
        return projected

    async def serve(self, stop_event: asyncio.Event) -> None:
        try:
            while not stop_event.is_set():
                await self.project_available()
                if stop_event.is_set():
                    break
                # A timeout always causes another durable scan. A notification
                # only wakes this wait early and its payload is never consumed.
                try:
                    await self.wakeup.wait(self.poll_interval_seconds)
                except Exception:
                    # LISTEN is an optimization. Connection loss degrades to the
                    # same bounded safety-poll interval instead of stopping projection.
                    await asyncio.sleep(self.poll_interval_seconds)
        finally:
            with suppress(Exception):
                await self.wakeup.close()

    def _release_failure(self, outbox_id: str, error: Exception) -> None:
        failure_class = _failure_class(error)
        with Session(self.engine) as session:
            self._begin_write(session)
            row = session.scalars(
                select(OutboxEventRow).where(OutboxEventRow.outbox_id == outbox_id).with_for_update()
            ).first()
            if row is None or row.status != "projecting" or row.owner_id != self.owner_id:
                session.rollback()
                return
            now = datetime.now(UTC)
            if failure_class in {"payload_conflict", "payload_invalid"} or row.attempts >= self.max_attempts:
                row.status = "dead_letter"
                row.dead_lettered_at = now
                row.next_attempt_at = None
            else:
                row.status = "retry_wait"
                delay = min(
                    self.max_retry_backoff_seconds,
                    self.retry_backoff_seconds * (2 ** max(0, row.attempts - 1)),
                )
                row.next_attempt_at = now + timedelta(seconds=delay)
            row.owner_id = None
            row.lease_until = None
            row.failure_class = failure_class
            row.last_error = f"{type(error).__name__}: outbox projection failed"
            session.commit()

    def _begin_write(self, session: Session) -> None:
        if self.engine.dialect.name == "sqlite":
            session.execute(text("BEGIN IMMEDIATE"))

    def _lock_run(self, session: Session, run_id: str) -> None:
        if self.engine.dialect.name == "postgresql":
            # Projection participates in the same per-run serialization domain
            # as CoordinatorStore and InvestigationStore.  Using a second lock
            # namespace allowed a projector to change quiescence between a
            # completion snapshot read and its transactional recheck.
            session.execute(
                text("SELECT pg_advisory_xact_lock(hashtext(:lock_key))"),
                {"lock_key": f"secmind:coordinator:{run_id}"},
            )
            session.execute(
                text("SELECT pg_advisory_xact_lock(hashtext(:lock_key))"),
                {"lock_key": f"secmind:run:{run_id}"},
            )


def _object_payload(value: str) -> dict[str, Any]:
    try:
        payload = json.loads(value)
    except json.JSONDecodeError as exc:
        raise OutboxProjectionError("outbox payload is invalid JSON") from exc
    if not isinstance(payload, dict):
        raise OutboxProjectionError("outbox payload must be a JSON object")
    return payload


def _failure_class(error: Exception) -> str:
    """Classify a projector failure without persisting provider/raw details.

    Payload and dedupe conflicts are deterministic and must never spin through
    the retry queue.  Unknown exceptions remain retryable: this preserves
    recovery for transient database/notification faults while retaining only
    the safe exception type in ``last_error``.
    """

    if isinstance(error, LedgerDedupeConflict):
        return "payload_conflict"
    if isinstance(error, OutboxProjectionError):
        message = str(error).lower()
        if "digest conflict" in message or "dedupe" in message or "conflict" in message:
            return "payload_conflict"
        if "payload" in message or "json" in message or "object" in message:
            return "payload_invalid" if "invalid" in message or "json" in message else "payload_conflict"
    return "transient"


def _event_from_row(row: EventRow) -> LedgerEvent:
    return LedgerEvent(
        event_id=row.event_id,
        run_id=row.run_id,
        sequence=row.sequence,
        event_type=row.event_type,
        timestamp=_aware(row.timestamp),
        actor=row.actor,
        dedupe_key=row.dedupe_key,
        payload=json.loads(row.payload_json),
        prev_hash=row.prev_hash,
        hash=row.hash,
    )


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)
