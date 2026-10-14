from __future__ import annotations

import asyncio
import json
import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from secmind.coordinator import CoordinatorStore, OutboxEventRow
from secmind.ledger import EventRow, LedgerStore
from secmind.outbox_projector import (
    OUTBOX_WAKE_CHANNEL,
    LocalNotificationWakeup,
    OutboxProjectionError,
    OutboxProjector,
    PollingWakeup,
    PostgresNotificationWakeup,
)


def _stores(tmp_path):
    url = f"sqlite:///{(tmp_path / 'projector.db').as_posix()}"
    coordinator = CoordinatorStore(url)
    ledger = LedgerStore(url)
    return coordinator, ledger


@pytest.mark.asyncio
async def test_projector_atomically_appends_ledger_and_marks_outbox(tmp_path) -> None:
    coordinator, ledger = _stores(tmp_path)
    coordinator.enqueue_outbox(
        "run-project",
        transition_id="transition-1",
        event_type="tool.completed",
        payload={"api_key": "must-not-leak", "status": "success"},
        actor="tool-broker",
    )
    published = []
    projector = OutboxProjector(
        coordinator.engine,
        owner_id="projector-a",
        on_projected=lambda event: published.append(event),
    )

    projected = await projector.project_available()

    assert len(projected) == 1 and projected == published
    assert projected[0].payload["api_key"] == "[REDACTED]"
    assert ledger.verify("run-project")
    with Session(coordinator.engine) as session:
        outbox = session.scalars(select(OutboxEventRow)).one()
        events = session.scalars(select(EventRow)).all()
        assert outbox.status == "projected" and outbox.projected_at is not None
        assert outbox.owner_id is None and outbox.lease_until is None
        assert len(events) == 1 and events[0].dedupe_key == "transition:transition-1"


@pytest.mark.asyncio
async def test_fault_between_ledger_and_outbox_rolls_back_both_then_retries(tmp_path) -> None:
    coordinator, ledger = _stores(tmp_path)
    coordinator.enqueue_outbox(
        "run-fault",
        transition_id="transition-fault",
        event_type="run.updated",
        payload={"status": "running"},
    )

    def fail(point: str) -> None:
        assert point == "after-ledger-before-outbox"
        raise RuntimeError("simulated crash")

    crashing = OutboxProjector(
        coordinator.engine,
        owner_id="projector-crash",
        max_attempts=3,
        retry_backoff_seconds=0,
        fault_injector=fail,
    )
    assert await crashing.project_available() == []
    assert ledger.events("run-fault") == []
    with Session(coordinator.engine) as session:
        outbox = session.scalars(select(OutboxEventRow)).one()
        assert outbox.status == "retry_wait" and outbox.last_error == "RuntimeError: outbox projection failed"

    recovered = OutboxProjector(coordinator.engine, owner_id="projector-recovered")
    assert len(await recovered.project_available()) == 1
    assert ledger.verify("run-fault")


def test_outbox_lease_prevents_two_projectors_claiming_same_event(tmp_path) -> None:
    coordinator, _ledger = _stores(tmp_path)
    outbox_id = coordinator.enqueue_outbox(
        "run-lease",
        transition_id="transition-lease",
        event_type="run.updated",
        payload={},
    )
    first = OutboxProjector(coordinator.engine, owner_id="projector-1")
    second = OutboxProjector(coordinator.engine, owner_id="projector-2")

    assert first.claim_batch() == [outbox_id]
    assert second.claim_batch() == []
    event = first.project_claimed(outbox_id)
    assert event.sequence == 1
    assert second.claim_batch() == []


@pytest.mark.asyncio
async def test_notification_is_only_wakeup_and_safety_poll_still_projects(tmp_path) -> None:
    coordinator, ledger = _stores(tmp_path)
    coordinator.enqueue_outbox(
        "run-poll",
        transition_id="transition-poll",
        event_type="run.updated",
        payload={"value": 1},
    )
    wakeup = LocalNotificationWakeup()
    projector = OutboxProjector(
        coordinator.engine,
        owner_id="projector-poll",
        poll_interval_seconds=0.01,
        wakeup=wakeup,
    )
    stop = asyncio.Event()

    async def stop_soon() -> None:
        await asyncio.sleep(0.03)
        stop.set()

    await asyncio.gather(projector.serve(stop), stop_soon())
    assert len(ledger.events("run-poll")) == 1


def test_invalid_outbox_payload_never_enters_ledger(tmp_path) -> None:
    coordinator, ledger = _stores(tmp_path)
    outbox_id = coordinator.enqueue_outbox(
        "run-invalid",
        transition_id="transition-invalid",
        event_type="run.updated",
        payload={},
    )
    with Session(coordinator.engine) as session:
        row = session.get(OutboxEventRow, outbox_id)
        assert row is not None
        row.payload_json = json.dumps(["not", "an", "object"])
        session.commit()
    projector = OutboxProjector(coordinator.engine, owner_id="projector-invalid", max_attempts=1)
    claimed = projector.claim_batch()
    assert claimed == [outbox_id]
    with pytest.raises(Exception, match="JSON object"):
        projector.project_claimed(outbox_id)
    assert ledger.events("run-invalid") == []


@pytest.mark.asyncio
async def test_wakeup_adapters_do_not_treat_payload_as_state(monkeypatch: pytest.MonkeyPatch) -> None:
    polling = PollingWakeup()
    assert await polling.wait(0.001) is False
    await polling.close()
    local = LocalNotificationWakeup()
    local.signal()
    assert await local.wait(0.01) is True
    assert await local.wait(0.001) is False

    class FakeConnection:
        def __init__(self) -> None:
            self.executed: list[str] = []
            self.closed = False

        async def execute(self, statement: str) -> None:
            self.executed.append(statement)

        async def notifies(self):
            yield object()
            await asyncio.Event().wait()

        async def close(self) -> None:
            self.closed = True

    connection = FakeConnection()

    async def connect(*_args, **_kwargs):
        return connection

    monkeypatch.setattr("psycopg.AsyncConnection.connect", connect)
    postgres = PostgresNotificationWakeup("postgresql://test")
    assert await postgres.wait(0.1) is True
    assert connection.executed == [f"LISTEN {OUTBOX_WAKE_CHANNEL}"]
    await postgres.close()
    assert connection.closed is True
    with pytest.raises(ValueError, match="channel"):
        PostgresNotificationWakeup("postgresql://test", channel="bad;drop")


def test_projector_rejects_invalid_config_wrong_owner_and_expired_lease(tmp_path) -> None:
    coordinator, _ledger = _stores(tmp_path)
    with pytest.raises(ValueError, match="configuration"):
        OutboxProjector(coordinator.engine, owner_id="", batch_size=0)
    outbox_id = coordinator.enqueue_outbox(
        "run-owner",
        transition_id="transition-owner",
        event_type="run.updated",
        payload={},
    )
    claimed_at = datetime.now(UTC)
    owner = OutboxProjector(coordinator.engine, owner_id="owner", lease_seconds=1)
    intruder = OutboxProjector(coordinator.engine, owner_id="intruder")
    assert owner.claim_batch(now=claimed_at) == [outbox_id]
    with pytest.raises(OutboxProjectionError, match="not leased"):
        intruder.project_claimed(outbox_id, now=claimed_at)
    with pytest.raises(OutboxProjectionError, match="expired"):
        owner.project_claimed(outbox_id, now=claimed_at + timedelta(seconds=2))


@pytest.mark.asyncio
async def test_projection_is_idempotent_and_callback_failure_is_advisory(tmp_path) -> None:
    coordinator, ledger = _stores(tmp_path)
    outbox_id = coordinator.enqueue_outbox(
        "run-idempotent",
        transition_id="transition-idempotent",
        event_type="run.updated",
        payload={"value": 1},
    )

    def callback(_event):
        raise RuntimeError("delivery failure")

    projector = OutboxProjector(
        coordinator.engine,
        owner_id="projector-idempotent",
        on_projected=callback,
    )
    projected = await projector.project_available()
    assert len(projected) == 1
    assert projector.project_claimed(outbox_id).event_id == projected[0].event_id
    assert len(ledger.events("run-idempotent")) == 1


@pytest.mark.asyncio
async def test_terminal_projection_failure_stops_retrying(tmp_path) -> None:
    coordinator, _ledger = _stores(tmp_path)
    coordinator.enqueue_outbox(
        "run-terminal",
        transition_id="transition-terminal",
        event_type="run.updated",
        payload={},
    )
    projector = OutboxProjector(
        coordinator.engine,
        owner_id="projector-terminal",
        max_attempts=1,
        fault_injector=lambda _: (_ for _ in ()).throw(RuntimeError("fail")),
    )
    assert await projector.project_available() == []
    assert projector.claim_batch() == []
    with Session(coordinator.engine) as session:
        assert session.scalars(select(OutboxEventRow)).one().status == "dead_letter"


@pytest.mark.asyncio
async def test_failed_outbox_uses_backoff_then_dead_letters(tmp_path) -> None:
    coordinator, ledger = _stores(tmp_path)
    outbox_id = coordinator.enqueue_outbox(
        "run-backoff",
        transition_id="transition-backoff",
        event_type="run.updated",
        payload={"status": "running"},
    )
    projector = OutboxProjector(
        coordinator.engine,
        owner_id="projector-backoff",
        max_attempts=2,
        retry_backoff_seconds=10,
        max_retry_backoff_seconds=10,
        fault_injector=lambda _: (_ for _ in ()).throw(RuntimeError("transient")),
    )

    assert await projector.project_available() == []
    with Session(coordinator.engine) as session:
        row = session.get(OutboxEventRow, outbox_id)
        assert row is not None
        assert row.status == "retry_wait"
        assert row.failure_class == "transient"
        assert row.next_attempt_at is not None
        retry_at = row.next_attempt_at
    assert projector.claim_batch(now=retry_at - timedelta(seconds=1)) == []
    assert projector.claim_batch(now=retry_at + timedelta(seconds=1)) == [outbox_id]
    with pytest.raises(RuntimeError):
        projector.project_claimed(outbox_id)
    projector._release_failure(outbox_id, RuntimeError("transient"))  # noqa: SLF001

    with Session(coordinator.engine) as session:
        row = session.get(OutboxEventRow, outbox_id)
        assert row is not None and row.status == "dead_letter"
        assert row.failure_class == "transient"
    assert ledger.events("run-backoff") == []


@pytest.mark.asyncio
async def test_payload_digest_conflict_is_dead_lettered_without_ledger_write(tmp_path) -> None:
    coordinator, ledger = _stores(tmp_path)
    outbox_id = coordinator.enqueue_outbox(
        "run-payload-conflict",
        transition_id="transition-payload-conflict",
        event_type="run.updated",
        payload={"status": "running"},
    )
    with Session(coordinator.engine) as session:
        row = session.get(OutboxEventRow, outbox_id)
        assert row is not None
        row.payload_json = json.dumps({"status": "tampered"})
        session.commit()
    projector = OutboxProjector(coordinator.engine, owner_id="projector-payload-conflict", max_attempts=3)
    assert await projector.project_available() == []
    with Session(coordinator.engine) as session:
        row = session.get(OutboxEventRow, outbox_id)
        assert row is not None
        assert row.status == "dead_letter"
        assert row.failure_class == "payload_conflict"
    assert ledger.events("run-payload-conflict") == []


@pytest.mark.integration
@pytest.mark.asyncio
async def test_postgres_projection_and_notify_wakeup_use_database_as_source_of_truth() -> None:
    database_url = os.getenv("SECMIND_TEST_DATABASE_URL")
    if not database_url:
        pytest.fail("PostgreSQL integration requires SECMIND_TEST_DATABASE_URL")
    coordinator = CoordinatorStore(database_url, initialize_schema=False)
    ledger = LedgerStore(database_url, initialize_schema=False)
    run_id = str(uuid4())
    coordinator.enqueue_outbox(
        run_id,
        transition_id="postgres-transition",
        event_type="run.updated",
        payload={"status": "running"},
    )
    first = OutboxProjector(coordinator.engine, owner_id="postgres-projector-1")
    second = OutboxProjector(coordinator.engine, owner_id="postgres-projector-2")
    claimed = first.claim_batch(run_id=run_id)
    assert len(claimed) == 1 and second.claim_batch(run_id=run_id) == []
    first.project_claimed(claimed[0])
    assert ledger.verify(run_id) and len(ledger.events(run_id)) == 1

    connection_url = database_url.replace("postgresql+psycopg://", "postgresql://", 1)
    wakeup = PostgresNotificationWakeup(connection_url)
    await wakeup.start()
    with Session(coordinator.engine) as session:
        session.execute(
            text("SELECT pg_notify(:channel, :payload)"),
            {"channel": OUTBOX_WAKE_CHANNEL, "payload": "untrusted-payload-is-ignored"},
        )
        session.commit()
    assert await wakeup.wait(2.0) is True
    await wakeup.close()
