from __future__ import annotations

import asyncio
import concurrent.futures
import json
import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from secmind.coordinator import CoordinatorStore, OutboxEventRow, RunJobRow
from secmind.ledger import LedgerStore
from secmind.outbox_projector import OutboxProjector
from secmind.schemas import AgentState, TaskRequest
from secmind.unit_of_work import ControlPlaneUnitOfWork, ProjectionHeadRow


def _sqlite_stores(tmp_path):
    url = f"sqlite:///{(tmp_path / 'outbox-quarantine.db').as_posix()}"
    return CoordinatorStore(url), LedgerStore(url)


@pytest.mark.asyncio
async def test_permanent_payload_is_quarantined_with_ordered_skip_receipt(tmp_path) -> None:
    coordinator, ledger = _sqlite_stores(tmp_path)
    bad_id = coordinator.enqueue_outbox(
        "run-quarantine",
        transition_id="bad-transition",
        event_type="run.bad",
        payload={"value": "immutable"},
    )
    good_id = coordinator.enqueue_outbox(
        "run-quarantine",
        transition_id="good-transition",
        event_type="run.good",
        payload={"value": "next"},
    )
    with Session(coordinator.engine) as session:
        bad = session.get(OutboxEventRow, bad_id)
        good = session.get(OutboxEventRow, good_id)
        assert bad is not None and good is not None
        bad.payload_json = json.dumps(["permanent", "payload"])
        bad.transition_ordinal = 1
        good.transition_ordinal = 2
        session.commit()

    projector = OutboxProjector(coordinator.engine, owner_id="operator-test", max_attempts=1)
    await projector.project_available(run_id="run-quarantine")
    assert projector.claim_batch(run_id="run-quarantine") == []

    receipt = projector.quarantine_and_skip(
        bad_id,
        operator_id="operator:test",
        reason="payload is permanently malformed",
        authorization_ref="ticket:test",
    )
    assert receipt.event_type == "outbox.skipped"
    assert receipt.payload["payload_digest"]
    assert "immutable" not in json.dumps(receipt.payload)
    assert projector.claim_batch(run_id="run-quarantine") == [good_id]
    projector.project_claimed(good_id)

    assert ledger.verify("run-quarantine")
    assert [event.event_type for event in ledger.events("run-quarantine")] == [
        "outbox.skipped",
        "run.good",
    ]
    assert coordinator.pending_outbox_ordinals("run-quarantine") == []
    assert (
        projector.quarantine_and_skip(bad_id, operator_id="different", reason="replayed").event_id == receipt.event_id
    )


def test_quarantine_receipt_and_outbox_state_rollback_together(tmp_path) -> None:
    coordinator, ledger = _sqlite_stores(tmp_path)
    outbox_id = coordinator.enqueue_outbox(
        "run-quarantine-rollback",
        transition_id="bad-transition",
        event_type="run.bad",
        payload={"value": 1},
    )
    with Session(coordinator.engine) as session:
        row = session.get(OutboxEventRow, outbox_id)
        assert row is not None
        row.payload_json = "not-json"
        session.commit()
    projector = OutboxProjector(
        coordinator.engine,
        owner_id="operator-test",
        max_attempts=1,
        fault_injector=lambda point: (_ for _ in ()).throw(RuntimeError(point)),
    )
    asyncio.run(projector.project_available(run_id="run-quarantine-rollback"))
    with pytest.raises(RuntimeError, match="after-skip-receipt-before-outbox"):
        projector.quarantine_and_skip(outbox_id, operator_id="operator:test", reason="rollback test")
    with Session(coordinator.engine) as session:
        row = session.get(OutboxEventRow, outbox_id)
        assert row is not None and row.status == "dead_letter" and row.skip_receipt_id is None
    assert ledger.events("run-quarantine-rollback") == []


def test_external_cause_retry_is_audited_and_replayable(tmp_path) -> None:
    coordinator, ledger = _sqlite_stores(tmp_path)
    outbox_id = coordinator.enqueue_outbox(
        "run-external-retry",
        transition_id="external-transition",
        event_type="run.external",
        payload={"value": 1},
    )
    projector = OutboxProjector(coordinator.engine, owner_id="retry-test", retry_backoff_seconds=0)
    projector.fault_injector = lambda _point: (_ for _ in ()).throw(RuntimeError("temporary database outage"))
    asyncio.run(projector.project_available(run_id="run-external-retry"))
    assert projector.retry_failed(
        outbox_id,
        operator_id="operator:test",
        reason="external database outage repaired",
    )
    recovered = OutboxProjector(coordinator.engine, owner_id="recovered", retry_backoff_seconds=0)
    assert len(asyncio.run(recovered.project_available(run_id="run-external-retry"))) == 1
    assert len(asyncio.run(recovered.project_available(run_id="run-external-retry"))) == 1
    assert ledger.verify("run-external-retry")


@pytest.mark.integration
def test_postgres_quarantine_concurrency_and_projection_receipt_cas() -> None:
    database_url = os.getenv("SECMIND_TEST_DATABASE_URL")
    if not database_url:
        pytest.fail("PostgreSQL integration requires SECMIND_TEST_DATABASE_URL")
    coordinator = CoordinatorStore(database_url, initialize_schema=False)
    ledger = LedgerStore(database_url, initialize_schema=False)

    run_id = uuid4().hex
    bad_id = coordinator.enqueue_outbox(run_id, transition_id="bad", event_type="run.bad", payload={"v": 1})
    good_id = coordinator.enqueue_outbox(run_id, transition_id="good", event_type="run.good", payload={"v": 2})
    with Session(coordinator.engine) as session:
        bad = session.get(OutboxEventRow, bad_id)
        good = session.get(OutboxEventRow, good_id)
        assert bad is not None and good is not None
        bad.payload_json = '["bad"]'
        bad.transition_ordinal = 1
        good.transition_ordinal = 2
        session.commit()
    projector = OutboxProjector(coordinator.engine, owner_id="pg-projector", max_attempts=1)
    asyncio.run(projector.project_available(run_id=run_id))

    operators = [OutboxProjector(coordinator.engine, owner_id=f"pg-operator-{index}") for index in range(2)]

    def quarantine(index: int):
        return operators[index].quarantine_and_skip(
            bad_id,
            operator_id="operator:pg",
            reason="permanent malformed payload",
            authorization_ref="ticket:pg",
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        receipts = list(executor.map(quarantine, range(2)))
    assert receipts[0].event_id == receipts[1].event_id
    assert projector.claim_batch(run_id=run_id) == [good_id]
    projector.project_claimed(good_id)
    assert ledger.verify(run_id)
    assert coordinator.pending_outbox_ordinals(run_id) == []

    cas_run_id = uuid4().hex
    state = AgentState(run_id=cas_run_id, task=TaskRequest(objective="audit", target_scope=["src"]))
    uow = ControlPlaneUnitOfWork(coordinator.engine, initialize_schema=False)
    assert uow.submit_run(state)
    uow.persist_cognitive_projection(state)
    owner_id = "pg-cas-worker"
    with Session(coordinator.engine) as session:
        job = session.get(RunJobRow, cas_run_id)
        assert job is not None
        job.status = "leased"
        job.owner_id = owner_id
        job.fence = 1
        job.lease_until = datetime.now(UTC) + timedelta(minutes=1)
        session.commit()
    newer = state.model_copy(deep=True)
    newer.lease.fence = 1
    coordinator.commit_transition(
        newer,
        expected_version=1,
        owner_id=owner_id,
        fence=1,
        transition_id="cas-transition",
        event_type="run.updated",
        payload={"state_version": 2},
    )
    with Session(coordinator.engine) as session:
        receipt = session.scalar(
            select(OutboxEventRow).where(
                OutboxEventRow.run_id == cas_run_id,
                OutboxEventRow.transition_id == "cas-transition",
            )
        )
        assert receipt is not None
        receipt_id = receipt.outbox_id
    newer.state_version = 2
    uow.persist_cognitive_projection(newer, source_transition_id="cas-transition", outbox_receipt_id=receipt_id)

    def replay_projection() -> None:
        ControlPlaneUnitOfWork(coordinator.engine, initialize_schema=False).persist_cognitive_projection(
            newer,
            source_transition_id="cas-transition",
            outbox_receipt_id=receipt_id,
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        list(executor.map(lambda _index: replay_projection(), range(2)))
    uow.persist_cognitive_projection(state)
    with Session(coordinator.engine) as session:
        head = session.get(ProjectionHeadRow, cas_run_id)
        assert head is not None
        assert head.source_state_version == 2
        assert head.source_fence == 1
        assert head.source_transition_id == "cas-transition"
        assert head.outbox_receipt_id == receipt_id
