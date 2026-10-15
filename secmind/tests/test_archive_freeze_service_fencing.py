from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine, update
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from secmind.coordinator import CoordinatorBase, CoordinatorStore, RunJobRow
from secmind.investigation.store import InvestigationBase, InvestigationStore
from secmind.ledger import Base, LedgerFrozenError, RunFreezeRow, RunRow
from secmind.schemas import AgentState, TaskRequest


def _engine():
    engine = create_engine(
        "sqlite://",
        future=True,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    CoordinatorBase.metadata.create_all(engine)
    InvestigationBase.metadata.create_all(engine)
    return engine


def _seed_run(engine, run_id: str, *, status: str = "complete") -> None:
    now = datetime.now(UTC)
    state = AgentState(run_id=run_id, task=TaskRequest(objective="freeze fencing"))
    with Session(engine) as session:
        session.add(
            RunRow(
                run_id=run_id,
                status=state.status.value,
                state_version=state.state_version,
                state_json=state.model_dump_json(),
                created_at=now,
                updated_at=now,
            )
        )
        session.add(
            RunJobRow(
                run_id=run_id,
                status="queued",
                next_attempt_at=now,
                attempts=0,
                created_at=now,
                updated_at=now,
            )
        )
        session.add(
            RunFreezeRow(
                run_id=run_id,
                freeze_id=f"freeze:{run_id}",
                status=status,
                state_version=state.state_version,
                latest_event_sequence=0,
                ledger_head_hash="0" * 64,
                frozen_at=now,
            )
        )
        session.commit()


def test_frozen_run_is_not_claimed_and_aborted_freeze_reopens_queue() -> None:
    engine = _engine()
    try:
        _seed_run(engine, "run-fenced")
        coordinator = CoordinatorStore(engine=engine, initialize_schema=False)

        assert coordinator.claim_jobs("worker") == []

        with Session(engine) as session:
            session.execute(
                update(RunFreezeRow).where(RunFreezeRow.run_id == "run-fenced").values(status="aborted")
            )
            session.commit()

        leases = coordinator.claim_jobs("worker")
        assert len(leases) == 1
        assert leases[0].run_id == "run-fenced"
    finally:
        engine.dispose()


def test_investigation_object_writes_are_fenced_until_abort() -> None:
    engine = _engine()
    try:
        _seed_run(engine, "run-investigation")
        store = InvestigationStore(engine=engine, initialize_schema=False)
        contract = AgentState(run_id="run-investigation", task=TaskRequest(objective="object"))

        with pytest.raises(LedgerFrozenError, match="frozen for archive"):
            store.put_object(
                contract,
                run_id="run-investigation",
                object_type="state",
                object_id="state-1",
                logical_key="state",
            )

        with Session(engine) as session:
            session.execute(
                update(RunFreezeRow).where(RunFreezeRow.run_id == "run-investigation").values(status="aborted")
            )
            session.commit()

        assert (
            store.put_object(
                contract,
                run_id="run-investigation",
                object_type="state",
                object_id="state-1",
                logical_key="state",
            )
            == "state-1"
        )
    finally:
        engine.dispose()
