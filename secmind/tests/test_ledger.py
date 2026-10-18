from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from secmind.ledger import EventRow, LedgerStore
from secmind.schemas import AgentState, RunStatus, TaskRequest


def test_hash_chain_and_redaction(settings) -> None:
    ledger = LedgerStore(settings.database_url)
    ledger.append("run", "one", {"api_key": "secret-value"})
    ledger.append("run", "two", {"authorization": "Bearer abcdefghijklmnop"})
    events = ledger.events("run")
    assert events[0].payload["api_key"] == "[REDACTED]"
    assert "abcdefghijklmnop" not in str(events[1].payload)
    assert ledger.verify("run")


def test_tampered_chain_is_detected(settings) -> None:
    ledger = LedgerStore(settings.database_url)
    ledger.append("run", "one", {"value": 1})
    with Session(ledger.engine) as session:
        row = session.scalars(select(EventRow).where(EventRow.run_id == "run")).first()
        assert row is not None
        row.payload_json = '{"value":2}'
        session.commit()
    assert not ledger.verify("run")


def test_state_snapshot_incomplete_and_export(settings, tmp_path) -> None:
    ledger = LedgerStore(settings.database_url)
    state = AgentState(run_id="snapshot", task=TaskRequest(objective="audit code"))
    ledger.save_state(state)
    assert ledger.load_state("snapshot") == state
    assert "snapshot" in ledger.incomplete_run_ids()
    ledger.append("snapshot", "created", {"value": 1})
    destination = ledger.export_jsonl("snapshot", tmp_path / "events.jsonl")
    assert '"event_type":"created"' in destination.read_text(encoding="utf-8")
    state.status = RunStatus.COMPLETED
    ledger.save_state(state)
    assert "snapshot" not in ledger.incomplete_run_ids()
    assert ledger.load_state("does-not-exist") is None
