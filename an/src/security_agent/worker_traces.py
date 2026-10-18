"""Import task-bound public Worker records from the Dispatcher journal."""
from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from sqlalchemy.orm import Session

from security_agent.ledger import RunRow


class WorkerTraceImporter:
    def __init__(self, ledger, journal: Path):
        self.ledger, self.journal = ledger, journal

    def sync(self, run_id: str) -> None:
        state = self.ledger.load_state(run_id)
        if state is None:
            raise KeyError(run_id)
        board = state.external_execution.get("blackboard") or {}
        project_id = board.get("project_id") or state.external_execution.get("project_id")
        if not project_id or not self.journal.is_file():
            return
        events = self.ledger.events(run_id, limit=1_000_000)
        attempts = {event.payload.get("attempt_id") for event in events
                    if event.event_type.startswith("runtime.")}
        attempts.discard(None)
        with Session(self.ledger.engine) as session:
            row = session.get(RunRow, run_id)
            start = row.created_at.replace(tzinfo=UTC) if row.created_at.tzinfo is None else row.created_at
            terminal = state.status.value in {"completed", "partial", "failed", "denied"}
            end = row.updated_at if terminal else datetime.now(UTC)
        end = end.replace(tzinfo=UTC) if end.tzinfo is None else end
        try:
            with closing(sqlite3.connect(self.journal.resolve().as_uri() + "?mode=ro", uri=True, timeout=2)) as conn:
                for trace_id, raw in conn.execute(
                    "SELECT trace_id,payload_json FROM worker_traces WHERE project_id=? ORDER BY sequence",
                    (project_id,),
                ):
                    payload = json.loads(raw)
                    if not isinstance(payload, dict) or payload.get("project_id") != project_id:
                        continue
                    if payload.get("attempt_id"):
                        if payload["attempt_id"] not in attempts:
                            continue
                    else:
                        occurred = datetime.fromisoformat(payload["occurred_at"]).astimezone(UTC)
                        if not start <= occurred <= end:
                            continue
                    identity = str(uuid5(NAMESPACE_URL, str(self.journal.resolve()) + ":" + run_id + ":" + trace_id))
                    self.ledger.append(run_id, "worker.trace." + payload.get("status", "unknown"), payload,
                                       actor="security_runtime_worker", event_id=identity)
        except sqlite3.OperationalError as exc:
            if "no such table" not in str(exc):
                raise
