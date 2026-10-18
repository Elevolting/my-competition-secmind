"""Rebuildable, task-scoped search projection over durable execution events."""
from __future__ import annotations

import json
from typing import Any

from sqlalchemy import Integer, String, Text, delete, func, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from security_agent.ledger import Base, LedgerStore, canonical_json
from security_agent.trace_redaction import redact_trace


class TraceRow(Base):
    __tablename__ = "execution_traces"

    run_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    trace_id: Mapped[str] = mapped_column(String(200), primary_key=True)
    sequence: Mapped[int] = mapped_column(Integer, index=True)
    module: Mapped[str] = mapped_column(String(50), index=True)
    worker: Mapped[str] = mapped_column(String(200), index=True)
    intent_id: Mapped[str | None] = mapped_column(String(200))
    attempt_id: Mapped[str | None] = mapped_column(String(200))
    step_id: Mapped[str | None] = mapped_column(String(200))
    tool: Mapped[str | None] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(String(50))
    timestamp: Mapped[str] = mapped_column(String(100))
    event_type: Mapped[str] = mapped_column(String(100))
    summary: Mapped[str] = mapped_column(Text)
    payload_json: Mapped[str] = mapped_column(Text)
    output_state: Mapped[str] = mapped_column(String(20))


class TraceCursorRow(Base):
    __tablename__ = "execution_trace_cursors"

    run_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    sequence: Mapped[int] = mapped_column(Integer, default=0)


def _truncated(value: Any) -> bool:
    if isinstance(value, dict):
        return any(item is True for key, item in value.items()
                   if key in {"truncated", "output_truncated"}) or any(_truncated(item) for item in value.values())
    return isinstance(value, list) and any(_truncated(item) for item in value)


def _public_content(payload: dict) -> Any:
    if payload.get("output_available") is False:
        return None
    for key in ("summary", "content", "output", "result", "data", "description", "error"):
        if payload.get(key) is not None:
            return payload[key]
    return None


class TraceStore:
    def __init__(self, ledger: LedgerStore, importer=None):
        self.ledger, self.importer = ledger, importer
        Base.metadata.create_all(ledger.engine)

    def sync(self, run_id: str, *, rebuild: bool = False) -> None:
        state = self.ledger.load_state(run_id)
        if state is None:
            raise KeyError(run_id)
        if self.importer:
            self.importer.sync(run_id)
        with self.ledger._lock_for(run_id), Session(self.ledger.engine) as session:
            cursor = session.get(TraceCursorRow, run_id)
            if cursor is None:
                cursor = TraceCursorRow(run_id=run_id, sequence=0)
                session.add(cursor)
            if rebuild:
                session.execute(delete(TraceRow).where(TraceRow.run_id == run_id))
                cursor.sequence = 0
            while True:
                events = self.ledger.events(run_id, after_sequence=cursor.sequence, limit=500)
                for event in events:
                    cursor.sequence = event.sequence
                    kind = event.event_type
                    if not kind.startswith(("tool.", "mcp.call.", "runtime.", "worker.trace.",
                                            "agent.thought", "agent.instruction", "llm.stream.")):
                        continue
                    if kind.startswith("llm.stream.") and not kind.endswith(("completed", "failed")):
                        continue
                    payload = redact_trace(event.payload)
                    binding = payload.get("blackboard") or {}
                    if not isinstance(binding, dict):
                        binding = {}
                    public = _public_content(payload)
                    content = (public if isinstance(public, str) else canonical_json(public)
                               if public is not None else "记录不可用")
                    output_state = ("truncated" if _truncated(payload) else
                                    "complete" if public is not None else "unavailable")
                    session.add(TraceRow(
                        run_id=run_id, trace_id=event.event_id, sequence=event.sequence,
                        module=state.module_route or state.scenario.value,
                        worker=str(payload.get("worker") or binding.get("worker") or event.actor),
                        intent_id=payload.get("intent_id") or binding.get("intent_id"),
                        attempt_id=payload.get("attempt_id") or binding.get("attempt_id"),
                        step_id=payload.get("step_id") or binding.get("step_id"),
                        tool=payload.get("tool") or payload.get("tool_name"),
                        status=str(payload.get("status") or kind.rsplit(".", 1)[-1]),
                        timestamp=str(payload.get("occurred_at") or payload.get("timestamp")
                                      or event.timestamp.isoformat()),
                        event_type=kind, summary=content[:700], payload_json=canonical_json(payload),
                        output_state=output_state,
                    ))
                session.flush()
                if len(events) < 500:
                    break
            session.commit()

    @staticmethod
    def _item(row: TraceRow) -> dict:
        return {key: getattr(row, key) for key in (
            "run_id", "trace_id", "sequence", "module", "worker", "intent_id", "attempt_id", "step_id",
            "tool", "status", "timestamp", "event_type", "summary", "output_state")}

    def search(self, run_id: str, *, keyword: str = "", module: str | None = None,
               worker: str | None = None, cursor: int = 0, limit: int = 50,
               exclude_intent: str | None = None) -> dict:
        if cursor < 0 or not 1 <= limit <= 100 or len(keyword) > 500:
            raise ValueError("无效的检索参数")
        self.sync(run_id)
        query = select(TraceRow).where(TraceRow.run_id == run_id, TraceRow.sequence > cursor)
        if keyword:
            query = query.where(func.lower(TraceRow.payload_json).contains(keyword.lower(), autoescape=True))
        if module:
            query = query.where(TraceRow.module == module)
        if worker:
            query = query.where(TraceRow.worker == worker)
        if exclude_intent:
            query = query.where((TraceRow.intent_id.is_(None)) | (TraceRow.intent_id != exclude_intent))
        with Session(self.ledger.engine) as session:
            rows = session.scalars(query.order_by(TraceRow.sequence).limit(limit + 1)).all()
            items = [self._item(row) for row in rows[:limit]]
            for item, row in zip(items, rows, strict=False):
                if keyword:
                    at = row.payload_json.lower().find(keyword.lower())
                    item["match_excerpt"] = row.payload_json[max(0, at - 100):at + len(keyword) + 200]
            return {"items": items, "next_cursor": rows[limit - 1].sequence if len(rows) > limit else None}

    def detail(self, run_id: str, trace_id: str) -> dict:
        self.sync(run_id)
        with Session(self.ledger.engine) as session:
            row = session.get(TraceRow, (run_id, trace_id))
            if row is None:
                raise KeyError(trace_id)
            return {**self._item(row), "payload": json.loads(row.payload_json)}
