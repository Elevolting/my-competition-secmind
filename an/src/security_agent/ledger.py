from __future__ import annotations

import hashlib
import json
import re
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from sqlalchemy import (
    DateTime,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    UniqueConstraint,
    case,
    create_engine,
    delete,
    func,
    inspect,
    select,
    update,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

from security_agent.report_sections import report_sections
from security_agent.schemas import AgentState, LedgerEvent, RunStatus

ZERO_HASH = "0" * 64
SECRET_KEYS = {"api_key", "apikey", "authorization", "password", "secret", "token"}
SECRET_PATTERN = re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{8,}")


class Base(DeclarativeBase):
    pass


class EventRow(Base):
    __tablename__ = "ledger_events"
    __table_args__ = (UniqueConstraint("run_id", "sequence"),)

    event_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(36), index=True)
    sequence: Mapped[int] = mapped_column(Integer)
    event_type: Mapped[str] = mapped_column(String(100), index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    actor: Mapped[str] = mapped_column(String(100))
    payload_json: Mapped[str] = mapped_column(Text)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))


class RunRow(Base):
    __tablename__ = "runs"

    run_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    status: Mapped[str] = mapped_column(String(30), index=True)
    state_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: "[REDACTED]" if key.lower() in SECRET_KEYS else redact(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return SECRET_PATTERN.sub(r"\1[REDACTED]", value)
    return value


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


class LedgerStore:

    def __init__(self, database_url: str) -> None:
        connect_args = {"check_same_thread": False} if database_url.startswith("sqlite") else {}
        self.engine = create_engine(database_url, future=True, connect_args=connect_args)
        self._locks: dict[str, threading.RLock] = {}
        self._locks_guard = threading.Lock()
        Base.metadata.create_all(self.engine)

    def _lock_for(self, run_id: str) -> threading.RLock:
        with self._locks_guard:
            return self._locks.setdefault(run_id, threading.RLock())

    def append(self, run_id: str, event_type: str, payload: dict[str, Any], actor: str = "system",
               *, event_id: str | None = None) -> LedgerEvent:
        safe_payload = redact(payload)
        with self._lock_for(run_id), Session(self.engine) as session:
            if event_id is not None:
                existing = session.get(EventRow, event_id)
                if existing is not None:
                    if (existing.run_id, existing.event_type, existing.payload_json) != (run_id, event_type, canonical_json(safe_payload)):
                        raise ValueError("Usage receipt identity was reused with different content")
                    return self._to_event(existing)
            previous = session.scalars(
                select(EventRow).where(EventRow.run_id == run_id).order_by(EventRow.sequence.desc()).limit(1)
            ).first()
            sequence = 1 if previous is None else previous.sequence + 1
            prev_hash = ZERO_HASH if previous is None else previous.hash
            timestamp = datetime.now(UTC)
            event_id = event_id or str(uuid4())
            digest_input = {
                "event_id": event_id,
                "run_id": run_id,
                "sequence": sequence,
                "event_type": event_type,
                "timestamp": timestamp.isoformat(),
                "actor": actor,
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
                payload_json=canonical_json(safe_payload),
                prev_hash=prev_hash,
                hash=digest,
            )
            session.add(row)
            session.commit()
            return self._to_event(row)

    def events(self, run_id: str, after_sequence: int = 0, limit: int = 1000) -> list[LedgerEvent]:
        with Session(self.engine) as session:
            rows = session.scalars(
                select(EventRow)
                .where(EventRow.run_id == run_id, EventRow.sequence > after_sequence)
                .order_by(EventRow.sequence)
                .limit(limit)
            ).all()
            return [self._to_event(row) for row in rows]

    def events_by_type(
        self,
        event_type: str,
        *,
        since: datetime | None = None,
        limit: int | None = 100_000,
    ) -> list[LedgerEvent]:
        """Return durable events across runs for aggregate dashboards."""
        with Session(self.engine) as session:
            statement = select(EventRow).where(EventRow.event_type == event_type)
            if since is not None:
                statement = statement.where(EventRow.timestamp >= since)
            rows = session.scalars(statement.order_by(EventRow.timestamp).limit(limit)).all()
            return [self._to_event(row) for row in rows]

    def event_windows(self, run_ids: list[str]) -> dict[str, tuple[datetime, datetime]]:
        """Return each platform run's own event bounds without imported usage events."""
        if not run_ids:
            return {}
        with Session(self.engine) as session:
            rows = session.execute(
                select(EventRow.run_id, func.min(EventRow.timestamp), func.max(EventRow.timestamp),
                       func.min(case((EventRow.event_type == 'report.generated', EventRow.timestamp))))
                .where(EventRow.run_id.in_(run_ids), ~EventRow.event_type.like('external.usage.%'))
                .group_by(EventRow.run_id)
            ).all()
        return {run_id: (start, finished or end) for run_id, start, end, finished in rows}

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
                "payload": event.payload,
                "prev_hash": event.prev_hash,
            }
            expected = hashlib.sha256(canonical_json(digest_input).encode()).hexdigest()
            if expected != event.hash:
                return False
            previous = event.hash
        return True

    def update_state(self, run_id: str, update: Callable[[AgentState], None]) -> AgentState:
        """Merge a short mutation into the latest snapshot under the run lock.

        Runtime callbacks and workers finish concurrently with the polling
        node.  Saving their original snapshot would discard one another's
        decisions or evidence.  No I/O or awaits belong inside ``update``.
        """
        with self._lock_for(run_id):
            state = self.load_state(run_id)
            if state is None:
                raise KeyError(run_id)
            update(state)
            self.save_state(state, merge_concurrent=False)
            return state

    def save_state(self, state: AgentState, *, merge_concurrent: bool = True) -> None:
        now = datetime.now(UTC)
        with self._lock_for(state.run_id), Session(self.engine) as session:
            row = session.get(RunRow, state.run_id)
            if merge_concurrent and row is not None:
                current = AgentState.model_validate_json(row.state_json)
                if current.task_revision > state.task_revision:
                    state.task = current.task.model_copy(deep=True)
                    state.task_revision = current.task_revision
                    state.pending_approval = (current.pending_approval.model_copy(deep=True)
                                              if current.pending_approval is not None else None)
                    if current.status == RunStatus.RUNNING and state.status == RunStatus.WAITING_APPROVAL:
                        state.status = RunStatus.RUNNING
                        state.resume_node = "guardrail"
            if merge_concurrent and row is not None and state.external_execution.get('blackboard', {}).get('planning_mode') == 'workbench':
                # Node snapshots can lag behind callbacks and parallel Workers.
                # Keep their durable writes while allowing node-owned routing,
                # report and terminal changes to advance normally.
                for key in ('planning_decisions', 'worker_model_requests', 'workbench_model_requests'):
                    state.external_execution[key] = {
                        **state.external_execution.get(key, {}), **current.external_execution.get(key, {})}
                if current.external_execution.get('model_usage_via_events'):
                    state.external_execution['model_usage_via_events'] = True
                if 'validated_goal_outputs' in current.external_execution:
                    state.external_execution['validated_goal_outputs'] = current.external_execution['validated_goal_outputs']
                if 'goal_review' in current.external_execution:
                    state.external_execution['goal_review'] = current.external_execution['goal_review']
                old_board = current.external_execution.get('blackboard', {})
                board = state.external_execution['blackboard']
                board['event_cursor'] = max(int(board.get('event_cursor') or 0), int(old_board.get('event_cursor') or 0))
                if len(current.external_execution.get('external_facts', [])) > len(state.external_execution.get('external_facts', [])):
                    state.external_execution['external_facts'] = current.external_execution['external_facts']
                for field in ('decisions', 'observations'):
                    incoming = getattr(state, field)
                    seen = {item.model_dump_json() for item in incoming}
                    incoming.extend(item for item in getattr(current, field) if item.model_dump_json() not in seen)
                for field, identity in (('evidence', 'evidence_id'), ('findings', 'finding_id')):
                    incoming = {getattr(item, identity): item for item in getattr(state, field)}
                    for item in getattr(current, field):
                        key = getattr(item, identity)
                        previous = incoming.get(key)
                        if previous is not None and field == 'findings':
                            selected = (item if item.raw.get('verification_status') in {'confirmed', 'excluded'}
                                        else previous)
                            bindings = [*previous.raw.get('traffic_bindings', []),
                                        *item.raw.get('traffic_bindings', [])]
                            if bindings:
                                selected.raw['traffic_bindings'] = list({
                                    (binding.get('evidence_id'), binding.get('role')): binding
                                    for binding in bindings if isinstance(binding, dict)
                                }.values())
                                selected.evidence_ids = list(dict.fromkeys([
                                    *selected.evidence_ids,
                                    *(binding['evidence_id'] for binding in selected.raw['traffic_bindings']
                                      if binding.get('evidence_id'))]))
                            incoming[key] = selected
                        elif previous is None:
                            incoming[key] = item
                    setattr(state, field, list(incoming.values()))
                if state.report is not None:
                    state.report = state.report.model_copy(update={
                        'findings': state.findings, 'evidence': state.evidence, **report_sections(state)})
                for field in ('provider_requests_used', 'model_calls_used', 'prompt_tokens_used',
                              'completion_tokens_used', 'cache_read_tokens_used', 'tool_calls_used', 'runtime_seconds_used'):
                    setattr(state.budget, field, max(getattr(state.budget, field), getattr(current.budget, field)))
                state.budget.model_usage_recorded |= current.budget.model_usage_recorded
                if current.status in {RunStatus.PARTIAL, RunStatus.FAILED, RunStatus.DENIED} and state.status == RunStatus.RUNNING:
                    state.status, state.last_error = current.status, current.last_error
            state_json = state.model_dump_json()
            if row is None:
                row = RunRow(
                    run_id=state.run_id,
                    status=state.status.value,
                    state_json=state_json,
                    created_at=now,
                    updated_at=now,
                )
                session.add(row)
            else:
                row.status = state.status.value
                row.state_json = state_json
                row.updated_at = now
            session.commit()

    def load_state(self, run_id: str) -> AgentState | None:
        with Session(self.engine) as session:
            row = session.get(RunRow, run_id)
            return None if row is None else AgentState.model_validate_json(row.state_json)

    def delete_run(self, run_id: str) -> None:
        """Remove one terminal run and its task-scoped records in one transaction."""
        terminal = {RunStatus.COMPLETED.value, RunStatus.PARTIAL.value,
                    RunStatus.FAILED.value, RunStatus.DENIED.value}
        with self._lock_for(run_id), self.engine.begin() as connection:
            row = connection.execute(select(RunRow.status).where(RunRow.run_id == run_id)).scalar_one_or_none()
            if row is None:
                raise KeyError(run_id)
            if row not in terminal:
                raise ValueError("请先终止任务，等待任务结束后再删除")

            tables = set(inspect(connection).get_table_names())
            metadata = MetaData()
            def table(name: str) -> Table:
                return Table(name, metadata, autoload_with=connection)

            if "run_retests" in tables:
                retests = table("run_retests")
                linked = connection.execute(select(retests.c.retest_id).where(
                    (retests.c.source_run_id == run_id) | (retests.c.child_run_id == run_id)
                ).limit(1)).first()
                if linked:
                    raise ValueError("任务已关联独立复核，请先处理复核关系")

            if "side_question_requests" in tables:
                questions = table("side_question_requests")
                active = connection.execute(select(questions.c.question_id).where(
                    questions.c.run_id == run_id,
                    questions.c.status.in_(("queued", "running")),
                ).limit(1)).first()
                if active:
                    raise ValueError("旁路问答仍在运行，请先取消并等待其结束")
                if "side_question_output_events" in tables:
                    outputs = table("side_question_output_events")
                    ids = select(questions.c.question_id).where(questions.c.run_id == run_id)
                    connection.execute(delete(outputs).where(outputs.c.question_id.in_(ids)))

            for name in sorted(tables - {"runs", "ledger_events", "run_retests", "side_question_output_events"}):
                scoped = table(name)
                if "run_id" in scoped.c:
                    connection.execute(delete(scoped).where(scoped.c.run_id == run_id))

            if "experiences" in tables:
                experiences = table("experiences")
                connection.execute(update(experiences).where(experiences.c.source_run_id == run_id)
                                   .values(source_run_id=None))
            connection.execute(delete(EventRow).where(EventRow.run_id == run_id))
            connection.execute(delete(RunRow).where(RunRow.run_id == run_id))

    def list_states(self, limit: int | None = 100, offset: int = 0,
                    before: tuple[datetime, str] | None = None) -> list[AgentState]:
        with Session(self.engine) as session:
            query = select(RunRow)
            if before is not None:
                created_at, run_id = before
                query = query.where((RunRow.created_at < created_at) |
                                    ((RunRow.created_at == created_at) & (RunRow.run_id < run_id)))
            rows = session.scalars(query.order_by(RunRow.created_at.desc(), RunRow.run_id.desc())
                                   .offset(offset).limit(limit)).all()
            return [AgentState.model_validate_json(row.state_json) for row in rows]

    def run_cursor(self, run_id: str) -> str | None:
        with Session(self.engine) as session:
            row = session.get(RunRow, run_id)
            return f"{row.created_at.isoformat()}|{row.run_id}" if row else None

    def count_states(self) -> int:
        with Session(self.engine) as session:
            return session.scalar(select(func.count()).select_from(RunRow)) or 0

    def incomplete_run_ids(self) -> list[str]:
        terminal = {
            RunStatus.COMPLETED.value,
            RunStatus.PARTIAL.value,
            RunStatus.DENIED.value,
            RunStatus.FAILED.value,
        }
        with Session(self.engine) as session:
            return list(session.scalars(select(RunRow.run_id).where(RunRow.status.not_in(terminal))).all())

    def export_jsonl(self, run_id: str, destination: Path) -> Path:
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("w", encoding="utf-8", newline="\n") as output:
            for event in self.events(run_id, limit=1_000_000):
                output.write(event.model_dump_json() + "\n")
        return destination

    def export_thought_markdown(self, run_id: str, destination: Path) -> Path:
        state = self.load_state(run_id)
        if state is None:
            raise KeyError(run_id)
        events = self.events(run_id, limit=1_000_000)
        instructions = [event for event in events if event.event_type == "agent.instruction"]
        agent_labels = {
            "interpreter": "理解任务与输入",
            "planner": "规划执行路径",
            "analyst": "分析工具结果",
            "verifier": "验证证据闭环",
            "reporter": "形成最终结论",
        }
        lines = [
            f"# {state.task.name or '安全任务'}：可审计思考过程",
            "",
            f"- 运行 ID：`{run_id}`",
            f"- 状态：`{state.status.value}`",
            f"- 任务目标：{state.task.objective}",
            f"- 导出时间：{datetime.now(UTC).isoformat()}",
            "",
            "> 本文档只包含编排指令、公开模型输出、工具记录与最终思考摘要，不包含模型隐藏推理。",
            "",
        ]
        for index, instruction in enumerate(instructions, start=1):
            payload = instruction.payload
            next_sequence = instructions[index].sequence if index < len(instructions) else 1_000_000_000
            scoped = [
                event
                for event in events
                if instruction.sequence < event.sequence < next_sequence
            ]
            agent_id = str(payload.get("agent_id") or "agent")
            node = str(payload.get("node") or "step")
            lines.extend(
                [
                    f"## {index}. {agent_labels.get(agent_id, agent_id)}",
                    "",
                    f"- 节点：`{node}`",
                    f"- 时间：{instruction.timestamp.isoformat()}",
                    f"- 编排指令：{payload.get('content') or '执行当前节点。'}",
                    "",
                ]
            )
            streams: dict[str, dict[str, Any]] = {}
            stream_order: list[str] = []
            for event in scoped:
                if not event.event_type.startswith("llm.stream."):
                    continue
                trace_id = str(event.payload.get("trace_id") or "")
                if not trace_id:
                    continue
                if trace_id not in streams:
                    streams[trace_id] = {"content": "", "status": "streaming", "model": None}
                    stream_order.append(trace_id)
                stream = streams[trace_id]
                stream["model"] = event.payload.get("model") or stream["model"]
                if event.event_type == "llm.stream.delta":
                    content = event.payload.get("content")
                    stream["content"] = content if isinstance(content, str) else stream["content"] + str(
                        event.payload.get("delta") or ""
                    )
                elif event.event_type == "llm.stream.completed":
                    stream["status"] = "completed"
                    content = event.payload.get("content")
                    if isinstance(content, str):
                        stream["content"] = content
                elif event.event_type == "llm.stream.failed":
                    stream["status"] = "failed"
            successful = [streams[key] for key in stream_order if streams[key]["status"] != "failed"]
            visible_streams = successful or ([streams[stream_order[-1]]] if stream_order else [])
            for stream in visible_streams:
                if not stream["content"]:
                    continue
                lines.extend(
                    [
                        f"### 公开模型过程 · {stream['model'] or 'AI'}",
                        "",
                        "````text",
                        str(stream["content"]),
                        "````",
                        "",
                    ]
                )
            thought = next((event for event in scoped if event.event_type == "agent.thought"), None)
            if thought is not None:
                lines.extend(["### 最终思考摘要", "", str(thought.payload.get("summary") or "已完成。"), ""])
            for event in scoped:
                if event.event_type == "tool.completed":
                    tool = event.payload.get("tool") or "受控工具"
                    status = event.payload.get("status") or "unknown"
                    lines.extend(["### 工具记录", "", f"- `{tool}`：{status}", ""])
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
        return destination

    @staticmethod
    def _to_event(row: EventRow) -> LedgerEvent:
        return LedgerEvent(
            event_id=row.event_id,
            run_id=row.run_id,
            sequence=row.sequence,
            event_type=row.event_type,
            timestamp=row.timestamp.replace(tzinfo=row.timestamp.tzinfo or UTC),
            actor=row.actor,
            payload=json.loads(row.payload_json),
            prev_hash=row.prev_hash,
            hash=row.hash,
        )
