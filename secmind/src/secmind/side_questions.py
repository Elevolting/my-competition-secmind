"""Durable side-question identity, budget reservation, and bounded execution."""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from sqlalchemy import Boolean, Integer, String, Text, func, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

from secmind.model_snapshots import ModelConfiguration, ModelSnapshotStore, SnapshotParent
from secmind.secret_scrubber import scrub_artifact


class SideQuestionError(RuntimeError):
    """Base class for bounded side-question conflicts."""


class SideQuestionConflict(SideQuestionError):
    pass


class SideQuestionBudgetExceeded(SideQuestionError):
    pass


class SideQuestionCancelled(SideQuestionError):
    pass


class SideQuestionBase(DeclarativeBase):
    pass


class SideQuestionRow(SideQuestionBase):
    __tablename__ = "side_question_requests"

    question_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    request_key: Mapped[str] = mapped_column(String(200), unique=True, index=True)
    parent_key: Mapped[str] = mapped_column(String(36), index=True)
    run_id: Mapped[str] = mapped_column(String(200), index=True)
    source: Mapped[str] = mapped_column(String(30))
    snapshot_id: Mapped[str] = mapped_column(String(36), index=True)
    snapshot_version: Mapped[int] = mapped_column(Integer)
    configuration_identity: Mapped[str] = mapped_column(String(64))
    question_sha256: Mapped[str] = mapped_column(String(64))
    question_text: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(30), index=True)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    reserved_input_tokens: Mapped[int] = mapped_column(Integer)
    reserved_output_tokens: Mapped[int] = mapped_column(Integer)
    settled_input_tokens: Mapped[int] = mapped_column(Integer, default=0)
    settled_output_tokens: Mapped[int] = mapped_column(Integer, default=0)
    provider_requests: Mapped[int] = mapped_column(Integer, default=0)
    answer_text: Mapped[str | None] = mapped_column(Text)
    error_type: Mapped[str | None] = mapped_column(String(100))
    created_at: Mapped[datetime] = mapped_column(String(40))
    updated_at: Mapped[datetime] = mapped_column(String(40))


@dataclass(frozen=True)
class SideQuestionBudget:
    input_tokens: int
    output_tokens: int
    provider_requests: int = 1


@dataclass(frozen=True)
class SideQuestionAnswer:
    question_id: str
    status: str
    answer: str | None
    usage: SideQuestionBudget


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _question_digest(question: str) -> str:
    return hashlib.sha256(question.encode("utf-8")).hexdigest()


class SideQuestionStore:
    """Persist independent requests without mutating the parent run."""

    ACTIVE = ("queued", "running")
    TERMINAL = ("completed", "failed", "cancelled")

    def __init__(
        self,
        engine: Engine,
        snapshot_store: ModelSnapshotStore,
        *,
        sanitize: Callable[[Any], Any] = scrub_artifact,
        initialize_schema: bool = True,
        max_concurrency: int = 2,
        budget_input_tokens: int = 32_000,
        budget_output_tokens: int = 8_192,
    ) -> None:
        if max_concurrency < 1 or budget_input_tokens < 1 or budget_output_tokens < 1:
            raise ValueError("side-question limits must be positive")
        self.engine = engine
        self.snapshot_store = snapshot_store
        self.sanitize = sanitize
        self.max_concurrency = max_concurrency
        self.budget_input_tokens = budget_input_tokens
        self.budget_output_tokens = budget_output_tokens
        if initialize_schema:
            SideQuestionBase.metadata.create_all(engine)

    def reserve(
        self,
        *,
        parent: SnapshotParent,
        snapshot_id: str,
        configuration: ModelConfiguration,
        request_key: str,
        question: str,
        estimated_input_tokens: int,
    ) -> dict[str, Any]:
        request_key = request_key.strip()
        question = question.strip()
        if not request_key or len(request_key) > 200:
            raise ValueError("side-question request key is required and bounded")
        if not question or len(question) > 8_000:
            raise ValueError("side-question text is required and bounded")
        if estimated_input_tokens < 1:
            raise ValueError("side-question input estimate must be positive")
        snapshot = self.snapshot_store.frozen(parent, snapshot_id, configuration)
        digest = _question_digest(question)
        safe_question = self.sanitize(question)
        now = _now()
        with Session(self.engine) as session, session.begin():
            existing = session.scalar(select(SideQuestionRow).where(SideQuestionRow.request_key == request_key))
            if existing is not None:
                if (
                    existing.parent_key != parent.key
                    or existing.snapshot_id != snapshot_id
                    or existing.question_sha256 != digest
                ):
                    raise SideQuestionConflict("request key was reused with a different side question")
                return self._document(existing)
            if estimated_input_tokens > self.budget_input_tokens:
                raise SideQuestionBudgetExceeded("side-question input budget exceeded")
            requested_output = self.budget_output_tokens
            settled_input, settled_output = session.execute(
                select(
                    func.coalesce(func.sum(SideQuestionRow.settled_input_tokens), 0),
                    func.coalesce(func.sum(SideQuestionRow.settled_output_tokens), 0),
                ).where(
                    SideQuestionRow.parent_key == parent.key,
                    SideQuestionRow.status.in_(self.TERMINAL),
                )
            ).one()
            active_reserved_input, active_reserved_output = session.execute(
                select(
                    func.coalesce(func.sum(SideQuestionRow.reserved_input_tokens), 0),
                    func.coalesce(func.sum(SideQuestionRow.reserved_output_tokens), 0),
                ).where(
                    SideQuestionRow.parent_key == parent.key,
                    SideQuestionRow.status.in_(self.ACTIVE),
                )
            ).one()
            if (
                int(settled_input or 0)
                + int(active_reserved_input or 0)
                + estimated_input_tokens
                > self.budget_input_tokens
            ):
                raise SideQuestionBudgetExceeded("side-question input budget exhausted")
            if (
                int(settled_output or 0)
                + int(active_reserved_output or 0)
                + requested_output
                > self.budget_output_tokens
            ):
                raise SideQuestionBudgetExceeded("side-question output budget exhausted")
            active_count = session.scalar(
                select(func.count()).select_from(SideQuestionRow).where(
                    SideQuestionRow.parent_key == parent.key,
                    SideQuestionRow.status.in_(self.ACTIVE),
                )
            ) or 0
            if int(active_count) >= self.max_concurrency:
                raise SideQuestionConflict("side-question concurrency limit reached")
            row = SideQuestionRow(
                question_id=str(uuid4()), request_key=request_key, parent_key=parent.key,
                run_id=parent.run_id, source=parent.source, snapshot_id=snapshot_id,
                snapshot_version=int(snapshot["version"]), configuration_identity=configuration.identity,
                question_sha256=digest, question_text=str(safe_question), status="queued",
                cancel_requested=False, reserved_input_tokens=estimated_input_tokens,
                reserved_output_tokens=requested_output, settled_input_tokens=0, settled_output_tokens=0,
                provider_requests=0, answer_text=None, error_type=None, created_at=now, updated_at=now,
            )
            session.add(row)
            session.flush()
            return self._document(row)

    def mark_running(self, question_id: str) -> dict[str, Any]:
        with Session(self.engine) as session, session.begin():
            row = session.get(SideQuestionRow, question_id)
            if row is None:
                raise LookupError("side-question request not found")
            if row.status == "cancelled" or row.cancel_requested:
                raise SideQuestionCancelled("side-question was cancelled before execution")
            if row.status == "completed":
                return self._document(row)
            if row.status != "queued":
                raise SideQuestionConflict(f"side-question cannot start from {row.status}")
            row.status = "running"
            row.updated_at = _now()
            return self._document(row)

    def settle(
        self,
        question_id: str,
        *,
        status: str,
        answer: str | None = None,
        usage: SideQuestionBudget | None = None,
        error_type: str | None = None,
    ) -> dict[str, Any]:
        if status not in self.TERMINAL:
            raise ValueError("side-question settlement must be terminal")
        usage = usage or SideQuestionBudget(0, 0, 0)
        if min(usage.input_tokens, usage.output_tokens, usage.provider_requests) < 0:
            raise ValueError("side-question usage cannot be negative")
        with Session(self.engine) as session, session.begin():
            row = session.get(SideQuestionRow, question_id)
            if row is None:
                raise LookupError("side-question request not found")
            if row.status in self.TERMINAL:
                return self._document(row)
            row.status = status
            # A cancellation is a fencing decision: a provider response that
            # arrives after it must never become visible as the answer.
            row.answer_text = None if status == "cancelled" or answer is None else str(self.sanitize(answer))
            row.error_type = error_type
            row.settled_input_tokens = min(usage.input_tokens, row.reserved_input_tokens)
            row.settled_output_tokens = min(usage.output_tokens, row.reserved_output_tokens)
            row.provider_requests = usage.provider_requests
            row.updated_at = _now()
            return self._document(row)

    def cancel(self, question_id: str) -> dict[str, Any]:
        with Session(self.engine) as session, session.begin():
            row = session.get(SideQuestionRow, question_id)
            if row is None:
                raise LookupError("side-question request not found")
            if row.status == "queued":
                row.status = "cancelled"
            elif row.status == "running":
                row.cancel_requested = True
            row.updated_at = _now()
            return self._document(row)

    def get(self, question_id: str) -> dict[str, Any] | None:
        with Session(self.engine) as session:
            row = session.get(SideQuestionRow, question_id)
            return None if row is None else self._document(row)

    @staticmethod
    def _document(row: SideQuestionRow) -> dict[str, Any]:
        return {
            "question_id": row.question_id, "request_key": row.request_key,
            "parent": {"run_id": row.run_id, "source": row.source},
            "snapshot_id": row.snapshot_id, "snapshot_version": row.snapshot_version,
            "configuration_identity": row.configuration_identity, "question_sha256": row.question_sha256,
            "question": row.question_text, "status": row.status,
            "cancel_requested": row.cancel_requested,
            "reserved": {"input_tokens": row.reserved_input_tokens, "output_tokens": row.reserved_output_tokens},
            "settled": {"input_tokens": row.settled_input_tokens, "output_tokens": row.settled_output_tokens,
                        "provider_requests": row.provider_requests},
            "answer": row.answer_text, "error_type": row.error_type,
            "created_at": row.created_at, "updated_at": row.updated_at,
        }


class SideQuestionRunner:
    """Execute side questions independently from the parent task graph."""

    def __init__(self, store: SideQuestionStore) -> None:
        self.store = store
        self._semaphore = asyncio.Semaphore(store.max_concurrency)

    async def ask(
        self,
        *,
        parent: SnapshotParent,
        snapshot_id: str,
        configuration: ModelConfiguration,
        request_key: str,
        question: str,
        estimated_input_tokens: int,
        call_model: Callable[[dict[str, Any], str], Awaitable[tuple[str, SideQuestionBudget]]],
    ) -> SideQuestionAnswer:
        reserved = self.store.reserve(
            parent=parent, snapshot_id=snapshot_id, configuration=configuration,
            request_key=request_key, question=question, estimated_input_tokens=estimated_input_tokens,
        )
        if reserved["status"] == "completed":
            return SideQuestionAnswer(reserved["question_id"], "completed", reserved["answer"],
                                       SideQuestionBudget(**reserved["settled"]))
        async with self._semaphore:
            try:
                running = self.store.mark_running(reserved["question_id"])
                snapshot = self.store.snapshot_store.frozen(parent, snapshot_id, configuration)
                result, usage = await call_model(snapshot, question)
            except SideQuestionCancelled:
                row = self.store.settle(reserved["question_id"], status="cancelled", error_type="cancelled")
                return SideQuestionAnswer(
                    row["question_id"], row["status"], row["answer"], SideQuestionBudget(**row["settled"])
                )
            except Exception as exc:
                row = self.store.settle(reserved["question_id"], status="failed", error_type=type(exc).__name__)
                raise SideQuestionError("side-question model call failed") from exc
            current = self.store.get(running["question_id"])
            status = "cancelled" if current and current["cancel_requested"] else "completed"
            row = self.store.settle(running["question_id"], status=status, answer=result, usage=usage,
                                    error_type="cancelled" if status == "cancelled" else None)
            return SideQuestionAnswer(
                row["question_id"], row["status"], row["answer"], SideQuestionBudget(**row["settled"])
            )


__all__ = [
    "SideQuestionAnswer", "SideQuestionBase", "SideQuestionBudget", "SideQuestionCancelled",
    "SideQuestionConflict", "SideQuestionError", "SideQuestionRow", "SideQuestionRunner",
    "SideQuestionStore", "SideQuestionBudgetExceeded",
]
