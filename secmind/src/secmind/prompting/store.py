from __future__ import annotations

import hashlib
import threading
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any, Protocol

from sqlalchemy import Boolean, DateTime, Engine, Float, Integer, String, Text, UniqueConstraint, inspect, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

from secmind.prompting.contracts import (
    PromptArtifact,
    PromptOptimizationAttempt,
    PromptOutcome,
    PromptSeed,
)


class PromptStoreConflict(RuntimeError):
    """An immutable prompt identity was reused with different content."""


PROMPT_VERSION_MAX_LENGTH = 180


def verify_prompt_version_schema(engine: Engine) -> None:
    """Reject a database whose prompt version columns predate the widening migration."""
    inspector = inspect(engine)
    for table_name, column_name in (("prompt_templates", "version"), ("prompt_artifacts", "template_version")):
        columns = {column["name"]: column for column in inspector.get_columns(table_name)}
        column = columns.get(column_name)
        length = getattr(column["type"], "length", None) if column is not None else None
        if length != PROMPT_VERSION_MAX_LENGTH:
            raise RuntimeError(
                f"数据库迁移未完成: {table_name}.{column_name} must allow "
                f"{PROMPT_VERSION_MAX_LENGTH} characters; run alembic upgrade head"
            )


class PromptStore(Protocol):
    def sync_templates(self, seeds: Iterable[PromptSeed]) -> None: ...

    def put_artifact(self, artifact: PromptArtifact) -> PromptArtifact: ...

    def get_artifact(self, run_id: str, artifact_id: str) -> PromptArtifact | None: ...

    def list_artifacts(self, run_id: str) -> tuple[PromptArtifact, ...]: ...

    def put_attempt(self, attempt: PromptOptimizationAttempt) -> PromptOptimizationAttempt: ...

    def get_attempt(self, attempt_id: str) -> PromptOptimizationAttempt | None: ...

    def put_outcome(self, outcome: PromptOutcome) -> PromptOutcome: ...


class PromptStoreBase(DeclarativeBase):
    pass


class PromptTemplateRow(PromptStoreBase):
    __tablename__ = "prompt_templates"

    template_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    version: Mapped[str] = mapped_column(String(PROMPT_VERSION_MAX_LENGTH), primary_key=True)
    role: Mapped[str] = mapped_column(String(30), index=True)
    status: Mapped[str] = mapped_column(String(30), index=True)
    digest: Mapped[str] = mapped_column(String(64))
    payload_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class PromptOptimizationAttemptRow(PromptStoreBase):
    __tablename__ = "prompt_optimization_attempts"

    attempt_id: Mapped[str] = mapped_column(String(160), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(64), index=True)
    context_id: Mapped[str] = mapped_column(String(160), index=True)
    context_digest: Mapped[str] = mapped_column(String(64))
    request_digest: Mapped[str] = mapped_column(String(64), index=True)
    selection_digest: Mapped[str] = mapped_column(String(64), index=True)
    logical_call_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    parent_logical_call_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    lineage_reason: Mapped[str] = mapped_column(
        String(80), default="optimizer_attempt", server_default="optimizer_attempt"
    )
    status: Mapped[str] = mapped_column(String(30), index=True)
    model_id: Mapped[str] = mapped_column(String(128))
    response_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    payload_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class PromptArtifactRow(PromptStoreBase):
    __tablename__ = "prompt_artifacts"
    __table_args__ = (UniqueConstraint("run_id", "context_id", "artifact_id"),)

    run_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    artifact_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    context_id: Mapped[str] = mapped_column(String(160), index=True)
    role: Mapped[str] = mapped_column(String(30), index=True)
    mode: Mapped[str] = mapped_column(String(30), index=True)
    template_id: Mapped[str] = mapped_column(String(128), index=True)
    template_version: Mapped[str] = mapped_column(String(PROMPT_VERSION_MAX_LENGTH))
    selection_digest: Mapped[str] = mapped_column(String(64), index=True)
    optimizer_attempt_id: Mapped[str | None] = mapped_column(String(160), nullable=True, index=True)
    lineage_reason: Mapped[str] = mapped_column(String(80), default="fixed_mode", server_default="fixed_mode")
    rendered_prompt_digest: Mapped[str] = mapped_column(String(64))
    payload_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class PromptOutcomeRow(PromptStoreBase):
    __tablename__ = "prompt_outcomes"

    outcome_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(64), index=True)
    artifact_id: Mapped[str] = mapped_column(String(64), index=True)
    model_receipt_id: Mapped[str] = mapped_column(String(160), index=True)
    schema_valid: Mapped[bool] = mapped_column(Boolean)
    input_tokens: Mapped[int] = mapped_column(Integer)
    output_tokens: Mapped[int] = mapped_column(Integer)
    cost_units: Mapped[float] = mapped_column(Float)
    payload_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


def _json(value: PromptSeed | PromptArtifact | PromptOptimizationAttempt | PromptOutcome) -> str:
    return value.model_dump_json(exclude_none=True)


def _artifact_identity(value: PromptArtifact) -> dict[str, Any]:
    return value.model_dump(mode="json", exclude={"created_at"})


class InMemoryPromptStore:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._templates: dict[tuple[str, str], PromptSeed] = {}
        self._artifacts: dict[tuple[str, str], PromptArtifact] = {}
        self._attempts: dict[str, PromptOptimizationAttempt] = {}
        self._outcomes: dict[str, PromptOutcome] = {}

    def sync_templates(self, seeds: Iterable[PromptSeed]) -> None:
        with self._lock:
            for seed in seeds:
                key = (seed.template_id, seed.version)
                existing = self._templates.get(key)
                if existing is not None and existing.seed_digest != seed.seed_digest:
                    raise PromptStoreConflict("prompt template version was reused with different content")
                self._templates[key] = seed

    def put_artifact(self, artifact: PromptArtifact) -> PromptArtifact:
        key = (artifact.run_id, artifact.artifact_id)
        with self._lock:
            existing = self._artifacts.get(key)
            if existing is not None:
                if _artifact_identity(existing) != _artifact_identity(artifact):
                    raise PromptStoreConflict("prompt artifact identity was reused with different content")
                return existing
            self._artifacts[key] = artifact
            return artifact

    def get_artifact(self, run_id: str, artifact_id: str) -> PromptArtifact | None:
        with self._lock:
            return self._artifacts.get((run_id, artifact_id))

    def list_artifacts(self, run_id: str) -> tuple[PromptArtifact, ...]:
        with self._lock:
            return tuple(
                sorted(
                    (item for (owner, _), item in self._artifacts.items() if owner == run_id),
                    key=lambda item: (item.created_at, item.artifact_id),
                )
            )

    def put_attempt(self, attempt: PromptOptimizationAttempt) -> PromptOptimizationAttempt:
        with self._lock:
            existing = self._attempts.get(attempt.attempt_id)
            if existing is not None and existing.model_dump(mode="json", exclude={"created_at"}) != attempt.model_dump(
                mode="json", exclude={"created_at"}
            ):
                raise PromptStoreConflict("prompt optimizer attempt identity conflict")
            self._attempts[attempt.attempt_id] = existing or attempt
            return existing or attempt

    def get_attempt(self, attempt_id: str) -> PromptOptimizationAttempt | None:
        with self._lock:
            return self._attempts.get(attempt_id)

    def put_outcome(self, outcome: PromptOutcome) -> PromptOutcome:
        identity = f"{outcome.run_id}:{outcome.artifact_id}:{outcome.model_receipt_id}"
        outcome_id = hashlib.sha256(identity.encode()).hexdigest()
        with self._lock:
            existing = self._outcomes.get(outcome_id)
            if existing is not None and existing.model_dump(mode="json", exclude={"created_at"}) != outcome.model_dump(
                mode="json", exclude={"created_at"}
            ):
                raise PromptStoreConflict("prompt outcome identity conflict")
            self._outcomes[outcome_id] = existing or outcome
            return existing or outcome


class SqlPromptStore:
    """PostgreSQL/SQLite adapter; callers persist artifacts before provider calls."""

    def __init__(self, engine: Engine, *, initialize_schema: bool = False) -> None:
        self.engine = engine
        self._lock = threading.RLock()
        if initialize_schema:
            PromptStoreBase.metadata.create_all(engine)
        verify_prompt_version_schema(engine)

    def sync_templates(self, seeds: Iterable[PromptSeed]) -> None:
        now = datetime.now(UTC)
        with self._lock, Session(self.engine) as session:
            for seed in seeds:
                key = (seed.template_id, seed.version)
                row = session.get(PromptTemplateRow, key)
                if row is not None:
                    if row.digest != seed.seed_digest:
                        raise PromptStoreConflict("prompt template version was reused with different content")
                    continue
                session.add(
                    PromptTemplateRow(
                        template_id=seed.template_id,
                        version=seed.version,
                        role=seed.role.value,
                        status=seed.status.value,
                        digest=seed.seed_digest,
                        payload_json=_json(seed),
                        created_at=now,
                    )
                )
            session.commit()

    def put_artifact(self, artifact: PromptArtifact) -> PromptArtifact:
        with self._lock, Session(self.engine) as session:
            key = (artifact.run_id, artifact.artifact_id)
            row = session.get(PromptArtifactRow, key)
            if row is not None:
                existing = PromptArtifact.model_validate_json(row.payload_json)
                if _artifact_identity(existing) != _artifact_identity(artifact):
                    raise PromptStoreConflict("prompt artifact identity was reused with different content")
                return existing
            session.add(
                PromptArtifactRow(
                    run_id=artifact.run_id,
                    artifact_id=artifact.artifact_id,
                    context_id=artifact.context_id,
                    role=artifact.role.value,
                    mode=artifact.mode.value,
                    template_id=artifact.template_id,
                    template_version=artifact.template_version,
                    selection_digest=artifact.selection_digest,
                    optimizer_attempt_id=artifact.optimizer_attempt_id,
                    lineage_reason=artifact.lineage_reason,
                    rendered_prompt_digest=artifact.rendered_prompt_digest,
                    payload_json=_json(artifact),
                    created_at=artifact.created_at,
                )
            )
            session.commit()
            return artifact

    def get_artifact(self, run_id: str, artifact_id: str) -> PromptArtifact | None:
        with Session(self.engine) as session:
            row = session.get(PromptArtifactRow, (run_id, artifact_id))
            return None if row is None else PromptArtifact.model_validate_json(row.payload_json)

    def list_artifacts(self, run_id: str) -> tuple[PromptArtifact, ...]:
        with Session(self.engine) as session:
            rows = session.scalars(
                select(PromptArtifactRow)
                .where(PromptArtifactRow.run_id == run_id)
                .order_by(PromptArtifactRow.created_at, PromptArtifactRow.artifact_id)
            ).all()
            return tuple(PromptArtifact.model_validate_json(row.payload_json) for row in rows)

    def put_attempt(self, attempt: PromptOptimizationAttempt) -> PromptOptimizationAttempt:
        with self._lock, Session(self.engine) as session:
            row = session.get(PromptOptimizationAttemptRow, attempt.attempt_id)
            if row is not None:
                existing = PromptOptimizationAttempt.model_validate_json(row.payload_json)
                if existing.model_dump(mode="json", exclude={"created_at"}) != attempt.model_dump(
                    mode="json", exclude={"created_at"}
                ):
                    raise PromptStoreConflict("prompt optimizer attempt identity conflict")
                return existing
            session.add(
                PromptOptimizationAttemptRow(
                    attempt_id=attempt.attempt_id,
                    run_id=attempt.run_id,
                    context_id=attempt.context_id,
                    context_digest=attempt.context_digest,
                    request_digest=attempt.request_digest,
                    selection_digest=attempt.selection_digest,
                    logical_call_id=attempt.logical_call_id,
                    parent_logical_call_id=attempt.parent_logical_call_id,
                    lineage_reason=attempt.lineage_reason,
                    status=attempt.status,
                    model_id=attempt.optimizer_model_id,
                    response_hash=attempt.response_hash,
                    payload_json=_json(attempt),
                    created_at=attempt.created_at,
                )
            )
            session.commit()
            return attempt

    def get_attempt(self, attempt_id: str) -> PromptOptimizationAttempt | None:
        with Session(self.engine) as session:
            row = session.get(PromptOptimizationAttemptRow, attempt_id)
            return None if row is None else PromptOptimizationAttempt.model_validate_json(row.payload_json)

    def put_outcome(self, outcome: PromptOutcome) -> PromptOutcome:
        identity = f"{outcome.run_id}:{outcome.artifact_id}:{outcome.model_receipt_id}"
        outcome_id = hashlib.sha256(identity.encode()).hexdigest()
        with self._lock, Session(self.engine) as session:
            row = session.get(PromptOutcomeRow, outcome_id)
            if row is not None:
                existing = PromptOutcome.model_validate_json(row.payload_json)
                if existing.model_dump(mode="json", exclude={"created_at"}) != outcome.model_dump(
                    mode="json", exclude={"created_at"}
                ):
                    raise PromptStoreConflict("prompt outcome identity conflict")
                return existing
            session.add(
                PromptOutcomeRow(
                    outcome_id=outcome_id,
                    run_id=outcome.run_id,
                    artifact_id=outcome.artifact_id,
                    model_receipt_id=outcome.model_receipt_id,
                    schema_valid=outcome.schema_valid,
                    input_tokens=outcome.input_tokens,
                    output_tokens=outcome.output_tokens,
                    cost_units=outcome.cost_units,
                    payload_json=_json(outcome),
                    created_at=outcome.created_at,
                )
            )
            session.commit()
            return outcome


__all__ = [
    "InMemoryPromptStore",
    "PromptStore",
    "PromptStoreBase",
    "PromptStoreConflict",
    "SqlPromptStore",
]
