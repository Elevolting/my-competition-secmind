"""Immutable, task-bound copies of actual model requests.

The two independently distributed APIs implement this same storage contract;
neither service imports the other service's application or runtime.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit
from uuid import NAMESPACE_URL, uuid4, uuid5

from sqlalchemy import Boolean, Integer, String, Text, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column


def canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def validate_tree(value: Any) -> None:
    """Reject unsupported trees before copying; sanitization must not truncate them."""
    stack = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        if depth >= 60:
            raise ValueError("Model snapshot nesting exceeds storage limit")
        if isinstance(item, dict):
            if any(not isinstance(key, str) for key in item):
                raise ValueError("Model snapshot requires string object keys")
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
        elif item is not None and not isinstance(item, (str, int, float, bool)):
            raise ValueError("Model snapshot requires JSON values")


def validate_messages(messages: Any) -> None:
    """Keep structured tool calls paired with their results in a usable snapshot."""
    if not isinstance(messages, list) or not messages:
        raise ValueError("Snapshot requires structured messages")
    pending: set[str] = set()
    seen: set[str] = set()
    for message in messages:
        if not isinstance(message, dict) or message.get("role") not in {
            "system", "developer", "user", "assistant", "tool",
        }:
            raise ValueError("Invalid snapshot message role")
        if message["role"] == "tool":
            call_id = message.get("tool_call_id")
            if not isinstance(call_id, str) or call_id not in pending:
                raise ValueError("Snapshot has an unpaired tool result")
            pending.remove(call_id)
        else:
            if pending:
                raise ValueError("Snapshot has an unpaired tool call")
            for call in message.get("tool_calls", []):
                call_id = call.get("id") if isinstance(call, dict) else None
                if message["role"] != "assistant" or not isinstance(call_id, str) or not call_id or call_id in seen:
                    raise ValueError("Invalid snapshot tool call identity")
                pending.add(call_id)
                seen.add(call_id)
    if pending:
        raise ValueError("Snapshot has an unpaired tool call")


@dataclass(frozen=True)
class SnapshotParent:
    run_id: str
    source: str
    step_id: str | None = None
    worker_id: str | None = None

    def __post_init__(self) -> None:
        if self.source not in {"workbench", "secmind"}:
            raise ValueError("Invalid snapshot source")
        if not isinstance(self.run_id, str):
            raise ValueError("Invalid snapshot run identity")
        for value in (self.run_id, self.step_id, self.worker_id):
            if value is not None and (not isinstance(value, str) or not value.strip() or len(value) > 200):
                raise ValueError("Invalid snapshot parent identity")

    @property
    def key(self) -> str:
        return str(uuid5(NAMESPACE_URL, canonical(vars(self))))


@dataclass(frozen=True)
class ModelConfiguration:
    base_url: str
    provider: str
    model_id: str
    planner_model: str
    worker_model: str
    fallback_model: str
    protocol: str = "openai-chat"

    def __post_init__(self) -> None:
        parsed = urlsplit(self.base_url)
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                or parsed.username or parsed.password or parsed.query or parsed.fragment):
            raise ValueError("Snapshot model address must not contain credentials or query parameters")
        if not self.provider or not self.model_id or self.protocol != "openai-chat":
            raise ValueError("Invalid snapshot model identity")

    @property
    def identity(self) -> str:
        fields = {**vars(self), "base_url": self.base_url.rstrip("/")}
        return hashlib.sha256(canonical(fields).encode()).hexdigest()


class SnapshotBase(DeclarativeBase):
    pass


class ModelSnapshotRow(SnapshotBase):
    __tablename__ = "model_request_snapshots"
    __table_args__ = {"sqlite_autoincrement": True}

    version: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    snapshot_id: Mapped[str] = mapped_column(String(36), unique=True)
    parent_key: Mapped[str] = mapped_column(String(36), index=True)
    run_id: Mapped[str] = mapped_column(String(200), index=True)
    source: Mapped[str] = mapped_column(String(30))
    step_id: Mapped[str | None] = mapped_column(String(200))
    worker_id: Mapped[str | None] = mapped_column(String(200))
    captured_at: Mapped[str] = mapped_column(String(40))
    model_id: Mapped[str] = mapped_column(String(200))
    configuration_identity: Mapped[str] = mapped_column(String(64))
    request_sha256: Mapped[str] = mapped_column(String(64))
    redacted: Mapped[bool] = mapped_column(Boolean)
    request_json: Mapped[str] = mapped_column(Text)
    provenance_json: Mapped[str] = mapped_column(Text)


class ModelSnapshotStore:
    def __init__(self, engine: Engine, *, sanitize: Callable[[Any], Any], initialize_schema: bool = True):
        self.engine = engine
        self.sanitize = sanitize
        if initialize_schema:
            SnapshotBase.metadata.create_all(engine)

    def capture(
        self, *, parent: SnapshotParent, configuration: ModelConfiguration,
        request: dict, provenance: dict,
    ) -> dict:
        if request.get("model") != configuration.model_id:
            raise ValueError("Snapshot model differs from actual request")
        validate_tree(request)
        validate_tree(provenance)
        validate_messages(request.get("messages"))
        if any(key.lower() in {"headers", "authorization", "api_key", "apikey", "proxy"} for key in request):
            raise ValueError("Credentials are not model request snapshot fields")
        raw = canonical(request)
        if len(raw.encode()) > 2_000_000:
            raise ValueError("Model request snapshot exceeds storage limit")
        # Sanitize a JSON copy, preserving the caller's actual request.
        safe_request = self.sanitize(json.loads(raw))
        validate_messages(safe_request.get("messages"))
        if safe_request.get("model") != configuration.model_id:
            raise ValueError("Sanitization changed the snapshot model identity")
        safe = canonical(safe_request)
        row = ModelSnapshotRow(
            snapshot_id=str(uuid4()), parent_key=parent.key,
            run_id=parent.run_id, source=parent.source, step_id=parent.step_id, worker_id=parent.worker_id,
            captured_at=datetime.now(UTC).isoformat(), model_id=configuration.model_id,
            configuration_identity=configuration.identity,
            request_sha256=hashlib.sha256(raw.encode()).hexdigest(), redacted=safe != raw,
            request_json=safe, provenance_json=canonical(self.sanitize(json.loads(canonical(provenance)))),
        )
        with Session(self.engine) as session, session.begin():
            session.add(row)
            session.flush()
            return self._document(row)

    def latest(self, parent: SnapshotParent) -> dict | None:
        with Session(self.engine) as session:
            row = session.scalar(
                select(ModelSnapshotRow).where(ModelSnapshotRow.parent_key == parent.key)
                .order_by(ModelSnapshotRow.version.desc()).limit(1)
            )
            return None if row is None else self._document(row)

    def frozen(self, parent: SnapshotParent, snapshot_id: str, configuration: ModelConfiguration) -> dict:
        with Session(self.engine) as session:
            row = session.scalar(select(ModelSnapshotRow).where(
                ModelSnapshotRow.snapshot_id == snapshot_id, ModelSnapshotRow.parent_key == parent.key,
            ))
            if row is None:
                raise LookupError("Model request snapshot is unavailable for this parent")
            if row.configuration_identity != configuration.identity:
                raise ValueError("Model configuration changed; run the main task to refresh its snapshot")
            return self._document(row)

    @staticmethod
    def _document(row: ModelSnapshotRow) -> dict:
        return {
            "snapshot_id": row.snapshot_id, "version": row.version,
            "parent": {"run_id": row.run_id, "source": row.source,
                       "step_id": row.step_id, "worker_id": row.worker_id},
            "captured_at": row.captured_at, "model_id": row.model_id,
            "configuration_identity": row.configuration_identity,
            "request_sha256": row.request_sha256, "redacted": row.redacted,
            "boundary": "request_send", "request": json.loads(row.request_json),
            "provenance": json.loads(row.provenance_json),
        }

