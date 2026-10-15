"""LangGraph checkpoint adapter for the versioned archive contract.

The archive module stores a backend-neutral JSONL representation.  This
adapter is intentionally synchronous because the archive API is synchronous;
callers using ``AsyncPostgresSaver`` must run archive work outside the active
event-loop thread (its synchronous facade enforces that rule).
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping
from typing import Any, cast

from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.base import BaseCheckpointSaver, ChannelVersions, Checkpoint, CheckpointMetadata

from secmind.archive_restore import (
    ArchiveError,
    CheckpointArchiveAdapter,
    CheckpointArchiveSnapshot,
    _checkpoint_restore_value,
)


def _record_from_tuple(item: Any) -> dict[str, Any]:
    fields = ("config", "checkpoint", "metadata", "parent_config", "pending_writes")
    record: dict[str, Any] = {}
    for field in fields:
        if not hasattr(item, field):
            raise ArchiveError(f"LangGraph checkpoint tuple is missing {field}")
        value = getattr(item, field)
        if field == "pending_writes" and value is None:
            value = []
        record[field] = value
    return record


class LangGraphCheckpointAdapter(CheckpointArchiveAdapter):
    """Adapt a synchronous view of a LangGraph checkpoint saver.

    The in-memory saver and the synchronous facade of the PostgreSQL saver
    both implement ``list``/``put``/``put_writes``.  Freeze calls are enforced
    for operations made through this adapter; the application must route
    production checkpoint writes through the same fence-aware boundary.
    """

    def __init__(self, checkpointer: BaseCheckpointSaver[Any]) -> None:
        self.checkpointer = checkpointer
        self._fences: dict[str, str] = {}
        self._completed: dict[str, str] = {}

    def begin_archive_freeze(self, run_id: str, *, freeze_id: str) -> None:
        existing = self._fences.get(run_id)
        if existing is not None:
            raise ArchiveError(f"checkpoint run already has an active archive freeze: {run_id}")
        self._fences[run_id] = freeze_id

    def snapshot(self, run_id: str) -> CheckpointArchiveSnapshot:
        try:
            rows = list(self.checkpointer.list({"configurable": {"thread_id": run_id}}))
        except Exception as exc:
            raise ArchiveError(f"checkpoint snapshot failed for {run_id}") from exc
        return CheckpointArchiveSnapshot(
            run_id=run_id,
            records=tuple(_record_from_tuple(row) for row in rows),
        )

    def complete_archive_freeze(
        self, run_id: str, *, freeze_id: str, checkpoint_snapshot_digest: str
    ) -> None:
        if self._fences.get(run_id) != freeze_id:
            raise ArchiveError(f"checkpoint archive freeze is not pending: {run_id}")
        if len(checkpoint_snapshot_digest) != 64:
            raise ArchiveError("checkpoint_snapshot_digest is invalid")
        self._completed[run_id] = freeze_id

    def abort_archive_freeze(self, run_id: str, *, freeze_id: str) -> None:
        if self._fences.get(run_id) == freeze_id:
            self._fences.pop(run_id, None)
        if self._completed.get(run_id) == freeze_id:
            self._completed.pop(run_id, None)

    def restore(
        self,
        run_id: str,
        snapshot: CheckpointArchiveSnapshot,
        *,
        id_map: Mapping[str, str],
    ) -> None:
        if snapshot.run_id != run_id:
            raise ArchiveError("checkpoint restore snapshot belongs to another run")
        try:
            existing = list(self.checkpointer.list({"configurable": {"thread_id": run_id}}))
        except Exception as exc:
            raise ArchiveError(f"checkpoint target inspection failed for {run_id}") from exc
        if existing:
            raise ArchiveError(f"checkpoint restore target already contains checkpoints: {run_id}")

        decoded_records: list[dict[str, Any]] = []
        for record in snapshot.records:
            decoded = _checkpoint_restore_value(record)
            if not isinstance(decoded, dict):
                raise ArchiveError("decoded checkpoint record is invalid")
            decoded_records.append(decoded)

        try:
            for record in decoded_records:
                config = record.get("config")
                checkpoint = record.get("checkpoint")
                metadata = record.get("metadata")
                if not isinstance(config, Mapping) or not isinstance(checkpoint, Mapping):
                    raise ArchiveError("checkpoint record has invalid config or checkpoint")
                if not isinstance(metadata, Mapping):
                    raise ArchiveError("checkpoint record metadata is invalid")
                mutable_config = {
                    str(key): value
                    for key, value in config.items()
                }
                configurable = dict(mutable_config.get("configurable", {}))
                configurable["thread_id"] = run_id
                mutable_config["configurable"] = configurable
                checkpoint_payload = cast(Checkpoint, dict(checkpoint))
                new_versions = checkpoint_payload.get("channel_versions", {})
                if not isinstance(new_versions, Mapping):
                    raise ArchiveError("checkpoint channel_versions is invalid")
                self.checkpointer.put(
                    cast(RunnableConfig, mutable_config),
                    checkpoint_payload,
                    cast(CheckpointMetadata, dict(metadata)),
                    cast(ChannelVersions, dict(new_versions)),
                )
                pending = record.get("pending_writes") or []
                if not isinstance(pending, list):
                    raise ArchiveError("checkpoint pending_writes is invalid")
                grouped: dict[str, list[tuple[str, Any, str]]] = defaultdict(list)
                for item in pending:
                    if not isinstance(item, (list, tuple)) or len(item) < 3:
                        raise ArchiveError("checkpoint pending write is invalid")
                    task_id = str(item[0])
                    channel = str(item[1])
                    task_path = str(item[3]) if len(item) >= 4 else ""
                    grouped[task_id].append((channel, item[2], task_path))
                for task_id, writes in grouped.items():
                    task_path = writes[0][2] if writes else ""
                    self.checkpointer.put_writes(
                        cast(RunnableConfig, mutable_config),
                        [(channel, value) for channel, value, _ in writes],
                        task_id,
                        task_path,
                    )
        except ArchiveError:
            raise
        except Exception as exc:
            raise ArchiveError(f"checkpoint restore failed for {run_id}") from exc


__all__ = ["LangGraphCheckpointAdapter"]
