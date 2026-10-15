from __future__ import annotations

import json
from pathlib import Path

import pytest
from langgraph.checkpoint.base import empty_checkpoint
from langgraph.checkpoint.memory import InMemorySaver

from secmind.archive_restore import (
    ArchiveError,
    CheckpointArchiveSnapshot,
    export_run_archive,
    freeze_run_for_archive,
    restore_archive,
    verify_archive,
)
from secmind.artifact_store import ContentAddressedArtifactStore
from secmind.checkpoint_archive import LangGraphCheckpointAdapter
from secmind.ledger import LedgerStore
from secmind.schemas import AgentState, RunStatus, TaskRequest


def _seed_checkpoint(saver: InMemorySaver, run_id: str, checkpoint_id: str = "checkpoint-source-1") -> None:
    config = {
        "configurable": {
            "thread_id": run_id,
            "checkpoint_ns": "",
            "checkpoint_id": checkpoint_id,
        }
    }
    checkpoint = empty_checkpoint()
    checkpoint["id"] = checkpoint_id
    checkpoint["channel_values"] = {"evidence": b"checkpoint-bytes"}
    checkpoint["channel_versions"] = {"evidence": 1}
    saver.put(config, checkpoint, {"source": "contract-test"}, {"evidence": 1})
    saver.put_writes(config, [("evidence", b"pending-write")], "task-source-1", "node/source")


def _build_checkpoint_archive(tmp_path: Path) -> tuple[Path, str, InMemorySaver, LangGraphCheckpointAdapter]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    run_id = "run-checkpoint-source"
    ledger = LedgerStore(f"sqlite:///{tmp_path / 'ledger.db'}")
    artifact_store = ContentAddressedArtifactStore(tmp_path / "cas")
    ledger.save_state(
        AgentState(
            run_id=run_id,
            task=TaskRequest(objective="archive a checkpoint"),
            status=RunStatus.COMPLETED,
        )
    )
    ledger.append(run_id, "run.completed", {"checkpoint": True}, actor="contract-test")
    saver = InMemorySaver()
    _seed_checkpoint(saver, run_id)
    adapter = LangGraphCheckpointAdapter(saver)
    freeze = freeze_run_for_archive(
        ledger=ledger,
        artifact_store=artifact_store,
        run_id=run_id,
        freeze_id="freeze-checkpoint",
        checkpoint_adapter=adapter,
    )
    assert freeze.checkpoint_snapshot_digest
    root = tmp_path / "archive"
    export_run_archive(
        root,
        ledger=ledger,
        artifact_store=artifact_store,
        run_id=run_id,
        archive_id="archive-checkpoint",
        created_at="2026-10-15T00:00:00Z",
        checkpoint_adapter=adapter,
    )
    ledger.close()
    return root, run_id, saver, adapter


def test_checkpoint_snapshot_digest_is_stable_and_rejects_duplicate_ids() -> None:
    first = {
        "config": {"configurable": {"thread_id": "run", "checkpoint_id": "cp-1"}},
        "checkpoint": {"id": "cp-1", "ts": "2026-01-02T00:00:00Z", "value": b"a"},
    }
    second = {
        "config": {"configurable": {"thread_id": "run", "checkpoint_id": "cp-2"}},
        "checkpoint": {"id": "cp-2", "ts": "2026-01-03T00:00:00Z", "value": b"b"},
    }
    left = CheckpointArchiveSnapshot(run_id="run", records=(second, first))
    right = CheckpointArchiveSnapshot(run_id="run", records=(first, second))
    assert left.digest() == right.digest()
    assert left.to_jsonl() == right.to_jsonl()
    with pytest.raises(ArchiveError, match="duplicate checkpoint_id"):
        CheckpointArchiveSnapshot(run_id="run", records=(first, first))


def test_checkpoint_export_restore_rewrites_run_and_checkpoint_ids(tmp_path: Path) -> None:
    root, run_id, _source_saver, _source_adapter = _build_checkpoint_archive(tmp_path)
    manifest = verify_archive(root)
    assert manifest.counts["checkpoints"] == 1
    assert manifest.source["checkpoint_count"] == 1
    assert any(member.kind == "checkpoint" for member in manifest.members)

    target_saver = InMemorySaver()
    target_adapter = LangGraphCheckpointAdapter(target_saver)
    target = tmp_path / "restored"
    result = restore_archive(
        root,
        target,
        target_run_id="run-checkpoint-target",
        checkpoint_adapter=target_adapter,
    )

    assert result.execution_allowed is False
    assert result.checkpoint_restored is True
    assert result.id_map[run_id] == "run-checkpoint-target"
    assert result.id_map["checkpoint-source-1"]
    restored = list(target_saver.list({"configurable": {"thread_id": "run-checkpoint-target"}}))
    assert len(restored) == 1
    assert restored[0].config["configurable"]["thread_id"] == "run-checkpoint-target"
    assert restored[0].config["configurable"]["checkpoint_id"] == result.id_map["checkpoint-source-1"]
    assert restored[0].checkpoint["channel_values"]["evidence"] == b"checkpoint-bytes"
    assert restored[0].pending_writes == [("task-source-1", "evidence", b"pending-write")]
    marker = json.loads((target / ".restore-complete.json").read_text(encoding="utf-8"))
    assert marker["execution_allowed"] is False
    assert marker["checkpoint_restored"] is True


def test_checkpoint_member_requires_adapter_and_tampering_is_rejected(tmp_path: Path) -> None:
    root, _run_id, _source_saver, _source_adapter = _build_checkpoint_archive(tmp_path)
    checkpoint_path = root / "checkpoints" / "checkpoints.jsonl"
    checkpoint_path.write_bytes(checkpoint_path.read_bytes() + b" ")
    with pytest.raises(ArchiveError, match="integrity mismatch"):
        verify_archive(root)

    # Restore is also required to fail before installing anything when the
    # caller did not provide the backend capable of importing checkpoints.
    root, _run_id, _source_saver, _source_adapter = _build_checkpoint_archive(tmp_path / "second")
    target = tmp_path / "second-target"
    with pytest.raises(ArchiveError, match="adapter is required"):
        restore_archive(root, target, target_run_id="run-target")
    assert not (target / ".restore-complete.json").exists()
    assert not (target / ".restore-journal.json").exists()


class _FailingRestoreAdapter:
    def begin_archive_freeze(self, run_id: str, *, freeze_id: str) -> None:
        raise AssertionError("not used")

    def snapshot(self, run_id: str) -> CheckpointArchiveSnapshot:
        raise AssertionError("not used")

    def complete_archive_freeze(self, run_id: str, *, freeze_id: str, checkpoint_snapshot_digest: str) -> None:
        raise AssertionError("not used")

    def abort_archive_freeze(self, run_id: str, *, freeze_id: str) -> None:
        raise AssertionError("not used")

    def restore(self, run_id: str, snapshot: CheckpointArchiveSnapshot, *, id_map: dict[str, str]) -> None:
        raise ArchiveError("injected checkpoint restore failure")


def test_checkpoint_restore_failure_cleans_file_journal_and_staging(tmp_path: Path) -> None:
    root, _run_id, _source_saver, _source_adapter = _build_checkpoint_archive(tmp_path)
    target = tmp_path / "restored"
    with pytest.raises(ArchiveError, match="injected checkpoint restore failure"):
        restore_archive(root, target, target_run_id="run-target", checkpoint_adapter=_FailingRestoreAdapter())
    assert not (target / ".restore-complete.json").exists()
    assert not (target / ".restore-journal.json").exists()
    assert not list(target.glob(".restore-*"))
    assert not (target / "checkpoints").exists()
