from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from secmind.archive_restore import (
    ArchiveError,
    ArchiveManifest,
    ArchiveMember,
    collect_members,
    export_run_archive,
    load_manifest,
    restore_archive,
    verify_archive,
    write_manifest,
)
from secmind.artifact_store import ContentAddressedArtifactStore
from secmind.ledger import EventRow, LedgerStore
from secmind.schemas import AgentState, RunStatus, TaskRequest


def _make_manifest(root: Path, *, archive_id: str = "archive-1") -> ArchiveManifest:
    (root / "ledger").mkdir(parents=True)
    (root / "artifacts").mkdir()
    (root / "ledger" / "events.jsonl").write_text('{"sequence":1}\n', encoding="utf-8")
    (root / "artifacts" / "evidence.bin").write_bytes(b"evidence")
    members = collect_members(
        root,
        kinds={"artifacts/evidence.bin": "artifact", "ledger/events.jsonl": "ledger"},
    )
    return ArchiveManifest(
        format_version=1,
        archive_id=archive_id,
        created_at="2026-10-15T00:00:00Z",
        source={"run_id": "run-source", "state_version": 3, "latest_event_sequence": 1},
        freeze={"freeze_id": "freeze-1", "status": "paused", "ledger_head_hash": "a" * 64},
        members=members,
        id_map={"run-source": "run-restored"},
        counts={"ledger_events": 1, "artifacts": 1},
    )


def test_manifest_is_canonical_and_member_hashes_are_complete(tmp_path: Path) -> None:
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first = _make_manifest(first_root)
    second = _make_manifest(second_root)

    assert first.digest() == second.digest()
    assert first.to_bytes() == second.to_bytes()
    write_manifest(first_root, first)
    assert verify_archive(first_root).digest() == first.digest()


def test_tampering_missing_and_extra_members_are_rejected(tmp_path: Path) -> None:
    root = tmp_path / "archive"
    manifest = _make_manifest(root)
    write_manifest(root, manifest)

    (root / "artifacts" / "evidence.bin").write_bytes(b"tampered")
    with pytest.raises(ArchiveError, match="integrity mismatch"):
        verify_archive(root)

    (root / "artifacts" / "evidence.bin").write_bytes(b"evidence")
    (root / "ledger" / "events.jsonl").unlink()
    with pytest.raises(ArchiveError, match="member set mismatch"):
        verify_archive(root)

    (root / "ledger" / "events.jsonl").write_text('{"sequence":1}\n', encoding="utf-8")
    (root / "unexpected.txt").write_text("unexpected", encoding="utf-8")
    with pytest.raises(ArchiveError, match="member set mismatch"):
        verify_archive(root)


def test_manifest_rejects_unsafe_members_and_wrong_digest(tmp_path: Path) -> None:
    with pytest.raises(ArchiveError, match="unsafe archive member path"):
        ArchiveMember(
            path="../escape.txt",
            kind="metadata",
            media_type="text/plain",
            size_bytes=1,
            sha256=hashlib.sha256(b"x").hexdigest(),
        )

    root = tmp_path / "archive"
    manifest = _make_manifest(root)
    write_manifest(root, manifest)
    payload = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    payload["archive_id"] = "changed"
    (root / "manifest.json").write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ArchiveError, match="manifest digest mismatch"):
        verify_archive(root)


def test_restore_is_isolated_idempotent_and_never_executable(tmp_path: Path) -> None:
    root = tmp_path / "archive"
    target = tmp_path / "restored"
    manifest = _make_manifest(root)
    write_manifest(root, manifest)

    first = restore_archive(root, target, target_run_id="run-restored")
    second = restore_archive(root, target, target_run_id="run-restored")

    assert first.already_restored is False
    assert second.already_restored is True
    assert first.execution_allowed is False
    assert second.execution_allowed is False
    assert (target / "ledger" / "events.jsonl").read_text(encoding="utf-8") == '{"sequence":1}\n'
    marker = json.loads((target / ".restore-complete.json").read_text(encoding="utf-8"))
    assert marker["execution_allowed"] is False
    assert manifest.id_map["run-source"] == "run-restored"

    with pytest.raises(ArchiveError, match="another archive"):
        restore_archive(root, target, target_run_id="different-run")


def test_export_run_archive_binds_state_ledger_and_cas_metadata(tmp_path: Path) -> None:
    ledger = LedgerStore(f"sqlite:///{tmp_path / 'ledger.db'}")
    artifact_store = ContentAddressedArtifactStore(tmp_path / "cas")
    run_id = "run-export"
    artifact = artifact_store.put(b"proof-bytes", media_type="text/plain", run_id=run_id)
    state = AgentState(
        run_id=run_id,
        task=TaskRequest(objective="export a verified archive"),
        status=RunStatus.COMPLETED,
        input_artifacts=[
            {
                "artifact_id": artifact.artifact_id,
                "original_name": "proof.txt",
                "relative_path": "proof.txt",
                "sha256": artifact.sha256,
                "size_bytes": artifact.size_bytes,
                "media_type": artifact.media_type,
            }
        ],
    )
    ledger.save_state(state)
    ledger.append(run_id, "run.completed", {"artifact_id": artifact.artifact_id}, actor="test")

    archive_root = tmp_path / "exported"
    manifest = export_run_archive(
        archive_root,
        ledger=ledger,
        artifact_store=artifact_store,
        run_id=run_id,
        archive_id="archive-export",
        created_at="2026-10-15T00:00:00Z",
    )

    assert manifest.source["run_id"] == run_id
    assert manifest.source["latest_event_sequence"] == 1
    assert manifest.source["ledger_head_hash"] == ledger.latest_event(run_id).hash
    assert manifest.counts == {
        "ledger_events": 1,
        "artifacts": 1,
        "artifact_metadata": 1,
        "state_snapshots": 1,
    }
    assert {member.kind for member in manifest.members} == {"state", "ledger", "artifact", "metadata"}
    assert load_manifest(archive_root).to_bytes() == manifest.to_bytes()
    assert verify_archive(archive_root).digest() == manifest.digest()
    metadata_path = archive_root / f"artifacts/metadata/{artifact.artifact_id[:2]}/{artifact.artifact_id}.json"
    assert json.loads(metadata_path.read_text(encoding="utf-8"))["artifact_id"] == artifact.artifact_id
    ledger.close()


def test_export_rejects_active_or_corrupt_runs(tmp_path: Path) -> None:
    ledger = LedgerStore(f"sqlite:///{tmp_path / 'ledger.db'}")
    artifact_store = ContentAddressedArtifactStore(tmp_path / "cas")
    state = AgentState(
        run_id="run-active",
        task=TaskRequest(objective="must remain active"),
        status=RunStatus.RUNNING,
    )
    ledger.save_state(state)
    with pytest.raises(ArchiveError, match="not frozen or terminal"):
        export_run_archive(
            tmp_path / "active-archive",
            ledger=ledger,
            artifact_store=artifact_store,
            run_id="run-active",
            archive_id="archive-active",
            created_at="2026-10-15T00:00:00Z",
        )

    state.status = RunStatus.COMPLETED
    ledger.save_state(state)
    ledger.append("run-active", "run.completed", {"ok": True})
    with Session(ledger.engine) as session:
        row = session.query(EventRow).one()
        row.hash = "f" * 64
        session.commit()
    with pytest.raises(ArchiveError, match="hash chain is invalid"):
        export_run_archive(
            tmp_path / "corrupt-archive",
            ledger=ledger,
            artifact_store=artifact_store,
            run_id="run-active",
            archive_id="archive-corrupt",
            created_at="2026-10-15T00:00:00Z",
        )
    ledger.close()


def test_restore_recovers_a_crashed_journal_before_installing(tmp_path: Path) -> None:
    root = tmp_path / "archive"
    target = tmp_path / "restored"
    manifest = _make_manifest(root)
    write_manifest(root, manifest)
    target.mkdir()
    staging = target / ".restore-crashed"
    (staging / "ledger").mkdir(parents=True)
    (staging / "ledger" / "events.jsonl").write_text("partial", encoding="utf-8")
    (target / "ledger").mkdir()
    (target / "ledger" / "events.jsonl").write_text("partial", encoding="utf-8")
    (target / ".restore-journal.json").write_text(
        json.dumps(
            {
                "archive_id": manifest.archive_id,
                "target_run_id": "run-restored",
                "manifest_digest": manifest.digest(),
                "staging_name": staging.name,
                "planned_paths": [member.path for member in manifest.members],
                "committed_paths": ["ledger/events.jsonl"],
                "phase": "committing",
            }
        ),
        encoding="utf-8",
    )

    result = restore_archive(root, target, target_run_id="run-restored")

    assert result.already_restored is False
    assert not staging.exists()
    assert not (target / ".restore-journal.json").exists()
    assert (target / "ledger" / "events.jsonl").read_text(encoding="utf-8") == '{"sequence":1}\n'


def test_restore_rejects_a_live_target_lock(tmp_path: Path) -> None:
    root = tmp_path / "archive"
    target = tmp_path / "restored"
    manifest = _make_manifest(root)
    write_manifest(root, manifest)
    target.mkdir()
    (target / ".restore-lock.json").write_text(json.dumps({"pid": os.getpid()}), encoding="utf-8")
    try:
        with pytest.raises(ArchiveError, match="target is locked"):
            restore_archive(root, target, target_run_id="run-restored")
    finally:
        (target / ".restore-lock.json").unlink(missing_ok=True)
