from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from security_agent.ingest import IngestError, InputIngestor
from security_agent.schemas import AttachmentRef


def test_ingest_file_and_hash(settings) -> None:
    settings.prepare_directories()
    source = settings.input_root / "app.py"
    source.write_text("print('ok')\n", encoding="utf-8")
    workspace, artifacts = InputIngestor(settings).ingest("run-1", [AttachmentRef(ref="app.py")])
    assert (workspace / "app.py").exists()
    assert len(artifacts) == 1
    assert len(artifacts[0].sha256) == 64


def test_rejects_zip_path_traversal(settings) -> None:
    settings.prepare_directories()
    archive = settings.input_root / "bad.zip"
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("../escaped.py", "print('bad')")
    with pytest.raises(IngestError, match="path traversal"):
        InputIngestor(settings).ingest("run-2", [AttachmentRef(ref="bad.zip")])


def test_rejects_reference_outside_roots(settings, tmp_path: Path) -> None:
    settings.prepare_directories()
    outside = tmp_path / "outside.py"
    outside.write_text("print('x')", encoding="utf-8")
    with pytest.raises(IngestError, match="escapes"):
        InputIngestor(settings).ingest("run-3", [AttachmentRef(ref=str(outside))])


def test_ingests_directory_and_valid_zip(settings) -> None:
    settings.prepare_directories()
    source_dir = settings.input_root / "project"
    source_dir.mkdir()
    (source_dir / "one.py").write_text("print(1)", encoding="utf-8")
    nested = source_dir / "nested"
    nested.mkdir()
    (nested / "two.py").write_text("print(2)", encoding="utf-8")
    _, directory_artifacts = InputIngestor(settings).ingest("run-directory", [AttachmentRef(ref="project")])
    assert len(directory_artifacts) == 2

    archive = settings.input_root / "good.zip"
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("src/app.py", "print('ok')")
    workspace, archive_artifacts = InputIngestor(settings).ingest("run-archive", [AttachmentRef(ref="good.zip")])
    assert len(archive_artifacts) == 1
    assert (workspace / "good" / "src" / "app.py").exists()


def test_rejects_missing_attachment(settings) -> None:
    settings.prepare_directories()
    with pytest.raises(IngestError, match="does not exist"):
        InputIngestor(settings).ingest("missing", [AttachmentRef(ref="missing.py")])


def test_rejects_attachments_with_the_same_workspace_name(settings) -> None:
    settings.prepare_directories()
    (settings.input_root / "first.py").write_text("first", encoding="utf-8")
    (settings.input_root / "second.py").write_text("second", encoding="utf-8")
    with pytest.raises(IngestError, match="already exists"):
        InputIngestor(settings).ingest("collision", [
            AttachmentRef(ref="first.py", name="same.py"),
            AttachmentRef(ref="second.py", name="same.py"),
        ])
    assert not (settings.run_root / "collision" / "workspace").exists()


def test_rejects_duplicate_zip_paths_before_extracting(settings) -> None:
    settings.prepare_directories()
    archive = settings.input_root / "duplicates.zip"
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("src/app.py", "first")
        output.writestr("src/APP.py", "second")
    with pytest.raises(IngestError, match="duplicate paths"):
        InputIngestor(settings).ingest("zip-duplicates", [AttachmentRef(ref="duplicates.zip")])
    assert not (settings.run_root / "zip-duplicates" / "workspace" / "duplicates" / "src").exists()


def test_rejects_zip_file_directory_conflict_before_extracting(settings) -> None:
    settings.prepare_directories()
    archive = settings.input_root / "conflict.zip"
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("src", "file")
        output.writestr("src/app.py", "code")
    with pytest.raises(IngestError, match="path conflict"):
        InputIngestor(settings).ingest("zip-conflict", [AttachmentRef(ref="conflict.zip")])
    assert not (settings.run_root / "zip-conflict" / "workspace" / "conflict" / "src").exists()


@pytest.mark.parametrize("name", ["sample:stream.py", "CON.txt", "trailing. ", "bad?.py"])
def test_rejects_unsafe_attachment_names(settings, name) -> None:
    settings.prepare_directories()
    (settings.input_root / "safe.py").write_text("safe", encoding="utf-8")
    with pytest.raises(IngestError, match="Invalid attachment name"):
        InputIngestor(settings).ingest("unsafe-name", [AttachmentRef(ref="safe.py", name=name)])


@pytest.mark.parametrize("entry", ["src/file:stream.py", "src/CON.txt", "src/trailing. "])
def test_rejects_unsafe_zip_entry_names(settings, entry) -> None:
    settings.prepare_directories()
    archive = settings.input_root / "unsafe.zip"
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr(entry, "data")
    with pytest.raises(IngestError, match="Invalid attachment name"):
        InputIngestor(settings).ingest("unsafe-zip", [AttachmentRef(ref="unsafe.zip")])


def test_rejects_directory_link_to_file_outside_source(settings) -> None:
    settings.prepare_directories()
    source = settings.input_root / "linked-project"
    source.mkdir()
    outside = settings.input_root / "outside.py"
    outside.write_text("private", encoding="utf-8")
    link = source / "linked.py"
    try:
        link.symlink_to(outside)
    except OSError as exc:
        if getattr(exc, "winerror", None) == 1314:
            pytest.skip("Windows account cannot create symlinks")
        raise
    with pytest.raises(IngestError, match="link"):
        InputIngestor(settings).ingest("directory-link", [AttachmentRef(ref="linked-project")])


def test_cumulative_attachment_file_and_size_limits(settings) -> None:
    settings.prepare_directories()
    (settings.input_root / "one.bin").write_bytes(b"a" * 700)
    (settings.input_root / "two.bin").write_bytes(b"b" * 700)
    attachments = [AttachmentRef(ref="one.bin"), AttachmentRef(ref="two.bin")]
    settings.max_files = 1
    with pytest.raises(IngestError, match="file count"):
        InputIngestor(settings).ingest("count-limit", attachments)
    settings.max_files = 10
    settings.max_extracted_bytes = 1024
    with pytest.raises(IngestError, match="extracted size"):
        InputIngestor(settings).ingest("size-limit", attachments)


@pytest.mark.parametrize("run_id", ["../escape", "nested/run", "C:\\escape", ".."])
def test_rejects_run_workspace_path_escape(settings, run_id) -> None:
    settings.prepare_directories()
    (settings.input_root / "safe.py").write_text("safe", encoding="utf-8")
    with pytest.raises(IngestError, match="run identifier"):
        InputIngestor(settings).ingest(run_id, [AttachmentRef(ref="safe.py")])


def test_rejects_preexisting_workspace_symlink(settings, tmp_path) -> None:
    settings.prepare_directories()
    (settings.input_root / "safe.py").write_text("safe", encoding="utf-8")
    run_dir = settings.run_root / "linked-run"
    run_dir.mkdir()
    outside = tmp_path / "outside-workspace"
    outside.mkdir()
    link = run_dir / "workspace"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        if getattr(exc, "winerror", None) == 1314:
            pytest.skip("Windows account cannot create symlinks")
        raise
    with pytest.raises(IngestError, match="symbolic link"):
        InputIngestor(settings).ingest("linked-run", [AttachmentRef(ref="safe.py")])


def test_failed_ingest_leaves_no_partial_workspace_and_can_retry(settings) -> None:
    settings.prepare_directories()
    (settings.input_root / "first.py").write_text("first", encoding="utf-8")
    attachments = [AttachmentRef(ref="first.py"), AttachmentRef(ref="missing.py")]
    ingestor = InputIngestor(settings)
    with pytest.raises(IngestError, match="does not exist"):
        ingestor.ingest("retry-ingest", attachments)
    assert not (settings.run_root / "retry-ingest" / "workspace").exists()
    (settings.input_root / "missing.py").write_text("second", encoding="utf-8")
    workspace, artifacts = ingestor.ingest("retry-ingest", attachments)
    assert {item.relative_path for item in artifacts} == {"first.py", "missing.py"}
    assert (workspace / "first.py").read_text(encoding="utf-8") == "first"
    assert (workspace / "missing.py").read_text(encoding="utf-8") == "second"


def test_failed_reingest_preserves_existing_workspace(settings) -> None:
    settings.prepare_directories()
    source = settings.input_root / "first.py"
    source.write_text("original", encoding="utf-8")
    ingestor = InputIngestor(settings)
    workspace, _ = ingestor.ingest("preserve-ingest", [AttachmentRef(ref="first.py")])
    source.write_text("changed", encoding="utf-8")
    with pytest.raises(IngestError, match="does not exist"):
        ingestor.ingest("preserve-ingest", [AttachmentRef(ref="first.py"), AttachmentRef(ref="missing.py")])
    assert (workspace / "first.py").read_text(encoding="utf-8") == "original"
