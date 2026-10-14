from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from secmind.ingest import IngestError, InputIngestor
from secmind.schemas import AttachmentRef


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


def test_rejects_duplicate_archive_and_attachment_paths(settings) -> None:
    settings.prepare_directories()
    archive = settings.input_root / "duplicate.zip"
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("src/app.py", "print(1)")
        output.writestr("src/app.py", "print(2)")
    with pytest.raises(IngestError, match="duplicate normalized"):
        InputIngestor(settings).ingest("duplicate-zip", [AttachmentRef(ref="duplicate.zip")])

    first = settings.input_root / "first.py"
    second = settings.input_root / "second.py"
    first.write_text("print(1)", encoding="utf-8")
    second.write_text("print(2)", encoding="utf-8")
    with pytest.raises(IngestError, match="collision"):
        InputIngestor(settings).ingest(
            "duplicate-files",
            [AttachmentRef(ref="first.py", name="same.py"), AttachmentRef(ref="second.py", name="same.py")],
        )


def test_upload_fallback_absolute_input_and_safe_names(settings) -> None:
    settings.prepare_directories()
    uploaded = settings.upload_root / "uploaded.py"
    uploaded.write_text("print(1)", encoding="utf-8")
    workspace, artifacts = InputIngestor(settings).ingest(
        "upload-fallback", [AttachmentRef(ref="uploaded.py", name="../renamed.py")]
    )
    assert artifacts[0].relative_path == "renamed.py"
    assert (workspace / "renamed.py").is_file()

    inside = settings.input_root / "absolute.py"
    inside.write_text("print(2)", encoding="utf-8")
    _, absolute = InputIngestor(settings).ingest("absolute", [AttachmentRef(ref=str(inside.resolve()))])
    assert absolute[0].original_name == "absolute.py"
    with pytest.raises(IngestError, match="Invalid attachment name"):
        InputIngestor._safe_name("\x00")


def test_rejects_file_directory_and_archive_resource_limits(settings) -> None:
    settings.prepare_directories()
    oversized = settings.input_root / "large.py"
    oversized.write_bytes(b"x" * (settings.max_upload_bytes + 1))
    with pytest.raises(IngestError, match="File exceeds"):
        InputIngestor(settings).ingest("large-file", [AttachmentRef(ref="large.py")])

    project = settings.input_root / "many"
    project.mkdir()
    (project / "a.py").write_text("a", encoding="utf-8")
    (project / "b.py").write_text("b", encoding="utf-8")
    settings.max_files = 1
    with pytest.raises(IngestError, match="too many files"):
        InputIngestor(settings).ingest("many-files", [AttachmentRef(ref="many")])

    settings.max_files = 10
    settings.max_extracted_bytes = 1
    with pytest.raises(IngestError, match="Directory exceeds"):
        InputIngestor(settings).ingest("large-directory", [AttachmentRef(ref="many")])

    archive = settings.input_root / "large.zip"
    settings.max_extracted_bytes = 32
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("large.txt", "x" * 33)
    with pytest.raises(IngestError, match="extracted size"):
        InputIngestor(settings).ingest("large-archive", [AttachmentRef(ref="large.zip")])


def test_rejects_zip_bomb_symlink_and_corruption(settings) -> None:
    settings.prepare_directories()
    bomb = settings.input_root / "bomb.zip"
    with zipfile.ZipFile(bomb, "w", compression=zipfile.ZIP_DEFLATED) as output:
        output.writestr("zeros.txt", "0" * 100_000)
    settings.max_extracted_bytes = 200_000
    settings.max_zip_ratio = 2
    with pytest.raises(IngestError, match="compression ratio"):
        InputIngestor(settings).ingest("bomb", [AttachmentRef(ref="bomb.zip")])

    symlink_archive = settings.input_root / "link.zip"
    link_info = zipfile.ZipInfo("link.py")
    link_info.external_attr = (0o120777 << 16) | 0xA000
    with zipfile.ZipFile(symlink_archive, "w") as output:
        output.writestr(link_info, "target.py")
    settings.max_zip_ratio = 100
    with pytest.raises(IngestError, match="symbolic link"):
        InputIngestor(settings).ingest("zip-link", [AttachmentRef(ref="link.zip")])

    corrupt = settings.input_root / "corrupt.zip"
    corrupt.write_bytes(b"not a zip")
    with pytest.raises(IngestError, match="valid ZIP"):
        InputIngestor(settings).ingest("corrupt", [AttachmentRef(ref="corrupt.zip")])


@pytest.mark.parametrize("run_id", ["../escape", "nested/run", "C:\\escape", ".."])
def test_run_identifier_cannot_escape_workspace(settings, run_id) -> None:
    settings.prepare_directories()
    (settings.input_root / "safe.py").write_text("safe", encoding="utf-8")
    with pytest.raises(IngestError, match="run identifier"):
        InputIngestor(settings).ingest(run_id, [AttachmentRef(ref="safe.py")])


def test_existing_workspace_link_is_not_followed(settings, tmp_path: Path) -> None:
    settings.prepare_directories()
    (settings.input_root / "safe.py").write_text("safe", encoding="utf-8")
    run_dir = settings.run_root / "linked-run"
    run_dir.mkdir()
    outside = tmp_path / "outside"
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
    assert not (outside / "safe.py").exists()


@pytest.mark.parametrize("entry", ["src/file:stream.py", "src/CON.txt", "src/trailing. "])
def test_zip_rejects_windows_unsafe_member_names(settings, entry) -> None:
    settings.prepare_directories()
    archive = settings.input_root / "unsafe.zip"
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr(entry, "data")
    with pytest.raises(IngestError, match="Invalid attachment name"):
        InputIngestor(settings).ingest("unsafe-zip", [AttachmentRef(ref="unsafe.zip")])
    assert not (settings.run_root / "unsafe-zip" / "workspace").exists()


def test_failed_ingest_is_atomic_and_cumulative_limits_apply(settings) -> None:
    settings.prepare_directories()
    (settings.input_root / "first.py").write_text("first", encoding="utf-8")
    (settings.input_root / "second.py").write_text("second", encoding="utf-8")
    ingestor = InputIngestor(settings)
    with pytest.raises(IngestError, match="does not exist"):
        ingestor.ingest("atomic", [AttachmentRef(ref="first.py"), AttachmentRef(ref="missing.py")])
    assert not (settings.run_root / "atomic" / "workspace").exists()
    settings.max_files = 1
    with pytest.raises(IngestError, match="file count"):
        ingestor.ingest("atomic", [AttachmentRef(ref="first.py"), AttachmentRef(ref="second.py")])
    assert not (settings.run_root / "atomic" / "workspace").exists()


def test_failed_reingest_preserves_existing_workspace(settings) -> None:
    settings.prepare_directories()
    source = settings.input_root / "safe.py"
    source.write_text("original", encoding="utf-8")
    ingestor = InputIngestor(settings)
    workspace, _ = ingestor.ingest("preserve", [AttachmentRef(ref="safe.py")])
    source.write_text("changed", encoding="utf-8")
    with pytest.raises(IngestError, match="does not exist"):
        ingestor.ingest("preserve", [AttachmentRef(ref="safe.py"), AttachmentRef(ref="missing.py")])
    assert (workspace / "safe.py").read_text(encoding="utf-8") == "original"
