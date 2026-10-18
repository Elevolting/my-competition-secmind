from __future__ import annotations

import hashlib
import mimetypes
import os
import re
import shutil
import zipfile
from pathlib import Path, PurePosixPath
from uuid import uuid4

from secmind.config import Settings
from secmind.schemas import AttachmentRef, InputArtifact


class IngestError(ValueError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


class InputIngestor:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def ingest(self, run_id: str, attachments: list[AttachmentRef]) -> tuple[Path, list[InputArtifact]]:
        workspace = self._workspace_for_run(run_id)
        workspace.parent.mkdir(parents=True, exist_ok=True)
        staging = workspace.parent / f".ingest-{uuid4().hex}"
        staging.mkdir()
        artifacts: list[InputArtifact] = []
        try:
            for attachment in attachments:
                source = self._resolve_reference(attachment.ref)
                if source.is_symlink():
                    raise IngestError(f"Symbolic links are not accepted: {attachment.ref}")
                remaining_files = self.settings.max_files - len(artifacts)
                remaining_bytes = self.settings.max_extracted_bytes - sum(item.size_bytes for item in artifacts)
                if source.is_dir():
                    artifacts.extend(self._copy_directory(source, staging / self._safe_name(source.name),
                                                          remaining_files, remaining_bytes))
                elif source.suffix.lower() == ".zip":
                    artifacts.extend(self._extract_zip(source, staging / self._safe_name(source.stem),
                                                       remaining_files, remaining_bytes))
                elif source.is_file():
                    size = source.stat().st_size
                    if size > self.settings.max_upload_bytes:
                        raise IngestError(f"File exceeds size limit: {attachment.ref}")
                    if remaining_files < 1 or size > remaining_bytes:
                        raise IngestError("Task attachments exceed file count or extracted size limit")
                    target = staging / self._safe_name(attachment.name or source.name)
                    self._copy_exclusive(source, target, staging)
                    artifacts.append(self._artifact(target, staging, source.name))
                else:
                    raise IngestError(f"Attachment does not exist: {attachment.ref}")
            self._publish_workspace(staging, workspace)
        finally:
            if staging.exists():
                shutil.rmtree(staging)
        return workspace, artifacts

    @staticmethod
    def _publish_workspace(staging: Path, workspace: Path) -> None:
        previous: Path | None = None
        if workspace.exists():
            if workspace.is_symlink() or (hasattr(workspace, "is_junction") and workspace.is_junction()):
                raise IngestError("Run workspace must not be a symbolic link or directory junction")
            if not workspace.is_dir():
                raise IngestError("Run workspace is not a directory")
            previous = workspace.parent / f".ingest-previous-{uuid4().hex}"
            os.replace(workspace, previous)
        try:
            os.replace(staging, workspace)
        except OSError:
            if previous is not None:
                os.replace(previous, workspace)
            raise
        if previous is not None:
            shutil.rmtree(previous)

    def _workspace_for_run(self, run_id: str) -> Path:
        if (not isinstance(run_id, str) or not run_id.strip() or run_id in {".", ".."}
                or Path(run_id).name != run_id
                or any(ord(char) < 32 or char in "/\\:" for char in run_id)):
            raise IngestError("Invalid run identifier")
        run_root = self.settings.run_root.resolve(strict=True)
        run_dir = run_root / run_id
        workspace = run_dir / "workspace"
        for path in (run_dir, workspace):
            if path.exists() and (path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction())):
                raise IngestError("Run workspace must not be a symbolic link or directory junction")
        resolved = workspace.resolve()
        if not resolved.is_relative_to(run_root):
            raise IngestError("Run workspace escapes configured run root")
        return resolved

    def _resolve_reference(self, reference: str) -> Path:
        candidate = Path(reference)
        roots = [self.settings.input_root.resolve(), self.settings.upload_root.resolve()]
        if candidate.is_absolute():
            if candidate.is_symlink():
                raise IngestError("Symbolic links are not accepted")
            resolved = candidate.resolve()
        else:
            if ((self.settings.input_root / candidate).is_symlink()
                    or (self.settings.upload_root / candidate).is_symlink()):
                raise IngestError("Symbolic links are not accepted")
            resolved = (self.settings.input_root / candidate).resolve()
            if not resolved.exists():
                resolved = (self.settings.upload_root / candidate).resolve()
        if not any(resolved == root or root in resolved.parents for root in roots):
            raise IngestError("Attachment reference escapes configured input roots")
        return resolved

    @staticmethod
    def _copy_exclusive(source: Path, target: Path, workspace: Path) -> None:
        root = workspace.resolve(strict=True)
        if not target.resolve().is_relative_to(root):
            raise IngestError("Attachment target escapes task workspace")
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            with source.open("rb") as reader, target.open("xb") as writer:
                shutil.copyfileobj(reader, writer)
        except FileExistsError as exc:
            raise IngestError(f"Attachment path collision: {target.name}") from exc

    def _copy_directory(self, source: Path, destination: Path,
                        remaining_files: int, remaining_bytes: int) -> list[InputArtifact]:
        files = [path for path in source.rglob("*") if path.is_file()]
        if len(files) > remaining_files:
            raise IngestError("Directory contains too many files")
        source_root = source.resolve(strict=True)
        for source_file in files:
            if not source_file.resolve(strict=True).is_relative_to(source_root):
                raise IngestError("Directory contains a link outside the authorized source")
            relative = source_file.relative_to(source)
            parts = [source.joinpath(*relative.parts[:index]) for index in range(1, len(relative.parts) + 1)]
            if any(part.is_symlink() or (hasattr(part, "is_junction") and part.is_junction()) for part in parts):
                raise IngestError("Directories containing symbolic links are not accepted")
        total = sum(path.stat().st_size for path in files)
        if total > remaining_bytes:
            raise IngestError("Directory exceeds extracted size limit")
        artifacts: list[InputArtifact] = []
        for source_file in files:
            if source_file.is_symlink():
                raise IngestError("Directories containing symbolic links are not accepted")
            relative = source_file.relative_to(source)
            if any(self._safe_name(part) != part for part in relative.parts):
                raise IngestError("Directory contains invalid path")
            target = destination / relative
            self._copy_exclusive(source_file, target, destination.parent)
            artifacts.append(self._artifact(target, destination.parent, source_file.name))
        return artifacts

    def _extract_zip(self, source: Path, destination: Path,
                     remaining_files: int, remaining_bytes: int) -> list[InputArtifact]:
        if source.stat().st_size > self.settings.max_upload_bytes:
            raise IngestError("Archive exceeds upload size limit")
        try:
            archive_context = zipfile.ZipFile(source)
        except zipfile.BadZipFile as exc:
            raise IngestError("Attachment is not a valid ZIP archive") from exc
        with archive_context as archive:
            entries = [item for item in archive.infolist() if not item.is_dir()]
            if len(entries) > remaining_files:
                raise IngestError("Archive contains too many files")
            total = sum(item.file_size for item in entries)
            compressed = max(1, sum(item.compress_size for item in entries))
            if total > remaining_bytes:
                raise IngestError("Archive exceeds extracted size limit")
            if total / compressed > self.settings.max_zip_ratio:
                raise IngestError("Suspicious archive compression ratio")
            for item in entries:
                normalized = PurePosixPath(item.filename.replace("\\", "/"))
                if normalized.is_absolute() or ".." in normalized.parts:
                    raise IngestError("Archive contains path traversal")
                if any(self._safe_name(part) != part for part in normalized.parts):
                    raise IngestError("Invalid attachment name in archive")
                if item.external_attr >> 16 & 0o170000 == 0o120000:
                    raise IngestError("Archive contains a symbolic link")
            normalized_names = [str(PurePosixPath(item.filename.replace("\\", "/"))).casefold() for item in entries]
            if len(normalized_names) != len(set(normalized_names)):
                raise IngestError("Archive contains duplicate normalized paths")
            seen = set(normalized_names)
            for key in seen:
                if any("/".join(key.split("/")[:index]) in seen
                       for index in range(1, len(key.split("/")))):
                    raise IngestError("Archive contains file and directory path conflict")
            artifacts: list[InputArtifact] = []
            for item in entries:
                normalized = PurePosixPath(item.filename.replace("\\", "/"))
                target = destination.joinpath(*normalized.parts)
                if not target.resolve().is_relative_to(destination.parent.resolve(strict=True)):
                    raise IngestError("Archive target escapes task workspace")
                target.parent.mkdir(parents=True, exist_ok=True)
                try:
                    with archive.open(item) as src, target.open("xb") as dst:
                        shutil.copyfileobj(src, dst)
                except FileExistsError as exc:
                    raise IngestError(f"Attachment path collision: {normalized}") from exc
                artifacts.append(self._artifact(target, destination.parent, item.filename))
            return artifacts

    @staticmethod
    def _safe_name(name: str) -> str:
        safe = Path(name).name
        reserved = re.fullmatch(r"(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?", safe, re.IGNORECASE)
        if (not safe or safe in {".", ".."} or safe.rstrip(" .") != safe
                or any(ord(char) < 32 or char in ':<>"|?*\\/' for char in safe)
                or reserved):
            raise IngestError("Invalid attachment name")
        return safe

    @staticmethod
    def _artifact(path: Path, workspace: Path, original_name: str) -> InputArtifact:
        media_type, _ = mimetypes.guess_type(path.name)
        return InputArtifact(
            original_name=original_name,
            relative_path=path.relative_to(workspace).as_posix(),
            sha256=sha256_file(path),
            size_bytes=path.stat().st_size,
            media_type=media_type or "application/octet-stream",
        )
