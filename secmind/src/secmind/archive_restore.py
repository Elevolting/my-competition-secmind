"""Versioned, verifiable archive manifests and isolated restore primitives.

This module deliberately owns only the file and manifest boundary.  It does
not load Python objects, acquire a worker lease, dispatch a tool, or replay a
model request.  Runtime/database adapters can build on the verified member
set while keeping restore separate from execution.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import shutil
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, date, datetime
from enum import Enum
from pathlib import Path
from typing import Any, Protocol

_SHA256_LENGTH = 64
_SUPPORTED_FORMAT_VERSIONS = frozenset({1})
_MEMBER_KINDS = frozenset({"ledger", "state", "audit", "artifact", "checkpoint", "metadata"})
_MANIFEST_NAME = "manifest.json"
_RESTORE_MARKER_NAME = ".restore-complete.json"
_CHUNK_BYTES = 1024 * 1024
_ARCHIVABLE_STATUSES = frozenset({"completed", "partial", "denied", "failed", "recovery_required", "cancelled"})
_ARTIFACT_ID_KEYS = frozenset({"artifact_id", "artifact_ids", "prompt_artifact_id", "response_artifact_id"})


class _LedgerAdapter(Protocol):
    def load_state(self, run_id: str) -> Any | None: ...

    def events(self, run_id: str, after_sequence: int = 0, limit: int = 1000) -> list[Any]: ...

    def verify(self, run_id: str) -> bool: ...


class _ArtifactAdapter(Protocol):
    def read(self, artifact_id: str) -> bytes: ...

    def metadata_for(self, artifact_id: str) -> Any: ...


class ArchiveError(ValueError):
    """Raised when an archive cannot be trusted or safely restored."""


def _jsonable(value: Any) -> Any:
    """Convert model/dataclass/enums into deterministic JSON-compatible data."""

    if hasattr(value, "model_dump"):
        return _jsonable(value.model_dump(mode="json"))
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonable(item) for item in value]
    if isinstance(value, Enum):
        return _jsonable(value.value)
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if hasattr(value, "__dataclass_fields__"):
        return _jsonable({key: getattr(value, key) for key in value.__dataclass_fields__})
    return value


def _canonical_json(value: Any) -> bytes:
    return json.dumps(_jsonable(value), ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _validate_sha256(value: str, field: str) -> str:
    if not isinstance(value, str) or len(value) != _SHA256_LENGTH or any(
        char not in "0123456789abcdef" for char in value
    ):
        raise ArchiveError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _safe_relative_path(value: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ArchiveError("archive member path must use a non-empty POSIX relative path")
    path = Path(value)
    if path.is_absolute() or value.startswith("/") or any(part in {"", ".", ".."} for part in value.split("/")):
        raise ArchiveError(f"unsafe archive member path: {value!r}")
    if path.parts[0] == "manifest.json" or value == _MANIFEST_NAME:
        raise ArchiveError("manifest.json cannot be listed as a member")
    return value


def _safe_target_path(root: Path, relative: str) -> Path:
    """Resolve a destination while rejecting symlinked parent components."""

    candidate = root / Path(_safe_relative_path(relative))
    current = root
    for part in Path(relative).parts[:-1]:
        current = current / part
        if current.is_symlink():
            raise ArchiveError(f"restore destination parent is a symlink: {relative}")
    try:
        resolved = candidate.resolve(strict=False)
    except OSError as exc:
        raise ArchiveError(f"restore destination cannot be resolved: {relative}") from exc
    if not resolved.is_relative_to(root):
        raise ArchiveError(f"restore destination escapes target: {relative}")
    return candidate


def _validate_mapping(value: Mapping[str, Any], field: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ArchiveError(f"{field} must be an object")
    return {str(key): item for key, item in value.items()}


@dataclass(frozen=True, slots=True)
class ArchiveMember:
    path: str
    kind: str
    media_type: str
    size_bytes: int
    sha256: str
    source_id: str | None = None
    schema_version: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", _safe_relative_path(self.path))
        if self.kind not in _MEMBER_KINDS:
            raise ArchiveError(f"unsupported archive member kind: {self.kind!r}")
        if not self.media_type or any(ord(char) < 32 for char in self.media_type):
            raise ArchiveError("archive member media_type is invalid")
        if not isinstance(self.size_bytes, int) or isinstance(self.size_bytes, bool) or self.size_bytes < 0:
            raise ArchiveError("archive member size_bytes must be a non-negative integer")
        object.__setattr__(self, "sha256", _validate_sha256(self.sha256, "archive member sha256"))
        if self.source_id is not None and (not self.source_id or any(ord(char) < 32 for char in self.source_id)):
            raise ArchiveError("archive member source_id is invalid")

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "path": self.path,
            "kind": self.kind,
            "media_type": self.media_type,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
        }
        if self.source_id is not None:
            payload["source_id"] = self.source_id
        if self.schema_version is not None:
            payload["schema_version"] = self.schema_version
        return payload

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> ArchiveMember:
        try:
            return cls(
                path=str(payload["path"]),
                kind=str(payload["kind"]),
                media_type=str(payload["media_type"]),
                size_bytes=payload["size_bytes"],
                sha256=str(payload["sha256"]),
                source_id=payload.get("source_id"),
                schema_version=payload.get("schema_version"),
            )
        except KeyError as exc:
            raise ArchiveError(f"archive member is missing {exc.args[0]}") from exc


@dataclass(frozen=True, slots=True)
class ArchiveManifest:
    format_version: int
    archive_id: str
    created_at: str
    source: dict[str, Any]
    freeze: dict[str, Any]
    members: tuple[ArchiveMember, ...]
    id_map: dict[str, str]
    counts: dict[str, int]
    warnings: tuple[str, ...] = ()
    manifest_digest: str | None = None

    def __post_init__(self) -> None:
        if self.format_version not in _SUPPORTED_FORMAT_VERSIONS:
            raise ArchiveError(f"unsupported archive format version: {self.format_version}")
        if not self.archive_id or any(ord(char) < 32 for char in self.archive_id):
            raise ArchiveError("archive_id is invalid")
        if not self.created_at or any(ord(char) < 32 for char in self.created_at):
            raise ArchiveError("created_at is invalid")
        _validate_mapping(self.source, "source")
        _validate_mapping(self.freeze, "freeze")
        paths = [member.path for member in self.members]
        if paths != sorted(paths):
            raise ArchiveError("archive members must be sorted by path")
        if len(paths) != len(set(paths)):
            raise ArchiveError("archive member paths must be unique")
        if any(not isinstance(key, str) or not key for key in self.id_map):
            raise ArchiveError("archive id_map keys must be non-empty strings")
        if any(not isinstance(value, str) or not value for value in self.id_map.values()):
            raise ArchiveError("archive id_map values must be non-empty strings")
        if any(not isinstance(key, str) or not key for key in self.counts):
            raise ArchiveError("archive count keys must be non-empty strings")
        if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in self.counts.values()):
            raise ArchiveError("archive counts must be non-negative integers")
        if any(not isinstance(item, str) or not item.strip() for item in self.warnings):
            raise ArchiveError("archive warnings must be non-empty strings")
        if self.manifest_digest is not None:
            _validate_sha256(self.manifest_digest, "manifest_digest")

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "format_version": self.format_version,
            "archive_id": self.archive_id,
            "created_at": self.created_at,
            "source": self.source,
            "freeze": self.freeze,
            "members": [member.to_dict() for member in self.members],
            "id_map": self.id_map,
            "counts": self.counts,
            "warnings": list(self.warnings),
        }

    def digest(self) -> str:
        return hashlib.sha256(_canonical_json(self.unsigned_dict())).hexdigest()

    def signed(self) -> ArchiveManifest:
        return ArchiveManifest(
            format_version=self.format_version,
            archive_id=self.archive_id,
            created_at=self.created_at,
            source=dict(self.source),
            freeze=dict(self.freeze),
            members=self.members,
            id_map=dict(self.id_map),
            counts=dict(self.counts),
            warnings=self.warnings,
            manifest_digest=self.digest(),
        )

    def to_dict(self) -> dict[str, Any]:
        signed = self.manifest_digest or self.digest()
        return {**self.unsigned_dict(), "manifest_digest": signed}

    def to_bytes(self) -> bytes:
        return _canonical_json(self.to_dict()) + b"\n"

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> ArchiveManifest:
        if not isinstance(payload, Mapping):
            raise ArchiveError("archive manifest must be an object")
        try:
            members = tuple(ArchiveMember.from_dict(item) for item in payload["members"])
            manifest = cls(
                format_version=payload["format_version"],
                archive_id=str(payload["archive_id"]),
                created_at=str(payload["created_at"]),
                source=dict(payload["source"]),
                freeze=dict(payload["freeze"]),
                members=members,
                id_map=dict(payload.get("id_map", {})),
                counts=dict(payload.get("counts", {})),
                warnings=tuple(payload.get("warnings", [])),
                manifest_digest=payload.get("manifest_digest"),
            )
        except KeyError as exc:
            raise ArchiveError(f"archive manifest is missing {exc.args[0]}") from exc
        expected = manifest.digest()
        if manifest.manifest_digest is None or not hmac.compare_digest(manifest.manifest_digest, expected):
            raise ArchiveError("archive manifest digest mismatch")
        return manifest


@dataclass(frozen=True, slots=True)
class RestoreResult:
    archive_id: str
    target_run_id: str
    restored_paths: tuple[str, ...]
    already_restored: bool
    execution_allowed: bool = False


def _hash_file(path: Path) -> tuple[int, str]:
    size = 0
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(_CHUNK_BYTES):
            size += len(chunk)
            hasher.update(chunk)
    return size, hasher.hexdigest()


def _write_bytes(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        Path(temporary).replace(path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def _member_for_file(
    root: Path,
    relative: str,
    *,
    kind: str,
    media_type: str,
    source_id: str | None = None,
) -> ArchiveMember:
    path = root / Path(relative)
    size, digest = _hash_file(path)
    return ArchiveMember(
        path=relative,
        kind=kind,
        media_type=media_type,
        size_bytes=size,
        sha256=digest,
        source_id=source_id,
    )


def _all_events(ledger: _LedgerAdapter, run_id: str) -> list[Any]:
    events: list[Any] = []
    after_sequence = 0
    while True:
        page = list(ledger.events(run_id, after_sequence=after_sequence, limit=1000))
        if not page:
            return events
        events.extend(page)
        last_event = page[-1]
        last_sequence_value = getattr(last_event, "sequence", None)
        if last_sequence_value is None and isinstance(last_event, Mapping):
            last_sequence_value = last_event.get("sequence", 0)
        last_sequence = int(last_sequence_value or 0)
        if last_sequence <= after_sequence:
            raise ArchiveError("ledger event pagination did not advance")
        after_sequence = last_sequence
        if len(page) < 1000:
            return events


def _artifact_ids(value: Any) -> set[str]:
    """Find explicit CAS references in state and ledger payloads."""

    found: set[str] = set()

    def visit(current: Any, key: str | None = None) -> None:
        if hasattr(current, "model_dump"):
            visit(current.model_dump(mode="json"), key)
            return
        if isinstance(current, Mapping):
            for child_key, child in current.items():
                normalized_key = str(child_key)
                if normalized_key in _ARTIFACT_ID_KEYS or normalized_key.endswith("_artifact_id"):
                    values = child if isinstance(child, (list, tuple, set, frozenset)) else (child,)
                    for candidate in values:
                        if isinstance(candidate, str) and len(candidate) == _SHA256_LENGTH:
                            try:
                                found.add(_validate_sha256(candidate.lower(), normalized_key))
                            except ArchiveError:
                                continue
                visit(child, normalized_key)
            return
        if isinstance(current, (list, tuple, set, frozenset)):
            for child in current:
                visit(child, key)

    visit(value)
    return found


def _artifact_metadata_payload(metadata: Any) -> dict[str, Any]:
    payload = _jsonable(metadata)
    if not isinstance(payload, dict):
        raise ArchiveError("artifact metadata must be an object")
    return payload


def export_run_archive(
    root: Path,
    *,
    ledger: _LedgerAdapter,
    artifact_store: _ArtifactAdapter,
    run_id: str,
    archive_id: str | None = None,
    created_at: str | None = None,
    freeze_id: str | None = None,
) -> ArchiveManifest:
    """Export one terminal run into a verified directory archive.

    This adapter deliberately consumes the existing LedgerStore and CAS
    interfaces.  It does not mutate the run, acquire execution leases, call a
    model/tool, or infer bytes from untrusted paths.  A future freeze service
    must fence writes before invoking this function.
    """

    state = ledger.load_state(run_id)
    if state is None:
        raise ArchiveError(f"run state does not exist: {run_id}")
    state_status = getattr(getattr(state, "status", None), "value", getattr(state, "status", None))
    if state_status not in _ARCHIVABLE_STATUSES:
        raise ArchiveError(f"run is not frozen or terminal: {run_id}")
    if not ledger.verify(run_id):
        raise ArchiveError(f"ledger hash chain is invalid: {run_id}")
    events = _all_events(ledger, run_id)
    for event in events:
        event_run_id = getattr(event, "run_id", None)
        if event_run_id is None and isinstance(event, Mapping):
            event_run_id = event.get("run_id")
        if event_run_id != run_id:
            raise ArchiveError("ledger event belongs to another run")

    root = root.resolve()
    if root.exists():
        if root.is_symlink() or not root.is_dir() or any(root.iterdir()):
            raise ArchiveError("archive destination must be a new or empty directory")
    else:
        root.mkdir(parents=True, exist_ok=False)

    archive_id = archive_id or f"archive-{run_id}-{getattr(events[-1], 'hash', '0' * 64)[:16]}"
    created_at = created_at or datetime.now(UTC).isoformat()
    freeze_id = freeze_id or f"freeze-{run_id}-{getattr(state, 'state_version', 1)}"

    state_payload = _jsonable(state)
    event_payloads = [_jsonable(event) for event in events]
    state_relative = "state/run.json"
    ledger_relative = "ledger/events.jsonl"
    _write_bytes(root / Path(state_relative), _canonical_json(state_payload) + b"\n")
    ledger_bytes = b"".join(_canonical_json(event) + b"\n" for event in event_payloads)
    _write_bytes(root / Path(ledger_relative), ledger_bytes)

    artifact_ids = sorted(_artifact_ids(state_payload) | _artifact_ids(event_payloads))
    artifact_members: list[ArchiveMember] = []
    artifact_descriptors: list[dict[str, Any]] = []
    for artifact_id in artifact_ids:
        try:
            content = artifact_store.read(artifact_id)
            metadata = _artifact_metadata_payload(artifact_store.metadata_for(artifact_id))
        except Exception as exc:
            raise ArchiveError(f"artifact {artifact_id} could not be exported") from exc
        if hashlib.sha256(content).hexdigest() != artifact_id:
            raise ArchiveError(f"artifact bytes do not match identity: {artifact_id}")
        metadata_artifact_id = metadata.get("artifact_id")
        if metadata_artifact_id != artifact_id:
            raise ArchiveError(f"artifact metadata identity mismatch: {artifact_id}")
        bytes_relative = f"artifacts/sha256/{artifact_id[:2]}/{artifact_id}"
        metadata_relative = f"artifacts/metadata/{artifact_id[:2]}/{artifact_id}.json"
        _write_bytes(root / Path(bytes_relative), content)
        _write_bytes(root / Path(metadata_relative), _canonical_json(metadata) + b"\n")
        artifact_members.append(
            _member_for_file(
                root,
                bytes_relative,
                kind="artifact",
                media_type=str(metadata.get("media_type", "application/octet-stream")),
                source_id=artifact_id,
            )
        )
        artifact_members.append(
            _member_for_file(
                root,
                metadata_relative,
                kind="metadata",
                media_type="application/json",
                source_id=artifact_id,
            )
        )
        artifact_descriptors.append({"artifact_id": artifact_id, "metadata": metadata})

    if events:
        latest_event = events[-1]
        latest_sequence_value = getattr(latest_event, "sequence", None)
        latest_hash_value = getattr(latest_event, "hash", None)
        if isinstance(latest_event, Mapping):
            latest_sequence_value = latest_event.get("sequence", latest_sequence_value)
            latest_hash_value = latest_event.get("hash", latest_hash_value)
        latest_sequence = int(latest_sequence_value or 0)
        ledger_head_hash = str(latest_hash_value or "0" * 64)
    else:
        latest_sequence = 0
        ledger_head_hash = "0" * 64
    artifact_snapshot_digest = hashlib.sha256(_canonical_json(artifact_descriptors)).hexdigest()
    members = tuple(
        sorted(
            (
                _member_for_file(root, state_relative, kind="state", media_type="application/json", source_id=run_id),
                _member_for_file(
                    root, ledger_relative, kind="ledger", media_type="application/x-ndjson", source_id=run_id
                ),
                *artifact_members,
            ),
            key=lambda member: member.path,
        )
    )
    manifest = ArchiveManifest(
        format_version=1,
        archive_id=archive_id,
        created_at=created_at,
        source={
            "run_id": run_id,
            "state_version": int(getattr(state, "state_version", 1)),
            "latest_event_sequence": latest_sequence,
            "ledger_head_hash": ledger_head_hash,
            "checkpoint_ref": getattr(state, "fork_checkpoint_id", None),
            "schema_version": getattr(state, "schema_version", None),
        },
        freeze={
            "freeze_id": freeze_id,
            "status": state_status,
            "frozen_at": created_at,
            "ledger_head_hash": ledger_head_hash,
            "artifact_snapshot_digest": artifact_snapshot_digest,
        },
        members=members,
        id_map={run_id: run_id},
        counts={
            "ledger_events": len(events),
            "artifacts": len(artifact_ids),
            "artifact_metadata": len(artifact_ids),
            "state_snapshots": 1,
        },
    )
    write_manifest(root, manifest)
    return verify_archive(root)


def collect_members(
    root: Path,
    *,
    kinds: Mapping[str, str],
    source_ids: Mapping[str, str] | None = None,
) -> tuple[ArchiveMember, ...]:
    """Collect regular files under *root* into deterministic manifest members."""

    root = root.resolve()
    if not root.is_dir() or root.is_symlink():
        raise ArchiveError("archive root must be a real directory")
    members: list[ArchiveMember] = []
    for path in sorted(root.rglob("*")):
        if path.name == _MANIFEST_NAME:
            continue
        if path.is_dir() and not path.is_symlink():
            continue
        if path.is_symlink() or not path.is_file():
            raise ArchiveError(f"archive tree contains an unsupported path: {path}")
        relative = path.relative_to(root).as_posix()
        if relative not in kinds:
            raise ArchiveError(f"archive member kind is missing for {relative}")
        size, digest = _hash_file(path)
        members.append(
            ArchiveMember(
                path=relative,
                kind=kinds[relative],
                media_type="application/octet-stream",
                size_bytes=size,
                sha256=digest,
                source_id=None if source_ids is None else source_ids.get(relative),
            )
        )
    return tuple(members)


def write_manifest(root: Path, manifest: ArchiveManifest) -> Path:
    """Atomically write a canonical manifest after validating its signature."""

    root = root.resolve()
    if not root.is_dir() or root.is_symlink():
        raise ArchiveError("archive root must be a real directory")
    signed = manifest.signed()
    destination = root / _MANIFEST_NAME
    fd, temporary = tempfile.mkstemp(prefix=".manifest-", dir=root)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(signed.to_bytes())
            handle.flush()
            os.fsync(handle.fileno())
        Path(temporary).replace(destination)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return destination


def load_manifest(root: Path) -> ArchiveManifest:
    root = root.resolve()
    manifest_path = root / _MANIFEST_NAME
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise ArchiveError("archive manifest is missing")
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ArchiveError("archive manifest is unreadable") from exc
    return ArchiveManifest.from_dict(payload)


def verify_archive(root: Path, manifest: ArchiveManifest | None = None) -> ArchiveManifest:
    """Verify every declared member and reject missing, extra, or unsafe files."""

    if root.is_symlink() or not root.is_dir():
        raise ArchiveError("archive root must be a real directory")
    root = root.resolve()
    disk_manifest = load_manifest(root)
    if manifest is not None and disk_manifest.to_bytes() != manifest.to_bytes():
        raise ArchiveError("provided archive manifest differs from manifest.json")
    manifest = disk_manifest
    if manifest.manifest_digest is None or not hmac.compare_digest(manifest.manifest_digest, manifest.digest()):
        raise ArchiveError("archive manifest digest mismatch")
    expected = {_safe_relative_path(member.path): member for member in manifest.members}
    observed: set[str] = set()
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        if relative == _MANIFEST_NAME:
            continue
        if path.is_dir() and not path.is_symlink():
            continue
        if path.is_symlink() or not path.is_file():
            raise ArchiveError(f"archive contains an unsupported path: {relative}")
        observed.add(relative)
    if observed != set(expected):
        missing = sorted(set(expected) - observed)
        extra = sorted(observed - set(expected))
        raise ArchiveError(f"archive member set mismatch (missing={missing}, extra={extra})")
    for relative, member in expected.items():
        path = root / Path(relative)
        size, digest = _hash_file(path)
        if size != member.size_bytes or not hmac.compare_digest(digest, member.sha256):
            raise ArchiveError(f"archive member integrity mismatch: {relative}")
    return manifest


def restore_archive(
    root: Path,
    target: Path,
    *,
    target_run_id: str,
    manifest: ArchiveManifest | None = None,
) -> RestoreResult:
    """Verify and copy an archive into an isolated target directory.

    The function intentionally has no execution callback.  It only copies
    verified bytes and writes a completion marker with ``execution_allowed``
    set to false.  A caller that wants to resume work must create a new
    authorization and execution plan outside this module.
    """

    if not target_run_id or any(ord(char) < 32 for char in target_run_id):
        raise ArchiveError("target_run_id is invalid")
    root = root.resolve()
    if target.is_symlink():
        raise ArchiveError("restore target must not be a symlink")
    manifest = verify_archive(root, manifest)
    target.mkdir(parents=True, exist_ok=True)
    if target.is_symlink():
        raise ArchiveError("restore target must not be a symlink")
    target = target.resolve()
    marker = target / _RESTORE_MARKER_NAME
    if marker.exists():
        if marker.is_symlink() or not marker.is_file():
            raise ArchiveError("restore marker is invalid")
        try:
            previous = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ArchiveError("restore marker is unreadable") from exc
        if previous.get("archive_id") != manifest.archive_id or previous.get("target_run_id") != target_run_id:
            raise ArchiveError("restore target already belongs to another archive")
        if previous.get("manifest_digest") != manifest.digest() or previous.get("execution_allowed") is not False:
            raise ArchiveError("restore marker does not attest to the verified archive")
        return RestoreResult(manifest.archive_id, target_run_id, tuple(previous.get("restored_paths", [])), True)

    restored: list[str] = []
    staging = Path(tempfile.mkdtemp(prefix=".restore-", dir=target))
    try:
        for member in manifest.members:
            source = root / Path(member.path)
            destination = staging / Path(member.path)
            destination.parent.mkdir(parents=True, exist_ok=True)
            if source.is_symlink() or not source.is_file():
                raise ArchiveError(f"archive member disappeared during restore: {member.path}")
            shutil.copyfile(source, destination)
            size, digest = _hash_file(destination)
            if size != member.size_bytes or not hmac.compare_digest(digest, member.sha256):
                raise ArchiveError(f"restored member integrity mismatch: {member.path}")
            restored.append(member.path)
        for member in manifest.members:
            staged = staging / Path(member.path)
            destination = _safe_target_path(target, member.path)
            if destination.exists() or destination.is_symlink():
                raise ArchiveError(f"restore destination already exists: {member.path}")
            destination.parent.mkdir(parents=True, exist_ok=True)
            staged.replace(destination)
        marker_payload = {
            "archive_id": manifest.archive_id,
            "target_run_id": target_run_id,
            "manifest_digest": manifest.digest(),
            "restored_paths": sorted(restored),
            "execution_allowed": False,
        }
        fd, temporary = tempfile.mkstemp(prefix=".restore-marker-", dir=target)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(_canonical_json(marker_payload) + b"\n")
                handle.flush()
                os.fsync(handle.fileno())
            Path(temporary).replace(marker)
        finally:
            Path(temporary).unlink(missing_ok=True)
        return RestoreResult(manifest.archive_id, target_run_id, tuple(sorted(restored)), False)
    except Exception:
        for relative in restored:
            (target / Path(relative)).unlink(missing_ok=True)
        raise
    finally:
        shutil.rmtree(staging, ignore_errors=True)


__all__ = [
    "ArchiveError",
    "ArchiveManifest",
    "ArchiveMember",
    "RestoreResult",
    "collect_members",
    "export_run_archive",
    "load_manifest",
    "restore_archive",
    "verify_archive",
    "write_manifest",
]
