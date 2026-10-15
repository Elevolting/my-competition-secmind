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
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from enum import Enum
from pathlib import Path
from typing import Any, Protocol

_SHA256_LENGTH = 64
_SUPPORTED_FORMAT_VERSIONS = frozenset({1})
_MEMBER_KINDS = frozenset({"ledger", "state", "audit", "artifact", "checkpoint", "metadata"})
_MANIFEST_NAME = "manifest.json"
_RESTORE_MARKER_NAME = ".restore-complete.json"
_RESTORE_JOURNAL_NAME = ".restore-journal.json"
_RESTORE_LOCK_NAME = ".restore-lock.json"
_CHUNK_BYTES = 1024 * 1024
_ARCHIVABLE_STATUSES = frozenset({"completed", "partial", "denied", "failed", "recovery_required", "cancelled"})
_ARTIFACT_ID_KEYS = frozenset({"artifact_id", "artifact_ids", "prompt_artifact_id", "response_artifact_id"})


class _LedgerAdapter(Protocol):
    def load_state(self, run_id: str) -> Any | None: ...

    def events(self, run_id: str, after_sequence: int = 0, limit: int = 1000) -> list[Any]: ...

    def verify(self, run_id: str) -> bool: ...

    def begin_archive_freeze(self, run_id: str, *, freeze_id: str | None = None) -> Any: ...

    def complete_archive_freeze(
        self, run_id: str, *, freeze_id: str, artifact_snapshot_digest: str
    ) -> Any: ...

    def abort_archive_freeze(self, run_id: str, *, freeze_id: str) -> None: ...

    def archive_freeze(self, run_id: str) -> Any | None: ...


class _ArtifactAdapter(Protocol):
    def read(self, artifact_id: str) -> bytes: ...

    def metadata_for(self, artifact_id: str) -> Any: ...

    def begin_archive_freeze(self, run_id: str, *, freeze_id: str) -> None: ...

    def complete_archive_freeze(self, run_id: str, *, freeze_id: str, artifact_snapshot_digest: str) -> None: ...

    def abort_archive_freeze(self, run_id: str, *, freeze_id: str) -> None: ...


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
    id_map: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ArchiveFreezeResult:
    run_id: str
    freeze_id: str
    state_version: int
    latest_event_sequence: int
    ledger_head_hash: str
    artifact_snapshot_digest: str
    frozen_at: str


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


def _write_json_atomic(path: Path, payload: Mapping[str, Any]) -> None:
    _write_bytes(path, _canonical_json(payload) + b"\n")


def _read_json(path: Path, *, error: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ArchiveError(error) from exc
    if not isinstance(payload, dict):
        raise ArchiveError(error)
    return payload


def _process_is_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except (OSError, ProcessLookupError):
        return False
    return True


def _acquire_restore_lock(target: Path) -> Path:
    lock = target / _RESTORE_LOCK_NAME
    payload = {"pid": os.getpid(), "created_at": datetime.now(UTC).isoformat()}
    for _ in range(2):
        try:
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            try:
                previous = _read_json(lock, error="restore lock is unreadable")
                previous_pid = int(previous.get("pid", 0))
            except (ArchiveError, TypeError, ValueError):
                raise ArchiveError("restore target is locked") from None
            if _process_is_alive(previous_pid):
                raise ArchiveError("restore target is locked") from None
            lock.unlink(missing_ok=True)
            continue
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(_canonical_json(payload) + b"\n")
                handle.flush()
                os.fsync(handle.fileno())
        except Exception:
            lock.unlink(missing_ok=True)
            raise
        return lock
    raise ArchiveError("restore target is locked")


def _recover_restore_journal(target: Path, manifest: ArchiveManifest, target_run_id: str) -> None:
    journal_path = target / _RESTORE_JOURNAL_NAME
    if not journal_path.exists():
        return
    if journal_path.is_symlink() or not journal_path.is_file():
        raise ArchiveError("restore journal is invalid")
    journal = _read_json(journal_path, error="restore journal is unreadable")
    if (
        journal.get("archive_id") != manifest.archive_id
        or journal.get("target_run_id") != target_run_id
        or journal.get("manifest_digest") != manifest.digest()
    ):
        raise ArchiveError("restore journal belongs to another archive")
    staging_name = journal.get("staging_name")
    if (
        not isinstance(staging_name, str)
        or not staging_name.startswith(".restore-")
        or Path(staging_name).name != staging_name
    ):
        raise ArchiveError("restore journal staging path is invalid")
    staging = target / staging_name
    if staging.is_symlink():
        raise ArchiveError("restore journal staging path is a symlink")
    if staging.exists():
        shutil.rmtree(staging)
    planned_paths = journal.get("planned_paths", [])
    if not isinstance(planned_paths, list) or any(not isinstance(item, str) for item in planned_paths):
        raise ArchiveError("restore journal planned paths are invalid")
    for relative in planned_paths:
        destination = _safe_target_path(target, relative)
        if destination.is_symlink() or destination.is_file():
            destination.unlink()
        elif destination.exists():
            raise ArchiveError(f"restore journal destination is not a file: {relative}")
    journal_path.unlink(missing_ok=True)


def _restore_id_map(manifest: ArchiveManifest, target_run_id: str) -> dict[str, str]:
    source_run_id = manifest.source.get("run_id")
    mapping = dict(manifest.id_map)
    if isinstance(source_run_id, str) and source_run_id:
        mapping[source_run_id] = target_run_id
    return mapping


def _rewrite_identity(value: Any, id_map: Mapping[str, str]) -> Any:
    if isinstance(value, str):
        return id_map.get(value, value)
    if isinstance(value, Mapping):
        return {_rewrite_identity(str(key), id_map): _rewrite_identity(item, id_map) for key, item in value.items()}
    if isinstance(value, list):
        return [_rewrite_identity(item, id_map) for item in value]
    return value


def _rewrite_ledger_jsonl(content: bytes, id_map: Mapping[str, str]) -> bytes:
    try:
        rows = [json.loads(line) for line in content.decode("utf-8").splitlines() if line.strip()]
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ArchiveError("ledger member is not valid JSONL") from exc
    if not rows or not all(isinstance(row, dict) for row in rows):
        raise ArchiveError("ledger member rows must be objects")
    rewritten = [_rewrite_identity(row, id_map) for row in rows]
    required = {"event_id", "run_id", "sequence", "event_type", "timestamp", "actor", "dedupe_key", "payload"}
    if not all(required.issubset(row) for row in rewritten):
        return content
    previous = "0" * 64
    output: list[bytes] = []
    for row in rewritten:
        row["prev_hash"] = previous
        digest_input = {
            "event_id": row["event_id"],
            "run_id": row["run_id"],
            "sequence": row["sequence"],
            "event_type": row["event_type"],
            "timestamp": row["timestamp"],
            "actor": row["actor"],
            "dedupe_key": row["dedupe_key"],
            "payload": row["payload"],
            "prev_hash": row["prev_hash"],
        }
        row["hash"] = hashlib.sha256(_canonical_json(digest_input)).hexdigest()
        previous = row["hash"]
        output.append(_canonical_json(row) + b"\n")
    return b"".join(output)


def _rewrite_restore_member(member: ArchiveMember, content: bytes, id_map: Mapping[str, str]) -> bytes:
    if member.kind == "ledger":
        return _rewrite_ledger_jsonl(content, id_map)
    if member.kind not in {"state", "metadata"}:
        return content
    try:
        payload = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ArchiveError(f"{member.kind} member is not valid JSON: {member.path}") from exc
    rewritten = _rewrite_identity(payload, id_map)
    if member.kind == "state" and isinstance(rewritten, dict) and "run_id" in rewritten:
        rewritten["status"] = "recovery_required"
    return _canonical_json(rewritten) + b"\n"


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


def _collect_artifact_snapshot(
    artifact_store: _ArtifactAdapter,
    state_payload: Any,
    event_payloads: Any,
) -> tuple[list[str], list[dict[str, Any]]]:
    """Read and verify referenced CAS bytes and return a stable snapshot."""

    artifact_ids = sorted(_artifact_ids(state_payload) | _artifact_ids(event_payloads))
    descriptors: list[dict[str, Any]] = []
    for artifact_id in artifact_ids:
        try:
            content = artifact_store.read(artifact_id)
            metadata = _artifact_metadata_payload(artifact_store.metadata_for(artifact_id))
        except Exception as exc:
            raise ArchiveError(f"artifact {artifact_id} could not be exported") from exc
        if hashlib.sha256(content).hexdigest() != artifact_id:
            raise ArchiveError(f"artifact bytes do not match identity: {artifact_id}")
        if metadata.get("artifact_id") != artifact_id:
            raise ArchiveError(f"artifact metadata identity mismatch: {artifact_id}")
        descriptors.append({"artifact_id": artifact_id, "metadata": metadata})
    return artifact_ids, descriptors


def freeze_run_for_archive(
    *,
    ledger: _LedgerAdapter,
    artifact_store: _ArtifactAdapter,
    run_id: str,
    freeze_id: str | None = None,
) -> ArchiveFreezeResult:
    """Freeze ledger and CAS writes, then seal one consistent archive boundary."""

    try:
        ledger_freeze = ledger.begin_archive_freeze(run_id, freeze_id=freeze_id)
    except (AttributeError, TypeError) as exc:
        raise ArchiveError("ledger adapter does not provide archive freeze fencing") from exc
    effective_freeze_id = str(getattr(ledger_freeze, "freeze_id", ""))
    if not effective_freeze_id:
        raise ArchiveError("ledger freeze did not return a freeze id")
    artifact_started = False
    artifact_completed = False
    try:
        artifact_store.begin_archive_freeze(run_id, freeze_id=effective_freeze_id)
        artifact_started = True
        state = ledger.load_state(run_id)
        if state is None:
            raise ArchiveError(f"run state does not exist: {run_id}")
        events = _all_events(ledger, run_id)
        if not ledger.verify(run_id):
            raise ArchiveError(f"ledger hash chain is invalid: {run_id}")
        state_payload = _jsonable(state)
        event_payloads = [_jsonable(event) for event in events]
        _, descriptors = _collect_artifact_snapshot(artifact_store, state_payload, event_payloads)
        snapshot_digest = hashlib.sha256(_canonical_json(descriptors)).hexdigest()
        artifact_store.complete_archive_freeze(
            run_id,
            freeze_id=effective_freeze_id,
            artifact_snapshot_digest=snapshot_digest,
        )
        artifact_completed = True
        completed = ledger.complete_archive_freeze(
            run_id,
            freeze_id=effective_freeze_id,
            artifact_snapshot_digest=snapshot_digest,
        )
    except Exception:
        if artifact_started or artifact_completed:
            artifact_store.abort_archive_freeze(run_id, freeze_id=effective_freeze_id)
        ledger.abort_archive_freeze(run_id, freeze_id=effective_freeze_id)
        raise
    return ArchiveFreezeResult(
        run_id=run_id,
        freeze_id=effective_freeze_id,
        state_version=int(getattr(completed, "state_version", 0)),
        latest_event_sequence=int(getattr(completed, "latest_event_sequence", 0)),
        ledger_head_hash=str(getattr(completed, "ledger_head_hash", "")),
        artifact_snapshot_digest=snapshot_digest,
        frozen_at=str(getattr(completed, "frozen_at", "")),
    )


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
    model/tool, or infer bytes from untrusted paths.  Call
    :func:`freeze_run_for_archive` before invoking this function.
    """

    freeze = getattr(ledger, "archive_freeze", lambda _run_id: None)(run_id)
    if freeze is None or getattr(freeze, "status", None) != "complete":
        raise ArchiveError(f"run archive freeze is required: {run_id}")
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

    requested_freeze_id = freeze_id
    effective_freeze_id = str(getattr(freeze, "freeze_id", ""))
    if not effective_freeze_id:
        raise ArchiveError("archive freeze identity is invalid")
    if requested_freeze_id is not None and requested_freeze_id != effective_freeze_id:
        raise ArchiveError("archive freeze identity mismatch")
    latest_hash_for_id = getattr(events[-1], "hash", "0" * 64) if events else "0" * 64
    archive_id = archive_id or f"archive-{run_id}-{latest_hash_for_id[:16]}"
    created_at = created_at or datetime.now(UTC).isoformat()

    state_payload = _jsonable(state)
    event_payloads = [_jsonable(event) for event in events]
    state_relative = "state/run.json"
    ledger_relative = "ledger/events.jsonl"
    _write_bytes(root / Path(state_relative), _canonical_json(state_payload) + b"\n")
    ledger_bytes = b"".join(_canonical_json(event) + b"\n" for event in event_payloads)
    _write_bytes(root / Path(ledger_relative), ledger_bytes)

    artifact_ids, artifact_descriptors = _collect_artifact_snapshot(artifact_store, state_payload, event_payloads)
    artifact_members: list[ArchiveMember] = []
    for artifact_id in artifact_ids:
        content = artifact_store.read(artifact_id)
        metadata = next(
            descriptor["metadata"]
            for descriptor in artifact_descriptors
            if descriptor["artifact_id"] == artifact_id
        )
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
    if int(getattr(freeze, "latest_event_sequence", latest_sequence)) != latest_sequence:
        raise ArchiveError("ledger changed after archive freeze")
    if str(getattr(freeze, "ledger_head_hash", ledger_head_hash)) != ledger_head_hash:
        raise ArchiveError("ledger head changed after archive freeze")
    if int(getattr(freeze, "state_version", getattr(state, "state_version", 1))) != int(
        getattr(state, "state_version", 1)
    ):
        raise ArchiveError("state changed after archive freeze")
    artifact_snapshot_digest = hashlib.sha256(_canonical_json(artifact_descriptors)).hexdigest()
    recorded_snapshot_digest = getattr(freeze, "artifact_snapshot_digest", None)
    if recorded_snapshot_digest != artifact_snapshot_digest:
        raise ArchiveError("artifact snapshot changed after archive freeze")
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
            "freeze_id": effective_freeze_id,
            "status": "terminal",
            "run_status": state_status,
            "frozen_at": str(getattr(freeze, "frozen_at", created_at)),
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
    lock = _acquire_restore_lock(target)
    try:
        id_map = _restore_id_map(manifest, target_run_id)
        if marker.exists():
            if marker.is_symlink() or not marker.is_file():
                raise ArchiveError("restore marker is invalid")
            previous = _read_json(marker, error="restore marker is unreadable")
            if previous.get("archive_id") != manifest.archive_id or previous.get("target_run_id") != target_run_id:
                raise ArchiveError("restore target already belongs to another archive")
            if previous.get("manifest_digest") != manifest.digest() or previous.get("execution_allowed") is not False:
                raise ArchiveError("restore marker does not attest to the verified archive")
            journal = target / _RESTORE_JOURNAL_NAME
            if journal.exists():
                if journal.is_symlink() or not journal.is_file():
                    raise ArchiveError("restore journal is invalid")
                journal.unlink()
            previous_map = previous.get("id_map", id_map)
            if not isinstance(previous_map, dict):
                raise ArchiveError("restore marker id_map is invalid")
            return RestoreResult(
                manifest.archive_id,
                target_run_id,
                tuple(previous.get("restored_paths", [])),
                True,
                False,
                {str(key): str(value) for key, value in previous_map.items()},
            )

        _recover_restore_journal(target, manifest, target_run_id)
        planned_paths = [member.path for member in manifest.members]
        for relative in planned_paths:
            destination = _safe_target_path(target, relative)
            if destination.exists() or destination.is_symlink():
                raise ArchiveError(f"restore destination already exists: {relative}")
        staging = Path(tempfile.mkdtemp(prefix=".restore-", dir=target))
        journal_path = target / _RESTORE_JOURNAL_NAME
        _write_json_atomic(
            journal_path,
            {
                "archive_id": manifest.archive_id,
                "target_run_id": target_run_id,
                "manifest_digest": manifest.digest(),
                "staging_name": staging.name,
                "planned_paths": planned_paths,
                "committed_paths": [],
                "phase": "staging",
            },
        )
        restored: list[str] = []
        try:
            for member in manifest.members:
                source = root / Path(member.path)
                destination = staging / Path(member.path)
                destination.parent.mkdir(parents=True, exist_ok=True)
                if source.is_symlink() or not source.is_file():
                    raise ArchiveError(f"archive member disappeared during restore: {member.path}")
                source_size, source_digest = _hash_file(source)
                if source_size != member.size_bytes or not hmac.compare_digest(source_digest, member.sha256):
                    raise ArchiveError(f"restored member integrity mismatch: {member.path}")
                if member.kind in {"state", "ledger", "metadata"}:
                    destination.write_bytes(_rewrite_restore_member(member, source.read_bytes(), id_map))
                else:
                    shutil.copyfile(source, destination)
                restored.append(member.path)
            _write_json_atomic(
                journal_path,
                {
                    "archive_id": manifest.archive_id,
                    "target_run_id": target_run_id,
                    "manifest_digest": manifest.digest(),
                    "staging_name": staging.name,
                    "planned_paths": planned_paths,
                    "committed_paths": [],
                    "phase": "committing",
                },
            )
            committed: list[str] = []
            for member in manifest.members:
                staged = staging / Path(member.path)
                destination = _safe_target_path(target, member.path)
                destination.parent.mkdir(parents=True, exist_ok=True)
                staged.replace(destination)
                committed.append(member.path)
                _write_json_atomic(
                    journal_path,
                    {
                        "archive_id": manifest.archive_id,
                        "target_run_id": target_run_id,
                        "manifest_digest": manifest.digest(),
                        "staging_name": staging.name,
                        "planned_paths": planned_paths,
                        "committed_paths": committed,
                        "phase": "committing",
                    },
                )
        except Exception:
            _recover_restore_journal(target, manifest, target_run_id)
            raise
        marker_payload = {
            "archive_id": manifest.archive_id,
            "target_run_id": target_run_id,
            "manifest_digest": manifest.digest(),
            "restored_paths": sorted(restored),
            "execution_allowed": False,
            "id_map": id_map,
        }
        _write_json_atomic(marker, marker_payload)
        (target / _RESTORE_JOURNAL_NAME).unlink(missing_ok=True)
        return RestoreResult(manifest.archive_id, target_run_id, tuple(sorted(restored)), False, False, id_map)
    finally:
        lock.unlink(missing_ok=True)
        staging_path = locals().get("staging")
        if isinstance(staging_path, Path):
            shutil.rmtree(staging_path, ignore_errors=True)


__all__ = [
    "ArchiveError",
    "ArchiveFreezeResult",
    "ArchiveManifest",
    "ArchiveMember",
    "RestoreResult",
    "collect_members",
    "export_run_archive",
    "freeze_run_for_archive",
    "load_manifest",
    "restore_archive",
    "verify_archive",
    "write_manifest",
]
