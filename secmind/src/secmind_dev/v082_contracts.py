"""Versioned contracts for the SecMind v0.8.2 evaluation boundary.

The product runtime has a richer, mutable state model.  The evaluation
boundary intentionally uses small immutable records instead.  A Bridge may
adapt many kinds of agents, but it must emit the same records before the
scorer is allowed to see a result.

This module is dependency-light on purpose: it can be used by a standalone
CLI, by an adapter running in a different virtual environment, and by tests
which do not start the SecMind service.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import subprocess  # nosec B404
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, fields, is_dataclass
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Any, ClassVar, Literal

V082_SCHEMA_VERSION = "secmind-evaluation-v0.8.2"
EVIDENCE_SCHEMA_VERSION = "secmind-evidence-v0.8.2"
BRIDGE_SCHEMA_VERSION = "secmind-bridge-v0.8.2"
UNKNOWN_NOT_CONTROLLED = "UNKNOWN_NOT_CONTROLLED"
_SHA256 = re.compile(r"^(?:sha256:)?[0-9a-fA-F]{64}$")
_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9._:/@+-]{1,256}$")
_SECRET_KEY = re.compile(r"(?:api[_-]?key|token|password|passwd|secret|authorization|private[_-]?key)", re.I)


class ContractError(ValueError):
    """Raised when untrusted evaluation material cannot be accepted."""


def canonical_json(value: Any) -> bytes:
    """Return the one JSON representation used for every v0.8.2 digest."""

    return json.dumps(
        _jsonable(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical_digest(value: Any) -> str:
    return sha256_bytes(canonical_json(value))


def normalize_sha256(value: object, *, field_name: str = "sha256", allow_empty: bool = False) -> str:
    if allow_empty and value in (None, ""):
        return ""
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ContractError(f"{field_name} must be a SHA-256 hexadecimal digest")
    return value.removeprefix("sha256:").lower()


def canonical_path(value: object, *, prefix_input: bool = False) -> str:
    """Normalize a public input path and reject traversal/absolute paths."""

    if not isinstance(value, str):
        raise ContractError("path must be a string")
    normalized = unicodedata.normalize("NFC", value.replace("\\", "/")).strip()
    if normalized.startswith("input/"):
        normalized = normalized[6:]
    path = PurePosixPath(normalized)
    if (
        not normalized
        or len(normalized) > 1_024
        or path.is_absolute()
        or (path.parts and path.parts[0].endswith(":"))
        or any(part in {"", ".", ".."} for part in path.parts)
        or any(ord(char) < 32 or ord(char) == 127 for char in normalized)
    ):
        raise ContractError(f"unsafe or non-canonical input path: {value!r}")
    result = path.as_posix()
    return f"input/{result}" if prefix_input else result


def public_path(value: object) -> str:
    return canonical_path(value, prefix_input=True)


def _require_text(value: object, *, field_name: str, maximum: int = 4_096, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value.strip()) or len(value) > maximum:
        state = "non-empty " if not allow_empty else ""
        raise ContractError(f"{field_name} must be {state}text of at most {maximum} characters")
    # Evidence excerpts and report prose legitimately contain newlines and
    # indentation. Keep those JSON-safe whitespace characters while rejecting
    # NUL, terminal escapes and every other C0/DEL control byte.
    if any((ord(char) < 32 and char not in "\t\r\n") or ord(char) == 127 for char in value):
        raise ContractError(f"{field_name} contains a control character")
    return value


def _require_identifier(value: object, *, field_name: str, maximum: int = 256) -> str:
    result = _require_text(value, field_name=field_name, maximum=maximum)
    if not _SAFE_IDENTIFIER.fullmatch(result):
        raise ContractError(f"{field_name} contains unsupported characters")
    return result


def _jsonable(value: Any) -> Any:
    if is_dataclass(value):
        return {item.name: _jsonable(getattr(value, item.name)) for item in fields(value)}
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))}
    if isinstance(value, (tuple, list, set, frozenset)):
        return [_jsonable(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat()
    if isinstance(value, Enum):
        return value.value
    return value


def _mapping_or_empty(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    return {str(key): item for key, item in value.items()}


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _tuple_strings(values: Sequence[object] | None, *, field_name: str, maximum: int = 100) -> tuple[str, ...]:
    if values is None:
        return ()
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes, bytearray)) or len(values) > maximum:
        raise ContractError(f"{field_name} must be a bounded string list")
    return tuple(_require_text(item, field_name=field_name, maximum=1_024) for item in values)


@dataclass(frozen=True, slots=True)
class InputArtifactRecord:
    artifact_id: str
    path: str
    sha256: str
    size_bytes: int
    media_type: str = "application/octet-stream"

    def __post_init__(self) -> None:
        object.__setattr__(self, "artifact_id", _require_identifier(self.artifact_id, field_name="artifact_id"))
        object.__setattr__(self, "path", canonical_path(self.path))
        object.__setattr__(self, "sha256", normalize_sha256(self.sha256, field_name="input artifact sha256"))
        if isinstance(self.size_bytes, bool) or not isinstance(self.size_bytes, int) or self.size_bytes < 0:
            raise ContractError("input artifact size_bytes must be a non-negative integer")
        object.__setattr__(self, "media_type", _require_text(self.media_type, field_name="media_type", maximum=256))

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "path": self.path,
            "relative_path": self.path,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "media_type": self.media_type,
        }


@dataclass(frozen=True, slots=True)
class InputManifest:
    artifacts: tuple[InputArtifactRecord, ...]
    dataset_version: str = "unknown"
    manifest_version: str = "input-manifest-v0.8.2"

    def __post_init__(self) -> None:
        items = tuple(self.artifacts)
        if not items:
            raise ContractError("input manifest must contain at least one artifact")
        paths = [item.path.casefold() for item in items]
        ids = [item.artifact_id for item in items]
        if len(paths) != len(set(paths)):
            raise ContractError("input manifest contains duplicate paths")
        if len(ids) != len(set(ids)):
            raise ContractError("input manifest contains duplicate artifact IDs")
        object.__setattr__(self, "artifacts", tuple(sorted(items, key=lambda item: item.path)))
        object.__setattr__(
            self, "dataset_version", _require_text(self.dataset_version, field_name="dataset_version", maximum=256)
        )

    @property
    def digest(self) -> str:
        return canonical_digest(self.to_dict())

    def find(self, path: str) -> InputArtifactRecord | None:
        wanted = canonical_path(path).casefold()
        return next((item for item in self.artifacts if item.path.casefold() == wanted), None)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.manifest_version,
            "dataset_version": self.dataset_version,
            "files": [item.to_dict() for item in self.artifacts],
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> InputManifest:
        if not isinstance(raw, Mapping):
            raise ContractError("input manifest must be an object")
        raw_files = raw.get("files", raw.get("artifacts"))
        if not isinstance(raw_files, list):
            raise ContractError("input manifest files must be a list")
        items: list[InputArtifactRecord] = []
        for index, item in enumerate(raw_files):
            if not isinstance(item, Mapping):
                raise ContractError(f"input manifest file {index} must be an object")
            items.append(
                InputArtifactRecord(
                    artifact_id=str(item.get("artifact_id") or item.get("id") or f"input-{index + 1}"),
                    path=str(item.get("path") or item.get("relative_path") or item.get("file") or ""),
                    sha256=str(item.get("sha256") or item.get("file_sha256") or ""),
                    size_bytes=int(item.get("size_bytes", item.get("size", 0))),
                    media_type=str(item.get("media_type", "application/octet-stream")),
                )
            )
        return cls(artifacts=tuple(items), dataset_version=str(raw.get("dataset_version", "unknown")))


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    evidence_id: str
    source: str
    summary: str = ""
    path: str = ""
    line: int | None = None
    file_sha256: str = ""
    finding_id: str | None = None
    artifact_ref: str | None = None
    sha256: str | None = None
    fact: str = ""
    extraction: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "evidence_id", _require_identifier(self.evidence_id, field_name="evidence_id", maximum=128)
        )
        object.__setattr__(self, "source", _require_text(self.source, field_name="evidence source", maximum=1_024))
        object.__setattr__(
            self, "summary", _require_text(self.summary, field_name="evidence summary", maximum=8_000, allow_empty=True)
        )
        if self.path:
            object.__setattr__(self, "path", canonical_path(self.path))
        if self.line is not None and (isinstance(self.line, bool) or not isinstance(self.line, int) or self.line < 1):
            raise ContractError("evidence line must be a positive integer")
        object.__setattr__(
            self, "file_sha256", normalize_sha256(self.file_sha256, field_name="evidence file_sha256", allow_empty=True)
        )
        if self.finding_id is not None:
            object.__setattr__(self, "finding_id", _require_identifier(self.finding_id, field_name="finding_id"))
        if self.artifact_ref is not None:
            object.__setattr__(
                self, "artifact_ref", _require_text(self.artifact_ref, field_name="artifact_ref", maximum=1_024)
            )
        if self.sha256 is not None:
            object.__setattr__(self, "sha256", normalize_sha256(self.sha256, field_name="evidence sha256"))
        object.__setattr__(
            self, "fact", _require_text(self.fact, field_name="evidence fact", maximum=8_000, allow_empty=True)
        )
        object.__setattr__(
            self,
            "extraction",
            _require_text(self.extraction, field_name="evidence extraction", maximum=8_000, allow_empty=True),
        )
        if not isinstance(self.metadata, Mapping):
            raise ContractError("evidence metadata must be an object")
        object.__setattr__(self, "metadata", dict(self.metadata))

    def to_dict(self, *, scorer_path: bool = False) -> dict[str, Any]:
        path = public_path(self.path) if self.path and scorer_path else self.path
        result: dict[str, Any] = {
            "evidence_id": self.evidence_id,
            "id": self.evidence_id,
            "source": self.source,
            "summary": self.summary,
            "path": path,
            "file": path,
            "line": self.line,
            "file_sha256": self.file_sha256 or None,
            "finding_id": self.finding_id,
            "artifact_ref": self.artifact_ref,
            "sha256": self.sha256,
            "fact": self.fact,
            "extraction": self.extraction,
            "metadata": dict(self.metadata),
        }
        return {key: value for key, value in result.items() if value is not None}


@dataclass(frozen=True, slots=True)
class FindingRecord:
    finding_id: str
    rule_id: str
    title: str
    description: str = ""
    severity: str = "UNKNOWN"
    confidence: str = "UNKNOWN"
    path: str = ""
    line: int | None = None
    file_sha256: str = ""
    remediation: str = ""
    evidence_ids: tuple[str, ...] = ()
    raw: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "finding_id", _require_identifier(self.finding_id, field_name="finding_id"))
        object.__setattr__(self, "rule_id", _require_text(self.rule_id, field_name="rule_id", maximum=256))
        object.__setattr__(self, "title", _require_text(self.title, field_name="finding title", maximum=8_000))
        for name in ("description", "remediation"):
            object.__setattr__(
                self, name, _require_text(getattr(self, name), field_name=name, maximum=8_000, allow_empty=True)
            )
        object.__setattr__(
            self, "severity", _require_text(self.severity, field_name="severity", maximum=64, allow_empty=True)
        )
        object.__setattr__(
            self, "confidence", _require_text(self.confidence, field_name="confidence", maximum=64, allow_empty=True)
        )
        if self.path:
            object.__setattr__(self, "path", canonical_path(self.path))
        if self.line is not None and (isinstance(self.line, bool) or not isinstance(self.line, int) or self.line < 1):
            raise ContractError("finding line must be a positive integer")
        object.__setattr__(
            self,
            "file_sha256",
            normalize_sha256(self.file_sha256, field_name="finding file_sha256", allow_empty=True),
        )
        ids = tuple(
            _require_identifier(item, field_name="finding evidence_id", maximum=128) for item in self.evidence_ids
        )
        if len(ids) != len(set(ids)):
            raise ContractError(f"finding {self.finding_id!r} repeats an evidence reference")
        object.__setattr__(self, "evidence_ids", ids)
        if not isinstance(self.raw, Mapping):
            raise ContractError("finding raw details must be an object")
        object.__setattr__(self, "raw", dict(self.raw))

    def fingerprint(self) -> str:
        raw = self.raw
        return canonical_digest(
            {
                "path": self.path.casefold(),
                "line": self.line,
                "rule_id": self.rule_id.casefold(),
                "root_cause": raw.get("root_cause", raw.get("data_flow", "")),
            }
        )

    def to_dict(self, *, scorer_path: bool = False) -> dict[str, Any]:
        path = public_path(self.path) if self.path and scorer_path else self.path
        result: dict[str, Any] = {
            "finding_id": self.finding_id,
            "id": self.finding_id,
            "rule_id": self.rule_id,
            "classification": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "confidence": self.confidence,
            "path": path,
            "file": path,
            "line": self.line,
            "file_sha256": self.file_sha256 or None,
            "remediation": self.remediation,
            "evidence_ids": list(self.evidence_ids),
            "fingerprint": self.fingerprint(),
            "raw": dict(self.raw),
        }
        # The scorer reads common semantic fields from the finding itself;
        # retaining them at the top level makes structured and plain answers
        # equivalent without trusting arbitrary raw keys.
        for key in ("cwe", "root_cause", "data_flow", "preconditions", "impact"):
            if key in self.raw:
                result[key] = self.raw[key]
        return result


AttemptStatus = Literal["SUCCESS", "FAILED", "TIMEOUT", "CRASH", "PARTIAL"]
AttemptType = Literal["primary", "fallback", "repair", "retry", "tool"]


@dataclass(frozen=True, slots=True)
class AttemptRecord:
    attempt_ordinal: int
    attempt_type: str
    status: str
    duration_ms: int
    stage: str
    retryable: bool
    request_digest: str
    provider_payload_digest: str | None = None
    response_digest: str | None = None
    error_type: str | None = None
    status_code: int | None = None
    ttft_ms: int | None = None
    time_to_headers_ms: int | None = None
    body_read_ms: int | None = None
    model_id: str = ""
    model_profile: str = ""
    completion_reason: str | None = None
    input_tokens: int = 0
    output_tokens: int = 0
    reasoning_tokens: int = 0
    cache_hit_input_tokens: int = 0
    cache_miss_input_tokens: int = 0
    stdout_sha256: str | None = None
    stderr_sha256: str | None = None

    ERROR_TYPES: ClassVar[frozenset[str]] = frozenset(
        {
            "timeout",
            "rate_limit",
            "http",
            "transport",
            "parse",
            "schema",
            "response_too_large",
            "cancelled",
            "crash",
            "unknown",
        }
    )
    ATTEMPT_TYPES: ClassVar[frozenset[str]] = frozenset({"primary", "fallback", "repair", "retry", "tool"})
    STATUSES: ClassVar[frozenset[str]] = frozenset({"SUCCESS", "FAILED", "TIMEOUT", "CRASH", "PARTIAL"})

    def __post_init__(self) -> None:
        if (
            isinstance(self.attempt_ordinal, bool)
            or not isinstance(self.attempt_ordinal, int)
            or self.attempt_ordinal < 1
        ):
            raise ContractError("attempt_ordinal must be a positive integer")
        for name in ("attempt_type", "status", "stage"):
            object.__setattr__(self, name, _require_text(getattr(self, name), field_name=name, maximum=64))
        if self.attempt_type not in self.ATTEMPT_TYPES:
            raise ContractError(f"unsupported attempt_type: {self.attempt_type}")
        if self.status.upper() not in self.STATUSES:
            raise ContractError(f"unsupported attempt status: {self.status}")
        object.__setattr__(self, "status", self.status.upper())
        if not isinstance(self.retryable, bool):
            raise ContractError("attempt retryable must be boolean")
        if isinstance(self.duration_ms, bool) or not isinstance(self.duration_ms, int) or self.duration_ms < 0:
            raise ContractError("attempt duration_ms must be a non-negative integer")
        object.__setattr__(self, "request_digest", normalize_sha256(self.request_digest, field_name="request_digest"))
        for name in ("provider_payload_digest", "response_digest", "stdout_sha256", "stderr_sha256"):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, normalize_sha256(value, field_name=name))
        if self.error_type is not None:
            normalized_error = self.error_type.casefold().replace("-", "_")
            if normalized_error not in self.ERROR_TYPES:
                raise ContractError(f"unknown attempt error_type: {self.error_type}")
            object.__setattr__(self, "error_type", normalized_error)
        for name in (
            "input_tokens",
            "output_tokens",
            "reasoning_tokens",
            "cache_hit_input_tokens",
            "cache_miss_input_tokens",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ContractError(f"{name} must be a non-negative integer")
        if self.cache_hit_input_tokens + self.cache_miss_input_tokens > self.input_tokens and self.input_tokens:
            raise ContractError("cache hit/miss input token counts exceed input_tokens")
        for name in ("ttft_ms", "time_to_headers_ms", "body_read_ms", "status_code"):
            value = getattr(self, name)
            if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value < 0):
                raise ContractError(f"{name} must be a non-negative integer when present")

    @property
    def successful(self) -> bool:
        return self.status == "SUCCESS" and self.error_type is None

    def to_dict(self) -> dict[str, Any]:
        return {key: value for key, value in _jsonable(self).items() if value is not None}


@dataclass(frozen=True, slots=True)
class FailureCapsule:
    task_id: str
    status: str
    final_error_type: str
    stage: str
    retryable: bool
    request_digest: str
    attempt_ordinals: tuple[int, ...]
    stdout_sha256: str | None = None
    stderr_sha256: str | None = None
    message: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "task_id", _require_identifier(self.task_id, field_name="task_id"))
        object.__setattr__(self, "status", _require_text(self.status, field_name="failure status", maximum=64))
        if not isinstance(self.retryable, bool):
            raise ContractError("failure retryable must be boolean")
        normalized_error = (
            _require_text(self.final_error_type, field_name="final_error_type", maximum=64).casefold().replace("-", "_")
        )
        if normalized_error not in AttemptRecord.ERROR_TYPES:
            raise ContractError(f"unknown failure capsule error_type: {self.final_error_type}")
        object.__setattr__(self, "final_error_type", normalized_error)
        object.__setattr__(self, "stage", _require_text(self.stage, field_name="failure stage", maximum=64))
        object.__setattr__(
            self, "request_digest", normalize_sha256(self.request_digest, field_name="failure request_digest")
        )
        ordinals = tuple(self.attempt_ordinals)
        if not ordinals or any(isinstance(item, bool) or not isinstance(item, int) or item < 1 for item in ordinals):
            raise ContractError("failure capsule must reference positive attempt ordinals")
        object.__setattr__(self, "attempt_ordinals", ordinals)
        for name in ("stdout_sha256", "stderr_sha256"):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, normalize_sha256(value, field_name=name))
        object.__setattr__(
            self, "message", _require_text(self.message, field_name="failure message", maximum=1_000, allow_empty=True)
        )

    def to_dict(self) -> dict[str, Any]:
        return _jsonable(self)


@dataclass(frozen=True, slots=True)
class QuarantineRecord:
    candidate_id: str
    finding_id: str
    rule_id: str
    path: str
    line: int | None
    evidence_ids: tuple[str, ...]
    disposition: Literal["QUARANTINED", "SHADOW", "REJECTED"] = "QUARANTINED"
    reason_code: str = "not_authorized"
    gate_version: str = "TOOL-GAIN-GATE-V2"
    summary: str = ""

    def __post_init__(self) -> None:
        for name in ("candidate_id", "finding_id"):
            object.__setattr__(self, name, _require_identifier(getattr(self, name), field_name=name))
        object.__setattr__(self, "rule_id", _require_text(self.rule_id, field_name="quarantine rule_id", maximum=256))
        object.__setattr__(self, "path", canonical_path(self.path))
        if self.line is not None and (isinstance(self.line, bool) or not isinstance(self.line, int) or self.line < 1):
            raise ContractError("quarantine line must be a positive integer")
        object.__setattr__(
            self, "evidence_ids", _tuple_strings(self.evidence_ids, field_name="quarantine evidence_ids", maximum=100)
        )
        object.__setattr__(
            self, "reason_code", _require_identifier(self.reason_code, field_name="reason_code", maximum=128)
        )
        object.__setattr__(
            self,
            "summary",
            _require_text(self.summary, field_name="quarantine summary", maximum=1_000, allow_empty=True),
        )

    def to_dict(self) -> dict[str, Any]:
        return _jsonable(self)


@dataclass(frozen=True, slots=True)
class RunIdentity:
    candidate_id: str
    candidate_version: str
    agent_git_sha: str = "UNKNOWN"
    agent_git_dirty: bool | None = None
    bridge_sha: str = "UNKNOWN"
    bridge_version: str = "UNKNOWN"
    adapter_sha: str = "UNKNOWN"
    adapter_version: str = "UNKNOWN"
    python_version: str = field(default_factory=lambda: platform.python_version())
    python_implementation: str = field(default_factory=platform.python_implementation)
    os_name: str = field(default_factory=platform.system)
    os_release: str = field(default_factory=platform.release)
    dependency_digest: str = "UNKNOWN"
    lockfile_digest: str = "UNKNOWN"
    effective_env: Mapping[str, str] = field(default_factory=dict)
    effective_env_digest: str = "UNKNOWN"
    workers: int = 1
    model_profile: str = "UNKNOWN"
    model_id: str = "UNKNOWN"
    model_parameters_digest: str = "UNKNOWN"
    prompt_digest: str = "UNKNOWN"
    schema_digest: str = "UNKNOWN"
    rule_digest: str = "UNKNOWN"
    input_manifest_digest: str = "UNKNOWN"
    task_order_seed: int | None = None
    provider_seed: int | None = None
    profile: str = "v0.8.2"
    created_at: str = field(default_factory=_utc_now)

    def __post_init__(self) -> None:
        for name in ("candidate_id", "candidate_version"):
            object.__setattr__(self, name, _require_identifier(getattr(self, name), field_name=name))
        for name in (
            "agent_git_sha",
            "bridge_sha",
            "bridge_version",
            "adapter_sha",
            "adapter_version",
            "python_version",
            "python_implementation",
            "os_name",
            "os_release",
            "dependency_digest",
            "lockfile_digest",
            "model_profile",
            "model_id",
            "model_parameters_digest",
            "prompt_digest",
            "schema_digest",
            "rule_digest",
            "input_manifest_digest",
            "profile",
            "created_at",
        ):
            object.__setattr__(self, name, _require_text(getattr(self, name), field_name=name, maximum=1_024))
        if self.agent_git_dirty is not None and not isinstance(self.agent_git_dirty, bool):
            raise ContractError("agent_git_dirty must be boolean or null")
        if isinstance(self.workers, bool) or not isinstance(self.workers, int) or not 1 <= self.workers <= 1_000:
            raise ContractError("workers must be between 1 and 1000")
        if self.task_order_seed is not None and (
            isinstance(self.task_order_seed, bool) or not isinstance(self.task_order_seed, int)
        ):
            raise ContractError("task_order_seed must be an integer or null")
        if self.provider_seed is not None and (
            isinstance(self.provider_seed, bool) or not isinstance(self.provider_seed, int)
        ):
            raise ContractError("provider_seed must be an integer or null")
        env = dict(self.effective_env)
        if any(not isinstance(key, str) or not isinstance(value, str) for key, value in env.items()):
            raise ContractError("effective_env must be a string map")
        if any(_SECRET_KEY.search(key) for key in env):
            raise ContractError("effective_env contains a secret-like key")
        object.__setattr__(self, "effective_env", dict(sorted(env.items())))
        computed_env_digest = canonical_digest(self.effective_env)
        if self.effective_env_digest == "UNKNOWN":
            object.__setattr__(self, "effective_env_digest", computed_env_digest)
        else:
            object.__setattr__(
                self,
                "effective_env_digest",
                normalize_sha256(self.effective_env_digest, field_name="effective_env_digest"),
            )
            if self.effective_env_digest != computed_env_digest:
                raise ContractError("effective_env_digest does not match effective_env")

    def to_dict(self) -> dict[str, Any]:
        return _jsonable(self)

    @property
    def digest(self) -> str:
        return canonical_digest(self.to_dict())


@dataclass(frozen=True, slots=True)
class EvidenceValidation:
    valid: bool
    finding_count: int
    evidence_count: int
    valid_finding_count: int
    invalid_finding_ids: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return _jsonable(self)


ReportStatus = Literal["SUCCESS", "PARTIAL", "FAILED", "TIMEOUT", "CRASH", "POLICY_BLOCKED", "RECOVERY_REQUIRED"]


@dataclass(frozen=True, slots=True)
class AgentReport:
    task_id: str
    run_id: str
    status: str
    summary: str = ""
    findings: tuple[FindingRecord, ...] = ()
    evidence: tuple[EvidenceRecord, ...] = ()
    limitations: tuple[str, ...] = ()
    usage: Mapping[str, Any] = field(default_factory=dict)
    decisions: tuple[Mapping[str, Any], ...] = ()
    answer: Mapping[str, Any] = field(default_factory=dict)
    run_proof: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "task_id", _require_identifier(self.task_id, field_name="task_id"))
        object.__setattr__(self, "run_id", _require_identifier(self.run_id, field_name="run_id"))
        object.__setattr__(self, "status", _require_text(self.status, field_name="report status", maximum=64).upper())
        object.__setattr__(
            self, "summary", _require_text(self.summary, field_name="report summary", maximum=16_000, allow_empty=True)
        )
        findings = tuple(self.findings)
        evidence = tuple(self.evidence)
        if len({item.finding_id for item in findings}) != len(findings):
            raise ContractError("report contains duplicate finding_id")
        if len({item.evidence_id for item in evidence}) != len(evidence):
            raise ContractError("report contains duplicate evidence_id")
        object.__setattr__(
            self, "findings", tuple(sorted(findings, key=lambda item: (item.path, item.line or 0, item.finding_id)))
        )
        object.__setattr__(self, "evidence", tuple(sorted(evidence, key=lambda item: item.evidence_id)))
        object.__setattr__(self, "limitations", _tuple_strings(self.limitations, field_name="limitations", maximum=500))
        for name in ("usage", "answer", "run_proof"):
            value = getattr(self, name)
            if not isinstance(value, Mapping):
                raise ContractError(f"{name} must be an object")
            object.__setattr__(self, name, dict(value))
        decisions = tuple(self.decisions)
        if any(not isinstance(item, Mapping) for item in decisions):
            raise ContractError("decisions must be objects")
        object.__setattr__(self, "decisions", tuple(dict(item) for item in decisions))

    @classmethod
    def from_dict(
        cls, raw: Mapping[str, Any], *, default_task_id: str = "task-unknown", default_run_id: str = "run-unknown"
    ) -> AgentReport:
        if not isinstance(raw, Mapping):
            raise ContractError("agent report must be an object")
        raw_findings = raw.get("findings", [])
        raw_evidence = raw.get("evidence", [])
        if not isinstance(raw_findings, list) or not isinstance(raw_evidence, list):
            raise ContractError("agent report findings/evidence must be lists")
        findings = tuple(
            FindingRecord(
                finding_id=str(item.get("finding_id") or item.get("id") or f"finding-{index + 1}"),
                rule_id=str(item.get("rule_id") or item.get("classification") or item.get("cwe") or "UNKNOWN"),
                title=str(item.get("title") or item.get("name") or "Security finding"),
                description=str(item.get("description") or item.get("evidence") or ""),
                severity=str(item.get("severity") or "UNKNOWN"),
                confidence=str(item.get("confidence") or "UNKNOWN"),
                path=str(item.get("path") or item.get("file") or ""),
                line=(item.get("line") if item.get("line") is not None else item.get("sink_line")),
                file_sha256=str(item.get("file_sha256") or item.get("input_sha256") or ""),
                remediation=str(item.get("remediation") or item.get("fix") or ""),
                evidence_ids=tuple(str(value) for value in (item.get("evidence_ids") or [])),
                raw={
                    **_mapping_or_empty(item.get("raw")),
                    **{
                        key: item[key]
                        for key in (
                            "cwe",
                            "root_cause",
                            "data_flow",
                            "preconditions",
                            "impact",
                            "verified",
                            "evidence_valid",
                            "evidence_complete",
                        )
                        if key in item
                    },
                },
            )
            for index, item in enumerate(raw_findings)
            if isinstance(item, Mapping)
        )
        evidence = tuple(
            EvidenceRecord(
                evidence_id=str(item.get("evidence_id") or item.get("id") or f"evidence-{index + 1}"),
                finding_id=(str(item["finding_id"]) if item.get("finding_id") else None),
                source=str(item.get("source") or "agent"),
                summary=str(item.get("summary") or item.get("fact") or ""),
                path=str(item.get("path") or item.get("file") or ""),
                line=item.get("line"),
                file_sha256=str(
                    item.get("file_sha256")
                    or item.get("input_sha256")
                    or (
                        item.get("metadata", {}).get("file_sha256") if isinstance(item.get("metadata"), Mapping) else ""
                    )
                    or ""
                ),
                artifact_ref=(str(item["artifact_ref"]) if item.get("artifact_ref") is not None else None),
                sha256=(
                    str(item.get("evidence_sha256") or item.get("sha256"))
                    if item.get("evidence_sha256") or item.get("sha256")
                    else None
                ),
                fact=str(item.get("fact") or ""),
                extraction=str(item.get("extraction") or ""),
                metadata=_mapping_or_empty(item.get("metadata")),
            )
            for index, item in enumerate(raw_evidence)
            if isinstance(item, Mapping)
        )
        return cls(
            task_id=str(raw.get("task_id") or default_task_id),
            run_id=str(raw.get("run_id") or default_run_id),
            status=str(raw.get("status") or "PARTIAL"),
            summary=str(
                raw.get("summary")
                or (raw.get("answer", {}).get("summary", "") if isinstance(raw.get("answer"), Mapping) else "")
            ),
            findings=findings,
            evidence=evidence,
            limitations=tuple(
                str(item) for item in (raw.get("limitations") or []) if isinstance(item, (str, int, float))
            ),
            usage=_mapping_or_empty(raw.get("usage")),
            decisions=tuple(item for item in (raw.get("decisions") or []) if isinstance(item, Mapping)),
            answer=_mapping_or_empty(raw.get("answer")),
            run_proof=_mapping_or_empty(raw.get("run_proof")),
        )

    def validate_evidence(self, manifest: InputManifest, *, require_lines: bool = True) -> EvidenceValidation:
        evidence_by_id = {item.evidence_id: item for item in self.evidence}
        invalid_ids: list[str] = []
        errors: list[str] = []
        valid_findings = 0
        for finding in self.findings:
            finding_errors: list[str] = []
            if not finding.path:
                finding_errors.append("missing path")
            if require_lines and finding.line is None:
                finding_errors.append("missing line")
            artifact = manifest.find(finding.path) if finding.path else None
            if artifact is None:
                finding_errors.append("path is not in input manifest")
            if artifact is not None:
                if not finding.file_sha256:
                    finding_errors.append("missing file_sha256")
                elif finding.file_sha256 != artifact.sha256:
                    finding_errors.append("file_sha256 does not match manifest")
            if not finding.evidence_ids:
                finding_errors.append("missing evidence_ids")
            for evidence_id in finding.evidence_ids:
                item = evidence_by_id.get(evidence_id)
                if item is None:
                    finding_errors.append(f"missing evidence {evidence_id}")
                    continue
                if item.finding_id not in (None, finding.finding_id):
                    finding_errors.append(f"evidence {evidence_id} has another finding_id")
                if artifact is not None:
                    evidence_artifact = manifest.find(item.path or finding.path)
                    if evidence_artifact is None or evidence_artifact.artifact_id != artifact.artifact_id:
                        finding_errors.append(f"evidence {evidence_id} path does not match finding")
                    if not item.file_sha256 or item.file_sha256 != artifact.sha256:
                        finding_errors.append(f"evidence {evidence_id} file_sha256 does not match manifest")
                if finding.line is not None and item.line not in (None, finding.line):
                    finding_errors.append(f"evidence {evidence_id} line does not match finding")
            if finding_errors:
                invalid_ids.append(finding.finding_id)
                errors.extend(f"{finding.finding_id}: {error}" for error in finding_errors)
            else:
                valid_findings += 1
        return EvidenceValidation(
            valid=not errors,
            finding_count=len(self.findings),
            evidence_count=len(self.evidence),
            valid_finding_count=valid_findings,
            invalid_finding_ids=tuple(sorted(invalid_ids)),
            errors=tuple(errors),
        )

    def to_dict(self, *, scorer_path: bool = False, include_evidence: bool = True) -> dict[str, Any]:
        result: dict[str, Any] = {
            "schema_version": EVIDENCE_SCHEMA_VERSION,
            "task_id": self.task_id,
            "run_id": self.run_id,
            "status": self.status,
            "summary": self.summary,
            "answer": dict(self.answer),
            "findings": [item.to_dict(scorer_path=scorer_path) for item in self.findings],
            "limitations": list(self.limitations),
            "usage": dict(self.usage),
            "decisions": [dict(item) for item in self.decisions],
            "run_proof": dict(self.run_proof),
        }
        if include_evidence:
            result["evidence"] = [item.to_dict(scorer_path=scorer_path) for item in self.evidence]
        return result


@dataclass(frozen=True, slots=True)
class SealedEvaluation:
    seal_id: str
    schema_version: str
    identity: RunIdentity
    report_sha256: str
    evidence_sha256: str
    input_manifest_sha256: str
    attempts_sha256: str
    failure_capsules_sha256: str | None
    quarantine_sha256: str | None
    status: str
    evidence_validation: EvidenceValidation
    created_at: str = field(default_factory=_utc_now)
    bridge_execution_sha256: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "seal_id", _require_identifier(self.seal_id, field_name="seal_id", maximum=256))
        object.__setattr__(
            self, "schema_version", _require_text(self.schema_version, field_name="schema_version", maximum=128)
        )
        for name in ("report_sha256", "evidence_sha256", "input_manifest_sha256", "attempts_sha256"):
            object.__setattr__(self, name, normalize_sha256(getattr(self, name), field_name=name))
        for name in ("failure_capsules_sha256", "quarantine_sha256"):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, normalize_sha256(value, field_name=name))
        object.__setattr__(self, "status", _require_text(self.status, field_name="seal status", maximum=64).upper())
        object.__setattr__(self, "created_at", _require_text(self.created_at, field_name="created_at", maximum=128))
        if self.bridge_execution_sha256 is not None:
            object.__setattr__(
                self,
                "bridge_execution_sha256",
                normalize_sha256(self.bridge_execution_sha256, field_name="bridge_execution_sha256"),
            )

    def to_dict(self) -> dict[str, Any]:
        return _jsonable(self)


def terminal_status(report: AgentReport, validation: EvidenceValidation, attempts: Sequence[AttemptRecord]) -> str:
    """Apply explicit SUCCESS/PARTIAL semantics without inventing findings."""

    failed_attempt = any(not item.successful for item in attempts)
    if report.status in {"POLICY_BLOCKED", "CRASH", "TIMEOUT", "RECOVERY_REQUIRED"}:
        return report.status
    if report.status == "SUCCESS" and validation.valid and not failed_attempt:
        return "SUCCESS"
    if report.status == "FAILED" and not validation.valid:
        return "PARTIAL"
    return "PARTIAL" if report.status != "SUCCESS" or not validation.valid or failed_attempt else report.status


def redacted_environment(environment: Mapping[str, str] | None = None) -> dict[str, str]:
    """Return an auditable, secret-free effective environment snapshot."""

    values = dict(os.environ if environment is None else environment)
    result: dict[str, str] = {}
    for key, value in sorted(values.items()):
        if _SECRET_KEY.search(key):
            continue
        if any(marker in value for marker in ("sk-", "Bearer ", "-----BEGIN ")):
            continue
        result[key] = value[:4_096]
    return result


def _run_git(root: Path, args: list[str]) -> str | None:
    try:
        result = subprocess.run(  # noqa: S603  # nosec B603 B607
            ["git", "-C", str(root), *args],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode:
        return None
    value = result.stdout.strip()
    return value or None


def file_digest(path: Path) -> str:
    try:
        return sha256_bytes(path.read_bytes())
    except OSError as exc:
        raise ContractError(f"cannot hash artifact {path}") from exc


def build_run_identity(
    *,
    candidate_id: str,
    candidate_version: str,
    agent_root: Path | None = None,
    bridge_path: Path | None = None,
    bridge_version: str | None = None,
    adapter_path: Path | None = None,
    adapter_version: str | None = None,
    lockfile_path: Path | None = None,
    dependency_files: Sequence[Path] = (),
    workers: int = 1,
    model_profile: str = "UNKNOWN",
    model_id: str = "UNKNOWN",
    model_parameters: Mapping[str, Any] | None = None,
    prompt: object = None,
    schema: object = None,
    rules: object = None,
    input_manifest_digest: str = "UNKNOWN",
    task_order_seed: int | None = None,
    provider_seed: int | None = None,
    profile: str = "v0.8.2",
    environment: Mapping[str, str] | None = None,
) -> RunIdentity:
    root = agent_root.resolve() if agent_root is not None else None
    agent_sha = _run_git(root, ["rev-parse", "HEAD"]) if root is not None else None
    dirty = _run_git(root, ["status", "--porcelain"]) if root is not None else None
    lock_digest = file_digest(lockfile_path) if lockfile_path is not None and lockfile_path.is_file() else "UNKNOWN"
    dependency_values = [file_digest(path) for path in sorted(dependency_files) if path.is_file()]
    dependency_digest = canonical_digest(dependency_values) if dependency_values else "UNKNOWN"
    effective = redacted_environment(environment)
    return RunIdentity(
        candidate_id=candidate_id,
        candidate_version=candidate_version,
        agent_git_sha=agent_sha or "UNKNOWN",
        agent_git_dirty=(dirty is not None and bool(dirty)),
        bridge_sha=file_digest(bridge_path) if bridge_path is not None and bridge_path.is_file() else "UNKNOWN",
        bridge_version=(bridge_version or "UNKNOWN") if bridge_path is not None else "UNKNOWN",
        adapter_sha=file_digest(adapter_path) if adapter_path is not None and adapter_path.is_file() else "UNKNOWN",
        adapter_version=(adapter_version or "UNKNOWN") if adapter_path is not None else "UNKNOWN",
        dependency_digest=dependency_digest,
        lockfile_digest=lock_digest,
        effective_env=effective,
        workers=workers,
        model_profile=model_profile,
        model_id=model_id,
        model_parameters_digest=canonical_digest(model_parameters or {}) if model_parameters is not None else "UNKNOWN",
        prompt_digest=canonical_digest(prompt) if prompt is not None else "UNKNOWN",
        schema_digest=canonical_digest(schema) if schema is not None else "UNKNOWN",
        rule_digest=canonical_digest(rules) if rules is not None else "UNKNOWN",
        input_manifest_digest=input_manifest_digest,
        task_order_seed=task_order_seed,
        provider_seed=provider_seed,
        profile=profile,
    )


def compare_identities(
    left: RunIdentity, right: RunIdentity, *, ignore: Sequence[str] = ("candidate_id", "candidate_version")
) -> dict[str, Any]:
    """Compare frozen controls without treating two missing values as equal."""

    ignored = set(ignore)
    left_values = left.to_dict()
    right_values = right.to_dict()
    fields_out: list[dict[str, Any]] = []
    unknown = False
    mismatch = False
    for name in sorted(set(left_values) | set(right_values)):
        if name in ignored or name == "created_at":
            continue
        a = left_values.get(name)
        b = right_values.get(name)
        if a in (None, "UNKNOWN") or b in (None, "UNKNOWN"):
            unknown = True
            state = UNKNOWN_NOT_CONTROLLED
        elif a == b:
            state = "CONTROLLED"
        else:
            mismatch = True
            state = "MISMATCH"
        fields_out.append({"field": name, "left": a, "right": b, "status": state})
    status = "MISMATCH" if mismatch else UNKNOWN_NOT_CONTROLLED if unknown else "CONTROLLED"
    return {"status": status, "controlled": status == "CONTROLLED", "fields": fields_out}


__all__ = [
    "AgentReport",
    "AttemptRecord",
    "AttemptStatus",
    "AttemptType",
    "BRIDGE_SCHEMA_VERSION",
    "ContractError",
    "EVIDENCE_SCHEMA_VERSION",
    "EvidenceRecord",
    "EvidenceValidation",
    "FailureCapsule",
    "FindingRecord",
    "InputArtifactRecord",
    "InputManifest",
    "QuarantineRecord",
    "RunIdentity",
    "SealedEvaluation",
    "UNKNOWN_NOT_CONTROLLED",
    "V082_SCHEMA_VERSION",
    "build_run_identity",
    "canonical_digest",
    "canonical_json",
    "canonical_path",
    "compare_identities",
    "file_digest",
    "normalize_sha256",
    "public_path",
    "redacted_environment",
    "sha256_bytes",
    "terminal_status",
]
