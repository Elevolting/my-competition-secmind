"""Offline release-candidate manifests, run ledgers and fail-closed gates.

This module is deliberately separate from the product runtime and from the
v0.8.2 compatibility contracts.  A release evaluation must be reproducible
even when the working tree is dirty, a process crashes, or one arm has fewer
completed rows.  The implementation therefore keeps three things explicit:

* the exact candidate inputs (source tree, distributions, bridge, adapter,
  profile, model parameters, prompt lineage, scorer, task set and lockfiles);
* an append-only ledger where failed and missing observations are never
  silently filtered; and
* an ITT comparison whose denominator is the pre-registered block/task grid.

Only the Python standard library is used here.  In particular, this module
never calls a model provider or a network endpoint.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import random
import re
import shutil
import subprocess  # nosec B404 - git metadata is invoked without a shell
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, fields, is_dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar

SCHEMA_VERSION = "secmind-release-evaluation-v1"
MANIFEST_SCHEMA_VERSION = "secmind-candidate-manifest-v1"
LEDGER_SCHEMA_VERSION = "secmind-run-ledger-v1"
RANDOMIZATION_SCHEMA_VERSION = "secmind-randomization-v1"
MIN_RANDOMIZED_BLOCKS = 5
UNKNOWN = "UNKNOWN"

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA = re.compile(r"^[0-9a-f]{40,64}$")
_SECRET_KEY = re.compile(
    r"(?:api[_-]?key|access[_-]?token|auth(?:orization)?|credential|password|passwd|secret|private[_-]?key|bearer|cookie|session)",
    re.IGNORECASE,
)
_SECRET_VALUE = re.compile(
    r"(?:sk-[A-Za-z0-9]|gh[pousr]_[A-Za-z0-9]|xox[baprs]-|bearer\s+|-----BEGIN\s+|AKIA[0-9A-Z]{12,})",
    re.IGNORECASE,
)
_SUCCESS_STATUSES = frozenset({"SUCCESS", "COMPLETED", "SUCCEEDED", "PASS", "PASSED"})
_GENERATED_EVALUATION_PREFIXES = ("evaluation/release/", "evaluation/runs/")


class ReleaseEvaluationError(ValueError):
    """Raised when a release input cannot be represented safely."""


def _jsonable(value: Any) -> Any:
    if is_dataclass(value):
        return {item.name: _jsonable(getattr(value, item.name)) for item in fields(value)}
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))}
    if isinstance(value, (tuple, list, set, frozenset)):
        return [_jsonable(item) for item in value]
    if isinstance(value, Path):
        return value.as_posix()
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat()
    if isinstance(value, bytes):
        return value.hex()
    return value


def canonical_json(value: Any) -> bytes:
    """Encode values once, with stable ordering, for every digest."""

    try:
        return json.dumps(
            _jsonable(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ReleaseEvaluationError(f"value is not canonical JSON: {exc}") from exc


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical_digest(value: Any) -> str:
    return sha256_bytes(canonical_json(value))


def _digest_or_unknown(value: object) -> str:
    if isinstance(value, str) and value == UNKNOWN:
        return UNKNOWN
    if isinstance(value, str) and _HEX64.fullmatch(value.lower()):
        return value.lower()
    if value in (None, ""):
        return UNKNOWN
    return canonical_digest(value)


def _require_digest(value: str, field_name: str, *, allow_unknown: bool = True) -> str:
    normalized = str(value).removeprefix("sha256:").lower()
    if allow_unknown and normalized == UNKNOWN.lower():
        return UNKNOWN
    if not _HEX64.fullmatch(normalized):
        raise ReleaseEvaluationError(f"{field_name} must be a SHA-256 digest")
    return normalized


def file_sha256(path: Path) -> str:
    """Hash a regular file without following an evaluation-specific shortcut."""

    try:
        if not path.is_file():
            raise ReleaseEvaluationError(f"artifact is not a regular file: {path}")
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError as exc:
        raise ReleaseEvaluationError(f"cannot hash artifact {path}: {exc}") from exc


def _safe_relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def redacted_environment(environment: Mapping[str, object] | None = None) -> dict[str, str]:
    """Return only auditable, non-secret environment values.

    Secret-like keys and values are omitted rather than replaced with a
    placeholder.  This prevents a placeholder digest from being mistaken for
    evidence that a secret was present, while ``environment_omitted_count`` in
    the manifest still makes the omission observable.
    """

    source = os.environ if environment is None else environment
    result: dict[str, str] = {}
    for raw_key, raw_value in sorted(source.items(), key=lambda pair: str(pair[0])):
        key = str(raw_key)
        value = str(raw_value)
        if _SECRET_KEY.search(key) or _SECRET_VALUE.search(value):
            continue
        if len(key) > 256 or len(value) > 4096:
            continue
        result[key] = value
    return result


def _secret_free(value: Any) -> Any:
    """Recursively remove secret-like fields from manifest metadata."""

    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for raw_key, raw_value in value.items():
            key = str(raw_key)
            if _SECRET_KEY.search(key):
                continue
            cleaned = _secret_free(raw_value)
            if isinstance(cleaned, str) and _SECRET_VALUE.search(cleaned):
                continue
            result[key] = cleaned
        return result
    if isinstance(value, (tuple, list, set, frozenset)):
        return [_secret_free(item) for item in value]
    if isinstance(value, str) and _SECRET_VALUE.search(value):
        return "[omitted]"
    return value


def _environment_omitted_count(environment: Mapping[str, object] | None) -> int:
    if environment is None:
        return 0
    return max(0, len(environment) - len(redacted_environment(environment)))


@dataclass(frozen=True, slots=True)
class ArtifactRef:
    """A distribution or executable component bound by path, size and digest."""

    name: str
    path: str = UNKNOWN
    sha256: str = UNKNOWN
    size_bytes: int | None = None
    version: str = UNKNOWN

    def __post_init__(self) -> None:
        if not str(self.name).strip():
            raise ReleaseEvaluationError("artifact name is required")
        object.__setattr__(self, "name", str(self.name))
        object.__setattr__(self, "path", str(self.path))
        object.__setattr__(self, "sha256", _require_digest(self.sha256, f"{self.name}.sha256"))
        if self.size_bytes is not None and (
            isinstance(self.size_bytes, bool) or not isinstance(self.size_bytes, int) or self.size_bytes < 0
        ):
            raise ReleaseEvaluationError(f"{self.name}.size_bytes must be a non-negative integer")
        object.__setattr__(self, "version", str(self.version))

    @classmethod
    def from_path(cls, name: str, path: Path, *, version: str = UNKNOWN, root: Path | None = None) -> ArtifactRef:
        if not path.is_file():
            raise ReleaseEvaluationError(f"artifact is not a regular file: {path}")
        return cls(
            name=name,
            path=_safe_relative(path, root) if root is not None else path.resolve().as_posix(),
            sha256=file_sha256(path),
            size_bytes=path.stat().st_size,
            version=version,
        )

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any], *, name: str = "artifact") -> ArtifactRef:
        return cls(
            name=str(raw.get("name", name)),
            path=str(raw.get("path", UNKNOWN)),
            sha256=str(raw.get("sha256", raw.get("digest", UNKNOWN))),
            size_bytes=raw.get("size_bytes", raw.get("size")),
            version=str(raw.get("version", UNKNOWN)),
        )

    @property
    def present(self) -> bool:
        return self.sha256 != UNKNOWN and self.size_bytes is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "path": self.path,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "version": self.version,
            "present": self.present,
        }


def _git(root: Path, args: Sequence[str]) -> str | None:
    executable = shutil.which("git")
    if executable is None:
        return None
    try:
        result = subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, no shell
            [executable, "-C", str(root), *args],
            capture_output=True,
            check=False,
            timeout=15,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return result.stdout


def _git_status(root: Path) -> tuple[str, ...] | None:
    raw = _git(root, ["status", "--porcelain=v1", "--untracked-files=all"])
    if raw is None:
        return None
    result: list[str] = []
    for line in raw.splitlines():
        if not line:
            continue
        path = line[3:] if len(line) > 3 else ""
        if _is_generated_evaluation_path(path):
            continue
        result.append(line)
    return tuple(result)


def _is_generated_evaluation_path(path: str) -> bool:
    normalized = path.replace("\\", "/").lstrip("./")
    return any(normalized.startswith(prefix) for prefix in _GENERATED_EVALUATION_PREFIXES)


def _working_tree_digest(root: Path) -> str:
    """Digest tracked and non-ignored untracked files, including dirty content."""

    raw = _git(root, ["ls-files", "-co", "--exclude-standard", "-z"])
    if raw is None:
        return UNKNOWN
    entries: list[dict[str, Any]] = []
    for item in raw.split("\x00"):
        if not item:
            continue
        if _is_generated_evaluation_path(item):
            continue
        path = root / item
        try:
            if path.is_file():
                entries.append(
                    {"path": item.replace("\\", "/"), "sha256": file_sha256(path), "size_bytes": path.stat().st_size}
                )
            elif path.is_symlink():
                entries.append({"path": item.replace("\\", "/"), "symlink": os.readlink(path)})
        except OSError as exc:
            raise ReleaseEvaluationError(f"cannot snapshot working tree file {path}: {exc}") from exc
    return canonical_digest(entries)


@dataclass(frozen=True, slots=True)
class CandidateManifest:
    """Exact, secret-free candidate identity used by every release gate."""

    schema_version: str = MANIFEST_SCHEMA_VERSION
    candidate_id: str = "candidate"
    candidate_version: str = UNKNOWN
    agent_git_sha: str = UNKNOWN
    agent_tree_sha256: str = UNKNOWN
    agent_git_dirty: bool = True
    agent_status_sha256: str = UNKNOWN
    working_tree_sha256: str = UNKNOWN
    agent_status: tuple[str, ...] = ()
    wheel: ArtifactRef | None = None
    sdist: ArtifactRef | None = None
    bridge: ArtifactRef | None = None
    adapter: ArtifactRef | None = None
    profile: str = UNKNOWN
    profile_config: Mapping[str, Any] = field(default_factory=dict)
    effective_env: Mapping[str, str] = field(default_factory=dict)
    effective_env_digest: str = UNKNOWN
    environment_omitted_count: int = 0
    model_parameters: Mapping[str, Any] = field(default_factory=dict)
    model_parameters_digest: str = UNKNOWN
    prompt_lineage: Mapping[str, Any] | Sequence[Any] = field(default_factory=dict)
    prompt_lineage_digest: str = UNKNOWN
    scorer_sha256: str = UNKNOWN
    task_set_sha256: str = UNKNOWN
    dependency_sha256: str = UNKNOWN
    lockfile_sha256: str = UNKNOWN
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    # Aliases kept as properties because older run proofs use ``tree_sha256``
    # and ``dependency_digest`` names.
    schema_name: ClassVar[str] = MANIFEST_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if not str(self.candidate_id).strip() or not str(self.candidate_version).strip():
            raise ReleaseEvaluationError("candidate id and version are required")
        object.__setattr__(self, "candidate_id", str(self.candidate_id))
        object.__setattr__(self, "candidate_version", str(self.candidate_version))
        for name in ("agent_git_sha",):
            value = str(getattr(self, name)).lower()
            if value != UNKNOWN.lower() and not _GIT_SHA.fullmatch(value):
                raise ReleaseEvaluationError(f"{name} must be a git SHA or UNKNOWN")
            object.__setattr__(self, name, value if value != UNKNOWN.lower() else UNKNOWN)
        for name in (
            "agent_tree_sha256",
            "agent_status_sha256",
            "working_tree_sha256",
            "effective_env_digest",
            "model_parameters_digest",
            "prompt_lineage_digest",
            "scorer_sha256",
            "task_set_sha256",
            "dependency_sha256",
            "lockfile_sha256",
        ):
            if name == "agent_tree_sha256":
                value = str(getattr(self, name)).lower()
                if value != UNKNOWN.lower() and not _GIT_SHA.fullmatch(value):
                    raise ReleaseEvaluationError("agent_tree_sha256 must be a git tree SHA or UNKNOWN")
                object.__setattr__(self, name, value if value != UNKNOWN.lower() else UNKNOWN)
            else:
                object.__setattr__(self, name, _require_digest(getattr(self, name), name))
        if not isinstance(self.agent_git_dirty, bool):
            raise ReleaseEvaluationError("agent_git_dirty must be boolean")
        object.__setattr__(self, "agent_status", tuple(str(item) for item in self.agent_status))
        for name in ("wheel", "sdist", "bridge", "adapter"):
            value = getattr(self, name)
            if isinstance(value, Mapping):
                object.__setattr__(self, name, ArtifactRef.from_mapping(value, name=name))
            elif value is not None and not isinstance(value, ArtifactRef):
                raise ReleaseEvaluationError(f"{name} must be an ArtifactRef or object")
        env = redacted_environment(self.effective_env)
        object.__setattr__(self, "effective_env", env)
        env_digest = canonical_digest(env)
        if self.effective_env_digest == UNKNOWN:
            object.__setattr__(self, "effective_env_digest", env_digest)
        elif self.effective_env_digest != env_digest:
            raise ReleaseEvaluationError("effective_env_digest does not match effective_env")
        if isinstance(self.profile_config, Mapping):
            object.__setattr__(self, "profile_config", _secret_free(self.profile_config))
        else:
            raise ReleaseEvaluationError("profile_config must be an object")
        if not isinstance(self.model_parameters, Mapping):
            raise ReleaseEvaluationError("model_parameters must be an object")
        object.__setattr__(self, "model_parameters", _secret_free(self.model_parameters))
        model_digest = canonical_digest(self.model_parameters)
        if self.model_parameters_digest == UNKNOWN:
            object.__setattr__(self, "model_parameters_digest", model_digest)
        elif self.model_parameters_digest != model_digest:
            raise ReleaseEvaluationError("model_parameters_digest does not match model_parameters")
        object.__setattr__(self, "prompt_lineage", _secret_free(self.prompt_lineage))
        prompt_digest = canonical_digest(self.prompt_lineage)
        if self.prompt_lineage_digest == UNKNOWN:
            object.__setattr__(self, "prompt_lineage_digest", prompt_digest)
        elif self.prompt_lineage_digest != prompt_digest:
            raise ReleaseEvaluationError("prompt_lineage_digest does not match prompt_lineage")
        if isinstance(self.environment_omitted_count, bool) or self.environment_omitted_count < 0:
            raise ReleaseEvaluationError("environment_omitted_count must be non-negative")

    @property
    def tree_sha256(self) -> str:
        return self.agent_tree_sha256

    @property
    def dependency_digest(self) -> str:
        return self.dependency_sha256

    @property
    def model_params(self) -> Mapping[str, Any]:
        return self.model_parameters

    @property
    def manifest_digest(self) -> str:
        return canonical_digest(self.to_dict(include_created_at=False, include_digest=False))

    def to_dict(self, *, include_created_at: bool = False, include_digest: bool = True) -> dict[str, Any]:
        value: dict[str, Any] = {
            "schema_version": self.schema_version,
            "candidate_id": self.candidate_id,
            "candidate_version": self.candidate_version,
            "agent_git_sha": self.agent_git_sha,
            "agent_tree_sha256": self.agent_tree_sha256,
            "agent_git_dirty": self.agent_git_dirty,
            "working_tree_sha256": self.working_tree_sha256,
            "agent": {
                "git_sha": self.agent_git_sha,
                "tree_sha256": self.agent_tree_sha256,
                "dirty": self.agent_git_dirty,
                "status_sha256": self.agent_status_sha256,
                "working_tree_sha256": self.working_tree_sha256,
                "status": list(self.agent_status),
            },
            "artifacts": {
                "wheel": self.wheel.to_dict() if self.wheel else None,
                "sdist": self.sdist.to_dict() if self.sdist else None,
                "bridge": self.bridge.to_dict() if self.bridge else None,
                "adapter": self.adapter.to_dict() if self.adapter else None,
            },
            "wheel_sha256": self.wheel.sha256 if self.wheel else UNKNOWN,
            "sdist_sha256": self.sdist.sha256 if self.sdist else UNKNOWN,
            "bridge_sha256": self.bridge.sha256 if self.bridge else UNKNOWN,
            "adapter_sha256": self.adapter.sha256 if self.adapter else UNKNOWN,
            "bridge_version": self.bridge.version if self.bridge else UNKNOWN,
            "adapter_version": self.adapter.version if self.adapter else UNKNOWN,
            "profile": self.profile,
            "profile_config": dict(self.profile_config),
            "effective_env": dict(self.effective_env),
            "effective_env_digest": self.effective_env_digest,
            "effective_env_nonsecret": dict(self.effective_env),
            "environment_omitted_count": self.environment_omitted_count,
            "model_parameters": dict(self.model_parameters),
            "model_params": dict(self.model_parameters),
            "model_parameters_digest": self.model_parameters_digest,
            "prompt_lineage": _jsonable(self.prompt_lineage),
            "prompt_lineage_digest": self.prompt_lineage_digest,
            "scorer_sha256": self.scorer_sha256,
            "scorer_digest": self.scorer_sha256,
            "task_set_sha256": self.task_set_sha256,
            "task_set_digest": self.task_set_sha256,
            "dependency_sha256": self.dependency_sha256,
            "dependency_digest": self.dependency_sha256,
            "lockfile_sha256": self.lockfile_sha256,
        }
        if include_created_at:
            value["created_at"] = self.created_at
        if include_digest:
            value["manifest_digest"] = self.manifest_digest
        return value

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> CandidateManifest:
        """Rehydrate a manifest emitted by :meth:`to_dict`.

        The loader accepts the nested canonical form and the flat aliases used
        by earlier run-proof JSON files.  Rehydration recomputes all derived
        digests through ``__post_init__``; a copied or edited manifest therefore
        cannot silently acquire the original digest.
        """

        if not isinstance(raw, Mapping):
            raise ReleaseEvaluationError("candidate manifest must be an object")
        agent = _mapping_or_empty(raw.get("agent"))
        artifacts = _mapping_or_empty(raw.get("artifacts"))

        def artifact(name: str) -> ArtifactRef | None:
            value = artifacts.get(name, raw.get(name))
            if value is None:
                digest = raw.get(f"{name}_sha256", UNKNOWN)
                if digest in (None, UNKNOWN):
                    return None
                return ArtifactRef(
                    name=name,
                    path=str(raw.get(f"{name}_path", UNKNOWN)),
                    sha256=str(digest),
                    size_bytes=raw.get(f"{name}_size_bytes"),
                    version=str(raw.get(f"{name}_version", UNKNOWN)),
                )
            if isinstance(value, ArtifactRef):
                return value
            if isinstance(value, Mapping):
                return ArtifactRef.from_mapping(value, name=name)
            raise ReleaseEvaluationError(f"manifest artifact {name} must be an object")

        return cls(
            schema_version=str(raw.get("schema_version", MANIFEST_SCHEMA_VERSION)),
            candidate_id=str(raw.get("candidate_id", "candidate")),
            candidate_version=str(raw.get("candidate_version", UNKNOWN)),
            agent_git_sha=str(raw.get("agent_git_sha", agent.get("git_sha", UNKNOWN))),
            agent_tree_sha256=str(
                raw.get("agent_tree_sha256", raw.get("tree_sha256", agent.get("tree_sha256", UNKNOWN)))
            ),
            agent_git_dirty=bool(raw.get("agent_git_dirty", agent.get("dirty", True))),
            agent_status_sha256=str(raw.get("agent_status_sha256", agent.get("status_sha256", UNKNOWN))),
            working_tree_sha256=str(raw.get("working_tree_sha256", agent.get("working_tree_sha256", UNKNOWN))),
            agent_status=tuple(
                str(item)
                for item in (
                    raw.get("agent_status", agent.get("status", ()))
                    if isinstance(raw.get("agent_status", agent.get("status", ())), Sequence)
                    else ()
                )
            ),
            wheel=artifact("wheel"),
            sdist=artifact("sdist"),
            bridge=artifact("bridge"),
            adapter=artifact("adapter"),
            profile=str(raw.get("profile", UNKNOWN)),
            profile_config=raw.get("profile_config", {}),
            effective_env=raw.get("effective_env", raw.get("effective_env_nonsecret", {})),
            effective_env_digest=str(raw.get("effective_env_digest", UNKNOWN)),
            environment_omitted_count=int(raw.get("environment_omitted_count", 0) or 0),
            model_parameters=raw.get("model_parameters", raw.get("model_params", {})),
            model_parameters_digest=str(raw.get("model_parameters_digest", UNKNOWN)),
            prompt_lineage=raw.get("prompt_lineage", {}),
            prompt_lineage_digest=str(raw.get("prompt_lineage_digest", UNKNOWN)),
            scorer_sha256=str(raw.get("scorer_sha256", raw.get("scorer_digest", UNKNOWN))),
            task_set_sha256=str(raw.get("task_set_sha256", raw.get("task_set_digest", UNKNOWN))),
            dependency_sha256=str(raw.get("dependency_sha256", raw.get("dependency_digest", UNKNOWN))),
            lockfile_sha256=str(raw.get("lockfile_sha256", raw.get("lockfile_digest", UNKNOWN))),
            created_at=str(raw.get("created_at", datetime.now(UTC).isoformat())),
        )

    def verify(self, *, require_clean_tree: bool = True, require_artifacts: bool = True) -> dict[str, Any]:
        blockers: list[str] = []
        if self.agent_git_sha == UNKNOWN:
            blockers.append("agent_git_sha_unknown")
        if self.agent_tree_sha256 == UNKNOWN or self.working_tree_sha256 == UNKNOWN:
            blockers.append("agent_tree_unknown")
        if require_clean_tree and self.agent_git_dirty:
            blockers.append("agent_tree_dirty")
        if require_artifacts:
            for name, artifact in (
                ("wheel", self.wheel),
                ("sdist", self.sdist),
                ("bridge", self.bridge),
                ("adapter", self.adapter),
            ):
                if artifact is None or not artifact.present:
                    blockers.append(f"{name}_not_pinned")
                elif artifact.version == UNKNOWN:
                    blockers.append(f"{name}_version_unknown")
        for name in ("scorer_sha256", "task_set_sha256", "dependency_sha256", "lockfile_sha256"):
            if getattr(self, name) == UNKNOWN:
                blockers.append(f"{name}_unknown")
        return {"valid": not blockers, "blockers": blockers, "manifest_digest": self.manifest_digest}


def _artifact_arg(value: Path | None, *, name: str, root: Path, version: str = UNKNOWN) -> ArtifactRef | None:
    return ArtifactRef.from_path(name, value, version=version, root=root) if value is not None else None


def _value_digest(value: Path | Mapping[str, Any] | Sequence[Any] | str | None, *, root: Path) -> str:
    if value is None:
        return UNKNOWN
    if isinstance(value, Path):
        return file_sha256(value)
    if isinstance(value, str):
        path = Path(value)
        if not path.is_absolute():
            path = root / path
        if path.is_file():
            return file_sha256(path)
    return canonical_digest(value)


def build_candidate_manifest(
    root: Path,
    *,
    candidate_id: str,
    candidate_version: str,
    wheel_path: Path | None = None,
    sdist_path: Path | None = None,
    bridge_path: Path | None = None,
    bridge_version: str = UNKNOWN,
    adapter_path: Path | None = None,
    adapter_version: str = UNKNOWN,
    profile: str = UNKNOWN,
    profile_config: Mapping[str, Any] | None = None,
    environment: Mapping[str, object] | None = None,
    model_parameters: Mapping[str, Any] | None = None,
    prompt_lineage: Mapping[str, Any] | Sequence[Any] | None = None,
    scorer: Path | Mapping[str, Any] | Sequence[Any] | str | None = None,
    task_set: Path | Mapping[str, Any] | Sequence[Any] | str | None = None,
    dependency_files: Sequence[Path] = (),
    lockfile: Path | None = None,
) -> CandidateManifest:
    """Build a manifest from local files and deterministic values only."""

    root = root.resolve()
    status = _git_status(root)
    head = (_git(root, ["rev-parse", "HEAD"]) or "").strip() or UNKNOWN
    tree = (_git(root, ["rev-parse", "HEAD^{tree}"]) or "").strip() or UNKNOWN
    status_digest = canonical_digest(status) if status is not None else UNKNOWN
    working_tree = _working_tree_digest(root)
    dependency_refs = []
    for path in sorted((Path(item) for item in dependency_files), key=lambda item: str(item)):
        if path.is_file():
            dependency_refs.append(
                {"path": _safe_relative(path, root), "sha256": file_sha256(path), "size_bytes": path.stat().st_size}
            )
    dependency_digest = canonical_digest(dependency_refs) if dependency_refs else UNKNOWN
    env = redacted_environment(environment)
    return CandidateManifest(
        candidate_id=candidate_id,
        candidate_version=candidate_version,
        agent_git_sha=head,
        agent_tree_sha256=tree,
        agent_git_dirty=status is None or bool(status) or head == UNKNOWN or tree == UNKNOWN or working_tree == UNKNOWN,
        agent_status_sha256=status_digest,
        working_tree_sha256=working_tree,
        agent_status=status or (),
        wheel=_artifact_arg(wheel_path, name="wheel", root=root),
        sdist=_artifact_arg(sdist_path, name="sdist", root=root),
        bridge=_artifact_arg(bridge_path, name="bridge", root=root, version=bridge_version),
        adapter=_artifact_arg(adapter_path, name="adapter", root=root, version=adapter_version),
        profile=profile,
        profile_config=dict(profile_config or {}),
        effective_env=env,
        environment_omitted_count=_environment_omitted_count(environment),
        model_parameters=dict(model_parameters or {}),
        prompt_lineage=prompt_lineage if prompt_lineage is not None else {},
        scorer_sha256=_value_digest(scorer, root=root),
        task_set_sha256=_value_digest(task_set, root=root),
        dependency_sha256=dependency_digest,
        lockfile_sha256=file_sha256(lockfile) if lockfile is not None else UNKNOWN,
    )


@dataclass(frozen=True, slots=True)
class RunRecord:
    """One immutable arm/block/task observation, including failures."""

    run_id: str
    arm: str
    block: int
    task_id: str
    domain: str = "unknown"
    status: str = "SUCCESS"
    score: float = 0.0
    correct: bool | None = None
    failure_type: str | None = None
    failure_message: str | None = None
    failures: tuple[str, ...] = ()
    manifest_digest: str = UNKNOWN
    provider_requests: int = 0
    tool_calls: int = 0
    accepted_delta_count: int = 0
    tool_accepted_delta_count: int | None = None
    eirs_accepted_delta_count: int | None = None
    live_api_used: bool = False
    metadata: Mapping[str, Any] = field(default_factory=dict)
    started_at: str | None = None
    finished_at: str | None = None

    def __post_init__(self) -> None:
        for name in ("run_id", "arm", "task_id"):
            if not str(getattr(self, name)).strip():
                raise ReleaseEvaluationError(f"{name} is required for a run record")
            object.__setattr__(self, name, str(getattr(self, name)))
        if isinstance(self.block, bool) or not isinstance(self.block, int) or self.block < 1:
            raise ReleaseEvaluationError("block must be a positive integer")
        status = str(self.status).upper()
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "domain", str(self.domain or "unknown"))
        if (
            isinstance(self.score, bool)
            or not isinstance(self.score, (int, float))
            or not math.isfinite(float(self.score))
        ):
            raise ReleaseEvaluationError("score must be a finite number")
        if not 0 <= float(self.score) <= 100:
            raise ReleaseEvaluationError("score must be between 0 and 100")
        object.__setattr__(self, "score", float(self.score))
        for name in ("provider_requests", "tool_calls", "accepted_delta_count"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ReleaseEvaluationError(f"{name} must be a non-negative integer")
        for name in ("tool_accepted_delta_count", "eirs_accepted_delta_count"):
            value = getattr(self, name)
            if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value < 0):
                raise ReleaseEvaluationError(f"{name} must be a non-negative integer or null")
        object.__setattr__(self, "failures", tuple(str(item) for item in self.failures))
        if not isinstance(self.metadata, Mapping):
            raise ReleaseEvaluationError("metadata must be an object")
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def successful(self) -> bool:
        return self.status in _SUCCESS_STATUSES and not self.failures

    @property
    def itt_score(self) -> float:
        return self.score if self.successful else 0.0

    @property
    def itt_correct(self) -> int:
        return int(self.successful and bool(self.correct if self.correct is not None else self.score >= 100.0))

    def accepted(self, kind: str) -> int:
        normalized = kind.lower()
        if normalized == "tool":
            value = self.tool_accepted_delta_count
            if value is None:
                value = self.metadata.get("tool_accepted_delta_count", self.metadata.get("accepted_delta_count"))
        elif normalized == "eirs":
            value = self.eirs_accepted_delta_count
            if value is None:
                nested = self.metadata.get("eirs")
                value = (
                    nested.get("accepted_delta_count")
                    if isinstance(nested, Mapping)
                    else self.metadata.get("eirs_accepted_delta_count")
                )
        else:
            value = self.accepted_delta_count
        if value is None:
            return 0
        try:
            return max(0, int(value))
        except (TypeError, ValueError):
            return 0

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any], *, default_arm: str = "unknown", default_block: int = 1) -> RunRecord:
        if not isinstance(raw, Mapping):
            raise ReleaseEvaluationError("run record must be an object")
        status = str(raw.get("status", raw.get("state", "SUCCESS"))).upper()
        failure_values = raw.get("failures", raw.get("failure_reasons", ()))
        if isinstance(failure_values, str):
            failure_values = (failure_values,)
        if not isinstance(failure_values, Sequence):
            failure_values = ()
        usage = _mapping_or_empty(raw.get("usage"))
        tool = _mapping_or_empty(raw.get("tool"))
        eirs = _mapping_or_empty(raw.get("eirs"))
        block_value = raw.get("block", raw.get("randomized_block", default_block))
        try:
            block = int(block_value)
        except (TypeError, ValueError) as exc:
            raise ReleaseEvaluationError("run block must be an integer") from exc
        task_id = str(raw.get("task_id", raw.get("case_id", "")))
        run_id = str(raw.get("run_id", f"{raw.get('arm', default_arm)}-b{block}-{task_id}"))
        score_value = raw.get("score", raw.get("outcome_score", raw.get("task_score", raw.get("metric", 0.0))))
        return cls(
            run_id=run_id,
            arm=str(raw.get("arm", default_arm)),
            block=block,
            task_id=task_id,
            domain=str(raw.get("domain", raw.get("primary_domain", "unknown"))),
            status=status,
            score=float(score_value or 0.0),
            correct=raw.get("correct", raw.get("outcome_correct")),
            failure_type=(str(raw["failure_type"]) if raw.get("failure_type") is not None else None),
            failure_message=(str(raw["failure_message"]) if raw.get("failure_message") is not None else None),
            failures=tuple(str(item) for item in failure_values),
            manifest_digest=str(raw.get("manifest_digest", raw.get("candidate_manifest_digest", UNKNOWN))),
            provider_requests=int(
                raw.get("provider_requests", usage.get("provider_requests", usage.get("requests", 0))) or 0
            ),
            tool_calls=int(raw.get("tool_calls", tool.get("calls", 0)) or 0),
            accepted_delta_count=int(raw.get("accepted_delta_count", raw.get("accepted_deltas", 0)) or 0),
            tool_accepted_delta_count=_optional_int(
                raw.get("tool_accepted_delta_count", tool.get("accepted_delta_count"))
            ),
            eirs_accepted_delta_count=_optional_int(
                raw.get("eirs_accepted_delta_count", eirs.get("accepted_delta_count"))
            ),
            live_api_used=bool(raw.get("live_api_used", raw.get("provider_live", False))),
            metadata=raw.get("metadata", {}),
            started_at=(str(raw["started_at"]) if raw.get("started_at") is not None else None),
            finished_at=(str(raw["finished_at"]) if raw.get("finished_at") is not None else None),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": LEDGER_SCHEMA_VERSION,
            "run_id": self.run_id,
            "arm": self.arm,
            "block": self.block,
            "task_id": self.task_id,
            "domain": self.domain,
            "status": self.status,
            "score": self.score,
            "correct": self.correct,
            "successful": self.successful,
            "failure_type": self.failure_type,
            "failure_message": self.failure_message,
            "failures": list(self.failures),
            "manifest_digest": self.manifest_digest,
            "provider_requests": self.provider_requests,
            "tool_calls": self.tool_calls,
            "accepted_delta_count": self.accepted_delta_count,
            "tool_accepted_delta_count": self.tool_accepted_delta_count,
            "eirs_accepted_delta_count": self.eirs_accepted_delta_count,
            "live_api_used": self.live_api_used,
            "metadata": dict(self.metadata),
            "started_at": self.started_at,
            "finished_at": self.finished_at,
        }


RunOutcome = RunRecord


def _optional_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ReleaseEvaluationError("counter must be an integer") from exc


def _mapping_or_empty(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


class RunLedger:
    """Append-only JSONL ledger with a hash chain and explicit failures."""

    def __init__(self, path: Path | None = None, records: Iterable[RunRecord] = ()) -> None:
        self.path = path
        self._events: list[dict[str, Any]] = []
        self._run_ids: set[str] = set()
        for record in records:
            self.append(record, persist=False)

    @property
    def records(self) -> tuple[RunRecord, ...]:
        return tuple(RunRecord.from_mapping(event["run"]) for event in self._events)

    @property
    def events(self) -> tuple[dict[str, Any], ...]:
        return tuple(dict(event) for event in self._events)

    def append(self, record: RunRecord | Mapping[str, Any], *, persist: bool = True) -> dict[str, Any]:
        item = record if isinstance(record, RunRecord) else RunRecord.from_mapping(record)
        if item.run_id in self._run_ids:
            raise ReleaseEvaluationError(f"duplicate run_id in ledger: {item.run_id}")
        previous = self._events[-1]["event_digest"] if self._events else "GENESIS"
        sequence = len(self._events) + 1
        event_body = {
            "schema_version": LEDGER_SCHEMA_VERSION,
            "sequence": sequence,
            "previous_digest": previous,
            "run": item.to_dict(),
        }
        event = {**event_body, "event_digest": canonical_digest(event_body)}
        self._events.append(event)
        self._run_ids.add(item.run_id)
        if persist and self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8", newline="\n") as stream:
                stream.write(json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
                stream.write("\n")
        return event

    def record_failure(
        self,
        *,
        run_id: str,
        arm: str,
        block: int,
        task_id: str,
        failure_type: str,
        message: str = "",
        domain: str = "unknown",
        manifest_digest: str = UNKNOWN,
    ) -> dict[str, Any]:
        return self.append(
            RunRecord(
                run_id=run_id,
                arm=arm,
                block=block,
                task_id=task_id,
                domain=domain,
                status="FAILED",
                failure_type=failure_type,
                failure_message=message,
                failures=(failure_type,),
                manifest_digest=manifest_digest,
            )
        )

    def verify(self) -> dict[str, Any]:
        errors: list[str] = []
        previous = "GENESIS"
        ids: set[str] = set()
        for expected_sequence, event in enumerate(self._events, start=1):
            if event.get("sequence") != expected_sequence:
                errors.append(f"sequence:{expected_sequence}")
            if event.get("previous_digest") != previous:
                errors.append(f"previous_digest:{expected_sequence}")
            body = {key: value for key, value in event.items() if key != "event_digest"}
            if event.get("event_digest") != canonical_digest(body):
                errors.append(f"event_digest:{expected_sequence}")
            try:
                item = RunRecord.from_mapping(event.get("run", {}))
                if item.run_id in ids:
                    errors.append(f"duplicate_run_id:{item.run_id}")
                ids.add(item.run_id)
            except ReleaseEvaluationError as exc:
                errors.append(f"run:{expected_sequence}:{exc}")
            previous = str(event.get("event_digest", ""))
        return {"valid": not errors, "event_count": len(self._events), "errors": errors}

    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": LEDGER_SCHEMA_VERSION, "events": list(self._events), "verification": self.verify()}

    def write(self, path: Path | None = None) -> Path:
        destination = path or self.path
        if destination is None:
            raise ReleaseEvaluationError("ledger output path is required")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(
            json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )
        return destination

    @classmethod
    def load(cls, path: Path) -> RunLedger:
        try:
            text = path.read_text(encoding="utf-8")
            lines = [line for line in text.splitlines() if line.strip()]
        except OSError as exc:
            raise ReleaseEvaluationError(f"cannot read run ledger: {path}") from exc
        ledger = cls(path=path)
        if not lines:
            return ledger
        try:
            document = json.loads(text)
        except json.JSONDecodeError:
            document = None
        if isinstance(document, Mapping) and isinstance(document.get("events"), list):
            events = document["events"]
        elif isinstance(document, list):
            events = document
        else:
            events = [json.loads(line) for line in lines]
        for event in events:
            if not isinstance(event, Mapping) or not isinstance(event.get("run"), Mapping):
                raise ReleaseEvaluationError("run ledger contains an invalid event")
            item = RunRecord.from_mapping(event["run"])
            expected = dict(event)
            expected["run"] = item.to_dict()
            ledger._events.append(expected)
            ledger._run_ids.add(item.run_id)
        verification = ledger.verify()
        if not verification["valid"]:
            raise ReleaseEvaluationError("run ledger hash chain is invalid: " + ", ".join(verification["errors"]))
        return ledger


@dataclass(frozen=True, slots=True)
class RandomizedBlock:
    block: int
    seed: int
    arm_order: tuple[str, ...]
    task_order: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": RANDOMIZATION_SCHEMA_VERSION,
            "block": self.block,
            "seed": self.seed,
            "arm_order": list(self.arm_order),
            "task_order": list(self.task_order),
        }


BlockPlan = RandomizedBlock


def _derived_seed(seed: int, block: int, label: str) -> int:
    return int.from_bytes(hashlib.sha256(f"{seed}:{block}:{label}".encode()).digest()[:8], "big")


def randomized_blocks(
    arms: Sequence[str],
    tasks: Sequence[str],
    *,
    block_count: int = MIN_RANDOMIZED_BLOCKS,
    seed: int = 0,
    scheme: str = "abba",
) -> tuple[RandomizedBlock, ...]:
    arm_values = tuple(dict.fromkeys(str(item) for item in arms if str(item)))
    task_values = tuple(dict.fromkeys(str(item) for item in tasks if str(item)))
    if len(arm_values) < 2 or not task_values:
        raise ReleaseEvaluationError("randomized blocks require at least two arms and one task")
    if block_count < MIN_RANDOMIZED_BLOCKS:
        raise ReleaseEvaluationError(f"at least {MIN_RANDOMIZED_BLOCKS} randomized blocks are required")
    if scheme not in {"abba", "latin-square"}:
        raise ReleaseEvaluationError("scheme must be abba or latin-square")
    result: list[RandomizedBlock] = []
    for block in range(1, block_count + 1):
        if scheme == "abba" and len(arm_values) == 2:
            order = arm_values if block % 2 else tuple(reversed(arm_values))
        else:
            rotation = (block - 1) % len(arm_values)
            order = arm_values[rotation:] + arm_values[:rotation]
            if block % 2 == 0 and len(arm_values) > 2:
                order = tuple(reversed(order))
        tasks_in_block = list(task_values)
        random.Random(_derived_seed(seed, block, "tasks")).shuffle(  # noqa: S311  # nosec B311 - deterministic only
            tasks_in_block
        )
        result.append(
            RandomizedBlock(
                block=block,
                seed=_derived_seed(seed, block, "block"),
                arm_order=tuple(order),
                task_order=tuple(tasks_in_block),
            )
        )
    return tuple(result)


def validate_randomized_blocks(
    plans: Sequence[RandomizedBlock],
    *,
    arms: Sequence[str] | None = None,
    tasks: Sequence[str] | None = None,
    minimum: int = MIN_RANDOMIZED_BLOCKS,
) -> dict[str, Any]:
    expected_arms = set(str(item) for item in arms or ())
    expected_tasks = set(str(item) for item in tasks or ())
    blockers: list[str] = []
    if len(plans) < minimum:
        blockers.append(f"requires_at_least_{minimum}_blocks")
    if len({item.block for item in plans}) != len(plans):
        blockers.append("duplicate_block")
    if expected_arms and any(set(item.arm_order) != expected_arms for item in plans):
        blockers.append("arm_order_not_complete")
    if expected_tasks and any(set(item.task_order) != expected_tasks for item in plans):
        blockers.append("task_order_not_complete")
    distinct_orders = len({item.arm_order for item in plans})
    if len(expected_arms) >= 2 and len(plans) >= minimum and distinct_orders < 2:
        blockers.append("arm_order_not_randomized")
    return {
        "valid": not blockers,
        "block_count": len(plans),
        "distinct_arm_orders": distinct_orders,
        "task_orders_distinct": len({item.task_order for item in plans}),
        "blockers": blockers,
    }


def _quantile(values: Sequence[float], probability: float) -> float:
    ordered = sorted(float(item) for item in values)
    if not ordered:
        raise ReleaseEvaluationError("quantile requires at least one value")
    position = (len(ordered) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    fraction = position - lower
    return ordered[lower] * (1 - fraction) + ordered[upper] * fraction


def bootstrap_ci(
    values: Sequence[float], *, iterations: int = 2000, seed: int = 0, confidence: float = 0.95, unit: str = "block"
) -> dict[str, Any] | None:
    items = [float(item) for item in values]
    if not items:
        return None
    if iterations < 100:
        raise ReleaseEvaluationError("bootstrap iterations must be at least 100")
    if not 0 < confidence < 1:
        raise ReleaseEvaluationError("confidence must be between 0 and 1")
    if len(items) == 1:
        return {"lower": items[0], "upper": items[0], "confidence": confidence, "unit": unit, "iterations": iterations}
    rng = random.Random(seed)  # noqa: S311  # nosec B311 - deterministic statistical resampling
    samples = [sum(rng.choice(items) for _ in items) / len(items) for _ in range(iterations)]
    alpha = (1 - confidence) / 2
    return {
        "lower": round(_quantile(samples, alpha), 8),
        "upper": round(_quantile(samples, 1 - alpha), 8),
        "confidence": confidence,
        "unit": unit,
        "iterations": iterations,
    }


def paired_sign_test(deltas: Sequence[float], *, confidence: float = 0.95) -> dict[str, Any]:
    nonzero = [float(item) for item in deltas if float(item) != 0]
    positive = sum(item > 0 for item in nonzero)
    negative = sum(item < 0 for item in nonzero)
    ties = len(deltas) - len(nonzero)
    n = len(nonzero)
    ci: tuple[float | None, float | None]
    if n:
        tail = sum(math.comb(n, index) for index in range(min(positive, negative) + 1)) / 2**n
        p_value = min(1.0, 2 * tail)
        proportion = positive / n
        z = 1.959963984540054
        denominator = 1 + z * z / n
        centre = (proportion + z * z / (2 * n)) / denominator
        radius = z * math.sqrt((proportion * (1 - proportion) + z * z / (4 * n)) / n) / denominator
        ci = (max(0.0, centre - radius), min(1.0, centre + radius))
    else:
        p_value = None
        ci = (None, None)
    ci_values: list[float | None]
    if ci[0] is None or ci[1] is None:
        ci_values = [None, None]
    else:
        ci_values = [round(ci[0], 8), round(ci[1], 8)]
    return {
        "n": n,
        "positive": positive,
        "negative": negative,
        "ties": ties,
        "p_two_sided": round(p_value, 8) if p_value is not None else None,
        "positive_fraction": positive / n if n else None,
        "positive_fraction_ci95": ci_values,
        "confidence": confidence,
    }


def _as_records(records: Iterable[RunRecord | Mapping[str, Any]]) -> tuple[RunRecord, ...]:
    result: list[RunRecord] = []
    for item in records:
        result.append(item if isinstance(item, RunRecord) else RunRecord.from_mapping(item))
    return tuple(result)


def _metric_summary(rows: Sequence[RunRecord], *, denominator: int) -> dict[str, Any]:
    values = [row.itt_score for row in rows]
    correct = sum(row.itt_correct for row in rows)
    successes = sum(row.successful for row in rows)
    total = max(1, denominator)
    return {
        "observed_rows": len(rows),
        "denominator": denominator,
        "itt_score": round(sum(values) / total, 8) if denominator else None,
        "itt_accuracy": round(correct / total, 8) if denominator else None,
        "completion_rate": round(successes / total, 8) if denominator else None,
        "score_sum": round(sum(values), 8),
        "correct_count": correct,
        "success_count": successes,
        "failure_count": sum(not row.successful for row in rows),
    }


def _domain_map(
    task_set: Sequence[str], task_domains: Mapping[str, str] | None, rows: Sequence[RunRecord]
) -> dict[str, str]:
    mapping = {str(key): str(value) for key, value in (task_domains or {}).items()}
    for row in rows:
        mapping.setdefault(row.task_id, row.domain)
    return mapping


def _counter_summary(rows: Sequence[RunRecord], *, denominator: int, kind: str) -> dict[str, Any]:
    total = sum(row.accepted(kind) for row in rows)
    return {
        "kind": kind,
        "observed_rows": len(rows),
        "denominator": denominator,
        "accepted_delta_count": total,
        "accepted_delta_rate": round(total / denominator, 8) if denominator else None,
    }


def aggregate_paired_runs(
    records: Iterable[RunRecord | Mapping[str, Any]],
    *,
    baseline_arm: str,
    candidate_arm: str,
    task_set: Sequence[str],
    task_domains: Mapping[str, str] | None = None,
    blocks: Sequence[int] | None = None,
    plan: Sequence[RandomizedBlock] | None = None,
    candidate_manifest: CandidateManifest | None = None,
    bootstrap_iterations: int = 2000,
    bootstrap_seed: int = 0,
    minimum_blocks: int = MIN_RANDOMIZED_BLOCKS,
) -> dict[str, Any]:
    """Produce fixed-denominator ITT, paired and domain summaries.

    Missing cells are represented by a zero-valued synthetic observation in
    the calculation and listed as blockers.  This is the important distinction
    between ITT and success-conditional semantics: a crash cannot disappear
    by filtering rows before computing the denominator.
    """

    rows = _as_records(records)
    task_values = tuple(dict.fromkeys(str(item) for item in task_set if str(item)))
    if not task_values:
        raise ReleaseEvaluationError("task_set must contain at least one task")
    if baseline_arm == candidate_arm:
        raise ReleaseEvaluationError("baseline and candidate arms must differ")
    selected = [row for row in rows if row.arm in {baseline_arm, candidate_arm}]
    observed_blocks = set(row.block for row in selected)
    block_values = tuple(sorted(set(int(item) for item in (blocks or observed_blocks))))
    if plan is not None:
        block_values = tuple(sorted({item.block for item in plan}))
    if not block_values:
        block_values = tuple(sorted(observed_blocks))
    denominator = len(block_values) * len(task_values)
    index: dict[tuple[str, int, str], RunRecord] = {}
    duplicate_keys: list[str] = []
    for row in selected:
        key = (row.arm, row.block, row.task_id)
        if key in index:
            duplicate_keys.append("/".join((row.arm, str(row.block), row.task_id)))
        else:
            index[key] = row
    missing: list[dict[str, Any]] = []
    arm_rows: dict[str, list[RunRecord]] = {baseline_arm: [], candidate_arm: []}
    synthetic: dict[tuple[str, int, str], RunRecord] = {}
    for arm in (baseline_arm, candidate_arm):
        for block in block_values:
            for task_id in task_values:
                key = (arm, block, task_id)
                found = index.get(key)
                if found is None:
                    row = RunRecord(
                        run_id=f"missing-{arm}-b{block}-{task_id}",
                        arm=arm,
                        block=block,
                        task_id=task_id,
                        domain=(task_domains or {}).get(task_id, "unknown"),
                        status="MISSING",
                        failures=("missing_run",),
                        manifest_digest=candidate_manifest.manifest_digest if candidate_manifest else UNKNOWN,
                    )
                    synthetic[key] = row
                    missing.append({"arm": arm, "block": block, "task_id": task_id, "reason": "missing_run"})
                else:
                    row = found
                arm_rows[arm].append(row)
    pair_rows: list[dict[str, Any]] = []
    block_deltas: list[float] = []
    conditional_deltas: list[float] = []
    for block in block_values:
        block_values_delta: list[float] = []
        for task_id in task_values:
            left = index.get((baseline_arm, block, task_id), synthetic.get((baseline_arm, block, task_id)))
            right = index.get((candidate_arm, block, task_id), synthetic.get((candidate_arm, block, task_id)))
            if left is None or right is None:  # defensive; grid construction above always fills both
                continue
            delta = right.itt_score - left.itt_score
            block_values_delta.append(delta)
            if left.successful and right.successful:
                conditional_deltas.append(right.score - left.score)
            pair_rows.append(
                {
                    "block": block,
                    "task_id": task_id,
                    "domain": (task_domains or {}).get(task_id, right.domain or left.domain),
                    "baseline_score": left.itt_score,
                    "candidate_score": right.itt_score,
                    "delta": delta,
                    "baseline_status": left.status,
                    "candidate_status": right.status,
                }
            )
        block_deltas.append(sum(block_values_delta) / len(task_values) if block_values_delta else 0.0)
    manifest_digest = candidate_manifest.manifest_digest if candidate_manifest else None
    manifest_mismatches = []
    if manifest_digest:
        manifest_mismatches = [row.run_id for row in selected if row.manifest_digest != manifest_digest]
    domain_mapping = _domain_map(task_values, task_domains, selected)
    domain_names = tuple(sorted({domain_mapping.get(task_id, "unknown") for task_id in task_values}))
    domain_results: dict[str, Any] = {}
    domain_blockers: list[str] = []
    for domain in domain_names:
        if domain == "unknown":
            domain_blockers.append("domain_mapping_missing")
        domain_tasks = tuple(task_id for task_id in task_values if domain_mapping.get(task_id, "unknown") == domain)
        domain_denominator = len(block_values) * len(domain_tasks)
        domain_results[domain] = {
            "task_ids": list(domain_tasks),
            "baseline": _metric_summary(
                [row for row in arm_rows[baseline_arm] if row.task_id in domain_tasks], denominator=domain_denominator
            ),
            "candidate": _metric_summary(
                [row for row in arm_rows[candidate_arm] if row.task_id in domain_tasks], denominator=domain_denominator
            ),
        }
        baseline_score = domain_results[domain]["baseline"]["itt_score"]
        candidate_score = domain_results[domain]["candidate"]["itt_score"]
        passed = baseline_score is not None and candidate_score is not None and candidate_score >= baseline_score
        domain_results[domain]["delta"] = (
            round(candidate_score - baseline_score, 8)
            if passed or (candidate_score is not None and baseline_score is not None)
            else None
        )
        domain_results[domain]["non_degraded"] = passed
        if not passed:
            domain_blockers.append(f"domain_non_degradation_failed:{domain}")
    candidate_rows = arm_rows[candidate_arm]
    baseline_rows = arm_rows[baseline_arm]
    tool_baseline = _counter_summary(baseline_rows, denominator=denominator, kind="tool")
    tool_candidate = _counter_summary(candidate_rows, denominator=denominator, kind="tool")
    eirs_baseline = _counter_summary(baseline_rows, denominator=denominator, kind="eirs")
    eirs_candidate = _counter_summary(candidate_rows, denominator=denominator, kind="eirs")
    tool_net = tool_candidate["accepted_delta_count"] - tool_baseline["accepted_delta_count"]
    eirs_net = eirs_candidate["accepted_delta_count"] - eirs_baseline["accepted_delta_count"]
    failures = [row.to_dict() for row in rows if not row.successful]
    live_rows = [row.run_id for row in rows if row.live_api_used or row.provider_requests > 0]
    randomization = (
        validate_randomized_blocks(
            plan,
            arms=(baseline_arm, candidate_arm),
            tasks=task_values,
            minimum=minimum_blocks,
        )
        if plan is not None
        else {
            "valid": False,
            "block_count": len(block_values),
            "distinct_arm_orders": None,
            "task_orders_distinct": None,
            "blockers": ["randomization_plan_missing"],
        }
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "baseline_arm": baseline_arm,
        "candidate_arm": candidate_arm,
        "task_set": list(task_values),
        "task_set_count": len(task_values),
        "blocks": list(block_values),
        "block_count": len(block_values),
        "randomization": randomization,
        "manifest": {
            "candidate_manifest_digest": manifest_digest,
            "mismatched_run_ids": manifest_mismatches,
            "consistent": not manifest_mismatches if manifest_digest else False,
        },
        "itt": {
            "denominator": denominator,
            "fixed_denominator": True,
            "grid_size": denominator * 2,
            "missing_cells": missing,
            "missing_count": len(missing),
            "complete": not missing and not duplicate_keys,
            "duplicate_keys": duplicate_keys,
            "baseline": _metric_summary(baseline_rows, denominator=denominator),
            "candidate": _metric_summary(candidate_rows, denominator=denominator),
        },
        "paired": {
            "pair_count": len(pair_rows),
            "block_deltas": [round(item, 8) for item in block_deltas],
            "cell_delta_mean": round(sum(item["delta"] for item in pair_rows) / len(pair_rows), 8)
            if pair_rows
            else None,
            "block_delta_mean": round(sum(block_deltas) / len(block_deltas), 8) if block_deltas else None,
            "bootstrap_ci95": bootstrap_ci(
                block_deltas, iterations=bootstrap_iterations, seed=bootstrap_seed, unit="randomized_block"
            ),
            "sign_test": paired_sign_test(block_deltas),
            "success_conditional": {
                "pair_count": len(conditional_deltas),
                "delta_mean": round(sum(conditional_deltas) / len(conditional_deltas), 8)
                if conditional_deltas
                else None,
                "undefined_when_no_joint_success": not bool(conditional_deltas),
            },
            "rows": pair_rows,
        },
        "domains": {
            "all_non_degraded": not domain_blockers,
            "blockers": domain_blockers,
            "results": domain_results,
        },
        "accepted_delta": {
            "tool": {
                "baseline": tool_baseline,
                "candidate": tool_candidate,
                "net_gain": tool_net,
                "net_gain_positive": tool_net > 0,
            },
            "eirs": {
                "baseline": eirs_baseline,
                "candidate": eirs_candidate,
                "net_gain": eirs_net,
                "net_gain_positive": eirs_net > 0,
            },
        },
        "runs": {
            "observed_count": len(rows),
            "selected_count": len(selected),
            "failure_count": len(failures),
            "failures": failures,
            "provider_or_live_ids": live_rows,
            "all_failures_recorded": True,
        },
        "_gate_context": {"manifest_missing": candidate_manifest is None, "tool_net": tool_net, "eirs_net": eirs_net},
    }


def evaluate_release_gate(
    summary: Mapping[str, Any],
    *,
    candidate_manifest: CandidateManifest | None = None,
    require_clean_tree: bool = True,
    require_artifacts: bool = True,
    require_offline: bool = True,
    require_bootstrap_lower_positive: bool = True,
    require_sign_ci_lower_positive: bool = False,
    require_tool_net_gain: bool = True,
    require_eirs_net_gain: bool = True,
    minimum_delta: float = 0.0,
) -> dict[str, Any]:
    """Apply all release checks; any recorded failure causes ``FAIL``."""

    blockers: list[str] = []
    manifest_check: Mapping[str, Any] = (
        candidate_manifest.verify(require_clean_tree=require_clean_tree, require_artifacts=require_artifacts)
        if candidate_manifest
        else {"valid": False, "blockers": ["manifest_missing"]}
    )
    blockers.extend(str(item) for item in manifest_check.get("blockers", ()))
    randomization = summary.get("randomization", {})
    if not randomization.get("valid", False):
        blockers.extend(str(item) for item in randomization.get("blockers", ()))
    itt = summary.get("itt", {})
    if not itt.get("fixed_denominator", False):
        blockers.append("itt_denominator_not_fixed")
    if not itt.get("complete", False):
        blockers.append("itt_grid_incomplete")
    if itt.get("duplicate_keys"):
        blockers.append("duplicate_run_cell")
    if summary.get("manifest", {}).get("mismatched_run_ids"):
        blockers.append("run_manifest_mismatch")
    if not summary.get("domains", {}).get("all_non_degraded", False):
        blockers.extend(str(item) for item in summary.get("domains", {}).get("blockers", ()))
    paired = summary.get("paired", {})
    delta = paired.get("block_delta_mean")
    if not isinstance(delta, (int, float)) or float(delta) < minimum_delta:
        blockers.append("overall_delta_below_threshold")
    ci = paired.get("bootstrap_ci95") or {}
    if require_bootstrap_lower_positive and (not isinstance(ci.get("lower"), (int, float)) or float(ci["lower"]) <= 0):
        blockers.append("bootstrap_ci_lower_not_positive")
    sign = paired.get("sign_test") or {}
    sign_ci = sign.get("positive_fraction_ci95", [None, None])
    if require_sign_ci_lower_positive and (
        not isinstance(sign_ci, Sequence) or sign_ci[0] is None or float(sign_ci[0]) <= 0.5
    ):
        blockers.append("sign_test_ci_lower_not_positive")
    failures = summary.get("runs", {}).get("failures", ())
    if failures:
        blockers.append("run_failure_recorded")
    if require_offline and summary.get("runs", {}).get("provider_or_live_ids"):
        blockers.append("live_provider_or_api_observed")
    accepted = summary.get("accepted_delta", {})
    if require_tool_net_gain and not accepted.get("tool", {}).get("net_gain_positive", False):
        blockers.append("tool_accepted_delta_net_gain_not_positive")
    if require_eirs_net_gain and not accepted.get("eirs", {}).get("net_gain_positive", False):
        blockers.append("eirs_accepted_delta_net_gain_not_positive")
    # Keep ordering deterministic while retaining the first occurrence as the
    # useful explanation in a CI log.
    blockers = list(dict.fromkeys(blockers))
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "PASS" if not blockers else "FAIL",
        "passed": not blockers,
        "blockers": blockers,
        "requirements": {
            "require_clean_tree": require_clean_tree,
            "require_artifacts": require_artifacts,
            "require_offline": require_offline,
            "require_bootstrap_lower_positive": require_bootstrap_lower_positive,
            "require_sign_ci_lower_positive": require_sign_ci_lower_positive,
            "require_tool_net_gain": require_tool_net_gain,
            "require_eirs_net_gain": require_eirs_net_gain,
            "minimum_delta": minimum_delta,
        },
        "manifest": manifest_check,
    }


def release_report(
    records: Iterable[RunRecord | Mapping[str, Any]],
    *,
    baseline_arm: str,
    candidate_arm: str,
    task_set: Sequence[str],
    candidate_manifest: CandidateManifest | None,
    task_domains: Mapping[str, str] | None = None,
    plan: Sequence[RandomizedBlock] | None = None,
    bootstrap_iterations: int = 2000,
    bootstrap_seed: int = 0,
    **gate_options: Any,
) -> dict[str, Any]:
    summary = aggregate_paired_runs(
        records,
        baseline_arm=baseline_arm,
        candidate_arm=candidate_arm,
        task_set=task_set,
        task_domains=task_domains,
        plan=plan,
        candidate_manifest=candidate_manifest,
        bootstrap_iterations=bootstrap_iterations,
        bootstrap_seed=bootstrap_seed,
    )
    summary["gate"] = evaluate_release_gate(summary, candidate_manifest=candidate_manifest, **gate_options)
    summary.pop("_gate_context", None)
    return summary


# Naming aliases make the boundary easy to discover for external Luna
# runners while retaining the explicit function names used above.
CandidateIdentity = CandidateManifest
RunLog = RunLedger
build_exact_candidate_manifest = build_candidate_manifest
aggregate_paired = aggregate_paired_runs
run_release_gate = evaluate_release_gate


__all__ = [
    "ArtifactRef",
    "BlockPlan",
    "CandidateIdentity",
    "CandidateManifest",
    "LEDGER_SCHEMA_VERSION",
    "MANIFEST_SCHEMA_VERSION",
    "MIN_RANDOMIZED_BLOCKS",
    "RANDOMIZATION_SCHEMA_VERSION",
    "ReleaseEvaluationError",
    "RandomizedBlock",
    "RunLedger",
    "RunLog",
    "RunOutcome",
    "RunRecord",
    "SCHEMA_VERSION",
    "UNKNOWN",
    "aggregate_paired_runs",
    "aggregate_paired",
    "bootstrap_ci",
    "build_candidate_manifest",
    "build_exact_candidate_manifest",
    "canonical_digest",
    "canonical_json",
    "evaluate_release_gate",
    "file_sha256",
    "paired_sign_test",
    "randomized_blocks",
    "redacted_environment",
    "release_report",
    "run_release_gate",
    "sha256_bytes",
    "validate_randomized_blocks",
]
