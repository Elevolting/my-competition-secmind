from __future__ import annotations

import argparse
import hashlib
import json
import mimetypes
import shutil
import subprocess
import sys
import tempfile
import unicodedata
from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from secmind.artifact_store import ContentAddressedArtifactStore
from secmind.canonical_primary import _indexed_path_priority, _path_priority
from secmind.repository_index import INDEX_FORMAT_VERSION, RepositoryIndexer, RepositoryIndexError
from secmind.schemas import InputArtifact

SCHEMA_VERSION = "secmind.source-triage-recall-at-k.v1"
DEFAULT_MAX_TASKS = 500
DEFAULT_MAX_FILES = 100_000
DEFAULT_MAX_BYTES = 2 * 1024 * 1024 * 1024
HARD_MAX_TASKS = 1_000
HARD_MAX_FILES = 200_000
HARD_MAX_BYTES = 8 * 1024 * 1024 * 1024
MAX_METADATA_BYTES = 32 * 1024 * 1024
FILE_CHUNK_BYTES = 1024 * 1024
HEX_DIGITS = frozenset("0123456789abcdef")
RELEASE_K = 10
RELEASE_MIN_TASKS = 8


class SourceTriageAcceptanceError(ValueError):
    """Benchmark input cannot be evaluated safely and deterministically."""


def _canonical_sha256(value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _git_value(*arguments: str) -> str | None:
    git = shutil.which("git")
    if git is None:
        return None
    try:
        completed = subprocess.run(  # noqa: S603 - fixed executable and internal arguments only
            [git, *arguments],
            check=True,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return completed.stdout.strip()


def _provenance(tasks: list[BenchmarkTask]) -> dict[str, Any]:
    commit = _git_value("rev-parse", "HEAD") or "unknown"
    tree = _git_value("rev-parse", "HEAD^{tree}") or "unknown"
    status = _git_value("status", "--porcelain", "--untracked-files=all")
    benchmark_payload = [
        {
            "task_id": task.task_id,
            "objective_sha256": hashlib.sha256(task.objective.encode("utf-8")).hexdigest(),
            "inputs": [
                {
                    "artifact_id": artifact.artifact_id,
                    "path": artifact.relative_path,
                    "sha256": artifact.sha256,
                    "size_bytes": artifact.size_bytes,
                }
                for artifact in task.artifacts
            ],
            "vulnerable_paths": list(task.vulnerable_paths),
        }
        for task in tasks
    ]
    return {
        "source_commit": commit,
        "source_tree_oid": tree,
        "source_dirty": "unknown" if status is None else str(bool(status)).lower(),
        "source_identity_method": (
            "git" if commit != "unknown" and tree != "unknown" and status is not None else "unavailable"
        ),
        "script_sha256": hashlib.sha256(Path(__file__).resolve().read_bytes()).hexdigest(),
        "benchmark_commitment_sha256": _canonical_sha256(benchmark_payload),
        "repository_index_format": INDEX_FORMAT_VERSION,
    }


@dataclass(frozen=True, slots=True)
class Limits:
    max_tasks: int = DEFAULT_MAX_TASKS
    max_files: int = DEFAULT_MAX_FILES
    max_bytes: int = DEFAULT_MAX_BYTES

    def validate(self) -> None:
        values = (
            ("max_tasks", self.max_tasks, HARD_MAX_TASKS),
            ("max_files", self.max_files, HARD_MAX_FILES),
            ("max_bytes", self.max_bytes, HARD_MAX_BYTES),
        )
        for name, value, maximum in values:
            if value < 1 or value > maximum:
                raise SourceTriageAcceptanceError(f"{name} must be between 1 and {maximum}")


@dataclass(frozen=True, slots=True)
class BenchmarkTask:
    task_id: str
    objective: str
    workspace: Path
    artifacts: tuple[InputArtifact, ...]
    vulnerable_paths: tuple[str, ...]


@dataclass(slots=True)
class InputBudget:
    limits: Limits
    files: int = 0
    bytes: int = 0

    def add(self, *, task_id: str, size_bytes: int) -> None:
        self.files += 1
        self.bytes += size_bytes
        if self.files > self.limits.max_files:
            raise SourceTriageAcceptanceError(
                f"input file limit exceeded while loading {task_id}: {self.files} > {self.limits.max_files}"
            )
        if self.bytes > self.limits.max_bytes:
            raise SourceTriageAcceptanceError(
                f"input byte limit exceeded while loading {task_id}: {self.bytes} > {self.limits.max_bytes}"
            )


def _normalize_relative_path(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SourceTriageAcceptanceError(f"{label} must be a non-empty relative path")
    normalized_text = unicodedata.normalize("NFC", value.replace("\\", "/"))
    posix = PurePosixPath(normalized_text)
    windows = PureWindowsPath(value)
    if (
        posix.is_absolute()
        or windows.is_absolute()
        or windows.drive
        or ".." in posix.parts
        or normalized_text.startswith("//")
    ):
        raise SourceTriageAcceptanceError(f"{label} contains traversal or an absolute path: {value!r}")
    normalized = posix.as_posix()
    if normalized in {"", "."} or any(ord(character) < 32 or ord(character) == 127 for character in normalized):
        raise SourceTriageAcceptanceError(f"{label} is unsafe: {value!r}")
    return normalized


def _validate_task_id(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SourceTriageAcceptanceError("task_id must be a non-empty string")
    task_id = value.strip()
    if (
        len(task_id) > 128
        or task_id in {".", ".."}
        or "/" in task_id
        or "\\" in task_id
        or any(ord(character) < 32 or ord(character) == 127 for character in task_id)
    ):
        raise SourceTriageAcceptanceError(f"unsafe task_id: {task_id!r}")
    return task_id


def _read_bounded_bytes(path: Path, *, label: str) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise SourceTriageAcceptanceError(f"{label} must be a regular file: {path}")
    size_bytes = path.stat().st_size
    if size_bytes > MAX_METADATA_BYTES:
        raise SourceTriageAcceptanceError(
            f"{label} exceeds the metadata byte limit: {size_bytes} > {MAX_METADATA_BYTES}"
        )
    return path.read_bytes()


def _load_json(path: Path, *, label: str) -> tuple[Any, bytes]:
    payload = _read_bounded_bytes(path, label=label)
    try:
        return json.loads(payload), payload
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SourceTriageAcceptanceError(f"{label} is not valid UTF-8 JSON: {path}") from exc


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    payload = _read_bounded_bytes(path, label="task manifest")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SourceTriageAcceptanceError(f"task manifest is not valid UTF-8 JSONL: {path}") from exc
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise SourceTriageAcceptanceError(f"invalid JSONL record at line {line_number}: {path}") from exc
        if not isinstance(value, dict):
            raise SourceTriageAcceptanceError(f"JSONL record at line {line_number} must be an object")
        records.append(value)
    if not records:
        raise SourceTriageAcceptanceError("task manifest contains no tasks")
    return records


def _sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size_bytes = 0
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(FILE_CHUNK_BYTES):
                size_bytes += len(chunk)
                digest.update(chunk)
    except OSError as exc:
        raise SourceTriageAcceptanceError(f"unable to read benchmark input: {path}") from exc
    return digest.hexdigest(), size_bytes


def _ensure_regular_root(path: Path, *, label: str) -> Path:
    if path.is_symlink() or not path.is_dir():
        raise SourceTriageAcceptanceError(f"{label} must be a real directory: {path}")
    try:
        return path.resolve(strict=True)
    except OSError as exc:
        raise SourceTriageAcceptanceError(f"unable to resolve {label}: {path}") from exc


def _path_within(root: Path, relative: str, *, label: str) -> Path:
    candidate = root.joinpath(*PurePosixPath(relative).parts)
    current = root
    for part in PurePosixPath(relative).parts:
        current = current / part
        if current.is_symlink():
            raise SourceTriageAcceptanceError(f"{label} traverses a symbolic link: {relative}")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise SourceTriageAcceptanceError(f"missing {label}: {relative}") from exc
    if not resolved.is_relative_to(root):
        raise SourceTriageAcceptanceError(f"{label} escapes its task workspace: {relative}")
    return resolved


def _valid_sha256(value: object) -> str:
    digest = str(value).strip().casefold()
    if len(digest) != 64 or any(character not in HEX_DIGITS for character in digest):
        raise SourceTriageAcceptanceError(f"invalid input sha256: {value!r}")
    return digest


def _metadata_path_values(value: Any, *, allow_item_path: bool = False) -> tuple[bool, list[object]]:
    """Read only explicit benchmark-label fields; never inspect source bytes."""

    if isinstance(value, list):
        if allow_item_path:
            item_paths: list[object] = []
            for item in value:
                if isinstance(item, str):
                    item_paths.append(item)
                elif isinstance(item, dict):
                    candidate = item.get("path") or item.get("file") or item.get("relative_path")
                    if candidate is not None:
                        item_paths.append(candidate)
            return True, item_paths
        return False, []
    if not isinstance(value, dict):
        return False, []

    for key in ("vulnerable_paths", "vulnerable_files", "ground_truth_paths", "affected_paths"):
        if key not in value:
            continue
        raw = value[key]
        if isinstance(raw, str):
            return True, [raw]
        if isinstance(raw, list):
            return True, list(raw)
        raise SourceTriageAcceptanceError(f"benchmark metadata field {key} must be a path or list of paths")

    for key in ("expected_findings", "findings", "vulnerabilities"):
        if key in value:
            raw = value[key]
            if not isinstance(raw, list):
                raise SourceTriageAcceptanceError(f"benchmark metadata field {key} must be a list")
            finding_paths: list[object] = []
            for item in raw:
                if not isinstance(item, dict):
                    continue
                candidate = item.get("path") or item.get("file") or item.get("relative_path")
                if candidate is not None:
                    finding_paths.append(candidate)
            return True, finding_paths

    if allow_item_path:
        candidate = value.get("path") or value.get("file") or value.get("relative_path")
        if candidate is not None:
            return True, [candidate]

    saw_label_container = False
    for key in ("ground_truth", "expected", "metadata"):
        if key not in value:
            continue
        saw_label_container = True
        found, paths = _metadata_path_values(value[key], allow_item_path=True)
        if found and paths:
            return True, paths
    return saw_label_container, []


def _ground_truth_from_metadata(*values: Any, task_id: str) -> list[object]:
    saw_metadata = False
    for value in values:
        found, paths = _metadata_path_values(value)
        saw_metadata = saw_metadata or found
        if paths:
            return paths
    qualifier = "empty" if saw_metadata else "missing"
    raise SourceTriageAcceptanceError(f"{qualifier} vulnerable-path ground truth for task {task_id}")


def _parse_input_artifacts(
    task: dict[str, Any],
    *,
    task_id: str,
    workspace: Path,
    budget: InputBudget,
) -> tuple[InputArtifact, ...]:
    raw_inputs = task.get("inputs", task.get("files"))
    if not isinstance(raw_inputs, list) or not raw_inputs:
        raise SourceTriageAcceptanceError(f"task {task_id} has no input manifest")
    artifacts: list[InputArtifact] = []
    seen_paths: dict[str, str] = {}
    for position, raw in enumerate(raw_inputs):
        item: dict[str, Any]
        if isinstance(raw, str):
            item = {"path": raw}
        elif isinstance(raw, dict):
            item = raw
        else:
            raise SourceTriageAcceptanceError(f"task {task_id} input {position} must be a path or object")
        relative = _normalize_relative_path(item.get("path", item.get("relative_path")), label=f"task {task_id} input")
        collision_key = relative.casefold()
        if collision_key in seen_paths:
            raise SourceTriageAcceptanceError(
                f"task {task_id} has duplicate input paths: {seen_paths[collision_key]!r} and {relative!r}"
            )
        seen_paths[collision_key] = relative
        source = _path_within(workspace, relative, label=f"task {task_id} input")
        if source.is_symlink() or not source.is_file():
            raise SourceTriageAcceptanceError(f"task {task_id} input must be a regular file: {relative}")
        stat_size = source.stat().st_size
        budget.add(task_id=task_id, size_bytes=stat_size)
        digest, measured_size = _sha256_file(source)
        if measured_size != stat_size:
            raise SourceTriageAcceptanceError(f"task {task_id} input changed while hashing: {relative}")
        if "size_bytes" in item or "bytes" in item:
            expected_size = item.get("size_bytes", item.get("bytes"))
            if not isinstance(expected_size, int) or isinstance(expected_size, bool) or expected_size < 0:
                raise SourceTriageAcceptanceError(f"task {task_id} input has invalid size: {relative}")
            if expected_size != measured_size:
                raise SourceTriageAcceptanceError(f"task {task_id} input size mismatch: {relative}")
        if "sha256" in item and _valid_sha256(item["sha256"]) != digest:
            raise SourceTriageAcceptanceError(f"task {task_id} input hash mismatch: {relative}")
        media_type = item.get("media_type")
        if not isinstance(media_type, str) or not media_type:
            media_type = mimetypes.guess_type(relative)[0] or "application/octet-stream"
        artifacts.append(
            InputArtifact(
                artifact_id=f"benchmark-{digest[:32]}",
                original_name=PurePosixPath(relative).name,
                relative_path=relative,
                sha256=digest,
                size_bytes=measured_size,
                media_type=media_type,
            )
        )
    return tuple(artifacts)


def _build_task(
    task: dict[str, Any],
    *,
    workspace: Path,
    budget: InputBudget,
    extra_metadata: tuple[Any, ...] = (),
    expected_task_id: str | None = None,
) -> BenchmarkTask:
    task_id = _validate_task_id(task.get("task_id", task.get("id")))
    if expected_task_id is not None and task_id != expected_task_id:
        raise SourceTriageAcceptanceError(
            f"task manifest identity mismatch: expected {expected_task_id!r}, found {task_id!r}"
        )
    objective_value = task.get("prompt", task.get("objective", ""))
    if not isinstance(objective_value, str):
        raise SourceTriageAcceptanceError(f"task {task_id} prompt/objective must be a string")
    artifacts = _parse_input_artifacts(task, task_id=task_id, workspace=workspace, budget=budget)
    raw_ground_truth = _ground_truth_from_metadata(*extra_metadata, task, task_id=task_id)
    input_paths = {artifact.relative_path.casefold(): artifact.relative_path for artifact in artifacts}
    vulnerable_paths: list[str] = []
    seen_ground_truth: dict[str, str] = {}
    for raw_path in raw_ground_truth:
        path = _normalize_relative_path(raw_path, label=f"task {task_id} ground truth")
        key = path.casefold()
        if key in seen_ground_truth:
            raise SourceTriageAcceptanceError(
                f"task {task_id} has duplicate ground-truth paths: {seen_ground_truth[key]!r} and {path!r}"
            )
        seen_ground_truth[key] = path
        canonical_input = input_paths.get(key)
        if canonical_input is None:
            raise SourceTriageAcceptanceError(f"task {task_id} ground truth is not an input path: {path}")
        vulnerable_paths.append(canonical_input)
    if not vulnerable_paths:
        raise SourceTriageAcceptanceError(f"empty vulnerable-path ground truth for task {task_id}")
    return BenchmarkTask(
        task_id=task_id,
        objective=objective_value,
        workspace=workspace,
        artifacts=artifacts,
        vulnerable_paths=tuple(sorted(vulnerable_paths, key=lambda value: (value.casefold(), value))),
    )


def _selected_task_ids(task_ids: list[str] | None) -> tuple[str, ...] | None:
    if not task_ids:
        return None
    selected: list[str] = []
    seen: set[str] = set()
    for raw in task_ids:
        task_id = _validate_task_id(raw)
        if task_id in seen:
            raise SourceTriageAcceptanceError(f"duplicate selected task_id: {task_id}")
        seen.add(task_id)
        selected.append(task_id)
    return tuple(selected)


def _select_records(
    records: list[tuple[str, Any]], selected: tuple[str, ...] | None, *, limits: Limits
) -> list[tuple[str, Any]]:
    seen: set[str] = set()
    by_id: dict[str, Any] = {}
    for raw_task_id, value in records:
        task_id = _validate_task_id(raw_task_id)
        if task_id in seen:
            raise SourceTriageAcceptanceError(f"duplicate benchmark task_id: {task_id}")
        seen.add(task_id)
        by_id[task_id] = value
    selected_ids = tuple(by_id) if selected is None else selected
    missing = sorted(set(selected_ids) - set(by_id), key=lambda value: (value.casefold(), value))
    if missing:
        raise SourceTriageAcceptanceError(f"unknown selected task ids: {missing}")
    if len(selected_ids) > limits.max_tasks:
        raise SourceTriageAcceptanceError(f"task limit exceeded: {len(selected_ids)} > {limits.max_tasks}")
    return sorted(
        ((task_id, by_id[task_id]) for task_id in selected_ids),
        key=lambda row: (row[0].casefold(), row[0]),
    )


def _optional_case_metadata(case_root: Path) -> Any | None:
    path = case_root / "metadata.json"
    if not path.exists():
        return None
    value, _payload = _load_json(path, label="case metadata")
    if not isinstance(value, dict):
        raise SourceTriageAcceptanceError(f"case metadata must be an object: {path}")
    return value


def load_benchmark_directory(
    benchmark_dir: Path,
    *,
    selected: tuple[str, ...] | None,
    limits: Limits,
) -> tuple[list[BenchmarkTask], InputBudget]:
    root = _ensure_regular_root(benchmark_dir, label="benchmark directory")
    dataset_path = root / "dataset.json"
    descriptors: list[tuple[str, tuple[Path, Any]]] = []
    if dataset_path.is_file():
        dataset, _payload = _load_json(dataset_path, label="benchmark dataset")
        if not isinstance(dataset, dict) or not isinstance(dataset.get("cases"), list):
            raise SourceTriageAcceptanceError("benchmark dataset must contain a cases list")
        for summary in dataset["cases"]:
            if not isinstance(summary, dict):
                raise SourceTriageAcceptanceError("benchmark case summaries must be objects")
            task_id = _validate_task_id(summary.get("task_id", summary.get("id")))
            relative_manifest = summary.get("task_manifest", summary.get("task_path"))
            if relative_manifest is None:
                relative_manifest = f"cases/{task_id}/task.json"
            normalized_manifest = _normalize_relative_path(relative_manifest, label=f"task {task_id} manifest path")
            task_path = _path_within(root, normalized_manifest, label=f"task {task_id} manifest")
            descriptors.append((task_id, (task_path, summary)))
    else:
        single = root / "task.json"
        if single.is_file():
            task, _payload = _load_json(single, label="task manifest")
            if not isinstance(task, dict):
                raise SourceTriageAcceptanceError("task manifest must be an object")
            task_id = _validate_task_id(task.get("task_id", task.get("id")))
            descriptors.append((task_id, (single, {})))
        else:
            candidates = [path for path in root.glob("cases/*/task.json") if path.is_file()]
            if not candidates:
                candidates = [path for path in root.glob("*/task.json") if path.is_file()]
            candidates.sort(key=lambda path: path.as_posix().casefold())
            if not candidates:
                raise SourceTriageAcceptanceError("benchmark directory contains no dataset.json or task.json files")
            if len(candidates) > HARD_MAX_TASKS:
                raise SourceTriageAcceptanceError(
                    f"benchmark task discovery exceeds hard limit: {len(candidates)} > {HARD_MAX_TASKS}"
                )
            for task_path in candidates:
                task, _payload = _load_json(task_path, label="task manifest")
                if not isinstance(task, dict):
                    raise SourceTriageAcceptanceError(f"task manifest must be an object: {task_path}")
                task_id = _validate_task_id(task.get("task_id", task.get("id")))
                descriptors.append((task_id, (task_path, {})))

    chosen = _select_records(descriptors, selected, limits=limits)
    budget = InputBudget(limits)
    tasks: list[BenchmarkTask] = []
    for task_id, descriptor in chosen:
        task_path, summary = descriptor
        task, raw_task = _load_json(task_path, label=f"task {task_id} manifest")
        if not isinstance(task, dict):
            raise SourceTriageAcceptanceError(f"task manifest must be an object: {task_path}")
        declared_hash = summary.get("task_sha256") if isinstance(summary, dict) else None
        if declared_hash is not None and _valid_sha256(declared_hash) != hashlib.sha256(raw_task).hexdigest():
            raise SourceTriageAcceptanceError(f"task manifest hash mismatch: {task_id}")
        case_root = _ensure_regular_root(task_path.parent, label=f"task {task_id} directory")
        case_metadata = _optional_case_metadata(case_root)
        extra_metadata = tuple(item for item in (case_metadata, summary) if item is not None)
        tasks.append(
            _build_task(
                task,
                workspace=case_root,
                budget=budget,
                extra_metadata=extra_metadata,
                expected_task_id=task_id,
            )
        )
    return tasks, budget


def _manifest_records(document: Any) -> tuple[list[dict[str, Any]], object | None]:
    if isinstance(document, list):
        records = document
        default_root: object | None = None
    elif isinstance(document, dict) and isinstance(document.get("tasks"), list):
        records = document["tasks"]
        default_root = document.get("root", document.get("workspace"))
    elif isinstance(document, dict) and isinstance(document.get("cases"), list):
        records = document["cases"]
        default_root = document.get("root", document.get("workspace"))
    elif isinstance(document, dict) and ("task_id" in document or "id" in document):
        records = [document]
        default_root = None
    else:
        raise SourceTriageAcceptanceError("JSON task manifest must be a task, list, or object with tasks/cases")
    if not records or any(not isinstance(item, dict) for item in records):
        raise SourceTriageAcceptanceError("task manifest records must be non-empty objects")
    return records, default_root


def _explicit_workspace(record: dict[str, Any], *, default_root: object | None, manifest_dir: Path) -> Path:
    raw_root = record.get("root", record.get("workspace", record.get("case_root", default_root)))
    if raw_root is None:
        candidate = manifest_dir
    elif not isinstance(raw_root, str) or not raw_root.strip():
        raise SourceTriageAcceptanceError("task root/workspace must be a non-empty path")
    else:
        supplied = Path(raw_root)
        candidate = supplied if supplied.is_absolute() else manifest_dir / supplied
    return _ensure_regular_root(candidate, label="task workspace")


def load_explicit_manifest(
    manifest_path: Path,
    *,
    selected: tuple[str, ...] | None,
    limits: Limits,
) -> tuple[list[BenchmarkTask], InputBudget]:
    path = manifest_path.resolve()
    if path.suffix.casefold() == ".jsonl":
        records = _load_jsonl(path)
        default_root: object | None = None
    else:
        document, _payload = _load_json(path, label="task manifest")
        records, default_root = _manifest_records(document)
    descriptors = [(_validate_task_id(record.get("task_id", record.get("id"))), record) for record in records]
    chosen = _select_records(descriptors, selected, limits=limits)
    budget = InputBudget(limits)
    tasks = [
        _build_task(
            record,
            workspace=_explicit_workspace(record, default_root=default_root, manifest_dir=path.parent),
            budget=budget,
            expected_task_id=task_id,
        )
        for task_id, record in chosen
    ]
    return tasks, budget


def _rounded(value: Fraction) -> float:
    return round(float(value), 6)


def evaluate_tasks(
    tasks: list[BenchmarkTask],
    *,
    k: int,
    limits: Limits,
    budget: InputBudget,
    selected: tuple[str, ...] | None,
    diagnostic: bool,
) -> dict[str, Any]:
    if k < 1 or k > limits.max_files:
        raise SourceTriageAcceptanceError(f"k must be between 1 and max_files ({limits.max_files})")
    task_count = len(tasks)
    if task_count == 0:
        raise SourceTriageAcceptanceError("no tasks selected")
    provenance = _provenance(tasks)
    if not diagnostic:
        if k != RELEASE_K:
            raise SourceTriageAcceptanceError(f"release acceptance fixes k at {RELEASE_K}; use --diagnostic to explore")
        if selected is None or task_count < RELEASE_MIN_TASKS:
            raise SourceTriageAcceptanceError(
                f"release acceptance requires at least {RELEASE_MIN_TASKS} explicitly selected tasks"
            )
        if all(len(task.artifacts) <= k for task in tasks):
            raise SourceTriageAcceptanceError("release cohort does not exercise the top-k boundary")
        if provenance["source_identity_method"] != "git" or provenance["source_dirty"] != "false":
            raise SourceTriageAcceptanceError("release acceptance requires a clean Git-derived source identity")
    rows: list[dict[str, Any]] = []
    legacy_sum = Fraction(0)
    indexed_sum = Fraction(0)
    legacy_hit_count = 0
    indexed_hit_count = 0
    ground_truth_count = 0
    with tempfile.TemporaryDirectory(prefix="secmind-source-triage-") as temporary:
        store = ContentAddressedArtifactStore(Path(temporary) / "artifacts")
        indexer = RepositoryIndexer(store, max_files=limits.max_files)
        for task in tasks:
            run_digest = hashlib.sha256(task.task_id.encode("utf-8")).hexdigest()[:24]
            try:
                reference = indexer.build(
                    f"triage-{run_digest}",
                    task.workspace,
                    list(task.artifacts),
                )
                document = indexer.load(reference, run_id=f"triage-{run_digest}")
            except (OSError, ValueError, RepositoryIndexError) as exc:
                raise SourceTriageAcceptanceError(f"Repository Index failed for task {task.task_id}: {exc}") from exc
            if document.format_version != INDEX_FORMAT_VERSION:
                raise SourceTriageAcceptanceError(
                    f"task {task.task_id} did not produce Repository Index v2: {document.format_version}"
                )
            indexed_entries = {entry.path: entry for entry in document.files}
            legacy_paths = [
                item.relative_path
                for item in sorted(task.artifacts, key=lambda item: _path_priority(item, task.objective))[:k]
            ]
            indexed_paths = [
                item.relative_path
                for item in sorted(
                    task.artifacts,
                    key=lambda item: _indexed_path_priority(item, task.objective, indexed_entries),
                )[:k]
            ]
            truth = set(task.vulnerable_paths)
            legacy_hits = [path for path in legacy_paths if path in truth]
            indexed_hits = [path for path in indexed_paths if path in truth]
            legacy_recall = Fraction(len(legacy_hits), len(truth))
            indexed_recall = Fraction(len(indexed_hits), len(truth))
            legacy_sum += legacy_recall
            indexed_sum += indexed_recall
            legacy_hit_count += len(legacy_hits)
            indexed_hit_count += len(indexed_hits)
            ground_truth_count += len(truth)
            rows.append(
                {
                    "task_id": task.task_id,
                    "ground_truth_paths": list(task.vulnerable_paths),
                    "legacy_top_k_paths": legacy_paths,
                    "indexed_top_k_paths": indexed_paths,
                    "legacy_hits": legacy_hits,
                    "indexed_hits": indexed_hits,
                    "legacy_recall_at_k": _rounded(legacy_recall),
                    "indexed_recall_at_k": _rounded(indexed_recall),
                    "delta": _rounded(indexed_recall - legacy_recall),
                }
            )

    legacy_macro = legacy_sum / task_count
    indexed_macro = indexed_sum / task_count
    micro_legacy = Fraction(legacy_hit_count, ground_truth_count)
    micro_indexed = Fraction(indexed_hit_count, ground_truth_count)
    macro_passed = indexed_macro >= legacy_macro
    micro_passed = micro_indexed >= micro_legacy
    passed = macro_passed and micro_passed
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": "diagnostic_offline_no_model" if diagnostic else "release_offline_no_model",
        "provenance": provenance,
        "k": k,
        "selection": {
            "mode": "explicit_task_ids" if selected is not None else "all_tasks",
            "task_ids": [task.task_id for task in tasks],
        },
        "limits": {
            "max_tasks": limits.max_tasks,
            "max_files": limits.max_files,
            "max_bytes": limits.max_bytes,
        },
        "tasks": rows,
        "aggregate": {
            "aggregation": "macro_average_over_tasks",
            "task_count": task_count,
            "file_count": budget.files,
            "input_bytes": budget.bytes,
            "ground_truth_path_count": ground_truth_count,
            "legacy_hit_count": legacy_hit_count,
            "indexed_hit_count": indexed_hit_count,
            "legacy_recall_at_k": _rounded(legacy_macro),
            "indexed_recall_at_k": _rounded(indexed_macro),
            "delta": _rounded(indexed_macro - legacy_macro),
            "micro_legacy_recall_at_k": _rounded(micro_legacy),
            "micro_indexed_recall_at_k": _rounded(micro_indexed),
            "macro_passed": macro_passed,
            "micro_passed": micro_passed,
            "passed": passed,
        },
    }


def _write_json(path: Path | None, value: dict[str, Any]) -> None:
    rendered = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if path is None:
        sys.stdout.write(rendered)
        return
    destination = path.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.write_text(rendered, encoding="utf-8")
    temporary.replace(destination)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Offline Recall-at-K acceptance comparison for Canonical and Repository Index v2 source triage"
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--benchmark-dir",
        "--public-dir",
        dest="benchmark_dir",
        type=Path,
        help="SecMind public benchmark root or task directory",
    )
    source.add_argument("--manifest", type=Path, help="Explicit JSON or JSONL task manifest")
    parser.add_argument("--k", "--top-k", dest="k", type=int, default=10)
    parser.add_argument("--task-id", action="append", default=[], help="Fixed task id; repeat to select several")
    parser.add_argument("--task-ids", default="", help="Comma-separated fixed task-id list")
    parser.add_argument("--max-tasks", type=int, default=DEFAULT_MAX_TASKS)
    parser.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES)
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    parser.add_argument(
        "--diagnostic",
        action="store_true",
        help="Allow exploratory K/task counts and dirty source; never use this mode as release evidence.",
    )
    parser.add_argument("--output", type=Path, help="Write stable JSON here instead of stdout")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        limits = Limits(max_tasks=args.max_tasks, max_files=args.max_files, max_bytes=args.max_bytes)
        limits.validate()
        combined_ids = list(args.task_id)
        combined_ids.extend(item.strip() for item in args.task_ids.split(",") if item.strip())
        selected = _selected_task_ids(combined_ids)
        if args.benchmark_dir is not None:
            tasks, budget = load_benchmark_directory(args.benchmark_dir, selected=selected, limits=limits)
        else:
            tasks, budget = load_explicit_manifest(args.manifest, selected=selected, limits=limits)
        result = evaluate_tasks(
            tasks,
            k=args.k,
            limits=limits,
            budget=budget,
            selected=selected,
            diagnostic=args.diagnostic,
        )
        _write_json(args.output, result)
    except SourceTriageAcceptanceError as exc:
        print(f"source triage acceptance error: {exc}", file=sys.stderr)
        return 2
    return 0 if bool(result["aggregate"]["passed"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
