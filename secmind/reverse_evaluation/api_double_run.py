"""Crash-safe orchestration for the 48 independent DeepSeek case reports.

This module intentionally has no facility for local-answer substitution.  Its
only model operation is :func:`secmind.reverse_api_runner.run_api_slot`, once
per planned slot.  Gold is not accepted by preflight or run and is opened only
by the separately invoked post-seal scorer.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import errno
import hashlib
import json
import os
import stat
import sys
import tempfile
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Literal, cast
from urllib.parse import quote

import httpx

from secmind import reverse_api_runner as _slot_report
from secmind.config import Settings
from secmind.model_policy import ModelPolicy, ModelPolicyError
from secmind.reverse_api_business import TaskIdentity, build_unavailable_business_report
from secmind.reverse_api_overview import OverviewResult, render_api_overview
from secmind.reverse_api_runner import ApiSlotResult, run_api_slot
from secmind.reverse_api_score import _validate_slot_directory, score_api_runs
from secmind.reverse_api_slots import ApiRunSlot, EvidenceArmPaths, plan_api_run_slots
from secmind.reverse_live_evaluation import estimate_deepseek_v4_flash_cny, validate_deepseek_identity
from secmind.schemas import ModelUsage

_ARMS = ("current", "optimized")
_LEDGER_NAME = "run-ledger.json"
_METRICS_NAME = "post-seal-api-metrics.json"
_ROWS_NAME = "post-seal-api-case-results.json"
_SCORE_RECEIPT_NAME = "post-seal-api-scoring-receipt.json"
_LEDGER_VERSION = "1.0"
_SCORE_RECEIPT_VERSION = "1.0"
_LEDGER_STATUSES = frozenset({"planned", "completed"})
_WINDOWS_LEASE_OFFSET = 0x7FFF_FFFF

ProgressCallback = Callable[[str], None]


class RunLeaseHeldError(RuntimeError):
    """Another process owns the output-root run lease."""


class RunLeaseUnavailableError(RuntimeError):
    """This platform cannot provide the required crash-safe run lease."""


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _safe_component(value: object, *, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value in {".", ".."}
        or "/" in value
        or "\\" in value
        or "\x00" in value
    ):
        raise ValueError(f"{label} must be a safe path component")
    return value


def _safe_root(path: Path, *, label: str) -> Path:
    if not isinstance(path, Path):
        raise ValueError(f"{label} must be a Path")
    resolved = path.resolve(strict=False)
    if any(part.casefold() == "gold" for part in (*path.parts, *resolved.parts)):
        raise ValueError(f"{label} must not be a gold path")
    if path.exists() and path.is_symlink():
        raise ValueError(f"{label} must not be a symlink")
    return resolved


@contextmanager
def _output_root_lease(output_root: Path, *, exclusive: bool, create_root: bool) -> Iterator[None]:
    """Hold a nonblocking OS lease; process exit releases it automatically."""

    if os.name not in {"posix", "nt"}:
        raise RunLeaseUnavailableError("output-root lease is unavailable")

    root = _safe_root(output_root, label="output root")
    if create_root:
        root.mkdir(parents=True, exist_ok=True)
    elif not root.is_dir():
        raise ValueError("output root must be an existing directory")
    if root.is_symlink():
        raise ValueError("output root must not be a symlink")
    lock_path = root / ".run-lease.lock"
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except OSError as exc:
        raise RunLeaseUnavailableError("output-root lease cannot be opened") from exc
    try:
        if os.name == "posix":
            os.fchmod(descriptor, 0o600)
        lock_stat = os.fstat(descriptor)
        path_stat = lock_path.lstat()
        if (
            not stat.S_ISREG(path_stat.st_mode)
            or (lock_stat.st_dev, lock_stat.st_ino) != (path_stat.st_dev, path_stat.st_ino)
            or lock_stat.st_size != 0
        ):
            raise RunLeaseUnavailableError("output-root lease file is invalid")
        if os.name == "nt":
            import msvcrt

            # A byte beyond EOF keeps the file empty and its contents readable.
            os.lseek(descriptor, _WINDOWS_LEASE_OFFSET, os.SEEK_SET)
            operation = msvcrt.LK_NBLCK if exclusive else msvcrt.LK_NBRLCK
            try:
                msvcrt.locking(descriptor, operation, 1)
            except OSError as exc:
                if exc.errno in {errno.EACCES, errno.EDEADLK}:
                    raise RunLeaseHeldError("output-root run lease is held") from exc
                raise RunLeaseUnavailableError("output-root lease cannot be acquired") from exc
            try:
                yield
            finally:
                os.lseek(descriptor, _WINDOWS_LEASE_OFFSET, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            operation = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
            try:
                fcntl.flock(descriptor, operation | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise RunLeaseHeldError("output-root run lease is held") from exc
            try:
                yield
            finally:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def _exclusive_output_lease(output_root: Path) -> AbstractContextManager[None]:
    """Internal/test entry for the crash-released exclusive run lease."""

    return _output_root_lease(output_root, exclusive=True, create_root=True)


def _shared_output_lease(output_root: Path) -> AbstractContextManager[None]:
    return _output_root_lease(output_root, exclusive=False, create_root=False)


def _slot_directory(root: Path, slot: ApiRunSlot) -> Path:
    _safe_component(slot.case_id, label="case_id")
    directory = root / slot.arm / f"run-{slot.repeat_id}" / slot.case_id
    resolved = directory.resolve(strict=False)
    if not resolved.is_relative_to(root):
        raise ValueError("slot output path escapes the configured root")
    return resolved


def _validate_gateway_preflight(settings: Settings, client: httpx.AsyncClient | None) -> None:
    """Prove every no-network gateway prerequisite before artifact creation."""

    validate_deepseek_identity(settings)
    if settings.demo_mode or settings.model_mode not in {"mock", "live"}:
        raise ValueError("DeepSeek gateway policy is not ready")
    if not settings.model_api_key_value("deepseek"):
        raise ValueError("DeepSeek gateway policy is not ready")
    try:
        policy = ModelPolicy.from_settings(settings, injected_client=client is not None)
    except ModelPolicyError as exc:
        raise ValueError("DeepSeek gateway policy is not ready") from exc
    if policy.chat_provider != "deepseek" or policy.base_url != "https://api.deepseek.com":
        raise ValueError("DeepSeek gateway policy is not ready")
    if settings.model_mode == "mock":
        transport = None if client is None else client._transport  # noqa: SLF001 - same boundary as QwenGateway
        if not isinstance(transport, httpx.MockTransport):
            raise ValueError("DeepSeek gateway policy requires an explicit MockTransport")


def _validate_interrupted_recovery_policy(settings: Settings) -> None:
    """Validate identity for a no-network recovery without inventing a client."""

    validate_deepseek_identity(settings)
    if settings.demo_mode or settings.model_mode not in {"mock", "live"}:
        raise ValueError("DeepSeek gateway policy is not ready")
    if not settings.model_api_key_value("deepseek"):
        raise ValueError("DeepSeek gateway policy is not ready")


def _arms(paths: Mapping[str, tuple[Path, Path] | EvidenceArmPaths]) -> dict[str, EvidenceArmPaths]:
    if set(paths) != set(_ARMS):
        raise ValueError("evidence arms must be exactly current and optimized")
    result: dict[str, EvidenceArmPaths] = {}
    for arm in _ARMS:
        value = paths[arm]
        if isinstance(value, EvidenceArmPaths):
            converted = value
        elif isinstance(value, tuple) and len(value) == 2 and all(isinstance(item, Path) for item in value):
            converted = EvidenceArmPaths(value[0], value[1])
        else:
            raise ValueError("evidence arm paths must contain prediction and seal Paths")
        _safe_root(converted.prediction_path, label=f"{arm} evidence")
        _safe_root(converted.seal_path, label=f"{arm} evidence seal")
        result[arm] = converted
    return result


def _load_manifest_identity(path: Path) -> tuple[str, list[str]]:
    _safe_root(path, label="manifest")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("manifest must be a readable JSON object") from exc
    if not isinstance(payload, dict):
        raise ValueError("manifest must be a JSON object")
    suite_id = payload.get("suite_id")
    cases = payload.get("cases")
    if not isinstance(suite_id, str) or not suite_id or not isinstance(cases, list) or len(cases) != 12:
        raise ValueError("manifest must contain a suite and exactly 12 cases")
    case_ids = [case.get("id") for case in cases if isinstance(case, dict)]
    if len(case_ids) != 12 or not all(isinstance(case_id, str) and case_id for case_id in case_ids):
        raise ValueError("manifest case IDs are invalid")
    if len(set(cast(list[str], case_ids))) != 12:
        raise ValueError("manifest case IDs must be unique")
    return suite_id, cast(list[str], case_ids)


def _load_object(path: Path, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} must be a readable JSON object") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _expected_identities(
    suite_id: str,
    slots: Sequence[ApiRunSlot],
    arms: Mapping[str, EvidenceArmPaths],
) -> dict[tuple[str, str, int], TaskIdentity]:
    cases_by_arm: dict[str, dict[str, dict[str, Any]]] = {}
    for arm in _ARMS:
        payload = _load_object(arms[arm].prediction_path, label=f"{arm} evidence")
        cases = payload.get("cases")
        if payload.get("suite_id") != suite_id or payload.get("arm") != arm or not isinstance(cases, list):
            raise ValueError("sealed evidence identity does not match the current plan")
        indexed = {
            str(item["id"]): item
            for item in cases
            if isinstance(item, dict) and isinstance(item.get("id"), str) and item["id"]
        }
        if len(indexed) != len(cases):
            raise ValueError("sealed evidence cases are invalid")
        cases_by_arm[arm] = indexed
    result: dict[tuple[str, str, int], TaskIdentity] = {}
    for slot in slots:
        case = cases_by_arm[slot.arm].get(slot.case_id)
        if case is None:
            raise ValueError("sealed evidence case does not match the current plan")
        facts = case.get("facts")
        candidate = facts.get("sha256") if isinstance(facts, dict) else None
        sample_sha256 = (
            candidate
            if isinstance(candidate, str)
            and len(candidate) == 64
            and set(candidate.casefold()) <= frozenset("0123456789abcdef")
            else _canonical_sha256(case)
        )
        result[slot.identity] = TaskIdentity(
            suite_id=suite_id,
            arm=cast(Literal["current", "optimized"], slot.arm),
            case_id=slot.case_id,
            repeat_id=cast(Literal[1, 2], slot.repeat_id),
            sample_sha256=sample_sha256,
            provider="deepseek",
            model="deepseek-v4-flash",
        )
    return result


@dataclass(frozen=True, slots=True)
class _PreparedPlan:
    suite_id: str
    slots: tuple[ApiRunSlot, ...]
    arms: dict[str, EvidenceArmPaths]
    root: Path
    identities: dict[tuple[str, str, int], TaskIdentity]


@dataclass(frozen=True, slots=True)
class _LedgerState:
    statuses: dict[tuple[str, str, int], Literal["planned", "completed"]]
    attempted: dict[tuple[str, str, int], bool]

    @property
    def model_calls(self) -> int:
        return sum(self.attempted.values())


def _slot_record(
    slot: ApiRunSlot,
    identity: TaskIdentity,
    *,
    status: Literal["planned", "completed"],
    attempted: bool,
) -> dict[str, Any]:
    return {
        **slot.to_dict(),
        "task_identity": identity.model_dump(mode="json"),
        "status": status,
        "attempted": attempted,
    }


def _ledger_payload(
    plan: _PreparedPlan,
    state: _LedgerState,
) -> dict[str, Any]:
    return {
        "schema_version": _LEDGER_VERSION,
        "suite_id": plan.suite_id,
        "provider": "deepseek",
        "base_url": "https://api.deepseek.com",
        "model": "deepseek-v4-flash",
        "slot_count": len(plan.slots),
        "model_calls": state.model_calls,
        "gold_read": False,
        "slots": [
            _slot_record(
                slot,
                plan.identities[slot.identity],
                status=state.statuses[slot.identity],
                attempted=state.attempted[slot.identity],
            )
            for slot in plan.slots
        ],
    }


def _atomic_write_json(path: Path, payload: object) -> None:
    """Atomically replace a state file without placing credentials in it."""

    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)
    if parent.is_symlink():
        raise ValueError("state directory must not be a symlink")
    descriptor: int | None = None
    temporary_name: str | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=parent)
        if os.name == "posix":
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            handle.write(_json_bytes(payload))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
        if os.name == "posix":
            directory_fd = os.open(parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary_name is not None:
            try:
                Path(temporary_name).unlink(missing_ok=True)
            except OSError:
                pass


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _score_receipt(metrics: Mapping[str, Any], rows: Sequence[Mapping[str, Any]], gold_path: Path) -> dict[str, Any]:
    return {
        "schema_version": _SCORE_RECEIPT_VERSION,
        "publication": "deepseek_api_score",
        "suite_id": metrics["suite_id"],
        "slot_count": metrics["slot_count"],
        "gold_sha256": _sha256_bytes(gold_path.read_bytes()),
        "files": {
            "metrics": {
                "name": _METRICS_NAME,
                "sha256": _sha256_bytes(_json_bytes(metrics)),
            },
            "rows": {
                "name": _ROWS_NAME,
                "sha256": _sha256_bytes(_json_bytes(rows)),
            },
        },
    }


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _load_persisted_score_locked(root: Path) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    receipt = _load_object(root / _SCORE_RECEIPT_NAME, label="scoring publication receipt")
    if set(receipt) != {"schema_version", "publication", "suite_id", "slot_count", "gold_sha256", "files"}:
        raise ValueError("scoring publication receipt is invalid")
    if (
        receipt["schema_version"] != _SCORE_RECEIPT_VERSION
        or receipt["publication"] != "deepseek_api_score"
        or not isinstance(receipt["suite_id"], str)
        or not receipt["suite_id"]
        or receipt["slot_count"] != 48
        or not _is_sha256(receipt["gold_sha256"])
        or not isinstance(receipt["files"], dict)
        or set(receipt["files"]) != {"metrics", "rows"}
    ):
        raise ValueError("scoring publication receipt is invalid")

    payloads: dict[str, object] = {}
    expected_names = {"metrics": _METRICS_NAME, "rows": _ROWS_NAME}
    for key, expected_name in expected_names.items():
        record = receipt["files"].get(key)
        if (
            not isinstance(record, dict)
            or set(record) != {"name", "sha256"}
            or record["name"] != expected_name
            or not _is_sha256(record["sha256"])
        ):
            raise ValueError("scoring publication receipt is invalid")
        try:
            encoded = (root / expected_name).read_bytes()
            payload = json.loads(encoded)
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError("scoring publication file is invalid") from exc
        if _sha256_bytes(encoded) != record["sha256"]:
            raise ValueError("scoring publication digest mismatch")
        payloads[key] = payload

    metrics = payloads["metrics"]
    rows = payloads["rows"]
    if (
        not isinstance(metrics, dict)
        or not isinstance(rows, list)
        or metrics.get("suite_id") != receipt["suite_id"]
        or metrics.get("slot_count") != receipt["slot_count"]
        or len(rows) != receipt["slot_count"]
        or not all(isinstance(row, dict) for row in rows)
    ):
        raise ValueError("scoring publication payload is invalid")
    return metrics, cast(list[dict[str, Any]], rows), receipt


def load_persisted_score(output_root: Path) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    """Read one fully published score generation or reject the whole pair."""

    with _shared_output_lease(output_root):
        root = _safe_root(output_root, label="output root")
        return _load_persisted_score_locked(root)


def _initial_state(plan: _PreparedPlan) -> _LedgerState:
    return _LedgerState(
        statuses={slot.identity: "planned" for slot in plan.slots},
        attempted={slot.identity: False for slot in plan.slots},
    )


def _load_ledger(path: Path, plan: _PreparedPlan) -> _LedgerState:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("run ledger is not a valid JSON document") from exc
    if not isinstance(payload, dict):
        raise ValueError("run ledger must be an object")
    if (
        payload.get("schema_version") != _LEDGER_VERSION
        or payload.get("suite_id") != plan.suite_id
        or payload.get("provider") != "deepseek"
        or payload.get("base_url") != "https://api.deepseek.com"
        or payload.get("model") != "deepseek-v4-flash"
        or payload.get("slot_count") != 48
        or payload.get("gold_read") is not False
    ):
        raise ValueError("run ledger identity is invalid")
    records = payload.get("slots")
    if not isinstance(records, list) or len(records) != 48:
        raise ValueError("run ledger must contain exactly 48 slots")
    statuses: dict[tuple[str, str, int], Literal["planned", "completed"]] = {}
    attempted: dict[tuple[str, str, int], bool] = {}
    for slot, record in zip(plan.slots, records, strict=True):
        if not isinstance(record, dict) or set(record) != {
            "arm",
            "case_id",
            "repeat_id",
            "evidence_sha256",
            "prompt_sha256",
            "task_identity",
            "status",
            "attempted",
        }:
            raise ValueError("run ledger slot record is invalid")
        status = record.get("status")
        if status not in _LEDGER_STATUSES:
            raise ValueError("run ledger slot status is invalid")
        attempted_value = record.get("attempted")
        if not isinstance(attempted_value, bool) or (status == "completed" and not attempted_value):
            raise ValueError("run ledger attempt state is invalid")
        expected = _slot_record(
            slot,
            plan.identities[slot.identity],
            status=cast(Literal["planned", "completed"], status),
            attempted=attempted_value,
        )
        if record != expected:
            raise ValueError("run ledger slots do not match the sealed input plan")
        statuses[slot.identity] = cast(Literal["planned", "completed"], status)
        attempted[slot.identity] = attempted_value
    state = _LedgerState(statuses, attempted)
    model_calls = payload.get("model_calls")
    if not isinstance(model_calls, int) or isinstance(model_calls, bool) or model_calls != state.model_calls:
        raise ValueError("run ledger logical attempt count is invalid")
    return state


def _verify_existing_slot(
    root: Path,
    slot: ApiRunSlot,
    expected_identity: TaskIdentity,
) -> bool:
    directory = _slot_directory(root, slot)
    if not directory.exists():
        return False
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("slot output directory is invalid")
    try:
        validated = _validate_slot_directory(root, directory / "seal.json")
    except ValueError as exc:
        raise ValueError("non-empty slot output is not a verified sealed report") from exc
    if validated.task_identity != expected_identity:
        raise ValueError("sealed slot task identity does not match the current plan")
    request = _load_object(directory / "request.json", label="sealed request")
    request_slot = request.get("slot")
    if not isinstance(request_slot, dict) or request_slot != slot.to_dict():
        raise ValueError("sealed request identity does not match the full current plan")
    return True


def _prepare(
    manifest_path: Path,
    evidence_arms: Mapping[str, tuple[Path, Path] | EvidenceArmPaths],
    output_root: Path,
    *,
    settings: Settings,
    client: httpx.AsyncClient | None,
    validate_gateway: bool = True,
) -> _PreparedPlan:
    if validate_gateway:
        _validate_gateway_preflight(settings, client)
    suite_id, _case_ids = _load_manifest_identity(manifest_path)
    arms = _arms(evidence_arms)
    slots = plan_api_run_slots(manifest_path, arms)
    if len(slots) != 48 or len({slot.identity for slot in slots}) != 48:
        raise ValueError("planned API run matrix must contain exactly 48 unique slots")
    root = _safe_root(output_root, label="output root")
    identities = _expected_identities(suite_id, slots, arms)
    return _PreparedPlan(suite_id, slots, arms, root, identities)


def _preflight_double_run_locked(
    manifest_path: Path,
    evidence_arms: Mapping[str, tuple[Path, Path] | EvidenceArmPaths],
    output_root: Path,
    *,
    settings: Settings,
    client: httpx.AsyncClient | None = None,
) -> dict[str, Any]:
    """Seal the public 48-slot plan without sending a model request or reading gold."""

    plan = _prepare(manifest_path, evidence_arms, output_root, settings=settings, client=client)
    ledger_path = plan.root / _LEDGER_NAME
    if ledger_path.exists():
        state = _load_ledger(ledger_path, plan)
    else:
        state = _initial_state(plan)
    statuses = dict(state.statuses)
    attempted = dict(state.attempted)
    # Validate the entire output tree before creating or replacing the ledger.
    # A stale suite/evidence/prompt bundle therefore leaves no new artifact.
    existing = {
        slot.identity: _verify_existing_slot(plan.root, slot, plan.identities[slot.identity])
        for slot in plan.slots
    }
    for slot in plan.slots:
        present = existing[slot.identity]
        if not present and (statuses[slot.identity] == "completed" or attempted[slot.identity]):
            raise ValueError("attempted ledger slot is missing its verified sealed report")
        if present:
            statuses[slot.identity] = "completed"
            attempted[slot.identity] = True
    reconciled = _LedgerState(statuses, attempted)
    if not ledger_path.exists() or reconciled != state:
        _atomic_write_json(ledger_path, _ledger_payload(plan, reconciled))
    return {
        "ready": True,
        "suite_id": plan.suite_id,
        "slot_count": len(plan.slots),
        "planned_slots": sum(value == "planned" for value in reconciled.statuses.values()),
        "completed_slots": sum(value == "completed" for value in reconciled.statuses.values()),
        "model_calls": reconciled.model_calls,
        "gold_read": False,
        "provider": "deepseek",
        "base_url": "https://api.deepseek.com",
        "model": "deepseek-v4-flash",
        "credential_present": True,
        "ledger": str(ledger_path),
    }


def preflight_double_run(
    manifest_path: Path,
    evidence_arms: Mapping[str, tuple[Path, Path] | EvidenceArmPaths],
    output_root: Path,
    *,
    settings: Settings,
    client: httpx.AsyncClient | None = None,
) -> dict[str, Any]:
    """Preflight under the same single-writer lease used by execution."""

    _validate_gateway_preflight(settings, client)
    with _exclusive_output_lease(output_root):
        return _preflight_double_run_locked(
            manifest_path,
            evidence_arms,
            output_root,
            settings=settings,
            client=client,
        )


async def _run_double_run_locked(
    manifest_path: Path,
    evidence_arms: Mapping[str, tuple[Path, Path] | EvidenceArmPaths],
    output_root: Path,
    *,
    settings: Settings,
    client: httpx.AsyncClient | None = None,
    progress: ProgressCallback | None = None,
) -> dict[str, Any]:
    """Sequentially run missing slots; a verified unavailable report is complete."""

    preflight = _preflight_double_run_locked(
        manifest_path,
        evidence_arms,
        output_root,
        settings=settings,
        client=client,
    )
    plan = _prepare(manifest_path, evidence_arms, output_root, settings=settings, client=client)
    ledger_path = plan.root / _LEDGER_NAME
    state = _load_ledger(ledger_path, plan)
    # Scan the entire matrix before any call.  A crash residue is never
    # overwritten and therefore cannot quietly launder an audit artifact.
    existing: dict[tuple[str, str, int], bool] = {
        slot.identity: _verify_existing_slot(plan.root, slot, plan.identities[slot.identity])
        for slot in plan.slots
    }

    def write_slot_failure_bundle_after_attempt(slot: ApiRunSlot) -> ApiSlotResult:
        """Private closure for a post-attempt exception with no slot directory.

        This closure is deliberately scoped to the exclusive run lease and the
        already-persisted logical attempt.  It never receives an exception:
        public artifacts carry only the fixed closed diagnostic below.
        """

        if not state.attempted[slot.identity]:
            raise ValueError("slot failure bundle requires a persisted logical attempt")
        if state.statuses[slot.identity] != "planned":
            raise ValueError("slot failure bundle requires a planned ledger status")
        evidence_path = plan.arms[slot.arm].prediction_path
        evidence_seal_path = plan.arms[slot.arm].seal_path
        approved_root = _slot_report._validate_input_boundary(  # noqa: SLF001 - sealed orchestration boundary
            slot,
            manifest_path=manifest_path,
            evidence_path=evidence_path,
            evidence_seal_path=evidence_seal_path,
            output_root=plan.root,
        )
        output_dir = _slot_report._confined_output_dir(approved_root, slot)  # noqa: SLF001
        if output_dir.exists():
            raise ValueError("slot failure refuses a partial slot artifact directory")
        prompt, _case, evidence, evidence_case, identity = _slot_report._require_slot_case(  # noqa: SLF001
            slot,
            manifest_path,
            evidence_path,
            evidence_seal_path,
        )
        evidence_dto = _slot_report._public_evidence_projection(evidence_case, evidence, identity)  # noqa: SLF001
        _slot_report.assert_safe_deliverable_payload(  # noqa: SLF001 - same public boundary as normal execution
            evidence_dto.case,
            active_secret=settings.model_api_key_value("deepseek"),
        )
        request, public_request_sha256 = _slot_report._request_record(  # noqa: SLF001
            slot,
            identity,
            prompt,
            evidence_case,
            _slot_report._safety_observation(  # noqa: SLF001
                evidence, identity, aliases=evidence_dto.aliases, reverse=evidence_dto.reverse
            ),
            evidence_dto.allowed_refs,
        )
        report = build_unavailable_business_report(
            task_identity=identity,
            model_receipt_ref="receipt.json",
            api_failure_type="ORCHESTRATION_SLOT_FAILURE",
            human_impact=(
                "已记录逻辑尝试后的本地编排步骤未完成，且没有可验证的模型回执；在独立人工验证前，不应依据本报告执行处置。"
            ),
            evidence_refs=[],
        )
        usage = ModelUsage()
        receipt: dict[str, Any] = {
            "schema_version": "1.0",
            "task_identity": identity.model_dump(mode="json"),
            "execution_status": "unavailable",
            "provider": "deepseek",
            "base_url": "https://api.deepseek.com",
            "model": "deepseek-v4-flash",
            "model_receipt_id": None,
            "model_request_sha256": None,
            "model_response_sha256": None,
            "public_request_sha256": public_request_sha256,
            "latency_ms": 0,
            "retry_count": 0,
            "attempts": [],
            "error_type": "ORCHESTRATION_SLOT_FAILURE",
            "orchestration_diagnostic": {"code": "POST_ATTEMPT_LOCAL_EXCEPTION"},
            "usage": _slot_report._receipt_usage(usage, []),  # noqa: SLF001
            "pricing": estimate_deepseek_v4_flash_cny(usage, priced_at=datetime.now(UTC)),
            "usage_provenance": {
                "provider_reported_usage": usage.model_dump(mode="json"),
                "conservative_reserved_usage": usage.model_dump(mode="json"),
                "unknown_usage_attempts": 1,
            },
            "accounting_status": "provider_outcome_unknown_no_receipt",
        }
        response = {
            "schema_version": "1.0",
            "task_identity": identity.model_dump(mode="json"),
            "execution_status": "unavailable",
            "model_response_sha256": None,
            "error_type": "ORCHESTRATION_SLOT_FAILURE",
            "report": report.model_dump(mode="json"),
        }
        artifacts = _slot_report._write_artifacts(  # noqa: SLF001 - private leased bundle writer
            output_dir,
            slot=slot,
            identity=identity,
            request=request,
            response=response,
            receipt=receipt,
            report=report,
            source_semantics=evidence_dto.source_semantics,
            active_secret=settings.model_api_key_value("deepseek"),
        )
        return ApiSlotResult(slot=slot, report=report, output_dir=output_dir, artifacts=artifacts)

    executed = 0
    resumed = 0
    for ordinal, slot in enumerate(plan.slots, start=1):
        if existing[slot.identity]:
            resumed += 1
            continue
        if state.attempted[slot.identity]:
            raise ValueError("attempted logical slot has no verified seal; refusing a duplicate request")
        # Persist the logical attempt before entering the gateway.  A crash can
        # never turn an uncertain paid request back into an unattempted slot.
        attempted = dict(state.attempted)
        attempted[slot.identity] = True
        state = _LedgerState(dict(state.statuses), attempted)
        _atomic_write_json(ledger_path, _ledger_payload(plan, state))
        arm_paths = plan.arms[slot.arm]
        try:
            result: ApiSlotResult = await run_api_slot(
                slot,
                manifest_path=manifest_path,
                evidence_path=arm_paths.prediction_path,
                evidence_seal_path=arm_paths.seal_path,
                output_root=plan.root,
                settings=settings,
                client=client,
                max_output_attempts=4,
            )
        except Exception:  # noqa: BLE001 - never serialize an untrusted exception into a public artifact
            if _verify_existing_slot(plan.root, slot, plan.identities[slot.identity]):
                raise ValueError("slot raised after producing a verified sealed report") from None
            result = write_slot_failure_bundle_after_attempt(slot)
        if not _verify_existing_slot(plan.root, slot, plan.identities[slot.identity]):
            raise ValueError("new slot did not produce a verified sealed report")
        statuses = dict(state.statuses)
        statuses[slot.identity] = "completed"
        state = _LedgerState(statuses, dict(state.attempted))
        _atomic_write_json(ledger_path, _ledger_payload(plan, state))
        executed += 1
        if progress is not None:
            progress(f"{ordinal}/48 {slot.arm}/run-{slot.repeat_id}/{slot.case_id} {result.report.execution_status}")
    return {
        "suite_id": plan.suite_id,
        "slot_count": 48,
        "completed_slots": sum(value == "completed" for value in state.statuses.values()),
        "executed_slots": executed,
        "resumed_slots": resumed,
        "sequential": True,
        "gold_read": False,
        "ledger": str(ledger_path),
        "preflight_model_calls": preflight["model_calls"],
        "model_calls": state.model_calls,
    }


async def run_double_run(
    manifest_path: Path,
    evidence_arms: Mapping[str, tuple[Path, Path] | EvidenceArmPaths],
    output_root: Path,
    *,
    settings: Settings,
    client: httpx.AsyncClient | None = None,
    progress: ProgressCallback | None = None,
) -> dict[str, Any]:
    """Own one output root from validation through the final ledger update."""

    _validate_gateway_preflight(settings, client)
    with _exclusive_output_lease(output_root):
        return await _run_double_run_locked(
            manifest_path,
            evidence_arms,
            output_root,
            settings=settings,
            client=client,
            progress=progress,
        )


def recover_interrupted_double_run(
    manifest_path: Path,
    evidence_arms: Mapping[str, tuple[Path, Path] | EvidenceArmPaths],
    output_root: Path,
    *,
    settings: Settings,
) -> dict[str, int]:
    """Seal only an exact no-artifact crash window without issuing a retry."""

    _validate_interrupted_recovery_policy(settings)
    with _exclusive_output_lease(output_root):
        plan = _prepare(
            manifest_path,
            evidence_arms,
            output_root,
            settings=settings,
            client=None,
            validate_gateway=False,
        )
        ledger_path = plan.root / _LEDGER_NAME
        if not ledger_path.exists():
            raise ValueError("interrupted recovery requires an existing run ledger")
        state = _load_ledger(ledger_path, plan)
        stranded: list[ApiRunSlot] = []
        for slot in plan.slots:
            present = _verify_existing_slot(plan.root, slot, plan.identities[slot.identity])
            if present:
                continue
            if state.statuses[slot.identity] == "completed" or not state.attempted[slot.identity]:
                continue
            directory = _slot_directory(plan.root, slot)
            if directory.exists():
                raise ValueError("interrupted recovery refuses a partial slot artifact directory")
            stranded.append(slot)
        if len(stranded) > 1:
            raise ValueError("interrupted recovery accepts exactly one stranded slot")
        if not stranded:
            return {
                "recovered_slots": 0,
                "model_calls": state.model_calls,
                "completed_slots": sum(value == "completed" for value in state.statuses.values()),
            }
        slot = stranded[0]

        def write_bundle_after_ledger_validation() -> None:
            """Private closure: only this leased, validated branch can mint it."""

            evidence_path = plan.arms[slot.arm].prediction_path
            evidence_seal_path = plan.arms[slot.arm].seal_path
            approved_root = _slot_report._validate_input_boundary(  # noqa: SLF001 - sealed recovery boundary
                slot,
                manifest_path=manifest_path,
                evidence_path=evidence_path,
                evidence_seal_path=evidence_seal_path,
                output_root=plan.root,
            )
            output_dir = _slot_report._confined_output_dir(approved_root, slot)  # noqa: SLF001
            if output_dir.exists():
                raise ValueError("interrupted recovery refuses a partial slot artifact directory")
            prompt, _case, evidence, evidence_case, identity = _slot_report._require_slot_case(  # noqa: SLF001
                slot,
                manifest_path,
                evidence_path,
                evidence_seal_path,
            )
            evidence_dto = _slot_report._public_evidence_projection(  # noqa: SLF001
                evidence_case, evidence, identity
            )
            _slot_report.assert_safe_deliverable_payload(  # noqa: SLF001 - same model/public boundary as normal slots
                evidence_dto.case,
                active_secret=settings.model_api_key_value("deepseek"),
            )
            request, public_request_sha256 = _slot_report._request_record(  # noqa: SLF001
                slot,
                identity,
                prompt,
                evidence_case,
                _slot_report._safety_observation(  # noqa: SLF001
                    evidence, identity, aliases=evidence_dto.aliases, reverse=evidence_dto.reverse
                ),
                evidence_dto.allowed_refs,
            )
            report = build_unavailable_business_report(
                task_identity=identity,
                model_receipt_ref="receipt.json",
                api_failure_type="ORCHESTRATION_INTERRUPTED",
                human_impact=(
                    "执行进程在已记录逻辑尝试后中断，且没有可验证的模型回执；在独立人工验证前，不应依据本报告执行处置。"
                ),
                evidence_refs=[],
            )
            usage = ModelUsage()
            receipt: dict[str, Any] = {
                "schema_version": "1.0",
                "task_identity": identity.model_dump(mode="json"),
                "execution_status": "unavailable",
                "provider": "deepseek",
                "base_url": "https://api.deepseek.com",
                "model": "deepseek-v4-flash",
                "model_receipt_id": None,
                "model_request_sha256": None,
                "model_response_sha256": None,
                "public_request_sha256": public_request_sha256,
                "latency_ms": 0,
                "retry_count": 0,
                "attempts": [],
                "error_type": "ORCHESTRATION_INTERRUPTED",
                "usage": _slot_report._receipt_usage(usage, []),  # noqa: SLF001
                "pricing": estimate_deepseek_v4_flash_cny(usage, priced_at=datetime.now(UTC)),
                "usage_provenance": {
                    "provider_reported_usage": usage.model_dump(mode="json"),
                    "conservative_reserved_usage": usage.model_dump(mode="json"),
                    "unknown_usage_attempts": 1,
                },
                "accounting_status": "provider_outcome_unknown_no_receipt",
            }
            response = {
                "schema_version": "1.0",
                "task_identity": identity.model_dump(mode="json"),
                "execution_status": "unavailable",
                "model_response_sha256": None,
                "error_type": "ORCHESTRATION_INTERRUPTED",
                "report": report.model_dump(mode="json"),
            }
            _slot_report._write_artifacts(  # noqa: SLF001
                output_dir,
                slot=slot,
                identity=identity,
                request=request,
                response=response,
                receipt=receipt,
                report=report,
                source_semantics=evidence_dto.source_semantics,
                active_secret=settings.model_api_key_value("deepseek"),
            )

        write_bundle_after_ledger_validation()
        if not _verify_existing_slot(plan.root, slot, plan.identities[slot.identity]):
            raise ValueError("interrupted recovery did not produce a verified sealed report")
        statuses = dict(state.statuses)
        statuses[slot.identity] = "completed"
        state = _LedgerState(statuses, dict(state.attempted))
        _atomic_write_json(ledger_path, _ledger_payload(plan, state))
        return {
            "recovered_slots": 1,
            "model_calls": state.model_calls,
            "completed_slots": sum(value == "completed" for value in state.statuses.values()),
        }


class _DeliveryHtmlParser(HTMLParser):
    """Small closed parser for self-contained per-slot HTML dossiers."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: list[tuple[str, dict[str, str]]] = []
        self._style_depth = 0
        self.styles: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        normalized = tag.casefold()
        self.tags.append((normalized, {key.casefold(): value or "" for key, value in attrs}))
        if normalized == "style":
            self._style_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag.casefold() == "style" and self._style_depth:
            self._style_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._style_depth:
            self.styles.append(data)

    def handle_comment(self, _data: str) -> None:
        if self._style_depth:
            self.styles.append("")


def _css_is_closed_safe(value: str) -> bool:
    """Per-case dossiers allow no CSS resource or escape mechanism."""

    compact = "".join(value.split()).casefold()
    if "\\" in value:
        return False
    return not any(marker in compact for marker in ("@import", "url(", "expression(", "javascript:", "data:"))


def _html_is_self_contained(value: str) -> bool:
    parser = _DeliveryHtmlParser()
    parser.feed(value)
    parser.close()
    if not value.lstrip().casefold().startswith("<!doctype html>"):
        return False
    if any(tag in {"script", "link", "base", "iframe", "object", "embed", "form"} for tag, _attrs in parser.tags):
        return False
    csp = next(
        (
            attrs.get("content", "")
            for tag, attrs in parser.tags
            if tag == "meta" and attrs.get("http-equiv", "").casefold() == "content-security-policy"
        ),
        "",
    )
    required_csp = ("default-src 'none'", "connect-src 'none'", "base-uri 'none'", "form-action 'none'")
    if not all(directive in csp for directive in required_csp):
        return False
    if not _css_is_closed_safe("".join(parser.styles)):
        return False
    for tag, attrs in parser.tags:
        if any(name.startswith("on") or name.startswith("xlink:") for name in attrs):
            return False
        if (
            tag == "meta"
            and attrs.get("http-equiv", "")
            and attrs.get("http-equiv", "").casefold() != "content-security-policy"
        ):
            return False
        if "srcset" in attrs:
            return False
        for name in ("src", "href", "action", "formaction", "poster", "data", "background", "ping", "cite", "longdesc"):
            if attrs.get(name, "").strip():
                return False
        if "style" in attrs and not _css_is_closed_safe(attrs["style"]):
            return False
    return True


def _secret_variants(secret: str) -> set[bytes]:
    """Generate exact raw/serialized forms without ever returning them to callers."""

    if not secret:
        return set()
    encoded = secret.encode("utf-8")
    return {
        encoded,
        json.dumps(secret, ensure_ascii=False).encode("utf-8"),
        quote(secret, safe="").encode("utf-8"),
        base64.b64encode(encoded),
    }


def verify_double_run(
    manifest_path: Path,
    evidence_arms: Mapping[str, tuple[Path, Path] | EvidenceArmPaths],
    output_root: Path,
    *,
    settings: Settings,
) -> dict[str, int | bool]:
    """Verify the complete delivery without network access or gold access."""

    _validate_interrupted_recovery_policy(settings)
    with _shared_output_lease(output_root):
        plan = _prepare(
            manifest_path,
            evidence_arms,
            output_root,
            settings=settings,
            client=None,
            validate_gateway=False,
        )
        state = _load_ledger(plan.root / _LEDGER_NAME, plan)
        if state.model_calls != 48 or any(status != "completed" for status in state.statuses.values()) or not all(
            state.attempted.values()
        ):
            raise ValueError("verification requires a completed 48-slot ledger")
        expected_dirs = {_slot_directory(plan.root, slot) for slot in plan.slots}
        expected_names = {
            "request.json", "response.json", "receipt.json", "report.json", "report.md", "report.html", "seal.json"
        }
        expected_files = {directory / name for directory in expected_dirs for name in expected_names}
        allowed_root_files = {
            plan.root / ".run-lease.lock",
            plan.root / _LEDGER_NAME,
            plan.root / _METRICS_NAME,
            plan.root / _ROWS_NAME,
            plan.root / _SCORE_RECEIPT_NAME,
        }
        all_paths = list(plan.root.rglob("*"))
        active_secret = settings.model_api_key_value("deepseek")
        secret_variants = _secret_variants(active_secret)
        for path in all_paths:
            if path.is_symlink() or (path.exists() and not path.is_dir() and not path.is_file()):
                raise ValueError("verification found an unsafe output-tree entry")
            if path != plan.root / ".run-lease.lock" and path.is_file() and any(
                variant in path.read_bytes() for variant in secret_variants
            ):
                raise ValueError("verification found a secret variant in an artifact")
        actual_files = {path for path in all_paths if path.is_file()}
        expected_tree_dirs = {plan.root, *expected_dirs}
        for arm in _ARMS:
            expected_tree_dirs.add(plan.root / arm)
            expected_tree_dirs.update({plan.root / arm / "run-1", plan.root / arm / "run-2"})
        actual_tree_dirs = {path.resolve() for path in all_paths if path.is_dir()} | {plan.root}
        if actual_tree_dirs != expected_tree_dirs:
            raise ValueError("verification found an extra or partial output directory")
        if not expected_files <= actual_files or actual_files - expected_files - allowed_root_files:
            raise ValueError("verification found an extra or partial output artifact")
        publications = {plan.root / _METRICS_NAME, plan.root / _ROWS_NAME, plan.root / _SCORE_RECEIPT_NAME}
        if actual_files & publications and not publications <= actual_files:
            raise ValueError("verification found incomplete score publications")
        if publications <= actual_files:
            _load_persisted_score_locked(plan.root)
        actual_dirs: set[Path] = set()
        for arm in _ARMS:
            arm_dir = plan.root / arm
            if not arm_dir.is_dir():
                raise ValueError("verification slot directories do not match the current full plan")
            for repeat_dir in arm_dir.iterdir():
                if not repeat_dir.is_dir() or repeat_dir.name not in {"run-1", "run-2"}:
                    raise ValueError("verification found an extra or partial slot directory")
                for case_dir in repeat_dir.iterdir():
                    if not case_dir.is_dir():
                        raise ValueError("verification found an extra or partial slot artifact")
                    actual_dirs.add(case_dir.resolve())
        if actual_dirs != expected_dirs:
            raise ValueError("verification slot directories do not match the current full plan")
        validated: dict[tuple[str, str, int], tuple[Path, dict[str, Any], dict[str, Any]]] = {}
        for slot in plan.slots:
            directory = _slot_directory(plan.root, slot)
            if {path.name for path in directory.iterdir()} != expected_names:
                raise ValueError("verification found an extra or partial slot artifact")
            if not _verify_existing_slot(plan.root, slot, plan.identities[slot.identity]):
                raise ValueError("verification found an invalid sealed slot")
            request = _load_object(directory / "request.json", label="verification request")
            response = _load_object(directory / "response.json", label="verification response")
            report_envelope = _load_object(directory / "report.json", label="verification report")
            receipt = _load_object(directory / "receipt.json", label="verification receipt")
            for payload in (request, response, receipt, report_envelope):
                _slot_report.assert_safe_deliverable_payload(payload, active_secret=active_secret)
            _slot_report.assert_safe_deliverable_payload(
                (directory / "report.md").read_text(encoding="utf-8"), active_secret=active_secret
            )
            html = (directory / "report.html").read_text(encoding="utf-8")
            if not _html_is_self_contained(html):
                raise ValueError("verification found a non-self-contained HTML report")
            validated[slot.identity] = (directory, response, report_envelope)
        if len(validated) != 48:
            raise ValueError("verification requires 48 unique slot identities")
        for arm in _ARMS:
            for case_id in {slot.case_id for slot in plan.slots}:
                first = validated[(arm, case_id, 1)]
                second = validated[(arm, case_id, 2)]
                for directory, _response, _report in (first, second):
                    sibling = second if directory == first[0] else first
                    sibling_digests = {
                        hashlib.sha256((sibling[0] / "response.json").read_bytes()).hexdigest(),
                        hashlib.sha256((sibling[0] / "report.json").read_bytes()).hexdigest(),
                    }
                    for artifact in directory.iterdir():
                        try:
                            own = artifact.read_text(encoding="utf-8")
                        except UnicodeDecodeError:
                            continue
                        other_marker = f"{arm}/run-{3 - _response['task_identity']['repeat_id']}/{case_id}"
                        if other_marker in own or any(digest in own for digest in sibling_digests):
                            raise ValueError("verification found a sibling-repeat reference")
        return {
            "slot_count": 48,
            "artifact_count": 336,
            "seal_count": 48,
            "cross_repeat_failures": 0,
            "secret_matches": 0,
            "gold_read": False,
            "model_calls": state.model_calls,
        }


def score_double_run(output_root: Path, gold_path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Score only after the scorer has verified the exact sealed 48-slot tree."""

    with _exclusive_output_lease(output_root):
        root = _safe_root(output_root, label="output root")
        metrics, rows = score_api_runs(root, gold_path)
        receipt = _score_receipt(metrics, rows, gold_path)
        _atomic_write_json(root / _METRICS_NAME, metrics)
        _atomic_write_json(root / _ROWS_NAME, rows)
        _atomic_write_json(root / _SCORE_RECEIPT_NAME, receipt)
        return metrics, rows


def render_double_run(manifest_path: Path, output_root: Path, gold_path: Path, delivery_root: Path) -> OverviewResult:
    """Verify the published score and render the API-only overview."""

    with _shared_output_lease(output_root):
        root = _safe_root(output_root, label="output root")
        _published_metrics, _published_rows, receipt = _load_persisted_score_locked(root)
        try:
            current_gold_sha256 = _sha256_bytes(gold_path.read_bytes())
        except OSError as exc:
            raise ValueError("scoring publication gold is unreadable") from exc
        if current_gold_sha256 != receipt["gold_sha256"]:
            raise ValueError("scoring publication gold digest mismatch")
        metrics, rows = score_api_runs(root, gold_path)
        if (
            _sha256_bytes(_json_bytes(metrics)) != receipt["files"]["metrics"]["sha256"]
            or _sha256_bytes(_json_bytes(rows)) != receipt["files"]["rows"]["sha256"]
        ):
            raise ValueError("scoring publication no longer binds the sealed run")
        return render_api_overview(
            metrics=metrics,
            case_rows=rows,
            run_root=root,
            output_dir=delivery_root,
            manifest=manifest_path,
            gold_path=gold_path,
        )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SecMind 48-slot independent DeepSeek reverse-report runner")
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("preflight", "run", "recover", "verify"):
        item = commands.add_parser(command)
        item.add_argument("--manifest", type=Path, required=True)
        item.add_argument("--current-evidence", type=Path, required=True)
        item.add_argument("--current-seal", type=Path, required=True)
        item.add_argument("--optimized-evidence", type=Path, required=True)
        item.add_argument("--optimized-seal", type=Path, required=True)
        item.add_argument("--output-root", type=Path, required=True)
    score = commands.add_parser("score")
    score.add_argument("--output-root", type=Path, required=True)
    score.add_argument("--gold", type=Path, required=True)
    render = commands.add_parser("render")
    render.add_argument("--manifest", type=Path, required=True)
    render.add_argument("--output-root", type=Path, required=True)
    render.add_argument("--gold", type=Path, required=True)
    render.add_argument("--delivery-root", type=Path, required=True)
    return parser


def _cli_arms(args: argparse.Namespace) -> dict[str, tuple[Path, Path]]:
    return {
        "current": (args.current_evidence, args.current_seal),
        "optimized": (args.optimized_evidence, args.optimized_seal),
    }


async def _cli_run(args: argparse.Namespace, settings: Settings) -> dict[str, Any]:
    return await run_double_run(
        args.manifest,
        _cli_arms(args),
        args.output_root,
        settings=settings,
        progress=lambda line: print(line, flush=True),
    )


def _execute_command(args: argparse.Namespace) -> object:
    settings = Settings()
    if args.command in {"preflight", "run", "recover"}:
        # Command-line execution is intentionally live-only.  Tests use the
        # library with MockTransport; there is no CLI switch to inject a URL,
        # command, credential, or alternative provider.
        if settings.model_mode != "live" or not settings.allow_live_models:
            raise RuntimeError("DeepSeek API execution requires live model mode and explicit live authorization")
        if args.command == "preflight":
            result: object = preflight_double_run(
                args.manifest,
                _cli_arms(args),
                args.output_root,
                settings=settings,
            )
        elif args.command == "run":
            result = asyncio.run(_cli_run(args, settings))
        else:
            result = recover_interrupted_double_run(
                args.manifest,
                _cli_arms(args),
                args.output_root,
                settings=settings,
            )
    elif args.command == "verify":
        result = verify_double_run(args.manifest, _cli_arms(args), args.output_root, settings=settings)
    elif args.command == "score":
        metrics, rows = score_double_run(args.output_root, args.gold)
        result = {
            "slot_count": metrics["slot_count"],
            "rows": len(rows),
            "metrics": str(args.output_root / _METRICS_NAME),
            "scoring_receipt": str(args.output_root / _SCORE_RECEIPT_NAME),
        }
    else:
        overview = render_double_run(args.manifest, args.output_root, args.gold, args.delivery_root)
        result = {
            "delivery_root": str(overview.output_dir),
            "index_html": str(overview.index_html),
            "metrics": str(overview.metrics_json),
        }
    return result


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = _execute_command(args)
    except Exception:  # noqa: BLE001 - production CLI emits a closed, credential-safe error
        error = {"ok": False, "error": "operation_failed", "command": str(args.command)}
        print(json.dumps(error, ensure_ascii=False, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
