"""Post-seal scoring for the 48 independent DeepSeek reverse-analysis runs.

This module deliberately has a narrow trust boundary: it validates every
per-run artifact and its seal before opening the private gold file.  It scores
only the structured DeepSeek business reports; pre-existing local/offline
aggregate metrics are neither read nor accepted as inputs.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import stat
from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Literal, cast

from pydantic import ValidationError

from secmind.reverse_api_business import SecurityBusinessReport, TaskIdentity
from secmind.reverse_evaluation import _passes_obligation
from secmind.reverse_live_evaluation import (
    DEEPSEEK_PRICING_SNAPSHOT,
    estimate_deepseek_v4_flash_cny,
)
from secmind.schemas import ModelUsage

_ARMS: tuple[Literal["current", "optimized"], ...] = ("current", "optimized")
_REPEATS = (1, 2)
_ARTIFACT_HASH_FIELDS = {
    "request.json": "request_sha256",
    "response.json": "response_sha256",
    "receipt.json": "receipt_sha256",
    "report.json": "report_json_sha256",
    "report.md": "report_md_sha256",
    "report.html": "report_html_sha256",
}
_REQUIRED_ARTIFACTS = frozenset((*_ARTIFACT_HASH_FIELDS, "seal.json"))
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFETY_FIELDS = ("real_network_requests", "host_pe_executions", "target_writes", "secret_leaks")
_FAILURE_CODES = frozenset(
    {
        "MODEL_GATEWAY_ERROR",
        "TIMEOUT",
        "AUTHENTICATION_FAILED",
        "RATE_LIMITED",
        "STRUCTURED_OUTPUT_INVALID",
        "UNSAFE_MODEL_PAYLOAD",
        "LOCAL_POST_RESPONSE_FAILURE",
        "ORCHESTRATION_INTERRUPTED",
        "ORCHESTRATION_SLOT_FAILURE",
        "API_FAILURE_UNCLASSIFIED",
    }
)
_ANALYSIS_DOMAIN_ERROR_CODES = frozenset({"MALFORMED_PE", "DYNAMIC_UNAVAILABLE"})
_POST_RESPONSE_FAILURE_CODES = frozenset(
    {"STRUCTURED_OUTPUT_INVALID", "UNSAFE_MODEL_PAYLOAD", "LOCAL_POST_RESPONSE_FAILURE"}
)
_ORCHESTRATION_FAILURE_CODES = frozenset({"ORCHESTRATION_INTERRUPTED", "ORCHESTRATION_SLOT_FAILURE"})
_PROVIDER_FAILURE_CODES = _FAILURE_CODES - _POST_RESPONSE_FAILURE_CODES - _ORCHESTRATION_FAILURE_CODES
_USAGE_FIELDS = frozenset(
    {
        "provider_requests",
        "input_tokens",
        "output_tokens",
        "cache_hit_input_tokens",
        "cache_miss_input_tokens",
        "cost_units",
    }
)


@dataclass(frozen=True, slots=True)
class _ValidatedSlot:
    arm: Literal["current", "optimized"]
    case_id: str
    repeat_id: Literal[1, 2]
    directory: Path
    task_identity: TaskIdentity
    report: SecurityBusinessReport
    receipt: dict[str, Any]
    safety_observation: dict[str, Any] | None
    unknown_usage_attempts: int

    @property
    def identity(self) -> tuple[str, str, int]:
        return self.arm, self.case_id, self.repeat_id


def _load_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid JSON artifact: {path}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"JSON artifact must be an object: {path}")
    return cast(dict[str, Any], value)


def _file_sha256(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise ValueError(f"required artifact is unavailable: {path}") from exc


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and bool(_SHA256.fullmatch(value.casefold()))


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


def _reject_gold_path(path: Path, *, label: str) -> Path:
    if not isinstance(path, Path):
        raise ValueError(f"{label} must be a Path")
    try:
        resolved = path.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise ValueError(f"{label} cannot be resolved") from exc
    if any(component.casefold() == "gold" for component in (*path.parts, *resolved.parts)):
        raise ValueError(f"{label} must not be a gold path")
    return resolved


def _canonical_sha256(payload: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _assert_regular_path(path: Path, *, root: Path, directory: Path | None = None, label: str) -> Path:
    """Reject link/device/FIFO substitution before any artifact bytes are read."""

    try:
        entry = path.lstat()
    except OSError as exc:
        raise ValueError(f"{label} is unavailable") from exc
    if stat.S_ISLNK(entry.st_mode):
        raise ValueError(f"{label} must not be a symlink")
    if not stat.S_ISREG(entry.st_mode):
        raise ValueError(f"{label} must be a regular file")
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ValueError(f"{label} cannot be resolved safely") from exc
    if any(component.casefold() == "gold" for component in (*path.parts, *resolved.parts)):
        raise ValueError(f"{label} must not resolve through a gold path")
    if directory is not None and resolved.parent != directory:
        raise ValueError(f"{label} resolves outside its sealed slot directory")
    if not resolved.is_relative_to(root):
        raise ValueError(f"{label} resolves outside the approved run root")
    return resolved


def _assert_directory_chain(root: Path, directory: Path) -> Path:
    """Validate each root-to-slot directory component before artifact access."""

    try:
        root_lstat = root.lstat()
    except OSError as exc:
        raise ValueError("run root is unavailable") from exc
    if stat.S_ISLNK(root_lstat.st_mode) or not stat.S_ISDIR(root_lstat.st_mode):
        raise ValueError("run root must be a non-symlink directory")
    try:
        resolved_root = root.resolve(strict=True)
        relative = directory.relative_to(root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ValueError("sealed report directory escapes the approved run root") from exc
    current = root
    for component in relative.parts:
        current = current / component
        try:
            entry = current.lstat()
        except OSError as exc:
            raise ValueError("sealed report directory is unavailable") from exc
        if stat.S_ISLNK(entry.st_mode) or not stat.S_ISDIR(entry.st_mode):
            raise ValueError("sealed report directory must not contain symlinks or non-directories")
    resolved_directory = directory.resolve(strict=True)
    if not resolved_directory.is_relative_to(resolved_root) or any(
        component.casefold() == "gold" for component in (*directory.parts, *resolved_directory.parts)
    ):
        raise ValueError("sealed report directory is unsafe")
    return resolved_directory


def _same_identity(value: object, expected: TaskIdentity, *, label: str) -> None:
    try:
        observed = TaskIdentity.model_validate(value)
    except ValidationError as exc:
        raise ValueError(f"{label} task identity is invalid") from exc
    if observed != expected:
        raise ValueError(f"{label} task identity does not match its sealed slot")


def _required_nonnegative_int(value: object, *, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{label} must be a non-negative integer")
    return value


def _typed_usage(value: object, *, label: str) -> ModelUsage:
    """Require the complete, closed ModelUsage wire shape on every ledger lane."""

    if not isinstance(value, Mapping) or set(value) != _USAGE_FIELDS:
        raise ValueError(f"{label} must be a closed ModelUsage object")
    try:
        usage = ModelUsage.model_validate(value)
    except ValidationError as exc:
        raise ValueError(f"{label} is not a valid ModelUsage object") from exc
    if not math.isfinite(usage.cost_units):
        raise ValueError(f"{label} cost_units must be finite")
    return usage


def _usage_equal(left: ModelUsage, right: ModelUsage) -> bool:
    return left.model_dump(mode="json") == right.model_dump(mode="json")


def _sum_usage(items: Iterable[ModelUsage]) -> ModelUsage:
    values = list(items)
    return ModelUsage(
        provider_requests=sum(item.provider_requests for item in values),
        input_tokens=sum(item.input_tokens for item in values),
        output_tokens=sum(item.output_tokens for item in values),
        cache_hit_input_tokens=sum(item.cache_hit_input_tokens for item in values),
        cache_miss_input_tokens=sum(item.cache_miss_input_tokens for item in values),
        cost_units=sum(item.cost_units for item in values),
    )


def _validate_usage(receipt: Mapping[str, Any]) -> ModelUsage:
    usage = receipt.get("usage")
    if not isinstance(usage, Mapping):
        raise ValueError("receipt usage must be an object")
    if set(usage) != (_USAGE_FIELDS | {"total_tokens"}):
        raise ValueError("receipt usage must be a closed ModelUsage object with total_tokens")
    typed = _typed_usage({field: usage[field] for field in _USAGE_FIELDS}, label="receipt usage")
    total_tokens = _required_nonnegative_int(usage.get("total_tokens"), label="receipt usage.total_tokens")
    if total_tokens != typed.total_tokens:
        raise ValueError("receipt usage total_tokens must equal input_tokens + output_tokens")
    _validate_pricing(receipt, usage)
    return typed


def _validate_pricing(receipt: Mapping[str, Any], usage: Mapping[str, Any]) -> None:
    """Recompute CNY from the pinned DeepSeek price snapshot and components."""

    pricing = receipt.get("pricing")
    if not isinstance(pricing, Mapping):
        raise ValueError("receipt pricing must be an object")
    price = pricing.get("estimated_cny")
    if (
        not isinstance(price, (int, float))
        or isinstance(price, bool)
        or not math.isfinite(float(price))
        or price < 0
    ):
        raise ValueError("receipt pricing.estimated_cny must be a finite non-negative number")
    if pricing.get("snapshot") != DEEPSEEK_PRICING_SNAPSHOT:
        raise ValueError("receipt pricing snapshot does not match the pinned DeepSeek snapshot")
    components = pricing.get("usage_components")
    if not isinstance(components, Mapping):
        raise ValueError("receipt pricing must seal usage components")
    hit = _required_nonnegative_int(components.get("cache_hit_input_tokens"), label="pricing cache-hit tokens")
    miss = _required_nonnegative_int(components.get("cache_miss_input_tokens"), label="pricing cache-miss tokens")
    output = _required_nonnegative_int(components.get("output_tokens"), label="pricing output tokens")
    if hit + miss != int(usage["input_tokens"]) or output != int(usage["output_tokens"]):
        raise ValueError("receipt pricing components do not match sealed token usage")
    cache_accounting = components.get("cache_accounting")
    raw_hit = _required_nonnegative_int(usage.get("cache_hit_input_tokens"), label="usage cache-hit tokens")
    raw_miss = _required_nonnegative_int(usage.get("cache_miss_input_tokens"), label="usage cache-miss tokens")
    if cache_accounting == "provider_reported":
        if raw_hit != hit or raw_miss != miss:
            raise ValueError("provider-reported cache token components do not match pricing")
    elif cache_accounting == "conservative_cache_miss_fallback":
        if raw_hit != 0 or raw_miss != 0 or hit != 0 or miss != int(usage["input_tokens"]):
            raise ValueError("conservative cache-miss pricing fallback is inconsistent")
    else:
        raise ValueError("receipt pricing cache accounting mode is invalid")
    priced_at = pricing.get("priced_at")
    if not isinstance(priced_at, str):
        raise ValueError("receipt pricing timestamp is invalid")
    try:
        parsed_at = datetime.fromisoformat(priced_at)
    except ValueError as exc:
        raise ValueError("receipt pricing timestamp is invalid") from exc
    if parsed_at.tzinfo is None:
        raise ValueError("receipt pricing timestamp must include a timezone")
    priced_usage = ModelUsage(
        input_tokens=int(usage["input_tokens"]),
        output_tokens=int(usage["output_tokens"]),
        cache_hit_input_tokens=hit,
        cache_miss_input_tokens=miss,
    )
    expected = estimate_deepseek_v4_flash_cny(priced_usage, priced_at=parsed_at)
    if (
        pricing.get("pricing_band") != expected["pricing_band"]
        or pricing.get("priced_at") != expected["priced_at"]
        or pricing.get("formula") != expected["formula"]
        or abs(float(price) - float(expected["estimated_cny"])) > 1e-8
    ):
        raise ValueError("receipt estimated CNY does not match pinned pricing formula")


def _validate_receipt_accounting(receipt: Mapping[str, Any], request: Mapping[str, Any]) -> int:
    """Check provider-accounting invariants without trusting a report status."""

    public_request_sha256 = request.get("public_request_sha256")
    if not _is_sha256(public_request_sha256):
        raise ValueError("request public_request_sha256 is invalid")
    request_without_digest = dict(request)
    request_without_digest.pop("public_request_sha256", None)
    if _canonical_sha256(request_without_digest) != public_request_sha256:
        raise ValueError("request public_request_sha256 does not bind the public request")
    if receipt.get("public_request_sha256") != public_request_sha256:
        raise ValueError("receipt is not bound to the sealed public request")
    error = receipt.get("error_type")
    if error is not None and error not in _FAILURE_CODES:
        raise ValueError("receipt error_type is outside the closed failure vocabulary")
    status = receipt.get("execution_status")
    interrupted = error in _ORCHESTRATION_FAILURE_CODES
    accounting_status = receipt.get("accounting_status")
    if interrupted:
        if accounting_status != "provider_outcome_unknown_no_receipt":
            raise ValueError("interrupted receipt must retain unknown provider accounting")
    elif accounting_status is not None:
        raise ValueError("non-interrupted receipt must not contain orchestration accounting")
    receipt_id = receipt.get("model_receipt_id")
    for field in ("model_request_sha256", "model_response_sha256"):
        value = receipt.get(field)
        if error is None and not _is_sha256(value):
            raise ValueError(f"successful receipt {field} must be a SHA256 digest")
        if error in _PROVIDER_FAILURE_CODES and value is not None:
            raise ValueError(f"failed receipt {field} must be null")
    if error is None:
        if not isinstance(receipt_id, str) or not receipt_id:
            raise ValueError("successful receipt must contain a model_receipt_id")
    elif error in _PROVIDER_FAILURE_CODES and (status != "unavailable" or receipt_id is not None):
        raise ValueError("failed provider receipt must be unavailable and have no model_receipt_id")
    elif error in _POST_RESPONSE_FAILURE_CODES:
        if status != "unavailable":
            raise ValueError("post-response failure receipt must be unavailable")
        values = [receipt.get("model_request_sha256"), receipt.get("model_response_sha256")]
        if receipt_id is None and any(value is not None for value in values):
            raise ValueError("unbound post-response receipt hashes are invalid")
        if receipt_id is not None and (
            not isinstance(receipt_id, str)
            or not receipt_id
            or not all(_is_sha256(value) for value in values)
        ):
            raise ValueError("post-response receipt must preserve complete response identity")
    attempts = receipt.get("attempts")
    if not isinstance(attempts, list):
        raise ValueError("receipt attempts must be a list")
    total_duration = 0
    provider_attempts = 0
    settled_usages: list[ModelUsage] = []
    reported_usages: list[ModelUsage] = []
    conservative_usages: list[ModelUsage] = []
    unknown_usage_attempts = 0
    final_provider_attempt: Mapping[str, Any] | None = None
    for ordinal, attempt in enumerate(attempts, start=1):
        if not isinstance(attempt, Mapping) or attempt.get("ordinal") != ordinal:
            raise ValueError("receipt attempts must have contiguous ordinals")
        duration = _required_nonnegative_int(attempt.get("duration_ms"), label="receipt attempt duration_ms")
        if not isinstance(attempt.get("retryable", False), bool):
            raise ValueError("receipt attempt retryable must be a boolean")
        provider_request = attempt.get("provider_request", True)
        if not isinstance(provider_request, bool):
            raise ValueError("receipt attempt provider_request must be a boolean")
        usage = _typed_usage(attempt.get("usage"), label="receipt attempt usage")
        reported = _typed_usage(attempt.get("provider_reported_usage"), label="receipt attempt provider_reported_usage")
        conservative = _typed_usage(
            attempt.get("conservative_reserved_usage"), label="receipt attempt conservative_reserved_usage"
        )
        unknown_usage = attempt.get("unknown_usage")
        if not isinstance(unknown_usage, bool):
            raise ValueError("receipt attempt unknown_usage must be a boolean")
        request_id = attempt.get("provider_request_id")
        logical_call_id = attempt.get("logical_call_id")
        request_digest = attempt.get("request_digest")
        response_digest = attempt.get("response_digest")
        if request_digest is not None and not _is_sha256(request_digest):
            raise ValueError("receipt attempt request_digest must be a SHA256 digest or null")
        if response_digest is not None and not _is_sha256(response_digest):
            raise ValueError("receipt attempt response_digest must be a SHA256 digest or null")
        if provider_request:
            if not isinstance(request_id, str) or not request_id or len(request_id) > 200:
                raise ValueError("provider attempt must contain a safe provider_request_id")
            if not isinstance(logical_call_id, str) or not logical_call_id or len(logical_call_id) > 128:
                raise ValueError("provider attempt must contain a safe logical_call_id")
            if not _is_sha256(request_digest):
                raise ValueError("provider attempt must contain a request digest")
            if reported.provider_requests + conservative.provider_requests != 1 or usage.provider_requests != 1:
                raise ValueError("provider attempt usage must represent exactly one provider request")
            if not _usage_equal(usage, _sum_usage((reported, conservative))):
                raise ValueError("provider attempt settled usage must equal its provenance lanes")
            if not unknown_usage and conservative != ModelUsage():
                raise ValueError("known provider usage cannot contain a conservative lane")
            if unknown_usage != (conservative.provider_requests > 0):
                raise ValueError("provider attempt unknown usage flag disagrees with conservative usage")
            total_duration += duration
            provider_attempts += 1
            settled_usages.append(usage)
            reported_usages.append(reported)
            conservative_usages.append(conservative)
            unknown_usage_attempts += int(unknown_usage)
            final_provider_attempt = attempt
        else:
            if (
                duration != 0
                or usage != ModelUsage()
                or reported != ModelUsage()
                or conservative != ModelUsage()
                or unknown_usage
            ):
                raise ValueError("local diagnostic attempts must not contribute provider usage, latency, or retries")
    top_usage = _validate_usage(receipt)
    aggregated_usage = _sum_usage(settled_usages)
    if not _usage_equal(top_usage, aggregated_usage):
        raise ValueError("receipt usage must equal the aggregate provider attempt usage")
    provenance = receipt.get("usage_provenance")
    if not isinstance(provenance, Mapping) or set(provenance) != {
        "provider_reported_usage",
        "conservative_reserved_usage",
        "unknown_usage_attempts",
    }:
        raise ValueError("receipt usage_provenance must be a closed object")
    provenance_reported = _typed_usage(
        provenance.get("provider_reported_usage"), label="receipt provenance provider usage"
    )
    provenance_conservative = _typed_usage(
        provenance.get("conservative_reserved_usage"), label="receipt provenance conservative usage"
    )
    provenance_unknown = _required_nonnegative_int(
        provenance.get("unknown_usage_attempts"), label="receipt provenance unknown_usage_attempts"
    )
    if not _usage_equal(provenance_reported, _sum_usage(reported_usages)) or not _usage_equal(
        provenance_conservative, _sum_usage(conservative_usages)
    ):
        raise ValueError("receipt usage_provenance must equal the provider attempt aggregation")
    if interrupted:
        if (
            attempts
            or top_usage != ModelUsage()
            or int(receipt["retry_count"]) != 0
            or int(receipt["latency_ms"]) != 0
            or provenance_unknown != 1
        ):
            raise ValueError("interrupted receipt must not fabricate provider accounting")
        unknown_usage_attempts = 1
    elif provenance_unknown != unknown_usage_attempts:
        raise ValueError("receipt usage_provenance must equal the provider attempt aggregation")
    if int(top_usage.provider_requests) != provider_attempts:
        raise ValueError("receipt provider_requests must equal recorded provider attempts")
    if int(receipt["retry_count"]) != max(0, provider_attempts - 1):
        raise ValueError("receipt retry_count must equal recorded provider attempts minus one")
    if int(receipt["latency_ms"]) != total_duration:
        raise ValueError("receipt latency_ms must equal summed attempt durations")
    if (error is None or (error in _POST_RESPONSE_FAILURE_CODES and receipt_id is not None)) and (
        not attempts
        or int(top_usage.provider_requests) < 1
        or top_usage.total_tokens < 1
    ):
        raise ValueError(
            "successful DeepSeek receipt must prove at least one attempted, token-bearing provider request"
        )
    if error is None or (error in _POST_RESPONSE_FAILURE_CODES and receipt_id is not None):
        if final_provider_attempt is None:
            raise ValueError("response-bound receipt must contain a final provider attempt")
        if (
            receipt.get("model_request_sha256") != final_provider_attempt.get("request_digest")
            or receipt.get("model_response_sha256") != final_provider_attempt.get("response_digest")
        ):
            raise ValueError("receipt response identity must match the selected provider attempt digests")
        allowed_receipt_ids = {
            final_provider_attempt.get("logical_call_id"),
            final_provider_attempt.get("provider_request_id"),
            final_provider_attempt.get("response_digest"),
        }
        if receipt_id not in allowed_receipt_ids:
            raise ValueError("receipt ID must match the selected provider attempt identity")
    return unknown_usage_attempts


def _validated_safety_observation(request: Mapping[str, Any], identity: TaskIdentity) -> dict[str, Any] | None:
    observation = request.get("safety_observation")
    if observation is None:
        return None
    if not isinstance(observation, Mapping):
        raise ValueError("safety observation must be an object")
    _same_identity(observation.get("task_identity"), identity, label="safety observation")
    if observation.get("status") != "verified":
        return None
    safety = observation.get("safety")
    receipts = observation.get("safety_receipts")
    if not isinstance(safety, Mapping) or not isinstance(receipts, Mapping):
        raise ValueError("verified safety observation requires safety and receipts")
    result: dict[str, Any] = {
        "task_identity": identity.model_dump(mode="json"),
        "status": "verified",
        "safety": {},
        "safety_receipts": {},
    }
    for field in _SAFETY_FIELDS:
        count = _required_nonnegative_int(safety.get(field), label=f"safety {field}")
        receipt = receipts.get(field)
        if (
            not isinstance(receipt, Mapping)
            or receipt.get("status") != "verified"
            or receipt.get("count") != count
            or not isinstance(receipt.get("evidence"), list)
            or not receipt["evidence"]
        ):
            raise ValueError(f"safety receipt for {field} is incomplete")
        result["safety"][field] = count
        result["safety_receipts"][field] = dict(receipt)
    return result


def _validate_slot_directory(root: Path, seal_path: Path) -> _ValidatedSlot:
    directory = seal_path.parent
    try:
        relative = directory.relative_to(root)
    except ValueError as exc:
        raise ValueError("sealed report directory escapes the approved run root") from exc
    if len(relative.parts) != 3:
        raise ValueError("sealed report directory must be arm/run-repeat/case")
    arm_raw, run_name, case_id = relative.parts
    if arm_raw not in _ARMS:
        raise ValueError("sealed report arm is not current or optimized")
    arm = cast(Literal["current", "optimized"], arm_raw)
    if run_name not in {"run-1", "run-2"}:
        raise ValueError("sealed report repeat directory is invalid")
    repeat_id = cast(Literal[1, 2], int(run_name.removeprefix("run-")))
    _safe_component(case_id, label="case_id")

    resolved_root = _reject_gold_path(root, label="run root")
    resolved_directory = _assert_directory_chain(root, directory)

    try:
        names = frozenset(entry.name for entry in directory.iterdir())
    except OSError as exc:
        raise ValueError("sealed report directory cannot be enumerated") from exc
    if names != _REQUIRED_ARTIFACTS:
        raise ValueError("sealed report directory must contain exactly the seven required artifacts")
    # Every filesystem object is checked before opening any JSON or hashing
    # bytes.  This keeps a valid hash from laundering a symlinked gold file.
    safe_paths = {
        name: _assert_regular_path(directory / name, root=resolved_root, directory=resolved_directory, label=name)
        for name in _REQUIRED_ARTIFACTS
    }
    seal = _load_object(safe_paths["seal.json"])
    if (
        seal.get("arm") != arm
        or seal.get("case_id") != case_id
        or seal.get("repeat_id") != repeat_id
        or not isinstance(seal.get("suite_id"), str)
        or not seal["suite_id"]
    ):
        raise ValueError("seal identity does not match its directory")
    for name, field in _ARTIFACT_HASH_FIELDS.items():
        expected = seal.get(field)
        if not _is_sha256(expected):
            raise ValueError(f"seal {field} is not a SHA256 digest")
        actual = _file_sha256(safe_paths[name])
        if actual != expected:
            raise ValueError(f"sealed artifact SHA256 mismatch: {name}")

    request = _load_object(safe_paths["request.json"])
    receipt = _load_object(safe_paths["receipt.json"])
    response = _load_object(safe_paths["response.json"])
    envelope = _load_object(safe_paths["report.json"])
    identity = TaskIdentity(
        suite_id=str(seal["suite_id"]),
        arm=arm,
        case_id=case_id,
        repeat_id=repeat_id,
        sample_sha256=str(envelope.get("task_identity", {}).get("sample_sha256", ""))
        if isinstance(envelope.get("task_identity"), Mapping)
        else "",
        provider="deepseek",
        model="deepseek-v4-flash",
    )
    if request.get("gold_read") is not False:
        raise ValueError("request records pre-seal gold access")
    if request.get("sibling_runs_read") is not False:
        raise ValueError("request records sibling-run access")
    _same_identity(request.get("task_identity"), identity, label="request")
    _same_identity(receipt.get("task_identity"), identity, label="receipt")
    _same_identity(response.get("task_identity"), identity, label="response")
    _same_identity(envelope.get("task_identity"), identity, label="report envelope")
    request_slot = request.get("slot")
    if not isinstance(request_slot, Mapping) or (
        request_slot.get("arm"), request_slot.get("case_id"), request_slot.get("repeat_id")
    ) != (arm, case_id, repeat_id):
        raise ValueError("request slot identity does not match its sealed directory")
    if (
        request.get("provider") != "deepseek"
        or request.get("model") != "deepseek-v4-flash"
        or request.get("base_url") != "https://api.deepseek.com"
    ):
        raise ValueError("request provider identity is invalid")
    if receipt.get("provider") != "deepseek" or receipt.get("model") != "deepseek-v4-flash":
        raise ValueError("receipt provider identity is invalid")
    if receipt.get("base_url") != "https://api.deepseek.com":
        raise ValueError("receipt does not bind the approved DeepSeek endpoint")
    if receipt.get("execution_status") not in {"completed", "partial", "unavailable"}:
        raise ValueError("receipt execution status is invalid")
    _required_nonnegative_int(receipt.get("latency_ms"), label="receipt latency_ms")
    _required_nonnegative_int(receipt.get("retry_count"), label="receipt retry_count")
    _validate_usage(receipt)
    unknown_usage_attempts = _validate_receipt_accounting(receipt, request)
    try:
        report = SecurityBusinessReport.model_validate(envelope.get("report"))
    except ValidationError as exc:
        raise ValueError("report payload is not a SecurityBusinessReport") from exc
    if envelope.get("artifact_type") != "reverse_api_case_business_report":
        raise ValueError("report artifact type is invalid")
    _same_identity(report.task_identity, identity, label="business report")
    if (
        envelope.get("execution_status") != report.execution_status
        or receipt.get("execution_status") != report.execution_status
        or response.get("execution_status") != report.execution_status
        or envelope.get("model_receipt_ref") != "receipt.json"
        or report.model_receipt_ref != "receipt.json"
    ):
        raise ValueError("report, response, and receipt status identities disagree")
    receipt_error = receipt.get("error_type")
    response_error = response.get("error_type")
    if response_error != receipt_error:
        raise ValueError("response and receipt provider error types disagree")
    claim_error = None if report.scoring_claims.error is None else report.scoring_claims.error.code
    if receipt_error is not None and claim_error != receipt_error:
        raise ValueError("failed provider receipt and machine scoring error disagree")
    if receipt_error is None and claim_error in _FAILURE_CODES:
        raise ValueError("successful provider receipt cannot claim a provider failure")
    if claim_error is not None and claim_error not in (_FAILURE_CODES | _ANALYSIS_DOMAIN_ERROR_CODES):
        raise ValueError("machine scoring error is outside the closed vocabulary")
    if response.get("model_response_sha256") != receipt.get("model_response_sha256"):
        raise ValueError("response and receipt model response hashes disagree")
    response_report = response.get("report")
    if not isinstance(response_report, Mapping) or dict(response_report) != report.model_dump(mode="json"):
        raise ValueError("response report does not match the sealed business report")
    safety_observation = _validated_safety_observation(request, identity)
    return _ValidatedSlot(
        arm,
        case_id,
        repeat_id,
        resolved_directory,
        identity,
        report,
        receipt,
        safety_observation,
        unknown_usage_attempts,
    )


def _validate_sealed_run_tree(run_root: Path) -> list[_ValidatedSlot]:
    _reject_gold_path(run_root, label="run root")
    root = run_root
    try:
        root_stat = run_root.lstat()
    except OSError as exc:
        raise ValueError("run root must be an existing directory") from exc
    if stat.S_ISLNK(root_stat.st_mode) or not stat.S_ISDIR(root_stat.st_mode):
        raise ValueError("run root must be an existing directory")
    try:
        seals = sorted(root.rglob("seal.json"))
        report_paths = sorted(root.rglob("report.json"))
    except OSError as exc:
        raise ValueError("run root cannot be enumerated") from exc
    if len(seals) != 48 or len(report_paths) != 48:
        raise ValueError("API scoring requires exactly 48 sealed report artifacts")
    sealed_dirs = {path.parent for path in seals}
    if {path.parent for path in report_paths} != sealed_dirs:
        raise ValueError("unsealed report artifact is present")
    slots = [_validate_slot_directory(root, seal_path) for seal_path in seals]
    identities = [slot.identity for slot in slots]
    if len(set(identities)) != 48:
        raise ValueError("duplicate sealed API slot identity")
    by_arm_repeat: dict[tuple[str, int], set[str]] = defaultdict(set)
    for slot in slots:
        by_arm_repeat[(slot.arm, slot.repeat_id)].add(slot.case_id)
    if set(by_arm_repeat) != {(arm, repeat) for arm in _ARMS for repeat in _REPEATS}:
        raise ValueError("sealed report matrix does not contain every arm and repeat")
    case_sets = list(by_arm_repeat.values())
    if any(len(case_ids) != 12 for case_ids in case_sets) or len({frozenset(ids) for ids in case_sets}) != 1:
        raise ValueError("sealed report matrix must contain the same 12 cases for every arm/repeat")
    suites = {slot.task_identity.suite_id for slot in slots}
    providers = {slot.task_identity.provider for slot in slots}
    models = {slot.task_identity.model for slot in slots}
    if len(suites) != 1 or providers != {"deepseek"} or models != {"deepseek-v4-flash"}:
        raise ValueError("sealed API matrix must bind one suite, provider, and model")
    sample_hashes: dict[str, set[str]] = defaultdict(set)
    for slot in slots:
        sample_hashes[slot.case_id].add(slot.task_identity.sample_sha256)
    if any(len(values) != 1 for values in sample_hashes.values()):
        raise ValueError("each case must bind one sample SHA256 across arms and repeats")
    receipt_ids = [slot.receipt.get("model_receipt_id") for slot in slots if slot.receipt.get("model_receipt_id")]
    if len(receipt_ids) != len(set(receipt_ids)):
        raise ValueError("successful model receipt IDs must be unique")
    return slots


def _load_gold_after_seal_validation(gold_path: Path) -> dict[str, Any]:
    """Private boundary kept separate so tests can prove ordering by absence."""

    if not isinstance(gold_path, Path):
        raise ValueError("gold path must be a Path")
    return _load_object(gold_path)


def _validate_gold(gold: Mapping[str, Any], slots: Iterable[_ValidatedSlot]) -> dict[str, dict[str, Any]]:
    cases = gold.get("cases")
    if not isinstance(cases, list) or len(cases) != 12:
        raise ValueError("gold must contain exactly 12 cases")
    first = next(iter(slots), None)
    if first is None or gold.get("suite_id") != first.task_identity.suite_id:
        raise ValueError("gold suite identity does not match sealed API reports")
    expected: dict[str, dict[str, Any]] = {}
    for case in cases:
        if not isinstance(case, dict) or not isinstance(case.get("id"), str) or not case["id"]:
            raise ValueError("gold case identity is invalid")
        if case["id"] in expected:
            raise ValueError("gold case IDs must be unique")
        obligations = case.get("obligations")
        behaviors = case.get("behaviors")
        if not isinstance(obligations, list) or not isinstance(behaviors, list):
            raise ValueError("gold case obligations and behaviors must be lists")
        expected[case["id"]] = case
    sealed_cases = {slot.case_id for slot in slots}
    if set(expected) != sealed_cases:
        raise ValueError("gold case IDs do not exactly match the sealed API matrix")
    return expected


def _projection(report: SecurityBusinessReport) -> dict[str, Any]:
    """Expose only explicit, schema-validated machine scoring claims.

    Human prose is deliberately excluded.  This makes negations, unrelated
    digits and translated finding titles incapable of changing benchmark
    scores, while preserving the complete obligation operator semantics.
    """

    claims = report.scoring_claims
    return {
        "id": report.task_identity.case_id,
        "status": claims.status,
        "facts": claims.facts,
        "behaviors": list(claims.behaviors),
        "evidence_refs": list(report.evidence_refs),
        "unknowns": list(report.unknowns),
        "error": claims.error.model_dump(mode="json") if claims.error is not None else {},
    }


def _value_at_with_presence(payload: Mapping[str, Any], path: str) -> dict[str, Any]:
    value: Any = payload
    for component in path.split("."):
        if not isinstance(value, Mapping) or component not in value:
            return {"state": "absent"}
        value = value[component]
    return {"state": "present", "value": value}


def _ratio(numerator: int | float, denominator: int | float) -> float:
    return numerator / denominator if denominator else 0.0


def _score_slot(slot: _ValidatedSlot, expected: Mapping[str, Any]) -> dict[str, Any]:
    projection = _projection(slot.report)
    obligations = [item for item in expected.get("obligations", []) if isinstance(item, dict)]
    checks = [_passes_obligation(projection, obligation) for obligation in obligations]
    exact_checks = [
        check
        for obligation, check in zip(obligations, checks, strict=True)
        if obligation.get("category") == "exact_fact"
    ]
    exact_claims = {
        str(obligation["path"]): _value_at_with_presence(projection, str(obligation["path"]))
        for obligation in obligations
        if obligation.get("category") == "exact_fact" and isinstance(obligation.get("path"), str)
    }
    expected_behaviors = {str(item) for item in expected.get("behaviors", [])}
    observed_behaviors = set(map(str, projection["behaviors"]))
    tp = len(expected_behaviors & observed_behaviors)
    fp = len(observed_behaviors - expected_behaviors)
    fn = len(expected_behaviors - observed_behaviors)
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    price = cast(Mapping[str, Any], slot.receipt["pricing"])
    usage = cast(Mapping[str, Any], slot.receipt["usage"])
    estimated_cny = float(price["estimated_cny"])
    cost_complete = slot.unknown_usage_attempts == 0
    return {
        "arm": slot.arm,
        "case_id": slot.case_id,
        "repeat_id": slot.repeat_id,
        "report_path": str(slot.directory / "report.json"),
        "execution_status": slot.report.execution_status,
        "obligations_passed": sum(checks),
        "obligations_total": len(checks),
        "obligation_score": _ratio(sum(checks), len(checks)),
        "behavior_tp": tp,
        "behavior_fp": fp,
        "behavior_fn": fn,
        "behavior_precision": precision,
        "behavior_recall": recall,
        "behavior_f1": _ratio(2 * precision * recall, precision + recall),
        "exact_fact_passed": sum(exact_checks),
        "exact_fact_total": len(exact_checks),
        "exact_fact_accuracy": _ratio(sum(exact_checks), len(exact_checks)),
        "evidence_ref_coverage": 1.0 if projection["evidence_refs"] else 0.0,
        "claimed_behaviors": sorted(observed_behaviors),
        "exact_fact_checks": exact_checks,
        "exact_fact_claims": exact_claims,
        "recommendation_priorities": [item.priority for item in slot.report.human_decision_recommendations],
        "provider_requests": int(usage["provider_requests"]),
        "input_tokens": int(usage["input_tokens"]),
        "output_tokens": int(usage["output_tokens"]),
        "total_tokens": int(usage["total_tokens"]),
        "latency_ms": int(slot.receipt["latency_ms"]),
        "retry_count": int(slot.receipt["retry_count"]),
        "estimated_cny": estimated_cny,
        "unknown_usage_attempts": slot.unknown_usage_attempts,
        "cost_complete": cost_complete,
        "known_estimated_cny": estimated_cny if cost_complete else 0.0,
        "conservative_estimated_cny": 0.0 if cost_complete else estimated_cny,
        "model_failure": slot.receipt.get("error_type") is not None,
    }


def _aggregate(rows: list[dict[str, Any]]) -> dict[str, Any]:
    if not rows:
        raise ValueError("cannot aggregate an empty API run group")
    tp = sum(int(row["behavior_tp"]) for row in rows)
    fp = sum(int(row["behavior_fp"]) for row in rows)
    fn = sum(int(row["behavior_fn"]) for row in rows)
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    exact_total = sum(int(row["exact_fact_total"]) for row in rows)
    return {
        "case_count": len(rows),
        "macro_obligation_score": sum(float(row["obligation_score"]) for row in rows) / len(rows),
        "micro_obligation_score": _ratio(
            sum(int(row["obligations_passed"]) for row in rows),
            sum(int(row["obligations_total"]) for row in rows),
        ),
        "behavior_precision": precision,
        "behavior_recall": recall,
        "behavior_f1": _ratio(2 * precision * recall, precision + recall),
        "exact_fact_accuracy": _ratio(sum(int(row["exact_fact_passed"]) for row in rows), exact_total),
        "evidence_reference_coverage": sum(float(row["evidence_ref_coverage"]) for row in rows) / len(rows),
        "completion_rate": _ratio(sum(row["execution_status"] == "completed" for row in rows), len(rows)),
        "partial_rate": _ratio(sum(row["execution_status"] == "partial" for row in rows), len(rows)),
        "unavailable_rate": _ratio(sum(row["execution_status"] == "unavailable" for row in rows), len(rows)),
        "receipt_count": len(rows),
        "provider_requests": sum(int(row["provider_requests"]) for row in rows),
        "input_tokens": sum(int(row["input_tokens"]) for row in rows),
        "output_tokens": sum(int(row["output_tokens"]) for row in rows),
        "total_tokens": sum(int(row["total_tokens"]) for row in rows),
        "latency_ms": sum(int(row["latency_ms"]) for row in rows),
        "retry_count": sum(int(row["retry_count"]) for row in rows),
        # Conservative receipts remain visible but never inflate a total that
        # is labelled as complete provider-reported cost.
        "estimated_cny": sum(float(row["known_estimated_cny"]) for row in rows),
        "conservative_estimated_cny": sum(float(row["conservative_estimated_cny"]) for row in rows),
        "unknown_usage_attempts": sum(int(row["unknown_usage_attempts"]) for row in rows),
        "cost_complete": not any(not bool(row["cost_complete"]) for row in rows),
        "model_failure_count": sum(bool(row["model_failure"]) for row in rows),
    }


def _population_summary(values: list[float]) -> dict[str, float]:
    if not values:
        raise ValueError("cannot summarize an empty API metric")
    mean = sum(values) / len(values)
    return {
        "mean": mean,
        "minimum": min(values),
        "maximum": max(values),
        "population_stddev": math.sqrt(sum((value - mean) ** 2 for value in values) / len(values)),
    }


def _jaccard(left: set[str], right: set[str]) -> float:
    union = left | right
    return 1.0 if not union else len(left & right) / len(union)


def _stability(rows: list[dict[str, Any]]) -> dict[str, float]:
    by_case: dict[str, dict[int, dict[str, Any]]] = defaultdict(dict)
    for row in rows:
        by_case[str(row["case_id"])][int(row["repeat_id"])] = row
    if len(by_case) != 12 or any(set(pair) != {1, 2} for pair in by_case.values()):
        raise ValueError("repeat stability requires exactly two reports for every case")
    status: list[float] = []
    behaviors: list[float] = []
    exact_facts: list[float] = []
    priorities: list[float] = []
    for pair in by_case.values():
        first, second = pair[1], pair[2]
        status.append(float(first["execution_status"] == second["execution_status"]))
        behaviors.append(_jaccard(set(first["claimed_behaviors"]), set(second["claimed_behaviors"])))
        exact_facts.append(float(first["exact_fact_claims"] == second["exact_fact_claims"]))
        priorities.append(float(first["recommendation_priorities"] == second["recommendation_priorities"]))
    return {
        "status_agreement": sum(status) / len(status),
        "behavior_jaccard": sum(behaviors) / len(behaviors),
        "exact_fact_agreement": sum(exact_facts) / len(exact_facts),
        "recommendation_priority_agreement": sum(priorities) / len(priorities),
    }


def _arm_metrics(rows: list[dict[str, Any]], arm: Literal["current", "optimized"]) -> dict[str, Any]:
    arm_rows = [row for row in rows if row["arm"] == arm]
    repeats = {str(repeat): _aggregate([row for row in arm_rows if row["repeat_id"] == repeat]) for repeat in _REPEATS}
    tracked = (
        "macro_obligation_score",
        "behavior_f1",
        "exact_fact_accuracy",
        "evidence_reference_coverage",
        "completion_rate",
        "partial_rate",
        "unavailable_rate",
        "provider_requests",
        "total_tokens",
        "latency_ms",
        "retry_count",
        "estimated_cny",
        "conservative_estimated_cny",
        "unknown_usage_attempts",
        "model_failure_count",
    )
    return {
        "repeats": repeats,
        "two_repeat_summary": {
            name: _population_summary([float(repeats[str(repeat)][name]) for repeat in _REPEATS]) for name in tracked
        },
        "stability": _stability(arm_rows),
    }


def _safety_summary(slots: Iterable[_ValidatedSlot]) -> tuple[dict[str, int], bool]:
    """Return conservative sample/tool safety, separate from DeepSeek traffic."""

    observations = [slot.safety_observation for slot in slots]
    if any(item is None for item in observations):
        return {field: -1 for field in _SAFETY_FIELDS}, False
    verified = [cast(dict[str, Any], item) for item in observations]
    values: dict[str, int] = {}
    for field in _SAFETY_FIELDS:
        counts = [int(cast(Mapping[str, Any], item["safety"])[field]) for item in verified]
        # A run can bind the same arm-level sealed safety ledger repeatedly;
        # maximum is conservative without falsely multiplying one observation.
        values[field] = max(counts)
    return values, all(value == 0 for value in values.values())


def score_api_runs(run_root: Path, gold_path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Score exactly 48 sealed API reports, opening gold only after validation.

    ``run_root`` is the root created by :func:`secmind.reverse_api_runner.run_api_slot`.
    It intentionally has no input for historic offline metrics; the only
    conclusions scored are the independently sealed DeepSeek reports.
    """

    slots = _validate_sealed_run_tree(run_root)
    # This is intentionally the first gold-path operation.  Do not move it
    # above sealed-tree validation: it is the anti-leak ordering boundary.
    gold = _load_gold_after_seal_validation(gold_path)
    expected_by_case = _validate_gold(gold, slots)
    rows = [_score_slot(slot, expected_by_case[slot.case_id]) for slot in slots]
    rows.sort(key=lambda row: (str(row["arm"]), str(row["case_id"]), int(row["repeat_id"])))
    arms = {arm: _arm_metrics(rows, arm) for arm in _ARMS}
    comparison_names = ("macro_obligation_score", "behavior_f1", "exact_fact_accuracy", "evidence_reference_coverage")
    comparison = {
        "optimized_minus_current": {
            name: arms["optimized"]["two_repeat_summary"][name]["mean"]
            - arms["current"]["two_repeat_summary"][name]["mean"]
            for name in comparison_names
        }
    }
    overall = _aggregate(rows)
    safety, safety_gate_passed = _safety_summary(slots)
    metrics: dict[str, Any] = {
        "schema_version": "1.0",
        "evaluation_lane": "deepseek_api_only",
        "suite_id": slots[0].task_identity.suite_id,
        "slot_count": len(rows),
        "receipt_count": len(rows),
        "gold_read_after_all_seals": True,
        "overall": overall,
        "arms": arms,
        "comparison": comparison,
        "model_control_plane": {
            "provider_requests": overall["provider_requests"],
            "input_tokens": overall["input_tokens"],
            "output_tokens": overall["output_tokens"],
            "total_tokens": overall["total_tokens"],
            "latency_ms": overall["latency_ms"],
            "retry_count": overall["retry_count"],
            "estimated_cny": overall["estimated_cny"],
            "conservative_estimated_cny": overall["conservative_estimated_cny"],
            "unknown_usage_attempts": overall["unknown_usage_attempts"],
            "cost_complete": overall["cost_complete"],
            "model_failure_count": overall["model_failure_count"],
        },
        "safety": safety,
        "safety_receipts_complete": all(slot.safety_observation is not None for slot in slots),
        "safety_gate_passed": safety_gate_passed,
    }
    return metrics, rows


__all__ = ["score_api_runs"]
