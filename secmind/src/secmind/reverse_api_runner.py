"""One-case DeepSeek execution and sealed artifact persistence.

This module deliberately keeps a logical API run to one manifest case and one
sealed evidence packet.  It never reads gold data or another repetition's
output, so the caller can execute the two repetitions independently.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, cast

import httpx
from pydantic import ValidationError

from secmind.config import Settings
from secmind.llm import QwenGateway
from secmind.model_gateway.budget import merge_usage
from secmind.model_gateway.contracts import ModelGatewayError
from secmind.reverse_api_business import (
    SecurityBusinessReport,
    TaskIdentity,
    build_unavailable_business_report,
)
from secmind.reverse_api_case_report import (
    UnsafeDeliverableError,
    assert_safe_deliverable_payload,
    build_source_semantics,
    render_case_html,
    render_case_json,
    render_case_markdown,
)
from secmind.reverse_api_slots import ApiRunSlot
from secmind.reverse_evaluation import verify_prediction_seal
from secmind.reverse_live_evaluation import estimate_deepseek_v4_flash_cny, validate_deepseek_identity
from secmind.schemas import ModelUsage

ARTIFACT_NAMES = (
    "request.json",
    "response.json",
    "receipt.json",
    "report.json",
    "report.md",
    "report.html",
    "seal.json",
)
_SHA256_HEX = frozenset("0123456789abcdef")


@dataclass(frozen=True, slots=True)
class ApiSlotResult:
    """The completed artifact bundle for exactly one API logical run."""

    slot: ApiRunSlot
    report: SecurityBusinessReport
    output_dir: Path
    artifacts: dict[str, Path]


def _load_object(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path.name} must contain a JSON object")
    return payload


def _json_bytes(payload: Any) -> bytes:
    return (json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _canonical_sha256(payload: Any) -> str:
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and set(value.casefold()) <= _SHA256_HEX


def _require_safe_path_segment(value: object, *, label: str) -> str:
    """Accept only one cross-platform-safe component before any file access."""

    if (
        not isinstance(value, str)
        or not value
        or value in {".", ".."}
        or "/" in value
        or "\\" in value
        or "\x00" in value
    ):
        raise ValueError(f"{label} must be a safe path segment")
    return value


def _resolved_path(path: Path, *, label: str) -> Path:
    if not isinstance(path, Path):
        raise ValueError(f"{label} must be a Path")
    try:
        return path.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise ValueError(f"{label} cannot be resolved safely") from exc


def _has_gold_component(path: Path) -> bool:
    return any(component.casefold() == "gold" for component in path.parts)


def _reject_gold_path(path: Path, *, label: str, expected_name: str | None = None) -> Path:
    if not isinstance(path, Path):
        raise ValueError(f"{label} must be a Path")
    if expected_name is not None and path.name != expected_name:
        raise ValueError(f"{label} must be named {expected_name}")
    resolved = _resolved_path(path, label=label)
    if _has_gold_component(path) or _has_gold_component(resolved):
        raise ValueError(f"{label} must not be a gold path")
    return resolved


def _validate_input_boundary(
    slot: ApiRunSlot,
    *,
    manifest_path: Path,
    evidence_path: Path,
    evidence_seal_path: Path,
    output_root: Path,
) -> Path:
    """Reject unsafe identities and paths before reading, networking, or writing."""

    if not isinstance(slot, ApiRunSlot):
        raise ValueError("slot must use the ApiRunSlot contract")
    if slot.arm not in {"current", "optimized"} or slot.repeat_id not in {1, 2}:
        raise ValueError("slot must use a reviewed arm and repeat identity")
    _require_safe_path_segment(slot.case_id, label="case_id")
    _reject_gold_path(manifest_path, label="manifest path")
    _reject_gold_path(evidence_path, label="evidence path", expected_name="predictions.json")
    _reject_gold_path(evidence_seal_path, label="evidence seal path", expected_name="predictions.seal.json")
    return _reject_gold_path(output_root, label="output root")


def _confined_output_dir(output_root: Path, slot: ApiRunSlot) -> Path:
    """Return a resolved per-slot directory that remains inside its slot root."""

    root = _resolved_path(output_root, label="output root")
    slot_root = _resolved_path(root / slot.arm / f"run-{slot.repeat_id}", label="slot output root")
    output_dir = _resolved_path(slot_root / slot.case_id, label="slot output directory")
    if not output_dir.is_relative_to(slot_root) or not output_dir.is_relative_to(root):
        raise ValueError("slot output directory escapes the approved output root")
    return output_dir


def _require_slot_case(
    slot: ApiRunSlot,
    manifest_path: Path,
    evidence_path: Path,
    evidence_seal_path: Path,
) -> tuple[str, dict[str, Any], dict[str, Any], dict[str, Any], TaskIdentity]:
    if slot.arm not in {"current", "optimized"} or slot.repeat_id not in {1, 2}:
        raise ValueError("slot must use a reviewed arm and repeat identity")
    arm = cast(Literal["current", "optimized"], slot.arm)
    repeat_id = cast(Literal[1, 2], slot.repeat_id)
    manifest = _load_object(manifest_path)
    suite_id = manifest.get("suite_id")
    if not isinstance(suite_id, str) or not suite_id:
        raise ValueError("manifest suite_id must be a non-empty string")
    _require_safe_path_segment(suite_id, label="suite_id")
    cases = manifest.get("cases")
    if not isinstance(cases, list):
        raise ValueError("manifest cases must be a list")
    matched_manifest = [item for item in cases if isinstance(item, dict) and item.get("id") == slot.case_id]
    if len(matched_manifest) != 1:
        raise ValueError("slot case must occur exactly once in the manifest")
    manifest_case = matched_manifest[0]
    prompt = manifest_case.get("prompt")
    if not isinstance(prompt, str) or not prompt or _text_sha256(prompt) != slot.prompt_sha256:
        raise ValueError("slot prompt hash does not match the manifest case")

    seal = verify_prediction_seal(evidence_path, evidence_seal_path)
    if seal.get("suite_id") != suite_id or seal.get("prediction_sha256") != slot.evidence_sha256:
        raise ValueError("slot evidence hash or suite does not match its sealed packet")
    evidence = _load_object(evidence_path)
    if evidence.get("suite_id") != suite_id or evidence.get("arm") != slot.arm:
        raise ValueError("sealed evidence identity does not match the slot")
    evidence_cases = evidence.get("cases")
    if not isinstance(evidence_cases, list):
        raise ValueError("sealed evidence cases must be a list")
    matched_evidence = [item for item in evidence_cases if isinstance(item, dict) and item.get("id") == slot.case_id]
    if len(matched_evidence) != 1:
        raise ValueError("slot case must occur exactly once in sealed evidence")
    evidence_case = matched_evidence[0]
    facts = evidence_case.get("facts")
    sample_sha256_candidate = facts.get("sha256") if isinstance(facts, dict) else None
    if _is_sha256(sample_sha256_candidate):
        sample_sha256 = str(sample_sha256_candidate)
    else:
        # Some source-only cases have no binary hash.  Bind their report to
        # the one sealed case packet rather than inventing a filesystem read.
        sample_sha256 = _canonical_sha256(evidence_case)
    identity = TaskIdentity(
        suite_id=suite_id,
        arm=arm,
        case_id=slot.case_id,
        repeat_id=repeat_id,
        sample_sha256=sample_sha256,
        provider="deepseek",
        model="deepseek-v4-flash",
    )
    return prompt, manifest_case, evidence, evidence_case, identity


def _allowed_evidence_refs(evidence_case: dict[str, Any]) -> set[str]:
    refs = evidence_case.get("evidence_refs")
    if not isinstance(refs, list) or not all(isinstance(item, str) for item in refs):
        raise ValueError("sealed evidence references must be a list of strings")
    return set(refs)


_PUBLIC_IDENTIFIER_KINDS = frozenset({"evidence", "source", "tool", "profile", "receipt", "artifact"})
_PUBLIC_OBSERVATION_TYPES = frozenset({"static", "emulated", "cape_fixture", "source", "unknown"})
_REVERSE_SOURCE_TYPES = {
    "speakeasy": "emulated",
    "cape_fixture": "cape_fixture",
    "source": "source",
}


@dataclass(frozen=True, slots=True)
class EvidenceDTO:
    """Closed, model-visible projection of one sealed evidence case.

    This is deliberately not a general JSON sanitizer.  Only fields below are
    eligible to cross the model/report boundary.  Technical fact and event
    containers are retained verbatim (then passed through the existing public
    payload safety gate); every other unregistered structural branch is
    dropped before serialization.
    """

    case: dict[str, Any]
    allowed_refs: set[str]
    aliases: dict[tuple[str, str], str]
    reverse: dict[str, tuple[str, str]]
    source_semantics: dict[str, object]


@dataclass(frozen=True, slots=True)
class PublicEventDTO:
    """One closed technical event approved for the model-visible DTO."""

    event: str
    api: dict[str, str | None]
    args: list[str | int | float | bool | None]
    ret_val: str | int | float | bool | None
    optional_fields: dict[str, str | int | float | bool | None | list[str | int | float | bool | None]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "event": self.event,
            "api": self.api,
            "args": self.args,
            "ret_val": self.ret_val,
            **self.optional_fields,
        }


def _canonical_identifier(value: object) -> str:
    if isinstance(value, str):
        if not value:
            raise ValueError("sealed internal identifier must not be empty")
        return value
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError) as exc:
        raise ValueError("sealed internal identifier is not JSON canonicalizable") from exc


def _public_identifier_alias(
    kind: str,
    value: object,
    aliases: dict[tuple[str, str], str],
    reverse: dict[str, tuple[str, str]],
) -> str:
    """Map one registered private identifier into its closed typed namespace."""

    if kind not in _PUBLIC_IDENTIFIER_KINDS:
        raise ValueError("unregistered public identifier kind")
    canonical = _canonical_identifier(value)
    identity = (kind, canonical)
    existing = aliases.get(identity)
    if existing is not None:
        return existing
    alias = f"{kind}-{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"
    prior = reverse.get(alias)
    if prior is not None and prior != identity:
        raise ValueError("sealed internal identifier alias collision")
    aliases[identity] = alias
    reverse[alias] = identity
    return alias


def _required_text_list(value: object, *, label: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"sealed {label} must be a list of strings")
    return list(value)


def _public_observation_type(reverse_analysis: dict[str, Any] | None) -> str:
    """Map a validated dynamic-observation kind into the closed public enum."""

    if reverse_analysis is None:
        return "static"
    source = reverse_analysis.get("source")
    if not isinstance(source, str) or not source:
        raise ValueError("sealed reverse-analysis source must be a non-empty string")
    observation_type = _REVERSE_SOURCE_TYPES.get(source, "unknown")
    if observation_type not in _PUBLIC_OBSERVATION_TYPES:  # pragma: no cover - closed map guard
        raise ValueError("unregistered reverse observation type")
    return observation_type


def _public_event_scalar(value: object, *, label: str) -> str | int | float | bool | None:
    """Accept only values that cannot contain a hidden object subtree."""

    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise ValueError(f"sealed reverse-analysis {label} must be a scalar")


def _public_event_scalar_list(value: object, *, label: str) -> list[str | int | float | bool | None]:
    if not isinstance(value, list):
        raise ValueError(f"sealed reverse-analysis {label} must be a list")
    return [_public_event_scalar(item, label=f"{label}[]") for item in value]


def _public_event_technical_text(
    field: str,
    value: object,
    aliases: dict[tuple[str, str], str],
    reverse: dict[str, tuple[str, str]],
) -> str:
    """Keep explicit technical labels, but never disclose path-like identities."""

    if not isinstance(value, str):
        raise ValueError(f"sealed reverse-analysis event.{field} must be a string")
    if "/" not in value and "\\" not in value and "\x00" not in value:
        return value
    if field not in {"source", "tool", "profile", "artifact"}:
        raise ValueError(f"sealed reverse-analysis event.{field} must not be path-like")
    return _public_identifier_alias(field, value, aliases, reverse)


def _public_event_api(value: object) -> dict[str, str | None]:
    """Represent a qualified API as closed module/function fields.

    Keeping a dotted qualified name as one string can look credential-like to
    the unchanged generic scanner.  The two semantic components remain fully
    available to the model and reports without opening an arbitrary mapping.
    """

    if not isinstance(value, str) or not value:
        raise ValueError("sealed reverse-analysis event.api_name must be a non-empty string")
    module, separator, function = value.partition(".")
    if separator and (not module or not function or "." in function):
        raise ValueError("sealed reverse-analysis event.api_name must be module.function")
    return {"module": module if separator else None, "function": function if separator else module}


def _require_matching_sample_identity(value: object, *, label: str, identity: TaskIdentity) -> None:
    """Bind one sealed sample identity to the slot before any public action."""

    if not _is_sha256(value):
        raise ValueError(f"sealed {label} must be a SHA256 digest")
    if value != identity.sample_sha256:
        raise ValueError(f"sealed {label} conflicts with task sample identity")


def _validate_optional_sample_fields(value: object, *, label: str, identity: TaskIdentity) -> None:
    """Validate only explicit sample-identity fields in a closed record."""

    if not isinstance(value, dict):
        raise ValueError(f"sealed {label} must be an object")
    for field in ("sample_sha256", "sample_hash"):
        if field in value:
            _require_matching_sample_identity(value[field], label=f"{label}.{field}", identity=identity)


def _validate_artifact_sample_fields(value: object, *, label: str, identity: TaskIdentity) -> None:
    """Validate sample references in an artifact record without publishing them."""

    _validate_optional_sample_fields(value, label=label, identity=identity)


def _validate_sealed_sample_identities(
    evidence_case: dict[str, Any], evidence: dict[str, Any], identity: TaskIdentity
) -> None:
    """Validate every schema-declared duplicate of the canonical sample hash."""

    facts = evidence_case.get("facts")
    if not isinstance(facts, dict):
        raise ValueError("sealed evidence facts must be an object")
    if "sha256" in facts:
        _require_matching_sample_identity(facts["sha256"], label="evidence facts.sha256", identity=identity)

    extensions = evidence_case.get("extensions")
    if extensions is not None:
        if not isinstance(extensions, dict):
            raise ValueError("sealed evidence extensions must be an object")
        reverse_analysis = extensions.get("reverse_analysis")
        if reverse_analysis is not None:
            if not isinstance(reverse_analysis, dict):
                raise ValueError("sealed reverse_analysis must be an object")
            if "sample_sha256" not in reverse_analysis:
                raise ValueError("sealed reverse-analysis sample_sha256 is required")
            _require_matching_sample_identity(
                reverse_analysis["sample_sha256"],
                label="reverse-analysis sample_sha256",
                identity=identity,
            )
            artifacts = reverse_analysis.get("artifacts")
            if artifacts is not None:
                _validate_artifact_sample_fields(
                    artifacts, label="reverse-analysis artifacts", identity=identity
                )

    observations = evidence_case.get("observations")
    if observations is not None:
        if not isinstance(observations, list) or not all(isinstance(item, dict) for item in observations):
            raise ValueError("sealed observations must be a list of objects")
        for index, observation in enumerate(observations):
            if "sample_sha256" not in observation:
                raise ValueError("sealed observation sample_sha256 is required")
            _require_matching_sample_identity(
                observation["sample_sha256"], label=f"observation[{index}] sample_sha256", identity=identity
            )
            artifacts = observation.get("artifacts")
            if artifacts is not None:
                _validate_artifact_sample_fields(
                    artifacts, label=f"observation[{index}] artifacts", identity=identity
                )

    for label, safety_observation in (
        ("case safety_observation", evidence_case.get("safety_observation")),
        ("evidence safety_observation", evidence.get("safety_observation")),
    ):
        if safety_observation is not None:
            _validate_optional_sample_fields(safety_observation, label=label, identity=identity)
            task_identity = safety_observation.get("task_identity")
            if task_identity is not None:
                _validate_optional_sample_fields(
                    task_identity, label=f"{label}.task_identity", identity=identity
                )

    for receipt_group_label, receipt_group in (
        ("case safety_receipts", evidence_case.get("safety_receipts")),
        ("evidence safety_receipts", evidence.get("safety_receipts")),
    ):
        if receipt_group is None:
            continue
        if not isinstance(receipt_group, dict):
            raise ValueError(f"sealed {receipt_group_label} must be an object")
        for receipt_name, receipt in receipt_group.items():
            _validate_optional_sample_fields(
                receipt, label=f"{receipt_group_label}.{receipt_name}", identity=identity
            )


def _project_public_event(
    value: object,
    aliases: dict[tuple[str, str], str],
    reverse: dict[str, tuple[str, str]],
) -> PublicEventDTO:
    """Whitelist the technical event schema; do not copy arbitrary mappings."""

    if not isinstance(value, dict):
        raise ValueError("sealed reverse-analysis events must contain objects")
    event = value.get("event")
    api_name = value.get("api_name")
    if not isinstance(event, str) or not event:
        raise ValueError("sealed reverse-analysis event.event must be a non-empty string")
    optional: dict[str, str | int | float | bool | None | list[str | int | float | bool | None]] = {}
    for field in ("action", "category"):
        if field in value:
            optional[field] = _public_event_technical_text(field, value[field], aliases, reverse)
    for field in ("source", "tool", "profile", "artifact"):
        if field in value:
            optional[field] = _public_event_technical_text(field, value[field], aliases, reverse)
    for field in ("arguments", "results"):
        if field in value:
            optional[field] = _public_event_scalar_list(value[field], label=f"event.{field}")
    if "result" in value:
        optional["result"] = _public_event_scalar(value["result"], label="event.result")
    return PublicEventDTO(
        event=event,
        api=_public_event_api(api_name),
        args=_public_event_scalar_list(value.get("args"), label="event.args"),
        ret_val=_public_event_scalar(value.get("ret_val"), label="event.ret_val"),
        optional_fields=optional,
    )


def _project_reverse_analysis(
    value: object,
    aliases: dict[tuple[str, str], str],
    reverse: dict[str, tuple[str, str]],
) -> tuple[dict[str, Any], str]:
    """Whitelist one reverse-analysis observation; drop all unknown branches."""

    if not isinstance(value, dict):
        raise ValueError("sealed reverse_analysis must be an object")
    observation_type = _public_observation_type(value)
    source = value.get("source")
    profile_id = value.get("profile_id")
    tool_identity = value.get("tool_identity")
    if not isinstance(source, str) or not source:
        raise ValueError("sealed reverse-analysis source must be a non-empty string")
    if not isinstance(profile_id, str) or not profile_id:
        raise ValueError("sealed reverse-analysis profile_id must be a non-empty string")
    if tool_identity is None:
        raise ValueError("sealed reverse-analysis tool_identity is required")
    evidence_refs = _required_text_list(value.get("evidence_refs"), label="reverse-analysis evidence_refs")
    events = value.get("events")
    if not isinstance(events, list):
        raise ValueError("sealed reverse-analysis events must be a list")
    artifacts = value.get("artifacts")
    if not isinstance(artifacts, dict):
        raise ValueError("sealed reverse-analysis artifacts must be an object")
    coverage = value.get("coverage")
    if not isinstance(coverage, dict):
        raise ValueError("sealed reverse-analysis coverage must be an object")

    projected_artifacts: dict[str, Any] = {}
    for field in ("created_files", "file_open_attempts"):
        labels = artifacts.get(field)
        if not isinstance(labels, list) or not all(isinstance(label, str) for label in labels):
            raise ValueError(f"sealed reverse-analysis artifacts.{field} must be a list of strings")
        projected_artifacts[field] = [
            _public_identifier_alias("artifact", label, aliases, reverse) for label in labels
        ]
    exit_code = artifacts.get("exit_code")
    if isinstance(exit_code, bool) or not isinstance(exit_code, int):
        raise ValueError("sealed reverse-analysis artifacts.exit_code must be an integer")
    projected_artifacts["exit_code"] = exit_code

    projected_coverage: dict[str, Any] = {}
    for field in (
        "architecture",
        "content_addressed_copy",
        "events_retained",
        "events_total",
        "host_pe_executions",
        "real_network_requests",
        "runtime_calls_observed",
        "sandbox_enforced",
        "sandbox_profile_sha256",
        "sandbox_scope",
        "truncated",
    ):
        if field == "sandbox_profile_sha256" and field in coverage:
            sandbox_profile_sha256 = coverage[field]
            if not _is_sha256(sandbox_profile_sha256):
                raise ValueError("sealed reverse-analysis coverage.sandbox_profile_sha256 must be a SHA256 digest")
            projected_coverage["sandbox_profile_ref"] = _public_identifier_alias(
                "profile", sandbox_profile_sha256, aliases, reverse
            )
        elif field in coverage:
            projected_coverage[field] = coverage[field]

    error = value.get("error")
    if error is not None:
        if not isinstance(error, dict) or not isinstance(error.get("code"), str):
            raise ValueError("sealed reverse-analysis error must be null or an object with a code")
        public_error: dict[str, Any] | None = {"code": error["code"]}
    else:
        public_error = None
    status = value.get("status")
    if not isinstance(status, str) or not status:
        raise ValueError("sealed reverse-analysis status must be a non-empty string")
    return (
        {
            "status": status,
            "source": _public_identifier_alias("source", source, aliases, reverse),
            "profile_id": _public_identifier_alias("profile", profile_id, aliases, reverse),
            "tool_identity": _public_identifier_alias("tool", tool_identity, aliases, reverse),
            "error": public_error,
            "evidence_refs": [
                _public_identifier_alias("evidence", label, aliases, reverse) for label in evidence_refs
            ],
            "events": [
                _project_public_event(event, aliases, reverse).to_dict() for event in events
            ],
            "artifacts": projected_artifacts,
            "coverage": projected_coverage,
        },
        observation_type,
    )


def _public_evidence_projection(
    evidence_case: dict[str, Any], evidence: dict[str, Any], identity: TaskIdentity
) -> EvidenceDTO:
    """Construct the sole closed EvidenceDTO for model-visible evidence."""

    _validate_sealed_sample_identities(evidence_case, evidence, identity)
    case_refs = _allowed_evidence_refs(evidence_case)
    aliases: dict[tuple[str, str], str] = {}
    reverse: dict[str, tuple[str, str]] = {}
    facts = evidence_case.get("facts")
    if not isinstance(facts, dict):
        raise ValueError("sealed evidence facts must be an object")
    public_facts = dict(facts)
    public_facts.pop("sha256", None)
    case_id = evidence_case.get("id")
    status = evidence_case.get("status", "completed")
    if not isinstance(case_id, str) or not case_id:
        raise ValueError("sealed evidence id must be a non-empty string")
    if not isinstance(status, str) or not status:
        raise ValueError("sealed evidence status must be a non-empty string")
    error = evidence_case.get("error")
    if error is not None:
        if not isinstance(error, dict) or not isinstance(error.get("code"), str):
            raise ValueError("sealed evidence error must be null or an object with a code")
        public_error: dict[str, Any] | None = {"code": error["code"]}
    else:
        public_error = None
    projected: dict[str, Any] = {
        "id": case_id,
        "status": status,
        # Facts are an explicit technical container, not an identity schema.
        "facts": public_facts,
        "behaviors": _required_text_list(evidence_case.get("behaviors"), label="evidence behaviors"),
        "evidence_refs": [
            _public_identifier_alias("evidence", raw, aliases, reverse) for raw in case_refs
        ],
        "limitations": _required_text_list(evidence_case.get("limitations"), label="evidence limitations"),
        "unknowns": _required_text_list(evidence_case.get("unknowns"), label="evidence unknowns"),
        "error": public_error,
    }
    extensions = evidence_case.get("extensions")
    observation_type = "static"
    if extensions is not None:
        if not isinstance(extensions, dict):
            raise ValueError("sealed evidence extensions must be an object")
        if "reverse_analysis" in extensions:
            projected_reverse, observation_type = _project_reverse_analysis(
                extensions["reverse_analysis"], aliases, reverse
            )
            projected["extensions"] = {"reverse_analysis": projected_reverse}
    projected["observation_type"] = observation_type
    allowed_refs = {_public_identifier_alias("evidence", raw, aliases, reverse) for raw in case_refs}
    facts_import_semantics = public_facts.get("import_semantics")
    return EvidenceDTO(
        case=projected,
        allowed_refs=allowed_refs,
        aliases=aliases,
        reverse=reverse,
        source_semantics=build_source_semantics(
            import_semantics=facts_import_semantics,
            observation_type=observation_type,
        ),
    )


def _safety_observation(
    evidence: dict[str, Any],
    identity: TaskIdentity,
    *,
    aliases: dict[tuple[str, str], str],
    reverse: dict[str, tuple[str, str]],
) -> dict[str, Any]:
    """Bind the sealed evidence safety ledger to this single API slot.

    Missing or malformed ledgers remain an explicit unknown.  The scorer then
    fails its safety gate rather than silently asserting zeros.
    """

    safety = evidence.get("safety")
    receipts = evidence.get("safety_receipts")
    fields = ("real_network_requests", "host_pe_executions", "target_writes", "secret_leaks")
    if not isinstance(safety, dict) or not isinstance(receipts, dict):
        return {"task_identity": identity.model_dump(mode="json"), "status": "unknown"}
    for field in fields:
        receipt = receipts.get(field)
        if (
            not isinstance(safety.get(field), int)
            or isinstance(safety.get(field), bool)
            or not isinstance(receipt, dict)
            or receipt.get("status") != "verified"
            or receipt.get("count") != safety[field]
            or not isinstance(receipt.get("evidence"), list)
            or not receipt["evidence"]
        ):
            return {"task_identity": identity.model_dump(mode="json"), "status": "unknown"}
    return {
        "task_identity": identity.model_dump(mode="json"),
        "status": "verified",
        "safety": {field: safety[field] for field in fields},
        "safety_receipts": {
            field: {
                "status": "verified",
                "count": safety[field],
                "evidence": [
                    _public_identifier_alias("evidence", label, aliases, reverse)
                    for label in receipts[field]["evidence"]
                ],
            }
            for field in fields
        },
    }


def _invalid_evidence_refs(report: SecurityBusinessReport, allowed: set[str]) -> set[str]:
    values = set(report.evidence_refs)
    for finding in report.findings:
        values.update(finding.evidence_refs)
    return values - allowed


def _limit_report_to_allowed_refs(
    report: SecurityBusinessReport,
    allowed: set[str],
) -> SecurityBusinessReport:
    findings = [
        finding.model_copy(update={"evidence_refs": [ref for ref in finding.evidence_refs if ref in allowed]})
        for finding in report.findings
    ]
    limitation = "模型返回了当前封存证据包之外的引用；这些引用已移除，结论需人工复核。"
    return report.model_copy(
        update={
            "execution_status": "partial",
            "scoring_claims": report.scoring_claims.model_copy(update={"status": "partial"}),
            "findings": findings,
            "evidence_refs": [ref for ref in report.evidence_refs if ref in allowed],
            "limitations": [*report.limitations, limitation],
        }
    )


# Output-integrity failures (schema-invalid or unsafe content) are stochastic
# per call, and MODEL_GATEWAY_ERROR covers transient provider transport
# failures (status_code=None / timeout) that typically clear within seconds to
# a few minutes.  All three are retried by ``run_api_slot`` so a slot can still
# produce a real answer instead of an unavailable receipt.
_RETRYABLE_OUTPUT_CODES = frozenset(
    {"STRUCTURED_OUTPUT_INVALID", "UNSAFE_MODEL_PAYLOAD", "MODEL_GATEWAY_ERROR"}
)

# Transport-level failures (MODEL_GATEWAY_ERROR) are often caused by a short
# provider outage window; a bounded exponential backoff between runner attempts
# lets that window pass instead of hammering the API with back-to-back calls.
# Content failures need no backoff and stay on the immediate-retry path.
_TRANSPORT_BACKOFF_START_SECONDS = 5.0
_TRANSPORT_BACKOFF_MAX_SECONDS = 30.0


async def _retry_backoff(attempt_index: int) -> None:
    await asyncio.sleep(min(_TRANSPORT_BACKOFF_START_SECONDS * (2**attempt_index), _TRANSPORT_BACKOFF_MAX_SECONDS))


def _failure_code(exc: BaseException) -> str:
    failure = exc.failure if isinstance(exc, ModelGatewayError) else None
    status_code = None if failure is None else failure.status_code
    if status_code in {401, 403}:
        return "AUTHENTICATION_FAILED"
    if status_code == 429:
        return "RATE_LIMITED"
    name = type(exc).__name__.casefold()
    if "timeout" in name:
        return "TIMEOUT"
    failure_type = "" if failure is None else failure.error_type.casefold()
    if failure_type in {"schema", "parse", "malformed_response"}:
        return "STRUCTURED_OUTPUT_INVALID"
    if failure_type == "timeout":
        return "TIMEOUT"
    if failure_type == "rate_limit":
        return "RATE_LIMITED"
    if isinstance(exc, (ValidationError, ValueError)):
        return "STRUCTURED_OUTPUT_INVALID"
    if isinstance(exc, ModelGatewayError):
        return "MODEL_GATEWAY_ERROR"
    return "API_FAILURE_UNCLASSIFIED"


def _safe_attempts(exc: BaseException) -> list[dict[str, Any]]:
    failure = exc.failure if isinstance(exc, ModelGatewayError) else None
    if failure is None:
        return []
    return [item.model_dump(mode="json") for item in failure.attempts]


def _safe_run_id(identity: TaskIdentity) -> str:
    digest = _canonical_sha256(identity.model_dump(mode="json"))[:16]
    return f"reverse-api-{identity.arm}-r{identity.repeat_id}-{digest}"


def _request_record(
    slot: ApiRunSlot,
    identity: TaskIdentity,
    prompt: str,
    evidence_case: dict[str, Any],
    safety_observation: dict[str, Any],
    allowed_refs: set[str],
) -> tuple[dict[str, Any], str]:
    public = {
        "schema_version": "1.0",
        "task_identity": identity.model_dump(mode="json"),
        "slot": slot.to_dict(),
        "provider": "deepseek",
        "base_url": "https://api.deepseek.com",
        "model": "deepseek-v4-flash",
        "prompt_version": "reverse-api-slot-v1",
        "question": prompt,
        "question_sha256": _text_sha256(prompt),
        "sealed_evidence_case_sha256": _canonical_sha256(evidence_case),
        "allowed_evidence_refs": sorted(allowed_refs),
        "gold_read": False,
        "sibling_runs_read": False,
        "safety_observation": safety_observation,
    }
    return {**public, "public_request_sha256": _canonical_sha256(public)}, _canonical_sha256(public)


def _system_prompt() -> str:
    return (
        "你是面向网络安全负责人和研发负责人的逆向分析报告撰写人。"
        "不要输出、复述或存储隐藏思维链、reasoning_content 或 chain_of_thought。"
        "只基于当前用户消息内的一道题和一个封存证据包；不得猜测未提供的运行时事实，"
        "不得将静态导入升级为运行时调用。返回完整的 SecurityBusinessReport JSON。"
        "task_identity 与 model_receipt_ref 必须使用用户消息提供的值，所有 evidence_refs 必须来自允许列表。"
        "必须提供 scoring_claims：status 与 execution_status 相同；facts 为明确机器可评分事实，"
        "behaviors 为去重 snake_case 行为 ID，error 仅使用允许的闭合错误码或 null。"
    )


def _user_prompt(
    identity: TaskIdentity,
    prompt: str,
    evidence_case: dict[str, Any],
    allowed_refs: set[str],
) -> str:
    return json.dumps(
        {
            "task_identity": identity.model_dump(mode="json"),
            "model_receipt_ref": "receipt.json",
            "question": prompt,
            "sealed_evidence": evidence_case,
            "allowed_evidence_refs": sorted(allowed_refs),
            "evidence_boundary": "Evidence is static or emulated unless the packet explicitly says observed_runtime.",
            "machine_scoring_contract": {
                "status": "must equal execution_status",
                "facts": "only explicit normalized facts; lists preserve all values",
                "behaviors": "unique snake_case identifiers",
                "error": "closed error code or null",
            },
        },
        ensure_ascii=False,
        sort_keys=True,
    )


def _write_artifacts(
    output_dir: Path,
    *,
    slot: ApiRunSlot,
    identity: TaskIdentity,
    request: dict[str, Any],
    response: dict[str, Any],
    receipt: dict[str, Any],
    report: SecurityBusinessReport,
    source_semantics: dict[str, object],
    active_secret: str,
) -> dict[str, Path]:
    """Render first, then create the directory only if every report is safe."""

    for payload in (request, response, receipt):
        assert_safe_deliverable_payload(payload, active_secret=active_secret)
    rendered_report_json = render_case_json(
        report,
        slot=slot,
        receipt_ref=report.model_receipt_ref,
        source_semantics=source_semantics,
        active_secret=active_secret,
    )
    rendered_report_markdown = render_case_markdown(
        report,
        slot=slot,
        receipt_ref=report.model_receipt_ref,
        source_semantics=source_semantics,
        active_secret=active_secret,
    )
    rendered_report_html = render_case_html(
        report,
        slot=slot,
        receipt_ref=report.model_receipt_ref,
        source_semantics=source_semantics,
        active_secret=active_secret,
    )
    output_dir.mkdir(parents=True, exist_ok=False)
    payloads: dict[str, bytes] = {
        "request.json": _json_bytes(request),
        "response.json": _json_bytes(response),
        "receipt.json": _json_bytes(receipt),
        "report.json": rendered_report_json.encode("utf-8"),
        "report.md": rendered_report_markdown.encode("utf-8"),
        "report.html": rendered_report_html.encode("utf-8"),
    }
    paths = {name: output_dir / name for name in ARTIFACT_NAMES}
    for name, content in payloads.items():
        paths[name].write_bytes(content)
    seal = {
        "schema_version": "1.0",
        "suite_id": identity.suite_id,
        "arm": slot.arm,
        "case_id": slot.case_id,
        "repeat_id": slot.repeat_id,
        "request_sha256": _file_sha256(paths["request.json"]),
        "response_sha256": _file_sha256(paths["response.json"]),
        "receipt_sha256": _file_sha256(paths["receipt.json"]),
        "report_json_sha256": _file_sha256(paths["report.json"]),
        "report_md_sha256": _file_sha256(paths["report.md"]),
        "report_html_sha256": _file_sha256(paths["report.html"]),
    }
    paths["seal.json"].write_bytes(_json_bytes(seal))
    return paths


def _quarantined_attempt_metadata(value: object) -> list[dict[str, int | bool | None]]:
    """Retain only non-sensitive timing/status metadata from a rejected run."""

    if not isinstance(value, list):
        return []
    attempts: list[dict[str, int | bool | None]] = []
    for index, item in enumerate(value, start=1):
        if not isinstance(item, dict):
            continue
        ordinal = item.get("ordinal")
        status_code = item.get("status_code")
        duration_ms = item.get("duration_ms")
        attempts.append(
            {
                "ordinal": ordinal if isinstance(ordinal, int) else index,
                "status_code": status_code if isinstance(status_code, int) else None,
                "duration_ms": duration_ms if isinstance(duration_ms, int) else 0,
                "retryable": bool(item.get("retryable", False)),
            }
        )
    return attempts


def _receipt_attempts(value: object) -> list[dict[str, Any]]:
    """Retain receipt-safe attempt accounting in a scorer-verifiable form."""

    raw = value if isinstance(value, list) else []
    attempts: list[dict[str, Any]] = []
    for ordinal, item in enumerate(raw, start=1):
        if not isinstance(item, dict):
            continue
        duration = item.get("duration_ms")
        provider_usage = _safe_model_usage(item.get("provider_reported_usage"))
        conservative_usage = _safe_model_usage(item.get("conservative_reserved_usage"))
        raw_usage = _safe_model_usage(item.get("usage"))
        # ModelAttemptSummary carries the settled value as the sum of these
        # two provenance lanes; use a direct settled field only when a future
        # compatible gateway supplies one.
        usage = raw_usage if raw_usage.provider_requests else merge_usage(provider_usage, conservative_usage)
        provider_request = any(
            candidate.provider_requests > 0 for candidate in (usage, provider_usage, conservative_usage)
        )
        attempts.append(
            {
                "ordinal": ordinal,
                # The schema-validation diagnostic mirrors the provider
                # duration. It is not a second paid request and must not
                # inflate latency or retry accounting.
                "duration_ms": duration if provider_request and isinstance(duration, int) and duration >= 0 else 0,
                "retryable": bool(item.get("retryable", False)),
                "status_code": item.get("status_code") if isinstance(item.get("status_code"), int) else None,
                "provider_request": provider_request,
                "provider_request_id": item.get("provider_request_id")
                if isinstance(item.get("provider_request_id"), str)
                else None,
                "logical_call_id": item.get("logical_call_id")
                if isinstance(item.get("logical_call_id"), str)
                else None,
                "request_digest": item.get("request_digest") if _is_sha256(item.get("request_digest")) else None,
                "response_digest": item.get("response_digest") if _is_sha256(item.get("response_digest")) else None,
                "usage": usage.model_dump(mode="json"),
                "provider_reported_usage": provider_usage.model_dump(mode="json"),
                "conservative_reserved_usage": conservative_usage.model_dump(mode="json"),
                "unknown_usage": bool(item.get("unknown_usage", False)),
            }
        )
    return attempts


def _safe_model_usage(value: object) -> ModelUsage:
    """Parse only bounded public usage counters from gateway diagnostics."""

    try:
        return ModelUsage.model_validate(value)
    except ValidationError:
        return ModelUsage()


def _provider_attempt_count(attempts: list[dict[str, Any]]) -> int:
    """Count provider calls, not local diagnostics such as schema validation."""

    return sum(bool(item.get("provider_request", True)) for item in attempts)


def _attempt_usage(attempts: list[dict[str, Any]], field: str) -> ModelUsage:
    return merge_usage(*(_safe_model_usage(item.get(field)) for item in attempts))


def _attempt_usage_provenance(attempts: list[dict[str, Any]]) -> dict[str, Any]:
    """Seal reported/conservative provenance so an unknown is never a silent zero."""

    return {
        "provider_reported_usage": _attempt_usage(attempts, "provider_reported_usage").model_dump(mode="json"),
        "conservative_reserved_usage": _attempt_usage(attempts, "conservative_reserved_usage").model_dump(
            mode="json"
        ),
        "unknown_usage_attempts": sum(bool(item.get("unknown_usage", False)) for item in attempts),
    }


def _failure_receipt_identity(
    exc: BaseException, attempts: list[dict[str, Any]]
) -> tuple[str | None, str | None, str | None]:
    """Recover only hash-bound provider identity already present in diagnostics."""

    failure = exc.failure if isinstance(exc, ModelGatewayError) else None
    provider_attempt = next((item for item in reversed(attempts) if item.get("provider_request")), None)
    if not isinstance(provider_attempt, dict):
        return None, None, None
    request_digest = provider_attempt.get("request_digest")
    response_digest = provider_attempt.get("response_digest")
    if not _is_sha256(request_digest) or not _is_sha256(response_digest):
        return None, None, None
    receipt_id = None if failure is None else failure.logical_call_id
    if not receipt_id:
        receipt_id = provider_attempt.get("provider_request_id") or response_digest
    return (
        receipt_id if isinstance(receipt_id, str) and receipt_id else None,
        str(request_digest),
        str(response_digest),
    )


def _response_bound_receipt_identity(
    *, logical_call_id: object, attempts: list[dict[str, Any]], fallback_response_sha256: object
) -> tuple[str | None, str, str]:
    """Bind a successful receipt to the final persisted provider attempt.

    Gateway-level request hashes can describe an internal structured-call
    envelope.  The sealed receipt instead uses the final outbound attempt
    digest, matching the auditable attempt ledger and response digest.
    """

    provider_attempt = next((item for item in reversed(attempts) if item.get("provider_request")), None)
    if not isinstance(provider_attempt, dict):
        raise ValueError("successful provider response has no provider attempt")
    request_digest = provider_attempt.get("request_digest")
    response_digest = provider_attempt.get("response_digest")
    if not _is_sha256(request_digest) or not _is_sha256(response_digest):
        raise ValueError("successful provider response has incomplete attempt identity")
    if _is_sha256(fallback_response_sha256) and fallback_response_sha256 != response_digest:
        raise ValueError("successful provider response identity disagrees with the final attempt")
    receipt_id = logical_call_id if isinstance(logical_call_id, str) and logical_call_id else response_digest
    return str(receipt_id), str(request_digest), str(response_digest)


def _received_meta_receipt_identity(meta: Any, attempts: list[dict[str, Any]]) -> tuple[str, str, str]:
    """Recover safe receipt bindings from a validated successful gateway result.

    This narrow fallback is intentionally independent of the normal receipt
    helper: an exception while constructing a local receipt must not discard a
    completed provider attempt or recategorize it as an unknown provider
    outcome.
    """

    provider_attempt = next((item for item in reversed(attempts) if item.get("provider_request")), None)
    if not isinstance(provider_attempt, dict):
        raise ValueError("successful gateway metadata has no provider attempt")
    request_digest = provider_attempt.get("request_digest")
    response_digest = provider_attempt.get("response_digest")
    if not _is_sha256(request_digest) or not _is_sha256(response_digest):
        raise ValueError("successful gateway metadata has incomplete attempt identity")
    fallback_response_sha256 = getattr(meta, "response_sha256", None)
    if _is_sha256(fallback_response_sha256) and fallback_response_sha256 != response_digest:
        raise ValueError("successful gateway metadata response identity disagrees with attempt")
    logical_call_id = getattr(meta, "logical_call_id", None)
    receipt_id = logical_call_id if isinstance(logical_call_id, str) and logical_call_id else response_digest
    return str(receipt_id), str(request_digest), str(response_digest)


def _local_post_response_failure_payload(
    *,
    identity: TaskIdentity,
    receipt: dict[str, Any],
    public_request_sha256: str,
    diagnostic_code: str,
) -> tuple[SecurityBusinessReport, dict[str, Any], dict[str, Any]]:
    """Replace a local post-response result without exposing exception details."""

    if diagnostic_code not in {
        "POST_RESPONSE_RECEIPT_FAILURE",
        "POST_RESPONSE_ARTIFACT_FAILURE",
        "POST_RESPONSE_QUARANTINE_FAILURE",
    }:
        raise ValueError("local post-response diagnostic code is invalid")
    report = build_unavailable_business_report(
        task_identity=identity,
        model_receipt_ref="receipt.json",
        api_failure_type="LOCAL_POST_RESPONSE_FAILURE",
        human_impact=(
            "模型响应已收到，但本地报告处理未完成；在独立人工验证前，不应仅依据本次运行执行隔离、封禁或升级处置。"
        ),
        evidence_refs=[],
    )
    safe_receipt = {
        **receipt,
        "execution_status": "unavailable",
        "public_request_sha256": public_request_sha256,
        "error_type": "LOCAL_POST_RESPONSE_FAILURE",
        "local_diagnostic": {"code": diagnostic_code},
    }
    safe_response = {
        "schema_version": "1.0",
        "task_identity": identity.model_dump(mode="json"),
        "execution_status": "unavailable",
        "model_response_sha256": safe_receipt.get("model_response_sha256"),
        "error_type": "LOCAL_POST_RESPONSE_FAILURE",
        "report": report.model_dump(mode="json"),
    }
    return report, safe_response, safe_receipt


def _write_emergency_local_post_response_bundle(
    output_dir: Path,
    *,
    slot: ApiRunSlot,
    identity: TaskIdentity,
    request: dict[str, Any],
    receipt: dict[str, Any],
    public_request_sha256: str,
    source_semantics: dict[str, object],
    active_secret: str,
    diagnostic_code: str,
) -> tuple[SecurityBusinessReport, dict[str, Any], dict[str, Any], dict[str, Path]]:
    """Write one safe replacement after a known-provider local failure.

    This code receives no exception object and constructs no content from the
    model report.  It rejects a partially created directory rather than
    overwriting it, so the only published result is the ordinary sealed bundle.
    """

    if output_dir.exists():
        raise FileExistsError("local post-response fallback refuses a partial output directory")
    report, response, safe_receipt = _local_post_response_failure_payload(
        identity=identity,
        receipt=receipt,
        public_request_sha256=public_request_sha256,
        diagnostic_code=diagnostic_code,
    )
    artifacts = _write_artifacts(
        output_dir,
        slot=slot,
        identity=identity,
        request=request,
        response=response,
        receipt=safe_receipt,
        report=report,
        source_semantics=source_semantics,
        active_secret=active_secret,
    )
    return report, response, safe_receipt, artifacts


def _receipt_usage(usage: ModelUsage, attempts: list[dict[str, Any]]) -> dict[str, int | float]:
    """Make provider-request count agree with the persisted attempt ledger."""

    return usage.model_dump(mode="json") | {
        "provider_requests": _provider_attempt_count(attempts),
        "total_tokens": usage.total_tokens,
    }


def _quarantine_unsafe_model_payload(
    *,
    identity: TaskIdentity,
    public_request_sha256: str,
    receipt: dict[str, Any],
    priced_at: datetime,
) -> tuple[SecurityBusinessReport, dict[str, Any], dict[str, Any]]:
    """Discard unsafe model content while retaining a sealed failure record."""

    # The runner has already constructed these attempt records from typed,
    # secret-free gateway diagnostics. Retain them so an unsafe report body
    # cannot erase paid-request accounting or provenance.
    raw_attempts = receipt.get("attempts")
    attempts = [dict(item) for item in raw_attempts if isinstance(item, dict)] if isinstance(raw_attempts, list) else []
    usage = receipt.get("usage")
    pricing = receipt.get("pricing")
    provenance = receipt.get("usage_provenance")
    safe_usage = usage if isinstance(usage, dict) else _receipt_usage(ModelUsage(), attempts)
    safe_pricing = (
        pricing
        if isinstance(pricing, dict)
        else estimate_deepseek_v4_flash_cny(ModelUsage(), priced_at=priced_at)
    )
    report = build_unavailable_business_report(
        task_identity=identity,
        model_receipt_ref="receipt.json",
        api_failure_type="UNSAFE_MODEL_PAYLOAD",
        human_impact=(
            "自动化结论不可用且已隔离，无法用于处置；在完成独立人工验证前，不应仅依据本次运行执行隔离、封禁或升级处置。"
        ),
        evidence_refs=[],
    )
    safe_receipt = {
        "schema_version": "1.0",
        "task_identity": identity.model_dump(mode="json"),
        "execution_status": "unavailable",
        "provider": "deepseek",
        "base_url": "https://api.deepseek.com",
        "model": "deepseek-v4-flash",
        "model_receipt_id": receipt.get("model_receipt_id"),
        "model_request_sha256": receipt.get("model_request_sha256"),
        "model_response_sha256": receipt.get("model_response_sha256"),
        "public_request_sha256": public_request_sha256,
        "latency_ms": receipt.get("latency_ms", sum(int(item.get("duration_ms", 0)) for item in attempts)),
        "retry_count": receipt.get("retry_count", max(0, _provider_attempt_count(attempts) - 1)),
        "attempts": attempts,
        "error_type": "UNSAFE_MODEL_PAYLOAD",
        "usage": safe_usage,
        "pricing": safe_pricing,
        "usage_provenance": provenance if isinstance(provenance, dict) else _attempt_usage_provenance(attempts),
    }
    safe_response = {
        "schema_version": "1.0",
        "task_identity": identity.model_dump(mode="json"),
        "execution_status": "unavailable",
        "model_response_sha256": receipt.get("model_response_sha256"),
        "error_type": "UNSAFE_MODEL_PAYLOAD",
        "report": report.model_dump(mode="json"),
    }
    return report, safe_response, safe_receipt


async def run_api_slot(
    slot: ApiRunSlot,
    *,
    manifest_path: Path,
    evidence_path: Path,
    evidence_seal_path: Path,
    output_root: Path,
    settings: Settings,
    client: httpx.AsyncClient | None = None,
    priced_at: datetime | None = None,
    max_output_attempts: int = 1,
) -> ApiSlotResult:
    """Run one sealed case through DeepSeek and persist a seven-file bundle.

    Model output quality is stochastic: the same sealed prompt can yield
    valid JSON on one call and a malformed or unsafe answer on the next.
    Provider transport can also fail transiently (``MODEL_GATEWAY_ERROR``).
    ``max_output_attempts`` bounds how many provider calls are made before a
    slot is declared unavailable, so transient output-integrity failures
    (``STRUCTURED_OUTPUT_INVALID`` / ``UNSAFE_MODEL_PAYLOAD``) and transport
    failures (``MODEL_GATEWAY_ERROR``) are retried instead of failing the
    slot.  Provider accounting from every attempt is merged into the
    persisted receipt.
    """

    validate_deepseek_identity(settings)
    approved_output_root = _validate_input_boundary(
        slot,
        manifest_path=manifest_path,
        evidence_path=evidence_path,
        evidence_seal_path=evidence_seal_path,
        output_root=output_root,
    )
    output_dir = _confined_output_dir(approved_output_root, slot)
    prompt, _manifest_case, evidence, evidence_case, identity = _require_slot_case(
        slot, manifest_path, evidence_path, evidence_seal_path
    )
    evidence_dto = _public_evidence_projection(evidence_case, evidence, identity)
    model_evidence_case = evidence_dto.case
    allowed_refs = evidence_dto.allowed_refs
    source_semantics = evidence_dto.source_semantics
    # This is the last boundary before the model request.  Facts/events remain
    # analytically useful, but credentials, paths, and high-entropy secrets
    # still fail closed instead of being silently rewritten.
    assert_safe_deliverable_payload(
        model_evidence_case,
        active_secret=settings.model_api_key_value("deepseek"),
    )
    request, public_request_sha256 = _request_record(
        slot,
        identity,
        prompt,
        evidence_case,
        _safety_observation(evidence, identity, aliases=evidence_dto.aliases, reverse=evidence_dto.reverse),
        allowed_refs,
    )
    if output_dir.exists():
        raise FileExistsError(f"API slot output already exists: {output_dir}")

    accumulated_attempts: list[dict[str, Any]] = []
    active_secret = settings.model_api_key_value("deepseek")
    max_attempts = max(1, max_output_attempts)
    for attempt_index in range(max_attempts):
        response: dict[str, Any]
        receipt: dict[str, Any]
        received_meta: Any | None = None
        model_receipt_id: str | None = None
        model_request_sha256: str | None = None
        model_response_sha256: str | None = None
        post_response_phase = "before_response"
        gateway = QwenGateway(settings, client)
        try:
            report, meta = await gateway.structured(
                role="planner",
                system_prompt=_system_prompt(),
                user_prompt=_user_prompt(identity, prompt, model_evidence_case, allowed_refs),
                output_model=SecurityBusinessReport,
                prompt_version="reverse-api-slot-v1",
                run_id=_safe_run_id(identity),
                task_kind="reasoning",
                thinking_enabled=False,
            )
            received_meta = meta
            post_response_phase = "report_validation"
            if report.task_identity != identity:
                raise ValueError("model task identity does not match the API slot")
            report = report.model_copy(update={"model_receipt_ref": "receipt.json"})
            if _invalid_evidence_refs(report, allowed_refs):
                report = _limit_report_to_allowed_refs(report, allowed_refs)
            attempts = _receipt_attempts(
                accumulated_attempts + [item.model_dump(mode="json") for item in meta.attempts]
            )
            settled_usage = _attempt_usage(attempts, "usage")
            post_response_phase = "receipt_binding"
            model_receipt_id, model_request_sha256, model_response_sha256 = _response_bound_receipt_identity(
                logical_call_id=meta.logical_call_id,
                attempts=attempts,
                fallback_response_sha256=meta.response_sha256,
            )
            receipt = {
                "schema_version": "1.0",
                "task_identity": identity.model_dump(mode="json"),
                "execution_status": report.execution_status,
                "provider": "deepseek",
                "base_url": "https://api.deepseek.com",
                "model": "deepseek-v4-flash",
                "model_receipt_id": model_receipt_id,
                "model_request_sha256": model_request_sha256,
                "model_response_sha256": model_response_sha256,
                "public_request_sha256": public_request_sha256,
                "latency_ms": sum(int(item["duration_ms"]) for item in attempts),
                "retry_count": max(0, _provider_attempt_count(attempts) - 1),
                "attempts": attempts,
                "error_type": None,
                "usage": _receipt_usage(settled_usage, attempts),
                "pricing": estimate_deepseek_v4_flash_cny(settled_usage, priced_at=priced_at or datetime.now(UTC)),
                "usage_provenance": _attempt_usage_provenance(attempts),
            }
            response = {
                "schema_version": "1.0",
                "task_identity": identity.model_dump(mode="json"),
                "execution_status": report.execution_status,
                "model_response_sha256": model_response_sha256,
                "report": report.model_dump(mode="json"),
            }
        except Exception as exc:  # noqa: BLE001 - unavailable still requires a complete business record
            code = (
                "LOCAL_POST_RESPONSE_FAILURE"
                if received_meta is not None and post_response_phase == "receipt_binding"
                else _failure_code(exc)
            )
            attempt_records = _safe_attempts(exc)
            if not attempt_records and received_meta is not None:
                attempt_records = [item.model_dump(mode="json") for item in received_meta.attempts]
            accumulated_attempts.extend(attempt_records)
            await gateway.close()
            if code in _RETRYABLE_OUTPUT_CODES and attempt_index + 1 < max_attempts:
                if code == "MODEL_GATEWAY_ERROR":
                    await _retry_backoff(attempt_index)
                continue
            report = build_unavailable_business_report(
                task_identity=identity,
                model_receipt_ref="receipt.json",
                api_failure_type=code,
                human_impact=("自动化结论不可用；在完成独立人工验证前，不应仅依据本次运行执行隔离、封禁或升级处置。"),
                evidence_refs=[],
            )
            attempts = _receipt_attempts(accumulated_attempts)
            accounted_usage = _attempt_usage(attempts, "usage")
            model_receipt_id, model_request_sha256, model_response_sha256 = _failure_receipt_identity(exc, attempts)
            if received_meta is not None:
                if code == "LOCAL_POST_RESPONSE_FAILURE":
                    model_receipt_id, model_request_sha256, model_response_sha256 = _received_meta_receipt_identity(
                        received_meta, attempts
                    )
                else:
                    model_receipt_id, model_request_sha256, model_response_sha256 = _response_bound_receipt_identity(
                        logical_call_id=received_meta.logical_call_id,
                        attempts=attempts,
                        fallback_response_sha256=received_meta.response_sha256,
                    )
            receipt = {
                "schema_version": "1.0",
                "task_identity": identity.model_dump(mode="json"),
                "execution_status": "unavailable",
                "provider": "deepseek",
                "base_url": "https://api.deepseek.com",
                "model": "deepseek-v4-flash",
                "model_receipt_id": model_receipt_id,
                "model_request_sha256": model_request_sha256,
                "model_response_sha256": model_response_sha256,
                "public_request_sha256": public_request_sha256,
                "latency_ms": sum(int(item["duration_ms"]) for item in attempts),
                "retry_count": max(0, _provider_attempt_count(attempts) - 1),
                "attempts": attempts,
                "error_type": code,
                "usage": _receipt_usage(accounted_usage, attempts),
                "pricing": estimate_deepseek_v4_flash_cny(accounted_usage, priced_at=priced_at or datetime.now(UTC)),
                "usage_provenance": _attempt_usage_provenance(attempts),
            }
            if code == "LOCAL_POST_RESPONSE_FAILURE":
                receipt["local_diagnostic"] = {"code": "POST_RESPONSE_RECEIPT_FAILURE"}
            response = {
                "schema_version": "1.0",
                "task_identity": identity.model_dump(mode="json"),
                "execution_status": "unavailable",
                "model_response_sha256": model_response_sha256,
                "error_type": code,
                "report": report.model_dump(mode="json"),
            }
        await gateway.close()
        try:
            artifacts = await asyncio.to_thread(
                _write_artifacts,
                output_dir,
                slot=slot,
                identity=identity,
                request=request,
                response=response,
                receipt=receipt,
                report=report,
                source_semantics=source_semantics,
                active_secret=active_secret,
            )
        except UnsafeDeliverableError:
            if received_meta is not None and attempt_index + 1 < max_attempts:
                accumulated_attempts.extend(item.model_dump(mode="json") for item in received_meta.attempts)
                continue
            try:
                report, response, receipt = _quarantine_unsafe_model_payload(
                    identity=identity,
                    public_request_sha256=public_request_sha256,
                    receipt=receipt,
                    priced_at=priced_at or datetime.now(UTC),
                )
                artifacts = await asyncio.to_thread(
                    _write_artifacts,
                    output_dir,
                    slot=slot,
                    identity=identity,
                    request=request,
                    response=response,
                    receipt=receipt,
                    report=report,
                    source_semantics=source_semantics,
                    active_secret=active_secret,
                )
            except Exception:  # noqa: BLE001 - a nested fallback must retain known provider accounting
                report, response, receipt, artifacts = await asyncio.to_thread(
                    _write_emergency_local_post_response_bundle,
                    output_dir,
                    slot=slot,
                    identity=identity,
                    request=request,
                    receipt=receipt,
                    public_request_sha256=public_request_sha256,
                    source_semantics=source_semantics,
                    active_secret=active_secret,
                    diagnostic_code="POST_RESPONSE_QUARANTINE_FAILURE",
                )
        except Exception:  # noqa: BLE001 - only a fixed local diagnostic crosses the artifact boundary
            report, response, receipt, artifacts = await asyncio.to_thread(
                _write_emergency_local_post_response_bundle,
                output_dir,
                slot=slot,
                identity=identity,
                request=request,
                receipt=receipt,
                public_request_sha256=public_request_sha256,
                source_semantics=source_semantics,
                active_secret=active_secret,
                diagnostic_code="POST_RESPONSE_ARTIFACT_FAILURE",
            )
        return ApiSlotResult(slot=slot, report=report, output_dir=output_dir, artifacts=artifacts)


__all__ = ["ARTIFACT_NAMES", "ApiSlotResult", "run_api_slot"]
