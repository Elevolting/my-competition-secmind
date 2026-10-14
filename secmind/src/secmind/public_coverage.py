"""Bounded projection of internal audit coverage for public reports.

The durable ``AgentState.audit_coverage`` intentionally contains replay data
such as candidate records, typed deltas and EIRS observations.  Those objects
belong in the control plane and content-addressed artifacts; embedding them in
``AgentReport.coverage`` duplicates megabytes of state and can make a report
read slower than the investigation itself.

This module is deliberately independent from the orchestrator and admission
layers so both terminal boundaries use exactly the same projection policy.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from enum import Enum
from typing import Any

PUBLIC_COVERAGE_MAX_BYTES = 256 * 1024
PUBLIC_VALUE_MAX_DEPTH = 7
PUBLIC_MAPPING_MAX_ITEMS = 96
PUBLIC_SEQUENCE_MAX_ITEMS = 64
PUBLIC_STRING_MAX_CHARS = 4096

# These keys contain replay/control-plane data.  Public reports retain a
# deterministic summary under the same key while the full value remains in the
# durable state or its referenced CAS artifact.
INTERNAL_COVERAGE_KEYS = frozenset(
    {
        "anchor_report",
        "candidate_store",
        "completion_proof",
        "delta_verification",
        "eirs_runtime",
        "enhanced_report",
        "failure_capsules",
        "independent_scout",
        "pre_primary_scenario_projection",
        "scenario_semantic_delta",
        "scenario_semantic_delta_receipt",
        "scenario_semantic_output",
        "scenario_projection",
        "typed_answer_runtime",
        "typed_deltas",
        "typed_semantic_deltas",
    }
)


def _json_default(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        return model_dump(mode="json")
    return str(value)


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=_json_default,
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _opaque_summary(value: Any, *, reason: str = "omitted_from_public_projection") -> dict[str, Any]:
    summary: dict[str, Any] = {
        "projection": "summary",
        "reason": reason,
        "sha256": _digest(value),
    }
    if isinstance(value, Mapping):
        summary["item_count"] = len(value)
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        summary["item_count"] = len(value)
    return summary


def _bounded(value: Any, *, depth: int = 0) -> Any:
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, str):
        if len(value) <= PUBLIC_STRING_MAX_CHARS:
            return value
        return {
            "projection": "truncated_string",
            "character_count": len(value),
            "prefix": value[:PUBLIC_STRING_MAX_CHARS],
            "sha256": hashlib.sha256(value.encode("utf-8")).hexdigest(),
        }
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        return {
            "projection": "binary_summary",
            "byte_count": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
        }
    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        value = model_dump(mode="json")
    if depth >= PUBLIC_VALUE_MAX_DEPTH:
        return _opaque_summary(value, reason="public_projection_depth_limit")
    if isinstance(value, Mapping):
        keys = sorted(((str(key), key) for key in value), key=lambda item: item[0])
        selected = keys[:PUBLIC_MAPPING_MAX_ITEMS]
        mapping_result = {text: _bounded(value[key], depth=depth + 1) for text, key in selected}
        if len(keys) > len(selected):
            mapping_result["__projection__"] = {
                "truncated": True,
                "item_count": len(keys),
                "emitted_count": len(selected),
                "sha256": _digest(value),
            }
        return mapping_result
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        selected = list(value[:PUBLIC_SEQUENCE_MAX_ITEMS])
        sequence_result = [_bounded(item, depth=depth + 1) for item in selected]
        if len(value) > len(selected):
            sequence_result.append(
                {
                    "projection": "truncated_sequence",
                    "item_count": len(value),
                    "emitted_count": len(selected),
                    "sha256": _digest(value),
                }
            )
        return sequence_result
    return str(value)[:PUBLIC_STRING_MAX_CHARS]


def _mapping_text(value: Mapping[str, Any], key: str) -> str | None:
    item = value.get(key)
    return item if isinstance(item, str) and item else None


def _internal_summary(key: str, value: Any) -> dict[str, Any]:
    base = _opaque_summary(value)
    if key == "scenario_semantic_delta_receipt" and isinstance(value, Mapping):
        # The full receipt repeats process provenance already present in the
        # typed semantic delta.  Retain only the self-authenticating scalar
        # identity needed to reconstruct and validate it at the Test3
        # boundary; never publish arbitrary receipt payload fields.
        for field in (
            "schema_version",
            "delta_schema_version",
            "run_id",
            "delta_id",
            "delta_digest",
            "semantic_digest",
            "process_id",
            "process_version",
            "operation",
            "process_digest",
            "admission_ready",
            "disposition",
            "anchor_preserved",
            "source_content_trust",
            "receipt_digest",
        ):
            if isinstance(value.get(field), (bool, int, float, str, type(None))):
                base[field] = value[field]
        return base
    if key == "typed_deltas" and isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        rows = [item for item in value if isinstance(item, Mapping)]
        base.update(
            {
                "delta_count": len(rows),
                "accepted_count": sum(str(item.get("disposition", "")) == "accepted" for item in rows),
                "quarantined_count": sum(str(item.get("disposition", "")) == "quarantined" for item in rows),
                "rejected_count": sum(str(item.get("disposition", "")) == "rejected" for item in rows),
            }
        )
        return base
    if (
        key == "typed_semantic_deltas"
        and isinstance(value, Sequence)
        and not isinstance(value, (str, bytes, bytearray))
    ):
        rows = [item for item in value if isinstance(item, Mapping)]
        base.update(
            {
                "delta_count": len(rows),
                "accepted_count": sum(str(item.get("disposition", "")) == "accepted" for item in rows),
                "rejected_count": sum(str(item.get("disposition", "")) == "rejected" for item in rows),
            }
        )
        return base
    if key == "typed_answer_runtime" and isinstance(value, Mapping):
        # Runtime answer revisions can contain exact values and provider text.
        # Keep only lifecycle counters/identity; the opaque digest above is
        # useful for replay without turning this control-plane field into a
        # second answer release channel.
        for field in ("schema_version", "runtime_id", "status", "revision_count", "published_revision_id"):
            field_value = value.get(field)
            if isinstance(field_value, (bool, int, float, str, type(None))):
                base[field] = field_value
        for field, target in (
            ("revisions", "revision_count"),
            ("proposals", "proposal_count"),
            ("deltas", "delta_count"),
        ):
            items = value.get(field)
            if isinstance(items, Sequence) and not isinstance(items, (str, bytes, bytearray)):
                base[target] = len(items)
        return base
    if key == "failure_capsules" and isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        base["capsule_count"] = len(value)
        return base
    if not isinstance(value, Mapping):
        return base
    if key == "candidate_store":
        records = value.get("records")
        events = value.get("events")
        quarantined = value.get("quarantined_candidate_ids")
        base.update(
            {
                "version": _mapping_text(value, "version"),
                "store_digest": _mapping_text(value, "store_digest"),
                "record_count": len(records) if isinstance(records, list) else 0,
                "event_count": len(events) if isinstance(events, list) else 0,
                "quarantined_count": len(quarantined) if isinstance(quarantined, list) else 0,
            }
        )
    elif key == "delta_verification":
        decisions = [item for item in value.values() if isinstance(item, bool)]
        base.update(
            {
                "decision_count": len(decisions),
                "verified_count": sum(decisions),
                "rejected_count": len(decisions) - sum(decisions),
            }
        )
    elif key == "eirs_runtime":
        plan = value.get("plan")
        result = value.get("result")
        base.update(
            {
                "status": _mapping_text(value, "status"),
                "reason": _mapping_text(value, "reason"),
                "result_digest": _mapping_text(value, "result_digest"),
                "plan_id": _mapping_text(plan, "plan_id") if isinstance(plan, Mapping) else None,
                "action_count": (
                    len(plan.get("actions", []))
                    if isinstance(plan, Mapping) and isinstance(plan.get("actions"), list)
                    else 0
                ),
                "observation_count": (
                    len(result.get("observations", []))
                    if isinstance(result, Mapping) and isinstance(result.get("observations"), list)
                    else 0
                ),
            }
        )
    elif key == "independent_scout":
        for field in ("ran", "scout_id", "candidate_count", "evidence_count", "reason", "digest"):
            if field in value and isinstance(value[field], (bool, int, float, str, type(None))):
                base[field] = value[field]
        for field in ("viewed_paths", "omitted_paths", "truncated_paths"):
            items = value.get(field)
            base[f"{field}_count"] = len(items) if isinstance(items, list) else 0
    elif key in {"anchor_report", "enhanced_report"}:
        for field in (
            "run_id",
            "schema_version",
            "sealed",
            "publishable",
            "precision_gate_met",
            "anchor_preserved",
            "anchor_report_digest",
            "anchor_semantic_digest",
            "semantic_digest",
            "reason",
            "artifact_id",
        ):
            if field in value and isinstance(value[field], (bool, int, float, str, type(None))):
                base[field] = value[field]
        for source, target in (
            ("findings", "finding_count"),
            ("evidence", "evidence_count"),
            ("deltas", "delta_count"),
            ("added_delta_ids", "added_delta_count"),
            ("corrected_delta_ids", "corrected_delta_count"),
            ("rejected_delta_ids", "rejected_delta_count"),
            ("quarantined_delta_ids", "quarantined_delta_count"),
        ):
            items = value.get(source)
            if isinstance(items, (list, tuple)):
                base[target] = len(items)
    return {key: item for key, item in base.items() if item is not None}


def public_coverage_projection(coverage: Mapping[str, Any]) -> dict[str, Any]:
    """Return a deterministic, size-bounded public coverage projection."""

    projected: dict[str, Any] = {}
    for key, value in sorted(((str(key), value) for key, value in coverage.items()), key=lambda item: item[0]):
        projected[key] = _internal_summary(key, value) if key in INTERNAL_COVERAGE_KEYS else _bounded(value)

    # Per-value limits handle normal operation.  This final pass is a hard
    # response-size guard for adversarial or future coverage fields: replace
    # the largest structured values until the complete object is bounded.
    while len(_canonical_bytes(projected)) > PUBLIC_COVERAGE_MAX_BYTES:
        candidates = [
            (len(_canonical_bytes(value)), key)
            for key, value in projected.items()
            if isinstance(value, (dict, list))
            and not (isinstance(value, dict) and value.get("projection") == "summary")
            if not isinstance(value, list) or value
        ]
        if not candidates:
            break
        _size, key = max(candidates)
        projected[key] = _opaque_summary(coverage.get(key), reason="public_coverage_byte_limit")
    return projected


__all__ = [
    "INTERNAL_COVERAGE_KEYS",
    "PUBLIC_COVERAGE_MAX_BYTES",
    "public_coverage_projection",
]
