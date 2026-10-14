"""Stable identities shared by model-gateway persistence and diagnostics."""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_sha256(value: Any) -> str:
    """Hash canonical JSON without changing the historical digest contract."""

    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def legacy_selection_digest(*, prompt_version: str, role: str = "legacy", task_kind: str = "legacy") -> str:
    """Return a metadata-only selector identity for legacy/unbound calls."""

    return canonical_sha256(
        {
            "lineage": "legacy_unbound_prompt",
            "prompt_version": prompt_version,
            "role": role,
            "task_kind": task_kind,
        }
    )


def lineage_stage(*, used_fallback: bool, repair_index: int) -> str:
    if used_fallback and repair_index > 0:
        return "fallback_repair"
    if used_fallback:
        return "fallback"
    if repair_index > 0:
        return "repair"
    return "primary"


def recovery_kind(
    *,
    used_fallback: bool,
    repair_index: int,
    fallback_guidance: str | None,
    primary_model_id: str,
    model_id: str,
) -> str:
    """Classify recovery without conflating syntax repair and semantic retry."""

    if used_fallback and fallback_guidance in {"schema", "parse"}:
        return "syntax_repair"
    if repair_index > 0:
        return "syntax_repair"
    if not used_fallback:
        return "primary"
    if primary_model_id == model_id:
        return "fallback_non_independent"
    return "semantic_fallback"


def recovery_independence(*, recovery_kind: str, same_model_lineage: bool = False) -> str:
    if same_model_lineage and recovery_kind != "primary":
        return "non_independent"
    if recovery_kind == "semantic_fallback":
        return "independent"
    if recovery_kind == "fallback_non_independent":
        return "non_independent"
    return "not_applicable"


def raw_response_slot_id(
    *,
    run_id: str,
    logical_call_id: str,
    model_id: str,
    candidate_index: int,
    repair_index: int,
    provider_request_sha256: str,
) -> str:
    return canonical_sha256(
        {
            "run_id": run_id,
            "logical_call_id": logical_call_id,
            "model_id": model_id,
            "candidate_index": candidate_index,
            "repair_index": repair_index,
            "provider_request_sha256": provider_request_sha256,
        }
    )
