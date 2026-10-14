"""Strict semantic projection boundary for deterministic non-code scenarios.

The scenario executor owns routing and CAS reads.  This module owns the
cross-domain output contract: source locators, evidence closure, raw/derived
artifact digests, process lineage and the one append-only semantic delta.  It
does not publish or replace an Anchor.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Sequence
from typing import Any, cast

from pydantic import BaseModel

from secmind.domain_answers import (
    DomainSemanticDelta,
    EvidenceClosure,
    ProcessProvenance,
    RecordLocator,
    ScenarioSemanticOutput,
    TypedSemanticDelta,
)
from secmind.schemas import SCHEMA_VERSION, AgentState, Evidence

SCENARIO_SEMANTIC_DELTA_RECEIPT_VERSION = "secmind-scenario-semantic-delta-receipt-v1"


def _receipt_digest(value: Any) -> str:
    """Digest one receipt component with the bridge's stable JSON rules."""

    return hashlib.sha256(
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()


def build_scenario_semantic_delta_receipt(delta: TypedSemanticDelta) -> dict[str, Any]:
    """Build the runtime-owned receipt consumed by the Test3 bridge.

    The delta remains the semantic payload.  This small receipt is an
    authority statement: every identity and disposition-bearing component is
    copied from the runtime-created delta and covered by a self-digest.  A
    provider can therefore not make a lookalike ``semantic_delta`` eligible
    merely by reproducing its semantic hash.
    """

    delta_payload = delta.model_dump(mode="json")
    process_payload = delta.process_provenance.model_dump(mode="json")
    receipt: dict[str, Any] = {
        "schema_version": SCENARIO_SEMANTIC_DELTA_RECEIPT_VERSION,
        "delta_schema_version": delta.schema_version,
        "run_id": delta.run_id,
        "delta_id": delta.delta_id,
        "delta_digest": _receipt_digest(delta_payload),
        "semantic_digest": delta.semantic_digest.lower(),
        "process_id": process_payload["process_id"],
        "process_version": process_payload["process_version"],
        "operation": process_payload["operation"],
        "process_digest": _receipt_digest(process_payload),
        "process_provenance": process_payload,
        "admission_ready": bool(delta.admission_ready),
        "disposition": delta.disposition,
        "anchor_preserved": bool(delta.anchor_preserved),
        "source_content_trust": delta.source_content_trust,
    }
    receipt["receipt_digest"] = _receipt_digest(receipt)
    return receipt


def _strict_record_locator(value: Any) -> RecordLocator | None:
    if not isinstance(value, dict):
        return None
    try:
        return RecordLocator.model_validate(value)
    except (TypeError, ValueError):
        return None


def _evidence_locator(item: Evidence) -> dict[str, Any] | None:
    locator = item.metadata.get("source_locator")
    return {str(key): value for key, value in locator.items()} if isinstance(locator, dict) else None


def _digest_values(metadata: dict[str, Any], *keys: str) -> set[str]:
    values: set[str] = set()
    for key in keys:
        value = metadata.get(key)
        if isinstance(value, str) and re.fullmatch(r"[a-fA-F0-9]{64}", value):
            values.add(value.lower())
        elif isinstance(value, (list, tuple)):
            values.update(
                str(item).lower() for item in value if isinstance(item, str) and re.fullmatch(r"[a-fA-F0-9]{64}", item)
            )
    return values


def _binding_digests(
    evidence_ids: Sequence[str],
    evidence_by_id: dict[str, Evidence],
) -> tuple[list[str], list[str]]:
    """Separate source bytes from derived projection digests without guessing."""

    raw: set[str] = set()
    derived: set[str] = set()
    for evidence_id in evidence_ids:
        item = evidence_by_id.get(str(evidence_id))
        if item is None:
            continue
        metadata = item.metadata
        raw.update(_digest_values(metadata, "source_artifact_sha256", "raw_artifact_sha256", "input_artifact_sha256"))
        derived.update(
            _digest_values(
                metadata,
                "event_content_sha256",
                "derived_artifact_sha256",
                "projection_sha256",
                "output_artifact_sha256",
            )
        )
        if isinstance(item.sha256, str) and re.fullmatch(r"[a-fA-F0-9]{64}", item.sha256):
            evidence_type = str(metadata.get("evidence_type") or "")
            if evidence_type in {"correlation_trace", "derived_projection", "exact_value_observation"}:
                derived.add(item.sha256.lower())
            else:
                raw.add(item.sha256.lower())
    return sorted(raw), sorted(derived)


def bind_evidence(
    evidence_ids: Sequence[str],
    evidence_by_id: dict[str, Evidence],
    *,
    fallback_locator: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return the compatibility binding plus strict closure diagnostics."""

    ids = sorted({str(item) for item in evidence_ids if str(item) in evidence_by_id})
    locators = [
        locator for evidence_id in ids if (locator := _evidence_locator(evidence_by_id[evidence_id])) is not None
    ]
    if not locators and fallback_locator is not None:
        locators = [dict(fallback_locator)]
    raw_digests, derived_digests = _binding_digests(ids, evidence_by_id)
    locator_model = _strict_record_locator(locators[0]) if locators else None
    missing: list[str] = []
    if not ids:
        missing.append("evidence_ids")
    if locator_model is None:
        missing.append("record_locator")
    if not raw_digests:
        missing.append("raw_artifact_digest")
    return {
        "evidence_ids": ids,
        "source_locator": locators[0] if locators else None,
        "source_locators": locators,
        "record_locator": locator_model.model_dump(mode="json") if locator_model is not None else None,
        "raw_artifact_digests": raw_digests,
        "derived_artifact_digests": derived_digests,
        "evidence_binding_status": "complete" if not missing else "partial",
        "evidence_binding_unknowns": missing,
    }


def _valid_digests(values: Sequence[Any]) -> list[str]:
    return sorted(
        {str(value).lower() for value in values if isinstance(value, str) and re.fullmatch(r"[a-fA-F0-9]{64}", value)}
    )


def _scenario_input_digests(state: AgentState) -> list[str]:
    values: list[Any] = [item.sha256 for item in state.input_artifacts]
    for evidence in state.evidence:
        values.append(evidence.sha256)
        source_digest = evidence.metadata.get("source_artifact_sha256")
        if source_digest is not None:
            values.append(source_digest)
    return _valid_digests(values)


def _row_values(answer: Any, field_name: str) -> list[dict[str, Any]]:
    rows = getattr(answer, field_name, [])
    if not isinstance(rows, list):
        return []
    return [
        row.model_dump(mode="json") if isinstance(row, BaseModel) else dict(row)
        for row in rows
        if isinstance(row, (BaseModel, dict))
    ]


def _answer_evidence_rows(answer: Any) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for field_name in (
        "facts",
        "inferences",
        "events",
        "actors",
        "iocs",
        "techniques",
        "tactics",
        "gaps",
        "items",
        "findings",
        "observations",
        "known",
        "conflicts",
        "blocked_claims",
        "next_evidence",
        "evidence",
        "behaviors",
        "persistence",
        "injection",
        "evasion",
    ):
        rows.extend(_row_values(answer, field_name))
    values = getattr(answer, "values", None)
    if isinstance(values, dict):
        for candidate in values.values():
            if isinstance(candidate, list):
                rows.extend(dict(item) for item in candidate if isinstance(item, dict))
    return rows


def _answer_evidence_ids(answer: Any) -> list[str]:
    identifiers: set[str] = set()
    for row in _answer_evidence_rows(answer):
        values = row.get("evidence_ids", [])
        if isinstance(values, (list, tuple)):
            identifiers.update(str(item) for item in values if str(item))
    derivation = getattr(answer, "derivation", [])
    if isinstance(derivation, list):
        for row in derivation:
            if isinstance(row, dict) and isinstance(row.get("evidence_ids"), list):
                identifiers.update(str(item) for item in row["evidence_ids"] if str(item))
    return sorted(identifiers)


def _answer_unknowns(answer: Any) -> list[str]:
    values: set[str] = {str(item) for item in getattr(answer, "unknowns", []) if str(item)}
    for row in _answer_evidence_rows(answer):
        for key in ("evidence_binding_unknowns", "unknowns"):
            candidate = row.get(key)
            if isinstance(candidate, (list, tuple)):
                values.update(str(item) for item in candidate if str(item))
    for row in _row_values(answer, "gaps"):
        for key in ("code", "gap", "message"):
            if row.get(key):
                values.add(str(row[key]))
    ordered = sorted(values)
    if len(ordered) <= 2_000:
        return ordered
    return [*ordered[:1_999], "semantic_unknowns_truncated"]


def _answer_semantic_facts(answer: Any) -> tuple[dict[str, Any], ...]:
    """Keep exact values and finding/observation rows in the shared fact lane."""

    facts = [
        dict(row) for row in [*getattr(answer, "facts", []), *getattr(answer, "known", [])] if isinstance(row, dict)
    ]
    for field_name in ("findings", "observations", "items", "behaviors", "persistence", "injection", "evasion"):
        for row in _row_values(answer, field_name):
            facts.append({"semantic_source": field_name, **row})
    for row in _row_values(answer, "tactics"):
        facts.append({"semantic_source": "tactic_hypothesis", **row})
    values = getattr(answer, "values", None)
    if values is not None:
        facts.append({"semantic_source": "exact_values", "value": values})
    mitre_attack = getattr(answer, "mitre_attack", None)
    if isinstance(mitre_attack, list) and mitre_attack:
        facts.append({"semantic_source": "mitre_attack", "values": list(mitre_attack)})
    # Incident hypotheses live in the typed extension because they are shared
    # by TimelineAnswer and EvidenceGapAnswer.  Promote them into the common
    # fact lane so ScenarioSemanticOutput/TypedSemanticDelta hydrate the same
    # hypothesis+rollback graph that the public answer exposes.
    extensions = getattr(answer, "extensions", {})
    if isinstance(extensions, dict):
        hypotheses = extensions.get("hypotheses")
        if isinstance(hypotheses, list):
            facts.extend(
                {"semantic_source": "incident_hypothesis", **row} for row in hypotheses if isinstance(row, dict)
            )
    decision = getattr(answer, "decision", None)
    if isinstance(decision, str) and decision:
        facts.append(
            {
                "semantic_source": "policy_decision",
                "decision": decision,
                "safe_actions": list(getattr(answer, "safe_actions", [])),
                "blocked_actions": list(getattr(answer, "blocked_actions", [])),
            }
        )
    if len(facts) <= 2_000:
        return tuple(facts)
    return tuple([*facts[:1_999], {"semantic_source": "projection_bound", "unknowns": ["facts"]}])


def _answer_record_locators(answer: Any) -> list[RecordLocator]:
    locators: list[RecordLocator] = []
    seen: set[str] = set()
    for row in _answer_evidence_rows(answer):
        candidate = row.get("record_locator") or row.get("source_locator")
        locator = _strict_record_locator(candidate)
        if locator is None:
            continue
        identity = json.dumps(locator.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        if identity not in seen:
            seen.add(identity)
            locators.append(locator)
    return locators


def _answer_artifact_digests(answer: Any, evidence_by_id: dict[str, Evidence]) -> tuple[list[str], list[str]]:
    raw, derived = _binding_digests(_answer_evidence_ids(answer), evidence_by_id)
    extensions = getattr(answer, "extensions", {})
    if isinstance(extensions, dict):
        raw.extend(_valid_digests(extensions.get("raw_artifact_digests", [])))
        derived.extend(_valid_digests(extensions.get("derived_artifact_digests", [])))
        for key in ("timeline_artifact_ids", "derived_artifact_ids"):
            value = extensions.get(key, [])
            if isinstance(value, list):
                derived.extend(_valid_digests(value))
    return sorted(set(raw)), sorted(set(derived))


def _process_provenance(
    state: AgentState,
    *,
    operation: str,
    output_artifact_digests: Sequence[str],
    rule_bundle_digest: str | None = None,
    parser_id: str | None = None,
    parser_version: str | None = None,
) -> ProcessProvenance:
    return ProcessProvenance(
        process_id="secmind.deterministic-scenario-analyzer",
        process_version=SCHEMA_VERSION,
        operation=operation,
        input_artifact_digests=tuple(_scenario_input_digests(state)),
        output_artifact_digests=tuple(_valid_digests(output_artifact_digests)),
        rule_bundle_digest=rule_bundle_digest,
        parser_id=parser_id,
        parser_version=parser_version,
        network_access_performed=False,
        model_calls=0,
    )


def _semantic_delta(
    state: AgentState,
    answer: Any,
    *,
    scenario: str,
    operation: str,
    evidence_by_id: dict[str, Evidence],
    derived_artifact_digests: Sequence[str] = (),
    endpoint_graph: dict[str, Any] | None = None,
    policy_decisions: Sequence[dict[str, Any]] = (),
    rule_bundle_digest: str | None = None,
    parser_id: str | None = None,
    parser_version: str | None = None,
    anchor_semantic_digest: str | None = None,
) -> tuple[ScenarioSemanticOutput, TypedSemanticDelta]:
    evidence_ids = _answer_evidence_ids(answer)
    raw_digests, row_derived = _answer_artifact_digests(answer, evidence_by_id)
    derived = sorted(set([*row_derived, *_valid_digests(derived_artifact_digests)]))
    projection_material = {
        "scenario": scenario,
        "answer_kind": answer.answer_kind,
        "answer": answer.model_dump(mode="json", exclude={"semantic_output", "semantic_delta"}),
        "raw_artifact_digests": raw_digests,
        "derived_artifact_digests": derived,
    }
    projection_digest = hashlib.sha256(
        json.dumps(projection_material, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    derived = sorted(set([*derived, projection_digest]))
    process = _process_provenance(
        state,
        operation=operation,
        output_artifact_digests=derived,
        rule_bundle_digest=rule_bundle_digest,
        parser_id=parser_id,
        parser_version=parser_version,
    )
    missing: set[str] = set()
    locators = _answer_record_locators(answer)
    if not evidence_ids:
        missing.add("evidence_ids")
    if not locators:
        missing.add("record_locator")
    if not raw_digests:
        missing.add("raw_artifact_digest")
    unknowns = _answer_unknowns(answer)
    closure = EvidenceClosure(
        evidence_ids=tuple(evidence_ids),
        record_locators=tuple(locators),
        raw_artifact_digests=tuple(raw_digests),
        derived_artifact_digests=tuple(derived),
        complete=not missing,
        missing=tuple(sorted(missing)),
    )
    facts = _answer_semantic_facts(answer)
    events = tuple(_row_values(answer, "events"))
    endpoint_graph_value = endpoint_graph or {}
    if not endpoint_graph_value:
        extensions = getattr(answer, "extensions", {})
        candidate = extensions.get("endpoint_graph") if isinstance(extensions, dict) else None
        if isinstance(candidate, dict):
            endpoint_graph_value = dict(candidate)
    status = str(getattr(answer, "execution_status", "unknown"))
    output = ScenarioSemanticOutput(
        scenario=scenario,
        answer_kind=answer.answer_kind,
        status=cast(Any, status),
        facts=facts,
        unknowns=tuple(unknowns),
        conflicts=tuple(_row_values(answer, "conflicts")),
        events=events,
        endpoint_graph=endpoint_graph_value,
        policy_decisions=tuple(dict(row) for row in policy_decisions),
        evidence_closure=closure,
        process_provenance=process,
    )
    semantic_payload = {
        "run_id": state.run_id,
        "scenario": scenario,
        "answer_kind": answer.answer_kind,
        "action": "gap" if answer.answer_kind == "evidence_gap" else "supplement",
        "disposition": "accepted" if closure.complete else "quarantined",
        "evidence_ids": evidence_ids,
        "finding_ids": [item.finding_id for item in getattr(state, "findings", [])],
        "facts": list(facts),
        "unknowns": unknowns,
        "conflicts": list(output.conflicts),
        "record_locators": [item.model_dump(mode="json") for item in closure.record_locators],
        "endpoint_graph": endpoint_graph_value,
        "policy_decisions": list(output.policy_decisions),
        "raw_artifact_digests": raw_digests,
        "derived_artifact_digests": derived,
        "process_provenance": process.model_dump(mode="json"),
        "evidence_closure": closure.model_dump(mode="json"),
        "anchor_semantic_digest": anchor_semantic_digest,
    }
    semantic_digest = hashlib.sha256(
        json.dumps(semantic_payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    delta = DomainSemanticDelta(
        delta_id=f"scenario-delta-{semantic_digest[:32]}",
        run_id=state.run_id,
        scenario=scenario,
        answer_kind=answer.answer_kind,
        action=cast(Any, semantic_payload["action"]),
        disposition=cast(Any, semantic_payload["disposition"]),
        semantic_digest=semantic_digest,
        evidence_ids=tuple(evidence_ids),
        finding_ids=tuple(item.finding_id for item in getattr(state, "findings", [])),
        facts=facts,
        unknowns=tuple(unknowns),
        conflicts=output.conflicts,
        record_locators=closure.record_locators,
        endpoint_graph=endpoint_graph_value,
        policy_decisions=output.policy_decisions,
        raw_artifact_digests=tuple(raw_digests),
        derived_artifact_digests=tuple(derived),
        process_provenance=process,
        evidence_closure=closure,
        anchor_semantic_digest=anchor_semantic_digest,
        anchor_preserved=True,
        # This flag describes whether the deterministic delta itself is
        # reference-closed and ready for typed admission.  The run may remain
        # PARTIAL for an unrelated limitation; coupling the two previously
        # discarded truthful process provenance from exactly those degraded
        # runs where it is most valuable.
        admission_ready=closure.complete,
        source_content_trust="deterministic_projection",
    )
    return output, delta


def attach_semantic_delta(answer: Any, output: ScenarioSemanticOutput, delta: TypedSemanticDelta) -> Any:
    unknowns = sorted(set([*getattr(answer, "unknowns", []), *output.unknowns]))
    return answer.model_copy(update={"semantic_output": output, "semantic_delta": delta, "unknowns": unknowns})


def build_scenario_semantic_projection(
    state: AgentState,
    answer: Any,
    *,
    scenario: str | None = None,
    operation: str = "scenario_projection",
    evidence_by_id: dict[str, Evidence] | None = None,
    derived_artifact_digests: Sequence[str] = (),
    endpoint_graph: dict[str, Any] | None = None,
    policy_decisions: Sequence[dict[str, Any]] = (),
    rule_bundle_digest: str | None = None,
    parser_id: str | None = None,
    parser_version: str | None = None,
    anchor_semantic_digest: str | None = None,
) -> tuple[ScenarioSemanticOutput, TypedSemanticDelta]:
    """Public, pure adapter boundary for Admission/EIRS consumers."""

    resolved_scenario = scenario or getattr(getattr(state, "scenario", None), "value", None) or "unknown"
    by_id = evidence_by_id if evidence_by_id is not None else {item.evidence_id: item for item in state.evidence}
    return _semantic_delta(
        state,
        answer,
        scenario=str(resolved_scenario),
        operation=operation,
        evidence_by_id=by_id,
        derived_artifact_digests=derived_artifact_digests,
        endpoint_graph=endpoint_graph,
        policy_decisions=policy_decisions,
        rule_bundle_digest=rule_bundle_digest,
        parser_id=parser_id,
        parser_version=parser_version,
        anchor_semantic_digest=anchor_semantic_digest,
    )


def build_scenario_semantic_delta(state: AgentState, answer: Any, **kwargs: Any) -> TypedSemanticDelta:
    return build_scenario_semantic_projection(state, answer, **kwargs)[1]


def record_scenario_semantic_projection(state: AgentState, answer: Any) -> None:
    """Persist an additive projection; never mutate a published Anchor."""

    delta = getattr(answer, "semantic_delta", None)
    output = getattr(answer, "semantic_output", None)
    if isinstance(delta, TypedSemanticDelta):
        state.audit_coverage["scenario_semantic_delta"] = delta.model_dump(mode="json")
        state.audit_coverage["typed_semantic_deltas"] = [delta.model_dump(mode="json")]
        state.audit_coverage["scenario_semantic_delta_receipt"] = build_scenario_semantic_delta_receipt(delta)
    if isinstance(output, ScenarioSemanticOutput):
        state.audit_coverage["scenario_semantic_output"] = output.model_dump(mode="json")


__all__ = [
    "SCENARIO_SEMANTIC_DELTA_RECEIPT_VERSION",
    "build_scenario_semantic_delta_receipt",
    "build_scenario_semantic_projection",
]
