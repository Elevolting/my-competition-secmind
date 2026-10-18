"""Deterministic execution for non-code-audit scenarios.

This collaborator owns the synchronous, offline scenario projections that used
to live inside the LangGraph facade. It may read immutable task inputs and write
content-addressed artifacts. Approved tool execution, when explicitly wired in
by the orchestrator, still happens through the same broker boundary as the rest
of the runtime. Those boundaries keep scenario code understandable in isolation
and prevent a new scenario from quietly gaining orchestration power.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import json
import re
from collections import OrderedDict
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, field, replace
from pathlib import PurePosixPath
from typing import Any, Literal, cast
from uuid import NAMESPACE_URL, uuid5

from secmind.api_assessment import assess_api_assets
from secmind.artifact_store import ArtifactStoreError, ContentAddressedArtifactStore, StoredArtifact
from secmind.domain_answers import (
    EvidenceGapAnswer,
    ExactAnswer,
    FindingAnswer,
    ReverseBehaviorAnswer,
    TacticHypothesis,
    TimelineAnswer,
)
from secmind.evidence_graph import EvidenceGraph, make_claim, make_link
from secmind.firmware_audit import (
    FIRMWARE_STATIC_CAPABILITY,
    FirmwareAuditLimits,
    FirmwareAuditSource,
    audit_firmware_sources,
)
from secmind.incident_response import build_incident_dry_run
from secmind.log_analysis import (
    LogAnalysisError,
    LogAnalysisResult,
    LogLimitError,
    ParserDiagnostic,
    analyze_offline_logs,
    merge_attack_mappings,
)
from secmind.log_parsers import BinaryParseLimits, detect_binary_format, extract_safe_zip
from secmind.orchestration.domain_projection import (
    attach_semantic_delta as _attach_semantic_delta,
)
from secmind.orchestration.domain_projection import (
    bind_evidence as _binding,
)
from secmind.orchestration.domain_projection import (
    build_scenario_semantic_projection,
    record_scenario_semantic_projection,
)
from secmind.reverse_triage import (
    REVERSE_RULE_BUNDLE_DIGEST,
    REVERSE_RULE_BUNDLE_VERSION,
    REVERSE_TRIAGE_CAPABILITY,
    ReverseTriageLimits,
    ReverseTriageSource,
    analyze_reverse_sources,
)
from secmind.schemas import (
    SCHEMA_VERSION,
    AgentReport,
    AgentState,
    ArtifactRef,
    ClaimStatus,
    DataView,
    DecisionRecord,
    Evidence,
    EvidenceRelation,
    Finding,
    InputArtifact,
    LogLayer,
    RunStatus,
    ToolContext,
    ToolResult,
    ToolStatus,
    VerificationResult,
)
from secmind.secret_scrubber import REDACTED, TRUNCATED
from secmind.task_context import require_resolved_task_contract
from secmind.task_specs import TaskSpecRepository
from secmind.tooling.broker import ToolBroker

_MAX_LOG_INPUT_BYTES = 8 * 1024 * 1024
_MAX_SCENARIO_CAS_CACHE_ENTRIES = 128
_EXACT_TOKEN_PATTERN = re.compile(
    r"(?i)\b(?:flag|ctf|secmind|htb)\{[^{}\r\n]{1,256}\}",
)
_EXACT_TOKEN_BYTES_PATTERN = re.compile(rb"(?i)\b(?:flag|ctf|secmind|htb)\{[^{}\r\n]{1,256}\}")
_ENCODED_COMMAND_PATTERN = re.compile(
    r"(?i)(?:-(?:e|enc|encoded|encodedcommand)\b|frombase64string\s*\()[\s\\\"']*"
    r"([A-Za-z0-9+/]{40,32768}={0,2})"
)
_TASK_NAME_PATTERN = re.compile(r"(?i)-TaskName\s+[\"']([^\"'\r\n]{3,192})[\"']")
_PAYLOAD_NAME_PATTERN = re.compile(
    r"(?i)(?:https?://[^\s\"'<>]+/|\bGET\s+/)([A-Za-z0-9][A-Za-z0-9_.-]{1,127}"
    r"\.(?:exe|dll|ps1|bat|cmd|zip))\b"
)
_MAX_EXACT_LOG_VALUES = 32
_MAX_EXACT_DECODED_BYTES = 64 * 1024
_MAX_CONTEXTUAL_EXACT_SOURCE_BYTES = 2 * 1024 * 1024
_MAX_ATTACK_PROVENANCE_REFS = 64
_LOG_CONTEXT_NAMES = frozenset(
    {"readme", "readme.md", "readme.txt", "manifest.json", "input_manifest.json", "task.json"}
)
_LOG_ARCHIVE_MEDIA = frozenset({"application/zip", "application/x-zip-compressed"})
_LOG_VIEW_SUFFIXES = (".jsonl", ".ndjson", ".json", ".txt")
_TECHNIQUE_TACTICS: dict[str, tuple[str, str]] = {
    "T1003.006": ("TA0006", "Credential Access"),
    "T1021.001": ("TA0008", "Lateral Movement"),
    "T1021.006": ("TA0008", "Lateral Movement"),
    "T1033": ("TA0007", "Discovery"),
    "T1059.001": ("TA0002", "Execution"),
    "T1059.003": ("TA0002", "Execution"),
    "T1110": ("TA0006", "Credential Access"),
    "T1112": ("TA0005", "Defense Evasion"),
    "T1548.003": ("TA0004", "Privilege Escalation"),
}
_SCRUB_MARKER_PATTERN = re.compile(
    r"\[[^\]\r\n]{0,64}(?:redacted|truncated)[^\]\r\n]{0,64}\]",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class LogInputSelection:
    artifact: InputArtifact
    role: Literal["authoritative", "alternate", "context", "archive"]
    affects_status: bool
    reason: str


def _log_input_selections(artifacts: Sequence[InputArtifact]) -> list[LogInputSelection]:
    """Classify immutable manifest entries without trusting their contents."""

    def clean(path: str) -> str:
        path = path.replace("\\", "/")
        while path.startswith("./"):
            path = path[2:]
        return path

    normalized = {item.artifact_id: clean(item.relative_path) for item in artifacts}
    native_basenames = {
        PurePosixPath(path).name.casefold()
        for path in normalized.values()
        if "/.secmind-derived/" not in f"/{path.casefold()}"
    }
    has_data_candidate = any(
        PurePosixPath(path).name.casefold() not in _LOG_CONTEXT_NAMES for path in normalized.values()
    )
    provisional: list[tuple[InputArtifact, Literal["authoritative", "alternate", "context", "archive"], str]] = []
    for artifact in sorted(artifacts, key=lambda item: item.relative_path.casefold()):
        path = normalized[artifact.artifact_id]
        lowered = path.casefold()
        name = PurePosixPath(path).name.casefold()
        derived = "/.secmind-derived/" in f"/{lowered}"
        parent_name = next((name[: -len(suffix)] for suffix in _LOG_VIEW_SUFFIXES if name.endswith(suffix)), name)
        if name in _LOG_CONTEXT_NAMES and has_data_candidate:
            provisional.append((artifact, "context", "manifest-declared contextual document"))
        elif derived and parent_name in native_basenames:
            provisional.append((artifact, "alternate", "derived view has a matching native manifest source"))
        elif name.endswith(".zip") or artifact.media_type.casefold() in _LOG_ARCHIVE_MEDIA:
            provisional.append((artifact, "archive", "archive container retained as source provenance"))
        else:
            provisional.append((artifact, "authoritative", "manifest source has no verified alternate parent"))

    has_authoritative = any(role == "authoritative" for _, role, _ in provisional)
    return [
        LogInputSelection(
            artifact=artifact,
            role=role,
            affects_status=role == "authoritative" or (role == "archive" and not has_authoritative),
            reason=reason,
        )
        for artifact, role, reason in provisional
    ]


def _is_scrubbed_exact_candidate(value: str) -> bool:
    """Reject parser output that merely re-encodes a scrubber marker.

    Normalized log events are intentionally scrubbed before they reach this
    deterministic answer extractor.  A value such as ``flag{[REDACTED]}``
    still matches the broad flag-token grammar, but it is not an observation
    of an exact value.  Treating it as one creates a second, misleading
    candidate alongside the source-bound value and can make a degraded report
    publish the marker as if it were an answer.  Restrict the rejection to
    bracketed redaction/truncation markers so a literal challenge value such
    as ``flag{redacted}`` remains a valid input-derived answer.
    """

    return bool(_SCRUB_MARKER_PATTERN.search(value)) or value in {REDACTED, TRUNCATED}


def _domain_execution_status(status: RunStatus) -> str:
    """Map the operational run state to the strict domain-answer vocabulary."""

    if status == RunStatus.COMPLETED:
        return "success"
    if status == RunStatus.DENIED:
        return "policy_blocked"
    if status in {
        RunStatus.PARTIAL,
        RunStatus.FAILED,
        RunStatus.RECOVERY_REQUIRED,
        RunStatus.CANCELLED,
        RunStatus.WAITING_APPROVAL,
        RunStatus.WAITING_CLARIFICATION,
    }:
        return "partial"
    return "unknown"


def _domain_epistemic_status(
    status: RunStatus,
    *,
    has_gaps: bool,
    has_conflicts: bool = False,
) -> str:
    """Keep parser uncertainty visible instead of turning a valid run into fact."""

    if has_conflicts:
        return "conflicting_evidence"
    if status == RunStatus.COMPLETED and not has_gaps:
        return "conclusive"
    return "insufficient_evidence"


def _answer_task_id(state: AgentState) -> str:
    """Use the sealed client identity, falling back to the durable run ID."""

    contract = require_resolved_task_contract(state)
    return (contract.client_request_id or state.run_id)[:128]


def _firmware_capability_requested(state: AgentState) -> bool:
    """Route only an explicit trusted secondary capability to firmware checks."""

    capabilities = require_resolved_task_contract(state).secondary_capabilities
    return any(str(item).strip().casefold() == FIRMWARE_STATIC_CAPABILITY for item in capabilities)


def _bounded_rows(
    rows: list[dict[str, Any]],
    maximum: int,
    field_name: str,
    limitations: list[str],
) -> list[dict[str, Any]]:
    """Bound answer arrays without making truncation look like full coverage."""

    if len(rows) <= maximum:
        return rows
    omitted = len(rows) - maximum
    limitations.append(f"DomainAnswer field {field_name} omitted {omitted} row(s) at its output bound")
    return rows[:maximum]


def _bounded_limitations(values: Sequence[str], *, maximum: int = 100) -> list[str]:
    """Keep parser diagnostics and coverage gaps within the public answer bound."""

    unique = sorted({str(value) for value in values if str(value)})
    if len(unique) <= maximum:
        return unique
    omitted = len(unique) - maximum + 1
    return [*unique[: maximum - 1], f"{omitted} limitation(s) omitted at the answer bound"]


def _log_evidence_indexes(result: LogAnalysisResult) -> dict[str, dict[str, str]]:
    indexes: dict[str, dict[str, str]] = {
        "event": {},
        "match": {},
        "ioc": {},
        "technique": {},
        "diagnostic": {},
    }
    for item in result.evidence:
        evidence_type = str(item.metadata.get("evidence_type") or "")
        if evidence_type == "normalized_event" and item.metadata.get("event_id"):
            indexes["event"][str(item.metadata["event_id"])] = item.evidence_id
        elif evidence_type == "sigma_match" and item.metadata.get("match_id"):
            indexes["match"][str(item.metadata["match_id"])] = item.evidence_id
        elif evidence_type == "ioc_occurrence" and item.metadata.get("observation_id"):
            indexes["ioc"][str(item.metadata["observation_id"])] = item.evidence_id
        elif evidence_type == "correlation_trace" and item.metadata.get("technique_id"):
            indexes["technique"][str(item.metadata["technique_id"])] = item.evidence_id
        elif evidence_type == "parser_diagnostic" and item.metadata.get("code"):
            indexes["diagnostic"][str(item.metadata["code"])] = item.evidence_id
    return indexes


def _log_technique_evidence_ids(result: LogAnalysisResult) -> dict[str, list[str]]:
    """Return every correlation receipt for a technique across source views."""

    indexes: dict[str, list[str]] = {}
    for item in result.evidence:
        if item.metadata.get("evidence_type") != "correlation_trace":
            continue
        technique_id = item.metadata.get("technique_id")
        if not isinstance(technique_id, str) or not technique_id:
            continue
        indexes.setdefault(technique_id, []).append(item.evidence_id)
    return {key: sorted(set(values))[:_MAX_ATTACK_PROVENANCE_REFS] for key, values in sorted(indexes.items())}


def _log_raw_artifact_digests(result: LogAnalysisResult) -> list[str]:
    """Preserve source bytes even when a parser emits no Evidence rows."""

    values: set[str] = {
        str(item.sha256).lower()
        for item in result.evidence
        if isinstance(item.sha256, str) and re.fullmatch(r"[a-fA-F0-9]{64}", item.sha256)
    }
    candidate = result.coverage.get("raw_artifact_digests", [])
    if isinstance(candidate, (list, tuple, set)):
        values.update(
            str(item).lower() for item in candidate if isinstance(item, str) and re.fullmatch(r"[a-fA-F0-9]{64}", item)
        )
    return sorted(values)


def _input_artifact_digests(artifacts: Sequence[InputArtifact]) -> set[str]:
    return {
        str(item.sha256).lower()
        for item in artifacts
        if isinstance(item.sha256, str) and re.fullmatch(r"[a-fA-F0-9]{64}", item.sha256)
    }


def _merge_log_results(results: Sequence[LogAnalysisResult]) -> LogAnalysisResult:
    """Create one deterministic answer input for a multi-artifact log run."""

    if not results:
        raise ValueError("at least one log result is required")
    if len(results) == 1:
        return results[0]
    events = tuple(event for result in results for event in result.events)
    rule_matches = tuple(match for result in results for match in result.rule_matches)
    iocs = tuple(observation for result in results for observation in result.iocs)
    mappings = merge_attack_mappings(*(result.attack_mappings for result in results))
    diagnostics = tuple(item for result in results for item in result.diagnostics)
    evidence_by_id = {item.evidence_id: item for result in results for item in result.evidence}
    coverage: dict[str, Any] = {"source_count": len(results)}
    for key in (
        "records_seen",
        "records_emitted",
        "records_normalized",
        "records_rejected",
        "duplicates_removed",
        "timestamped_records",
        "diagnostics_seen",
    ):
        coverage[key] = sum(
            int(result.coverage.get(key, 0)) for result in results if isinstance(result.coverage.get(key, 0), int)
        )
    for key in (
        "rule_match_limit_reached",
        "ioc_limit_reached",
        "evidence_truncated",
        "diagnostics_truncated",
    ):
        coverage[key] = any(bool(result.coverage.get(key)) for result in results)
    coverage["network_access_performed"] = False
    coverage["model_calls"] = 0
    coverage["provider_cost"] = 0
    ordered_events = tuple(sorted(events, key=lambda item: (item.timestamp_utc or "", item.event_id)))
    return LogAnalysisResult(
        status=("completed" if all(result.status == "completed" for result in results) else "partial"),
        source_format="mixed",
        events=ordered_events,
        timeline_event_ids=tuple(event.event_id for event in ordered_events),
        rule_matches=tuple(sorted(rule_matches, key=lambda item: item.match_id)),
        iocs=tuple(sorted(iocs, key=lambda item: item.observation_id)),
        attack_mappings=mappings,
        diagnostics=tuple(diagnostics),
        evidence=tuple(evidence_by_id[key] for key in sorted(evidence_by_id)),
        coverage=coverage,
    )


def _log_tactic_hypotheses(
    result: LogAnalysisResult,
) -> list[TacticHypothesis]:
    """Lift verified technique mappings into conservative tactic hypotheses."""

    technique_evidence = _log_technique_evidence_ids(result)
    grouped: dict[tuple[str, str], list[Any]] = {}
    mappings_by_id = {item.technique_id: item for item in result.attack_mappings}
    for mapping in result.attack_mappings:
        tactic = _TECHNIQUE_TACTICS.get(mapping.technique_id)
        if tactic is not None and technique_evidence.get(mapping.technique_id):
            grouped.setdefault(tactic, []).append(mapping)
    output = [
        TacticHypothesis(
            tactic_id=tactic[0],
            tactic_name=tactic[1],
            technique_ids=sorted(item.technique_id for item in mappings),
            evidence_ids=sorted(
                {value for item in mappings for value in technique_evidence.get(item.technique_id, [])}
            )[:_MAX_ATTACK_PROVENANCE_REFS],
            confidence=min(item.confidence for item in mappings),
            interpretation=(
                "low_confidence_context"
                if any(item.interpretation.startswith("low_confidence_context_only") for item in mappings)
                else "evidence_bound_hypothesis"
            ),
            limitations=(
                ["Does not prove malicious activity or a successful remote session."]
                if any(item.interpretation.startswith("low_confidence_context_only") for item in mappings)
                else []
            ),
        )
        for tactic, mappings in sorted(grouped.items())
    ]

    users = {
        entity.value.casefold()
        for event in result.events
        for entity in event.entities
        if entity.kind == "user" and entity.value
    }
    chain_ids = {"T1021.006", "T1059.003", "T1033"}
    if (
        chain_ids <= set(mappings_by_id)
        and any("local service" in user for user in users)
        and any(user.endswith("\\system") or user == "system" for user in users)
    ):
        evidence_ids = {
            evidence_id for technique_id in chain_ids for evidence_id in technique_evidence.get(technique_id, [])
        }
        if evidence_ids:
            output.append(
                TacticHypothesis(
                    tactic_id="TA0004",
                    tactic_name="Privilege Escalation",
                    technique_ids=sorted(chain_ids),
                    evidence_ids=sorted(evidence_ids)[:_MAX_ATTACK_PROVENANCE_REFS],
                    confidence=min(mappings_by_id[item].confidence for item in chain_ids),
                    interpretation="evidence_bound_hypothesis",
                    limitations=[
                        "Privilege-boundary transition is a hypothesis; the mechanism is unknown.",
                        "This does not assert Exploitation for Privilege Escalation (T1068).",
                    ],
                )
            )
    return sorted(output, key=lambda item: item.tactic_id)


def _attack_mapping_pipeline_metrics(
    state: AgentState,
    source_results: Sequence[LogAnalysisResult],
    merged_result: LogAnalysisResult,
) -> dict[str, Any]:
    """Project the mapping candidate-to-admission path from verified links."""

    candidate_count = sum(len(item.attack_mappings) for item in source_results)
    mapping_claims = {
        item.subject_ref.removeprefix("attack-mapping:"): item.claim_id
        for item in state.claims
        if item.claim_type == "attack_mapping_supported"
        and item.status == ClaimStatus.VERIFIED
        and item.subject_ref.startswith("attack-mapping:")
    }
    verified_links = {
        (item.claim_id, item.evidence_id)
        for item in state.evidence_links
        if item.relation == EvidenceRelation.SUPPORTS and item.verifier_status == ClaimStatus.VERIFIED
    }
    evidence_by_technique = _log_technique_evidence_ids(merged_result)
    verified_ids: list[str] = []
    for mapping in merged_result.attack_mappings:
        claim_id = mapping_claims.get(mapping.technique_id)
        evidence_ids = evidence_by_technique.get(mapping.technique_id, [])
        if claim_id and evidence_ids and all((claim_id, evidence_id) in verified_links for evidence_id in evidence_ids):
            verified_ids.append(mapping.technique_id)
    admitted_ids = sorted(set(verified_ids))
    return {
        "version": "log-attack-mapping-pipeline-v1",
        "candidate_count": candidate_count,
        "correlated_count": len(merged_result.attack_mappings),
        "verified_count": len(verified_ids),
        "admitted_count": len(admitted_ids),
        "admitted_technique_ids": admitted_ids[:200],
        "rejected_count": max(0, candidate_count - len(admitted_ids)),
        "evidence_closure_complete": len(admitted_ids) == len(merged_result.attack_mappings),
    }


def _log_timeline_answer(
    state: AgentState,
    result: LogAnalysisResult,
    *,
    timeline_artifact_ids: list[str],
    limitations: list[str],
) -> TimelineAnswer:
    """Build a loss-aware, evidence-bound timeline answer from one parser result."""

    evidence_by_id = {item.evidence_id: item for item in result.evidence}
    indexes = _log_evidence_indexes(result)
    events: list[dict[str, Any]] = []
    facts: list[dict[str, Any]] = []
    actors_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for event in result.events:
        evidence_id = indexes["event"].get(event.event_id)
        binding = _binding([evidence_id] if evidence_id else [], evidence_by_id, fallback_locator=asdict(event.locator))
        entities = [asdict(entity) for entity in event.entities]
        event_row = {
            "event_id": event.event_id,
            "timestamp_utc": event.timestamp_utc,
            "timestamp": event.timestamp_utc,
            "timestamp_quality": event.timestamp_quality,
            "source_format": event.source_format,
            "event_type": event.event_type,
            "severity": event.severity,
            "message": event.message,
            "entities": entities,
            "attributes": dict(event.attributes),
            "event_content_sha256": event.content_sha256,
            **binding,
        }
        events.append(event_row)
        facts.append(
            {
                "fact_type": "normalized_security_event",
                "event_id": event.event_id,
                "value": {
                    "event_type": event.event_type,
                    "timestamp_utc": event.timestamp_utc,
                    "severity": event.severity,
                    "entities": entities,
                },
                "event_content_sha256": event.content_sha256,
                **binding,
            }
        )
        for entity in event.entities:
            key = (entity.kind, entity.value)
            row = actors_by_key.setdefault(
                key,
                {
                    "kind": entity.kind,
                    "value": entity.value,
                    "event_ids": [],
                    "evidence_ids": [],
                    "source_locators": [],
                },
            )
            row["event_ids"].append(event.event_id)
            if evidence_id:
                row["evidence_ids"].append(evidence_id)
            locator = binding.get("source_locator")
            if isinstance(locator, dict) and locator not in row["source_locators"]:
                row["source_locators"].append(locator)

    inferences: list[dict[str, Any]] = []
    for match in result.rule_matches:
        evidence_id = indexes["match"].get(match.match_id)
        event_evidence_id = indexes["event"].get(match.event_id)
        binding = _binding(
            [item for item in (evidence_id, event_evidence_id) if item],
            evidence_by_id,
            fallback_locator=asdict(match.locator),
        )
        inferences.append(
            {
                "inference_type": "rule_match",
                "match_id": match.match_id,
                "rule_id": match.rule_id,
                "title": match.title,
                "severity": match.severity,
                "event_id": match.event_id,
                "attack_ids": list(match.attack_ids),
                "matched_on": list(match.matched_on),
                **binding,
            }
        )

    iocs: list[dict[str, Any]] = []
    for observation in result.iocs:
        evidence_id = indexes["ioc"].get(observation.observation_id)
        iocs.append(
            {
                "observation_id": observation.observation_id,
                "ioc_type": observation.ioc_type,
                "normalized_value": observation.normalized_value,
                "display_value": observation.display_value,
                "confidence": observation.confidence,
                "event_id": observation.event_id,
                **_binding(
                    [evidence_id] if evidence_id else [],
                    evidence_by_id,
                    fallback_locator=asdict(observation.locator),
                ),
            }
        )

    techniques: list[dict[str, Any]] = []
    technique_evidence = _log_technique_evidence_ids(result)
    for mapping in result.attack_mappings:
        evidence_ids = technique_evidence.get(mapping.technique_id, [])
        fallback = None
        if mapping.event_ids:
            for event in result.events:
                if event.event_id == mapping.event_ids[0]:
                    fallback = asdict(event.locator)
                    break
        techniques.append(
            {
                "technique_id": mapping.technique_id,
                "technique_name": mapping.technique_name,
                "knowledge_version": mapping.knowledge_version,
                "event_ids": list(mapping.event_ids),
                "rule_ids": list(mapping.rule_ids),
                "confidence": mapping.confidence,
                "interpretation": mapping.interpretation,
                "unknowns": [] if mapping.event_ids else ["event_ids"],
                "source_refs": list(mapping.source_refs),
                **_binding(evidence_ids, evidence_by_id, fallback_locator=fallback),
            }
        )
    tactics = _log_tactic_hypotheses(result)

    gaps: list[dict[str, Any]] = []
    for diagnostic in result.diagnostics:
        evidence_id = indexes["diagnostic"].get(diagnostic.code)
        gaps.append(
            {
                "code": diagnostic.code,
                "message": diagnostic.message,
                "severity": diagnostic.severity,
                "unknowns": ["event_id"] if diagnostic.locator is None else [],
                **_binding(
                    [evidence_id] if evidence_id else [],
                    evidence_by_id,
                    fallback_locator=asdict(diagnostic.locator) if diagnostic.locator is not None else None,
                ),
            }
        )
    gaps = _bounded_rows(gaps, 200, "gaps", limitations)
    events = _bounded_rows(events, 1_000, "events", limitations)
    facts = _bounded_rows(facts, 500, "facts", limitations)
    actors = _bounded_rows(list(actors_by_key.values()), 200, "actors", limitations)
    iocs = _bounded_rows(iocs, 500, "iocs", limitations)
    inferences = _bounded_rows(inferences, 500, "inferences", limitations)
    techniques = _bounded_rows(techniques, 200, "techniques", limitations)
    has_gaps = bool(limitations or gaps or result.status != "completed")
    answer = TimelineAnswer.model_validate(
        {
            "task_id": _answer_task_id(state),
            "execution_status": _domain_execution_status(state.status),
            "epistemic_status": _domain_epistemic_status(state.status, has_gaps=has_gaps),
            "executive_summary": (
                f"Offline log analysis normalized {len(result.events)} event(s), "
                f"{len(result.iocs)} IOC observation(s), and {len(result.rule_matches)} rule match(es)."
            ),
            "limitations": _bounded_limitations(limitations),
            "facts": facts,
            "inferences": inferences,
            "events": events,
            "actors": actors,
            "iocs": iocs,
            "techniques": techniques,
            "tactics": [item.model_dump(mode="json") for item in tactics],
            "gaps": gaps,
            "extensions": {
                "coverage": dict(result.coverage),
                "timeline_artifact_ids": list(timeline_artifact_ids),
                "source_format": result.source_format,
                "evidence_ids": sorted(evidence_by_id),
                "raw_artifact_digests": _log_raw_artifact_digests(result),
                "field_bindings": {
                    "facts": sorted({item for row in facts for item in row.get("evidence_ids", [])}),
                    "events": sorted({item for row in events for item in row.get("evidence_ids", [])}),
                    "iocs": sorted({item for row in iocs for item in row.get("evidence_ids", [])}),
                    "tactics": sorted({item for row in tactics for item in row.evidence_ids}),
                },
            },
        }
    )
    semantic_output, semantic_delta = build_scenario_semantic_projection(
        state,
        answer,
        scenario="log_analysis",
        operation="offline_log_analysis",
        evidence_by_id=evidence_by_id,
        derived_artifact_digests=timeline_artifact_ids,
        rule_bundle_digest=(
            str(result.coverage.get("rule_bundle_digest"))
            if isinstance(result.coverage.get("rule_bundle_digest"), str)
            and re.fullmatch(r"[a-fA-F0-9]{64}", str(result.coverage.get("rule_bundle_digest")))
            else None
        ),
        parser_id=result.source_format,
        parser_version=(
            str(result.coverage.get("rule_bundle_version")) if result.coverage.get("rule_bundle_version") else None
        ),
    )
    return _attach_semantic_delta(answer, semantic_output, semantic_delta)


def _api_document_locator(
    asset_id: str,
    assets: Sequence[Any],
    input_by_id: dict[str, InputArtifact],
) -> dict[str, Any] | None:
    asset = next((item for item in assets if item.parsed_asset_id == asset_id), None)
    if asset is None:
        return None
    source = input_by_id.get(asset.artifact_id)
    locator = {
        "source_ref": asset.relative_path,
        "segment_id": "api-document",
        "record_number": 0,
        "line_number": 0,
        "byte_offset": 0,
        "byte_length": source.size_bytes if source is not None else 0,
        "locator_scope": "document",
    }
    if source is not None:
        locator["artifact_sha256"] = source.sha256.lower()
    return locator


def _api_exact_answer(
    state: AgentState,
    result: Any,
    assets: Sequence[Any],
    input_by_id: dict[str, InputArtifact],
    evidence_by_id: dict[str, Evidence],
    verified_evidence_ids: set[str],
    limitations: list[str],
) -> ExactAnswer:
    binding_evidence_by_id = {
        evidence_id: item for evidence_id, item in evidence_by_id.items() if evidence_id in verified_evidence_ids
    }
    evidence_by_asset = {
        str(item.metadata.get("parsed_asset_id")): item.evidence_id
        for item in binding_evidence_by_id.values()
        if item.metadata.get("parsed_asset_id")
    }
    endpoints: list[dict[str, Any]] = []
    for endpoint in result.asset_graph.endpoints:
        evidence_id = evidence_by_asset.get(endpoint.asset_id)
        fallback = _api_document_locator(endpoint.asset_id, assets, input_by_id)
        endpoints.append(
            {
                "endpoint_id": endpoint.endpoint_id,
                "asset_id": endpoint.asset_id,
                "method": endpoint.method,
                "path": endpoint.path,
                "parameter_names": list(endpoint.parameter_names),
                "auth_schemes": list(endpoint.auth_schemes),
                "source_content_trust": endpoint.source_content_trust,
                **_binding(
                    [evidence_id] if evidence_id else [],
                    binding_evidence_by_id,
                    fallback_locator=fallback,
                ),
            }
        )
    endpoints = _bounded_rows(endpoints, 1_000, "items", limitations)

    findings: list[dict[str, Any]] = []
    for finding in result.findings:
        evidence_ids = [item for item in finding.evidence_ids if item in binding_evidence_by_id]
        endpoint = next((item for item in endpoints if item["path"] == finding.path), None)
        fallback = endpoint.get("source_locator") if endpoint else None
        findings.append(
            {
                "finding_id": finding.finding_id,
                "rule_id": finding.rule_id,
                "severity": finding.severity,
                "title": finding.title,
                "description": finding.description,
                "path": finding.path,
                "remediation": finding.remediation,
                **_binding(evidence_ids, binding_evidence_by_id, fallback_locator=fallback),
            }
        )
    findings = _bounded_rows(findings, 1_000, "values.findings", limitations)
    endpoint_graph = {
        "nodes": [
            {
                "node_id": row["endpoint_id"],
                "node_type": "endpoint",
                "asset_id": row["asset_id"],
                "method": row["method"],
                "path": row["path"],
            }
            for row in endpoints
        ],
        "edges": [],
    }
    source_offsets = [
        {
            "endpoint_id": row["endpoint_id"],
            "asset_id": row["asset_id"],
            **_binding(
                row.get("evidence_ids", []),
                binding_evidence_by_id,
                fallback_locator=row.get("source_locator"),
            ),
        }
        for row in endpoints
    ]
    all_evidence_ids = sorted(evidence_by_id)
    derivation_fallback = None
    if assets:
        derivation_fallback = _api_document_locator(assets[0].parsed_asset_id, assets, input_by_id)
    has_gaps = bool(limitations or result.coverage_gaps or result.status != RunStatus.COMPLETED)
    answer = ExactAnswer.model_validate(
        {
            "task_id": _answer_task_id(state),
            "execution_status": _domain_execution_status(state.status),
            "epistemic_status": _domain_epistemic_status(state.status, has_gaps=has_gaps),
            "executive_summary": (
                f"Static API assessment retained {len(result.asset_graph.endpoints)} endpoint(s) "
                f"and {len(result.findings)} evidence-bound finding(s); no network request was made."
            ),
            "limitations": _bounded_limitations([*limitations, *result.coverage_gaps]),
            "values": {"endpoints": endpoints, "findings": findings, "endpoint_graph": endpoint_graph},
            "items": endpoints,
            "mapping": {row["endpoint_id"]: row for row in endpoints},
            "derivation": [
                {
                    "operation": "static_api_projection",
                    "endpoint_count": len(endpoints),
                    **_binding(
                        all_evidence_ids,
                        binding_evidence_by_id,
                        fallback_locator=derivation_fallback,
                    ),
                }
            ],
            "source_offsets": source_offsets,
            "validation": {
                "status": result.status.value,
                "static_only": True,
                "dynamic_probes_enabled": result.dynamic_probes_enabled,
                "network_requests": result.network_requests_performed,
                "verified_evidence_ids": sorted(verified_evidence_ids),
                "rejected_evidence_count": len(evidence_by_id) - len(verified_evidence_ids),
                "coverage_gaps": list(result.coverage_gaps[:100]),
                "policy_decision": result.dynamic_probe_policy.model_dump(mode="json"),
            },
            "extensions": {
                "asset_ids": list(result.asset_graph.asset_ids),
                "method_counts": dict(result.asset_graph.method_counts),
                "evidence_ids": all_evidence_ids,
                "raw_artifact_digests": sorted(
                    _input_artifact_digests(tuple(input_by_id.values()))
                    | {
                        str(item.sha256).lower()
                        for item in binding_evidence_by_id.values()
                        if isinstance(item.sha256, str) and re.fullmatch(r"[a-fA-F0-9]{64}", item.sha256)
                    }
                ),
                "endpoint_graph": endpoint_graph,
            },
        }
    )
    semantic_output, semantic_delta = build_scenario_semantic_projection(
        state,
        answer,
        scenario="api_assessment",
        operation="static_api_projection",
        evidence_by_id=binding_evidence_by_id,
        endpoint_graph=endpoint_graph,
        policy_decisions=[result.dynamic_probe_policy.model_dump(mode="json")],
        parser_id="api-static-assessment",
        parser_version="1.0",
    )
    return _attach_semantic_delta(answer, semantic_output, semantic_delta)


def _firmware_finding_answer(
    state: AgentState,
    result: Any,
    findings: Sequence[Finding],
    evidence_by_id: dict[str, Evidence],
    verified_evidence_ids: set[str],
    limitations: list[str],
) -> FindingAnswer:
    """Project firmware findings and scan observations into the typed answer."""

    bound_findings: list[dict[str, Any]] = []
    for finding in findings:
        evidence_ids = [item for item in finding.evidence_ids if item in verified_evidence_ids]
        if not evidence_ids:
            continue
        bound_findings.append(
            {
                "finding_id": finding.finding_id,
                "rule_id": finding.rule_id,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "path": finding.path,
                "line": finding.line,
                "title": finding.title,
                "description": finding.description,
                "remediation": finding.remediation,
                "cwe_ids": list(finding.raw.get("cwe_ids", [])),
                **_binding(evidence_ids, evidence_by_id),
            }
        )
    observations: list[dict[str, Any]] = []
    for observation in result.observations:
        evidence_ids = [item for item in observation.get("evidence_ids", []) if item in verified_evidence_ids]
        if not evidence_ids:
            continue
        observations.append(
            {
                **{key: value for key, value in observation.items() if key not in {"evidence_ids", "source_locator"}},
                **_binding(evidence_ids, evidence_by_id, fallback_locator=observation.get("source_locator")),
            }
        )
    bound_findings = _bounded_rows(bound_findings, 100, "findings", limitations)
    observations = _bounded_rows(observations, 100, "negative_evidence", limitations)
    all_bound = all(bool(row.get("evidence_ids")) for row in [*bound_findings, *observations])
    has_gaps = bool(limitations) or result.status != RunStatus.COMPLETED
    answer = FindingAnswer.model_validate(
        {
            "task_id": _answer_task_id(state),
            "execution_status": _domain_execution_status(state.status),
            "epistemic_status": "conclusive" if not has_gaps else "insufficient_evidence",
            "executive_summary": (
                f"Deterministic firmware static audit retained {len(bound_findings)} evidence-bound finding(s) "
                f"across {len(result.checked_paths)} checked artifact(s)."
            ),
            "limitations": _bounded_limitations(limitations),
            "findings": bound_findings,
            "checked_paths": list(result.checked_paths),
            "negative_evidence": observations,
            "patches": [],
            "extensions": {
                "capability": FIRMWARE_STATIC_CAPABILITY,
                "coverage": dict(result.coverage),
                "verified_evidence_ids": sorted(verified_evidence_ids),
                "all_published_fields_evidence_bound": all_bound,
                "network_requests": 0,
                "execution_performed": False,
                "primary_is_supplemental": True,
                "raw_artifact_digests": sorted(
                    _input_artifact_digests(state.input_artifacts)
                    | {
                        str(item.sha256).lower()
                        for item in evidence_by_id.values()
                        if isinstance(item.sha256, str) and re.fullmatch(r"[a-fA-F0-9]{64}", item.sha256)
                    }
                ),
            },
        }
    )
    semantic_output, semantic_delta = build_scenario_semantic_projection(
        state,
        answer,
        scenario="firmware_static_audit",
        operation="firmware_static_projection",
        evidence_by_id=evidence_by_id,
        parser_id="firmware-static-audit",
        parser_version="1.0",
    )
    return _attach_semantic_delta(answer, semantic_output, semantic_delta)


def _incident_domain_answer(
    state: AgentState,
    result: Any,
    evidence_by_id: dict[str, Evidence],
) -> TimelineAnswer | EvidenceGapAnswer:
    action_rows: list[dict[str, Any]] = []
    for action in result.actions:
        action_rows.append(
            {
                "action_id": action.action_id,
                "phase": action.phase,
                "title": action.title,
                "subject_ref": action.subject_ref,
                "policy_action": action.policy_decision.action.value,
                "risk": int(action.policy_decision.effective_risk),
                "policy_decision": action.policy_decision.model_dump(mode="json"),
                "execution_enabled": action.execution_enabled,
                "expected_impact": action.expected_impact,
                "rollback_condition": action.rollback_condition,
                "human_role": action.human_role,
                **_binding(action.prerequisite_evidence_ids, evidence_by_id),
            }
        )
    known = [
        {
            "fact_type": "dry_run_action",
            "value": row,
            "evidence_ids": list(row.get("evidence_ids", [])),
            "source_locator": row.get("source_locator"),
            "source_locators": list(row.get("source_locators", [])),
        }
        for row in action_rows
    ]
    alternatives = [
        {
            "claim_id": item.claim_id,
            "explanation": item.explanation,
            "treated_as_fact": item.treated_as_fact,
            **_binding(item.evidence_ids, evidence_by_id),
        }
        for item in result.alternative_explanations
    ]
    # Preserve the verifier-owned incident hypothesis itself, not only the
    # dry-run actions derived from it.  The old renderer exposed a hypothesis
    # only when it was conflicted (``alternative_explanations``); verified
    # and unverified claims therefore vanished from the typed IR plan even
    # though they were the reason the playbook was built.
    linked_evidence_by_claim: dict[str, list[str]] = {}
    for link in state.evidence_links:
        if link.verifier_status in {ClaimStatus.VERIFIED, ClaimStatus.CONFLICTED}:
            linked_evidence_by_claim.setdefault(link.claim_id, []).append(link.evidence_id)
    hypotheses: list[dict[str, Any]] = []
    for claim in sorted(state.claims, key=lambda item: item.claim_id):
        claim_type = claim.claim_type.casefold()
        if "incident" not in claim_type and "hypothes" not in claim_type:
            continue
        status = claim.status.value
        if status not in {"verified", "conflicted", "candidate", "rejected"}:
            status = "unknown"
        if status == "candidate":
            status = "unverified"
        hypotheses.append(
            {
                "hypothesis_id": claim.claim_id,
                "statement": claim.statement,
                "subject_ref": claim.subject_ref,
                "status": status,
                "evidence_ids": sorted(set(linked_evidence_by_claim.get(claim.claim_id, []))),
                "source_content_trust": "untrusted_data",
            }
        )
    hypotheses = _bounded_rows(hypotheses, 1_000, "hypotheses", [])
    gaps = [
        {
            "gap": gap,
            "required_evidence": ["operator_scope_confirmation", "integrity_checked_evidence"],
            "evidence_ids": [],
            "source_locator": None,
            "source_locators": [],
        }
        for gap in result.coverage_gaps
    ]
    mode = require_resolved_task_contract(state).scoring_mode
    answer: TimelineAnswer | EvidenceGapAnswer
    if mode == "evidence_gap":
        answer = EvidenceGapAnswer.model_validate(
            {
                "task_id": _answer_task_id(state),
                "execution_status": _domain_execution_status(state.status),
                "epistemic_status": _domain_epistemic_status(
                    state.status,
                    has_gaps=bool(gaps),
                    has_conflicts=bool(alternatives),
                ),
                "executive_summary": (
                    f"Incident dry run produced {len(action_rows)} non-executing action(s) "
                    f"and {len(gaps)} evidence gap(s)."
                ),
                "limitations": _bounded_limitations(result.coverage_gaps),
                "observations": action_rows,
                "known": known,
                "unknown_fields": [str(item["gap"]) for item in gaps],
                "conflicts": alternatives,
                "blocked_claims": gaps,
                "next_evidence": gaps,
                "extensions": {
                    "mode": result.mode,
                    "executed_action_count": result.executed_action_count,
                    "policy_actions": action_rows,
                    "hypotheses": hypotheses,
                    "policy_decisions": [row["policy_decision"] for row in action_rows],
                    "raw_artifact_digests": sorted(
                        _input_artifact_digests(state.input_artifacts)
                        | {
                            str(item.sha256).lower()
                            for item in evidence_by_id.values()
                            if isinstance(item.sha256, str) and re.fullmatch(r"[a-fA-F0-9]{64}", item.sha256)
                        }
                    ),
                },
            }
        )
        semantic_output, semantic_delta = build_scenario_semantic_projection(
            state,
            answer,
            scenario="incident_response",
            operation="incident_response_dry_run",
            evidence_by_id=evidence_by_id,
            policy_decisions=[row["policy_decision"] for row in action_rows],
            parser_id="incident-response-dry-run",
            parser_version="1.0",
        )
        return _attach_semantic_delta(answer, semantic_output, semantic_delta)
    events = [
        {
            "event_type": "incident_dry_run_action",
            "action_id": row["action_id"],
            "phase": row["phase"],
            "subject_ref": row["subject_ref"],
            **_binding(row.get("evidence_ids", []), evidence_by_id),
        }
        for row in action_rows
    ]
    answer = TimelineAnswer.model_validate(
        {
            "task_id": _answer_task_id(state),
            "execution_status": _domain_execution_status(state.status),
            "epistemic_status": _domain_epistemic_status(
                state.status,
                has_gaps=bool(gaps),
                has_conflicts=bool(alternatives),
            ),
            "executive_summary": (
                f"Incident dry run produced {len(action_rows)} non-executing action(s) and {len(gaps)} evidence gap(s)."
            ),
            "limitations": _bounded_limitations(result.coverage_gaps),
            "facts": known,
            "inferences": alternatives,
            "events": events,
            "actors": [
                {
                    "subject_ref": row["subject_ref"],
                    **_binding(row.get("evidence_ids", []), evidence_by_id),
                }
                for row in action_rows
            ],
            "iocs": [],
            "techniques": [],
            "gaps": gaps,
            "extensions": {
                "mode": result.mode,
                "executed_action_count": result.executed_action_count,
                "policy_actions": action_rows,
                "hypotheses": hypotheses,
                "alternatives": alternatives,
                "policy_decisions": [row["policy_decision"] for row in action_rows],
                "raw_artifact_digests": sorted(
                    _input_artifact_digests(state.input_artifacts)
                    | {
                        str(item.sha256).lower()
                        for item in evidence_by_id.values()
                        if isinstance(item.sha256, str) and re.fullmatch(r"[a-fA-F0-9]{64}", item.sha256)
                    }
                ),
            },
        }
    )
    semantic_output, semantic_delta = build_scenario_semantic_projection(
        state,
        answer,
        scenario="incident_response",
        operation="incident_response_dry_run",
        evidence_by_id=evidence_by_id,
        policy_decisions=[row["policy_decision"] for row in action_rows],
        parser_id="incident-response-dry-run",
        parser_version="1.0",
    )
    return _attach_semantic_delta(answer, semantic_output, semantic_delta)


def _decoded_command_text(token: str) -> str | None:
    """Decode one context-bound PowerShell-style Base64 token within hard limits."""

    if len(token) > 32_768:
        return None
    try:
        decoded = base64.b64decode(token, validate=True)
    except (binascii.Error, ValueError):
        return None
    if not decoded or len(decoded) > _MAX_EXACT_DECODED_BYTES:
        return None
    candidates: list[str] = []
    if len(decoded) % 2 == 0:
        try:
            candidates.append(decoded.decode("utf-16le"))
        except UnicodeDecodeError:
            pass
    try:
        candidates.append(decoded.decode("utf-8"))
    except UnicodeDecodeError:
        pass
    for text in candidates:
        if not text or len(text) > _MAX_EXACT_DECODED_BYTES:
            continue
        printable = sum(character.isprintable() or character in "\r\n\t" for character in text)
        if printable / len(text) >= 0.85:
            return text
    return None


def _contextual_exact_values(serialized: str) -> list[tuple[str, str]]:
    """Return bounded exact values only from explicit payload/task contexts."""

    values: list[tuple[str, str]] = []
    for match in _PAYLOAD_NAME_PATTERN.finditer(serialized):
        values.append((match.group(1), "explicit_payload_name"))
    for encoded in _ENCODED_COMMAND_PATTERN.finditer(serialized):
        decoded = _decoded_command_text(encoded.group(1))
        if decoded is None:
            continue
        for match in _EXACT_TOKEN_PATTERN.finditer(decoded):
            value = match.group(0)
            if not _is_scrubbed_exact_candidate(value):
                values.append((value, "decoded_flag_token"))
        for match in _TASK_NAME_PATTERN.finditer(decoded):
            values.append((match.group(1), "decoded_scheduled_task_name"))
        for match in _PAYLOAD_NAME_PATTERN.finditer(decoded):
            values.append((match.group(1), "decoded_payload_name"))
    return values[:_MAX_EXACT_LOG_VALUES]


def _contextual_exact_source_values(content: bytes) -> list[tuple[str, str, int, int]]:
    """Decode context-bound exact values even when a JSON view has no log rows.

    Public preprocessors may expose packet payload strings in a derived JSON
    document whose shape is intentionally not accepted as a security-log
    event.  The old path therefore produced zero normalized events and never
    reached :func:`_contextual_exact_values`, despite the immutable bytes
    containing a complete encoded command.  This bounded source pass recovers
    only explicit payload names plus conventional flag, scheduled-task, and
    payload values from a syntactically bound PowerShell Base64 argument.  It
    never executes content.  Plain-text values retain their exact byte range;
    decoded values cite the immutable encoded token's byte range.
    """

    if not content or len(content) > _MAX_CONTEXTUAL_EXACT_SOURCE_BYTES:
        return []
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        return []
    rows: list[tuple[str, str, int, int]] = []
    seen: set[str] = set()
    for match in _PAYLOAD_NAME_PATTERN.finditer(text):
        value = match.group(1)
        if value in seen:
            continue
        seen.add(value)
        byte_start = len(text[: match.start(1)].encode("utf-8"))
        byte_length = len(value.encode("utf-8"))
        rows.append((value, "explicit_payload_name", byte_start, byte_length))
        if len(rows) >= _MAX_EXACT_LOG_VALUES:
            return rows
    for encoded in _ENCODED_COMMAND_PATTERN.finditer(text):
        decoded = _decoded_command_text(encoded.group(1))
        if decoded is None:
            continue
        observed = [
            *((match.group(0), "decoded_flag_token") for match in _EXACT_TOKEN_PATTERN.finditer(decoded)),
            *((match.group(1), "decoded_scheduled_task_name") for match in _TASK_NAME_PATTERN.finditer(decoded)),
            *((match.group(1), "decoded_payload_name") for match in _PAYLOAD_NAME_PATTERN.finditer(decoded)),
        ]
        byte_start = len(text[: encoded.start(1)].encode("utf-8"))
        byte_length = len(encoded.group(1).encode("ascii"))
        for value, match_kind in observed:
            if _is_scrubbed_exact_candidate(value):
                continue
            if value in seen:
                continue
            seen.add(value)
            rows.append((value, match_kind, byte_start, byte_length))
            if len(rows) >= _MAX_EXACT_LOG_VALUES:
                return rows
    return rows


def _log_exact_candidates(result: LogAnalysisResult) -> list[dict[str, Any]]:
    """Extract bounded, source-bound exact tokens from normalized log rows.

    This is intentionally narrower than generic secret discovery. It only
    recognizes conventional challenge/incident flag tokens and always binds a
    value to the normalized event evidence that contained it. Uploaded text is
    data, never an instruction, and no value is synthesized from the task.
    """

    indexes = _log_evidence_indexes(result)
    evidence_by_id = {item.evidence_id: item for item in result.evidence}
    candidates: dict[str, dict[str, Any]] = {}
    for event in result.events:
        serialized = json.dumps(asdict(event), ensure_ascii=False, sort_keys=True, default=str)
        evidence_id = indexes["event"].get(event.event_id)
        if evidence_id is None or evidence_id not in evidence_by_id:
            continue
        observed = [
            (match.group(0), "bounded_flag_token")
            for match in _EXACT_TOKEN_PATTERN.finditer(serialized)
            if not _is_scrubbed_exact_candidate(match.group(0))
        ]
        observed.extend(
            (value, match_kind)
            for value, match_kind in _contextual_exact_values(serialized)
            if not _is_scrubbed_exact_candidate(value)
        )
        for value, match_kind in observed:
            candidates.setdefault(
                value,
                {
                    "value": value,
                    "event_id": event.event_id,
                    "match_kind": match_kind,
                    **_binding(
                        [evidence_id],
                        evidence_by_id,
                        fallback_locator=asdict(event.locator),
                    ),
                },
            )
            if len(candidates) >= _MAX_EXACT_LOG_VALUES:
                return list(candidates.values())
    return list(candidates.values())


def _log_exact_answer(
    state: AgentState,
    result: LogAnalysisResult,
    *,
    limitations: list[str],
    source_candidates: Sequence[dict[str, Any]] = (),
) -> ExactAnswer:
    candidates_by_value: dict[str, dict[str, Any]] = {}

    # Prefer the immutable byte-source locator over a normalized event locator
    # for duplicate values.  The latter may only identify the first record and
    # therefore cannot support exact byte-level replay. When the evaluator
    # supplies both an original artifact and a derived convenience view,
    # prefer the original observation for the same value while still parsing
    # and retaining both inputs. This changes provenance selection only; a
    # path name never bypasses analysis or verification.
    def source_priority(item: Mapping[str, Any]) -> tuple[int, int, str, int]:
        locator = item.get("source_locator")
        locator = locator if isinstance(locator, Mapping) else {}
        source_ref = str(locator.get("source_ref", "")).replace("\\", "/")
        normalized = source_ref.casefold()
        while normalized.startswith("./"):
            normalized = normalized[2:]
        derived = normalized.startswith(".secmind-derived/") or "/.secmind-derived/" in f"/{normalized}"
        match_kind = str(item.get("match_kind", "")).casefold()
        if "flag_token" in match_kind:
            semantic_rank = 0
        elif "scheduled_task_name" in match_kind:
            semantic_rank = 1
        elif "payload_name" in match_kind:
            semantic_rank = 2
        else:
            semantic_rank = 3
        offset = locator.get("byte_offset")
        return (semantic_rank, int(derived), normalized, offset if isinstance(offset, int) else 0)

    ordered_sources = sorted((dict(item) for item in source_candidates), key=source_priority)
    for item in [*ordered_sources, *_log_exact_candidates(result)]:
        value = item.get("value")
        if value and not _is_scrubbed_exact_candidate(str(value)):
            candidates_by_value.setdefault(str(value), dict(item))
    candidates = list(candidates_by_value.values())[:_MAX_EXACT_LOG_VALUES]
    values = [str(item["value"]) for item in candidates]
    source_offsets = [
        {
            **dict(item["source_locator"]),
            "record_locator": dict(item["source_locator"]),
        }
        for item in candidates
        if isinstance(item.get("source_locator"), dict)
    ]
    has_values = bool(values)
    answer = ExactAnswer.model_validate(
        {
            "task_id": _answer_task_id(state),
            "execution_status": _domain_execution_status(state.status),
            "epistemic_status": "conclusive" if has_values else "insufficient_evidence",
            "executive_summary": (
                f"Deterministic offline parsing recovered {len(values)} source-bound exact token(s)."
                if has_values
                else "Deterministic offline parsing found no source-bound exact token in the supplied bytes."
            ),
            "limitations": _bounded_limitations(limitations),
            "values": values,
            "items": candidates,
            "mapping": {"accepted_answer_candidates": values},
            "derivation": [
                {
                    "method": "bounded_normalized_event_pattern",
                    "pattern_class": "flag_token",
                    "evidence_ids": sorted(
                        {evidence_id for item in candidates for evidence_id in item.get("evidence_ids", [])}
                    ),
                }
            ],
            "source_offsets": source_offsets,
            "validation": {
                "method": "deterministic_offline_parser",
                "candidate_count": len(values),
                "all_candidates_evidence_bound": all(bool(item.get("evidence_ids")) for item in candidates),
            },
            "extensions": {
                "source_format": result.source_format,
                "records_seen": result.coverage.get("records_seen", 0),
                "raw_artifact_digests": _log_raw_artifact_digests(result),
            },
        }
    )
    semantic_output, semantic_delta = build_scenario_semantic_projection(
        state,
        answer,
        scenario="log_analysis",
        operation="offline_exact_answer_projection",
        evidence_by_id={item.evidence_id: item for item in state.evidence},
        rule_bundle_digest=(
            str(result.coverage.get("rule_bundle_digest"))
            if isinstance(result.coverage.get("rule_bundle_digest"), str)
            and re.fullmatch(r"[a-fA-F0-9]{64}", str(result.coverage.get("rule_bundle_digest")))
            else None
        ),
        parser_id=result.source_format,
        parser_version=(
            str(result.coverage.get("rule_bundle_version")) if result.coverage.get("rule_bundle_version") else None
        ),
    )
    return _attach_semantic_delta(answer, semantic_output, semantic_delta)


@dataclass(frozen=True, slots=True)
class ScenarioCasRead:
    """One typed CAS read outcome shared by evidence bound to the same object."""

    size_bytes: int | None
    digest: str | None
    error_code: str | None


@dataclass(slots=True)
class ScenarioEvidenceCache:
    """Run-scoped LRU cache that never turns a failed read into a digest error."""

    run_id: str
    max_entries: int = _MAX_SCENARIO_CAS_CACHE_ENTRIES
    _entries: OrderedDict[str, ScenarioCasRead] = field(default_factory=OrderedDict)

    def __post_init__(self) -> None:
        if not self.run_id or len(self.run_id) > 100 or any(ord(character) < 32 for character in self.run_id):
            raise ValueError("run_id is invalid")
        if self.max_entries < 1 or self.max_entries > _MAX_SCENARIO_CAS_CACHE_ENTRIES:
            raise ValueError(f"max_entries must be between 1 and {_MAX_SCENARIO_CAS_CACHE_ENTRIES}")

    def read(self, artifact_store: ContentAddressedArtifactStore, artifact_ref: str) -> ScenarioCasRead:
        cached = self._entries.get(artifact_ref)
        if cached is not None:
            self._entries.move_to_end(artifact_ref)
            return cached

        try:
            metadata = artifact_store.metadata_for(artifact_ref)
            if not metadata.globally_bound and self.run_id not in metadata.run_ids:
                outcome = ScenarioCasRead(None, None, "CAS_SCOPE_MISMATCH")
                self._remember(artifact_ref, outcome)
                return outcome
            content = artifact_store.read(artifact_ref)
        except PermissionError:
            outcome = ScenarioCasRead(None, None, "CAS_PERMISSION_DENIED")
        except FileNotFoundError:
            outcome = ScenarioCasRead(None, None, "CAS_OBJECT_UNAVAILABLE")
        except OSError:
            outcome = ScenarioCasRead(None, None, "CAS_OBJECT_UNAVAILABLE")
        except ArtifactStoreError as exc:
            message = str(exc).casefold()
            if "digest" in message:
                error_code = "CAS_DIGEST_MISMATCH"
            elif "invalid artifact id" in message or "invalid artifact path" in message:
                error_code = "CAS_REFERENCE_INVALID"
            else:
                error_code = "CAS_OBJECT_INVALID"
            outcome = ScenarioCasRead(None, None, error_code)
        except ValueError:
            outcome = ScenarioCasRead(None, None, "CAS_REFERENCE_INVALID")
        else:
            outcome = ScenarioCasRead(len(content), hashlib.sha256(content).hexdigest(), None)

        self._remember(artifact_ref, outcome)
        return outcome

    def _remember(self, artifact_ref: str, outcome: ScenarioCasRead) -> None:
        self._entries[artifact_ref] = outcome
        self._entries.move_to_end(artifact_ref)
        if len(self._entries) > self.max_entries:
            self._entries.popitem(last=False)

    def __len__(self) -> int:
        return len(self._entries)


@dataclass(frozen=True, slots=True)
class ScenarioClaimRequest:
    claim_type: str
    subject_ref: str
    statement: str
    evidence_ids: tuple[str, ...]


@dataclass(slots=True)
class ScenarioExecutor:
    """Run bounded deterministic scenario analyzers against immutable inputs."""

    artifact_store: ContentAddressedArtifactStore
    task_specs: TaskSpecRepository
    binary_log_parsers_enabled: bool = False
    broker: ToolBroker | None = None
    reverse_dynamic_enabled: bool = False

    def execute_log_analysis(self, state: AgentState) -> None:
        """Analyze supported logs and publish only integrity-verified claims."""

        if _firmware_capability_requested(state):
            self.execute_firmware_static_audit(state)
            return

        limitations: list[str] = []
        timeline_artifact_ids: list[str] = []
        log_results: list[LogAnalysisResult] = []
        exact_source_candidates: list[dict[str, Any]] = []
        analyzed_sources = 0
        known_evidence_ids = {item.evidence_id for item in state.evidence}
        cas_cache = ScenarioEvidenceCache(run_id=state.run_id)
        non_authoritative_diagnostics: list[dict[str, str]] = []

        selections = _log_input_selections(state.input_artifacts)
        state.audit_coverage["log_input_roles"] = [
            {
                "artifact_id": item.artifact.artifact_id,
                "path": item.artifact.relative_path,
                "sha256": item.artifact.sha256.lower(),
                "media_type": item.artifact.media_type,
                "role": item.role,
                "affects_status": item.affects_status,
                "reason": item.reason,
            }
            for item in selections
        ]
        candidates = [item for item in selections if item.role != "context"]
        omitted = candidates[100:]
        if omitted:
            state.audit_coverage["scenario_sources_omitted"] = len(omitted)
            if any(item.affects_status for item in omitted):
                limitations.append(f"{len(omitted)} source artifact(s) omitted by the 100-source bound")

        for selection in candidates[:100]:
            artifact = selection.artifact
            artifact_limitations: list[str] = []
            try:
                if require_resolved_task_contract(state).scoring_mode == "exact_answer_with_evidence":
                    exact_source_candidates.extend(self._extract_exact_source_candidates(state, artifact, cas_cache))
                result = self._analyze_log_input(state, artifact)
            except (ArtifactStoreError, FileNotFoundError, PermissionError) as exc:
                if not selection.affects_status:
                    non_authoritative_diagnostics.append(
                        {"path": artifact.relative_path, "role": selection.role, "reason": type(exc).__name__}
                    )
                    continue
                self._finish_log_integrity_failure(
                    state,
                    artifact=artifact,
                    analyzed_sources=analyzed_sources,
                    limitations=limitations,
                    reason_code=type(exc).__name__,
                )
                return
            except (LogAnalysisError, OSError, ValueError) as exc:
                message = f"{artifact.relative_path}: {type(exc).__name__}"
                if selection.affects_status:
                    limitations.append(message)
                else:
                    non_authoritative_diagnostics.append(
                        {"path": artifact.relative_path, "role": selection.role, "reason": type(exc).__name__}
                    )
                continue

            failures: dict[str, tuple[str, ...]] = {}
            verified = verify_scenario_evidence(
                self.artifact_store,
                result.evidence,
                run_id=state.run_id,
                cache=cas_cache,
                failure_reasons=failures,
            )
            if len(verified) != len(result.evidence):
                reason_codes = sorted({reason for reasons in failures.values() for reason in reasons})
                if not selection.affects_status:
                    non_authoritative_diagnostics.append(
                        {
                            "path": artifact.relative_path,
                            "role": selection.role,
                            "reason": "evidence_integrity:" + ",".join(reason_codes),
                        }
                    )
                    continue
                self._finish_log_integrity_failure(
                    state,
                    artifact=artifact,
                    analyzed_sources=analyzed_sources,
                    limitations=limitations,
                    reason_code=",".join(reason_codes),
                    create_claim=False,
                )
                return

            analyzed_sources += 1
            self._merge_log_evidence(state, result, known_evidence_ids)
            self._materialize_log_claims(state, result, verified, artifact_limitations)
            if selection.affects_status:
                limitations.extend(artifact_limitations)
            else:
                non_authoritative_diagnostics.extend(
                    {"path": artifact.relative_path, "role": selection.role, "reason": item}
                    for item in artifact_limitations
                )
            effective_result = result
            if not selection.affects_status and result.status != "completed":
                non_authoritative_diagnostics.append(
                    {
                        "path": artifact.relative_path,
                        "role": selection.role,
                        "reason": "partial parsing or analysis coverage",
                    }
                )
                effective_result = replace(result, status="completed", diagnostics=())
            log_results.append(effective_result)
            timeline = self._store_timeline(state.run_id, artifact.relative_path, result)
            timeline_artifact_ids.append(timeline.artifact_id)
            self._record_log_observation(state, artifact.relative_path, result, timeline)
            if result.status != "completed" and selection.affects_status:
                limitations.append(f"{artifact.relative_path}: partial parsing or analysis coverage")

        if analyzed_sources == 0:
            if not selections:
                raise LogAnalysisError("no supported log artifact produced a result")
            degraded_sources = [item.artifact for item in selections if item.affects_status][:100]
            if not degraded_sources:
                degraded_sources = [item.artifact for item in selections[:100]]
            degraded_paths = [item.relative_path for item in degraded_sources]
            limitations.append(
                "No enabled offline parser produced a typed result; source bytes were retained as an evidence gap."
            )
            log_results.append(
                LogAnalysisResult(
                    status="partial",
                    source_format="unsupported",
                    events=(),
                    timeline_event_ids=(),
                    rule_matches=(),
                    iocs=(),
                    attack_mappings=(),
                    diagnostics=(
                        ParserDiagnostic(
                            code="parser_unavailable",
                            message=(
                                "No enabled offline parser produced a normalized record for source(s): "
                                + ", ".join(degraded_paths)
                            ),
                            severity="warning",
                        ),
                    ),
                    evidence=(),
                    coverage={
                        "sources_seen": len(degraded_sources),
                        "parser_available": False,
                        "no_tool_degradation": True,
                        "raw_artifact_digests": [item.sha256.lower() for item in degraded_sources],
                        "network_access_performed": False,
                        "model_calls": 0,
                    },
                )
            )
            analyzed_sources = len(degraded_sources)
        state.audit_coverage["log_non_authoritative_diagnostics"] = non_authoritative_diagnostics[:200]
        self._finish_log_report(
            state,
            analyzed_sources,
            timeline_artifact_ids,
            limitations,
            log_results,
            exact_source_candidates=exact_source_candidates,
        )

    def execute_firmware_static_audit(self, state: AgentState) -> None:
        """Run the capability-gated, read-only firmware evidence compiler."""

        limits = FirmwareAuditLimits()
        limitations: list[str] = []
        sources: list[FirmwareAuditSource] = []
        total_bytes = 0
        artifacts = sorted(state.input_artifacts, key=lambda item: item.relative_path.casefold())
        if len(artifacts) > limits.max_artifacts:
            limitations.append(
                f"{len(artifacts) - limits.max_artifacts} firmware artifact(s) omitted by the "
                f"{limits.max_artifacts}-artifact bound"
            )
        for artifact in artifacts[: limits.max_artifacts]:
            if artifact.size_bytes > limits.max_bytes_per_artifact:
                limitations.append(
                    f"{artifact.relative_path}: artifact exceeds the {limits.max_bytes_per_artifact}-byte bound"
                )
                continue
            if total_bytes + artifact.size_bytes > limits.max_total_bytes:
                limitations.append(f"{artifact.relative_path}: total firmware audit byte budget exhausted")
                break
            try:
                content = self._read_input_artifact(state.run_id, artifact)
            except (ArtifactStoreError, FileNotFoundError, OSError, PermissionError, ValueError) as exc:
                limitations.append(f"{artifact.relative_path}: immutable source unavailable ({type(exc).__name__})")
                continue
            total_bytes += len(content)
            sources.append(FirmwareAuditSource(artifact=artifact, content=content))

        result = audit_firmware_sources(sources, limits=limits)
        limitations.extend(result.limitations)
        evidence_by_id = {item.evidence_id: item for item in state.evidence}
        conflicting_evidence_ids: set[str] = set()
        for evidence in result.evidence:
            existing = evidence_by_id.get(evidence.evidence_id)
            if existing is None:
                state.evidence.append(evidence)
                evidence_by_id[evidence.evidence_id] = evidence
            elif existing != evidence:
                conflicting_evidence_ids.add(evidence.evidence_id)
                limitations.append(f"Evidence identity conflict for {evidence.evidence_id}; record withheld")
        cache = ScenarioEvidenceCache(run_id=state.run_id)
        verification_failures: dict[str, tuple[str, ...]] = {}
        verified_evidence_ids = verify_scenario_evidence(
            self.artifact_store,
            list(result.evidence),
            run_id=state.run_id,
            cache=cache,
            failure_reasons=verification_failures,
        )
        verified_evidence_ids.difference_update(conflicting_evidence_ids)
        if len(verified_evidence_ids) != len(result.evidence):
            reasons = sorted({reason for values in verification_failures.values() for reason in values})
            limitations.append(
                "firmware evidence integrity gate rejected "
                f"{len(result.evidence) - len(verified_evidence_ids)} record(s) ({','.join(reasons)})"
            )

        existing_finding_ids = {item.finding_id for item in state.findings}
        accepted_findings: list[Finding] = []
        for finding in result.findings:
            if finding.finding_id in existing_finding_ids:
                accepted_findings.append(finding)
                continue
            if verify_scenario_claim(
                state,
                claim_type="firmware_static_finding",
                subject_ref=finding.finding_id,
                statement=(
                    f"Firmware static rule {finding.rule_id} matched {finding.path}:{finding.line or 0} "
                    "and is supported by immutable source evidence."
                ),
                evidence_ids=finding.evidence_ids,
                verified_evidence_ids=verified_evidence_ids,
            ):
                state.findings.append(finding)
                existing_finding_ids.add(finding.finding_id)
                accepted_findings.append(finding)
            else:
                limitations.append(f"Finding {finding.finding_id} failed the firmware evidence gate")

        if verification_failures or limitations:
            state.status = RunStatus.PARTIAL
        else:
            state.status = result.status
        evidence_by_id = {item.evidence_id: item for item in state.evidence}
        answer = _firmware_finding_answer(
            state,
            result,
            accepted_findings,
            evidence_by_id,
            verified_evidence_ids,
            limitations,
        )
        record_scenario_semantic_projection(state, answer)
        state.decisions.append(
            DecisionRecord(
                decision="firmware_static_audit_completed",
                rationale_summary=(
                    "Bounded firmware text/configuration checks ran against manifest-bound CAS bytes; "
                    "no artifact content was executed or sent to a network."
                ),
                evidence_ids=sorted(verified_evidence_ids),
                policy_ids=["FIRMWARE-STATIC-READ-ONLY-V1", "EVIDENCE-REQUIRED-V1", "CAS-MANIFEST-BOUND-V1"],
                model_id="deterministic-firmware-static-audit",
                confidence=1.0,
            )
        )
        state.audit_coverage.update(
            {
                **result.coverage,
                "sources_unavailable": len(artifacts) - len(sources),
                "verified_evidence_count": len(verified_evidence_ids),
                "primary_is_supplemental": True,
            }
        )
        state.report = AgentReport(
            run_id=state.run_id,
            status=state.status,
            executive_summary=(
                f"Firmware static audit checked {len(result.checked_paths)} artifact(s) and retained "
                f"{len(accepted_findings)} evidence-bound finding(s)."
            ),
            answer_type=answer.answer_kind,
            answer_payload=answer.model_dump(mode="json"),
            findings=list(state.findings),
            decisions=list(state.decisions),
            evidence=state.evidence,
            limitations=_bounded_limitations(limitations),
            coverage=dict(state.audit_coverage),
            claim_ids=[item.claim_id for item in state.claims if item.status == ClaimStatus.VERIFIED],
        )

    def execute_reverse_triage(self, state: AgentState) -> None:
        """Compile high-confidence reverse behavior from immutable source bytes."""

        limits = ReverseTriageLimits()
        artifacts = sorted(state.input_artifacts, key=lambda item: item.relative_path.casefold())
        limitations: list[str] = []
        sources: list[ReverseTriageSource] = []
        total_bytes = 0
        pe_tool_result: ToolResult | None = None
        dynamic_observations: list[dict[str, Any]] = []
        pe_artifact = self._reverse_pe_candidate(artifacts)
        if self.broker is not None and pe_artifact is not None:
            try:
                tool_result = self._invoke_reverse_pe_tool(state, pe_artifact)
            except Exception as exc:  # noqa: BLE001 - keep reverse triage moving if tool execution fails
                limitations.append(f"pe_reverse_analysis failed: {type(exc).__name__}")
            else:
                pe_tool_result = tool_result
                state.observations.append(tool_result)
                pe_data = tool_result.data if isinstance(tool_result.data, dict) else {}
                pe_file_value = pe_data.get("file")
                pe_file: dict[str, Any] = pe_file_value if isinstance(pe_file_value, dict) else {}
                pe_info_value = pe_data.get("pe")
                pe_info: dict[str, Any] = pe_info_value if isinstance(pe_info_value, dict) else {}
                state.audit_coverage["reverse_pe_tool"] = {
                    "tool_name": "pe_reverse_analysis",
                    "status": tool_result.status.value,
                    "summary": tool_result.summary,
                    "error_code": tool_result.error_code,
                    "error_message": tool_result.error_message,
                    "evidence_count": len(tool_result.evidence),
                    "architecture": pe_file.get("architecture"),
                    "section_count": pe_info.get("section_count"),
                    "import_library_count": pe_info.get("import_library_count"),
                }
                existing_ids = {item.evidence_id for item in state.evidence}
                for item in tool_result.evidence:
                    if item.evidence_id not in existing_ids:
                        state.evidence.append(item)
                        existing_ids.add(item.evidence_id)
                if tool_result.status == ToolStatus.SUCCESS and tool_result.evidence:
                    verified_pe_evidence = verify_scenario_evidence(
                        self.artifact_store,
                        tool_result.evidence,
                        run_id=state.run_id,
                        cache=ScenarioEvidenceCache(run_id=state.run_id),
                    )
                    if verified_pe_evidence:
                        verify_scenario_claim(
                            state,
                            claim_type="reverse_static_structure",
                            subject_ref=f"reverse:pe:{pe_artifact.sha256.lower()}",
                            statement=tool_result.summary or "Static PE structure was parsed from immutable sample bytes.",
                            evidence_ids=[item.evidence_id for item in tool_result.evidence],
                            verified_evidence_ids=verified_pe_evidence,
                        )
                    else:
                        limitations.append("PE static evidence did not pass immutable source verification")
                state.decisions.append(
                    DecisionRecord(
                        decision="pe_reverse_analysis_completed",
                        rationale_summary=tool_result.summary or "Static PE reverse analysis completed.",
                        evidence_ids=[item.evidence_id for item in tool_result.evidence],
                        policy_ids=["REVERSE-STATIC-READ-ONLY-V1", "APPROVED-TOOL-MANIFEST-V1"],
                        model_id="pe_reverse_analysis",
                        confidence=1.0 if tool_result.status == ToolStatus.SUCCESS else 0.0,
                    )
                )
        if self.reverse_dynamic_enabled and self.broker is not None and pe_artifact is not None:
            from secmind.reverse_analysis_observation import ReverseAnalysisObservation

            for profile_id in ("wrong_token", "correct_token"):
                try:
                    dynamic_result = self._invoke_reverse_dynamic_tool(state, pe_artifact, profile_id)
                except Exception as exc:  # noqa: BLE001 - dynamic failure must preserve static results
                    dynamic_result = ToolResult(
                        status=ToolStatus.ERROR,
                        error_code="SPEAKEASY_INVOCATION_FAILED",
                        error_message=type(exc).__name__,
                    )
                state.observations.append(dynamic_result)
                if dynamic_result.status == ToolStatus.SUCCESS and isinstance(dynamic_result.data, dict):
                    try:
                        observation = ReverseAnalysisObservation.model_validate(dynamic_result.data)
                    except ValueError:
                        observation = None
                    if observation is not None:
                        if observation.sample_sha256 != pe_artifact.sha256.lower():
                            dynamic_observations.append(
                                ReverseAnalysisObservation(
                                    source="speakeasy",
                                    status="unavailable",
                                    sample_sha256=pe_artifact.sha256.lower(),
                                    tool_identity={"name": "speakeasy_dynamic_analysis", "version": "1"},
                                    profile_id=profile_id,
                                    coverage={"real_network_requests": 0, "host_pe_executions": 0},
                                    error={"code": "SPEAKEASY_SAMPLE_HASH_MISMATCH"},
                                ).model_dump(mode="json")
                            )
                            limitations.append(f"speakeasy {profile_id} sample hash did not match the input artifact")
                            continue
                        for item in dynamic_result.evidence:
                            if all(existing.evidence_id != item.evidence_id for existing in state.evidence):
                                state.evidence.append(item)
                        dynamic_observations.append(observation.model_dump(mode="json"))
                        if observation.status != "completed":
                            limitations.append(f"speakeasy {profile_id} profile returned {observation.status}")
                        continue
                dynamic_observations.append(
                    ReverseAnalysisObservation(
                        source="speakeasy",
                        status="unavailable",
                        sample_sha256=pe_artifact.sha256.lower(),
                        tool_identity={"name": "speakeasy_dynamic_analysis", "version": "1"},
                        profile_id=profile_id,
                        coverage={"real_network_requests": 0, "host_pe_executions": 0},
                        error={
                            "code": dynamic_result.error_code or "DYNAMIC_UNAVAILABLE",
                            "message": dynamic_result.error_message or "Dynamic emulation was unavailable.",
                        },
                    ).model_dump(mode="json")
                )
                limitations.append(f"speakeasy {profile_id} profile unavailable")
            state.audit_coverage["reverse_dynamic_tool"] = {
                "tool_name": "speakeasy_dynamic_analysis",
                "profiles": [item.get("profile_id") for item in dynamic_observations],
                "statuses": [item.get("status") for item in dynamic_observations],
                "real_network_requests": 0,
                "host_pe_executions": 0,
            }
        if len(artifacts) > limits.max_artifacts:
            limitations.append(
                f"{len(artifacts) - limits.max_artifacts} reverse source(s) omitted by the artifact bound"
            )
        for artifact in artifacts[: limits.max_artifacts]:
            if artifact.size_bytes > limits.max_bytes_per_artifact:
                limitations.append(f"{artifact.relative_path}: source exceeds the per-artifact byte bound")
                continue
            if total_bytes + artifact.size_bytes > limits.max_total_bytes:
                limitations.append(f"{artifact.relative_path}: total reverse-triage byte budget exhausted")
                break
            try:
                content = self._read_input_artifact(state.run_id, artifact)
            except (ArtifactStoreError, FileNotFoundError, OSError, PermissionError, ValueError) as exc:
                limitations.append(f"{artifact.relative_path}: immutable source unavailable ({type(exc).__name__})")
                continue
            total_bytes += len(content)
            sources.append(ReverseTriageSource(artifact=artifact, content=content))

        result = analyze_reverse_sources(sources, limits=limits, preexisting_limitations=limitations)
        evidence_by_id = {item.evidence_id: item for item in state.evidence}
        conflicting_evidence_ids: set[str] = set()
        for item in result.evidence:
            existing = evidence_by_id.get(item.evidence_id)
            if existing is None:
                state.evidence.append(item)
                evidence_by_id[item.evidence_id] = item
            elif existing != item:
                conflicting_evidence_ids.add(item.evidence_id)
                limitations.append(f"Evidence identity conflict for {item.evidence_id}; reverse row withheld")
        failure_reasons: dict[str, tuple[str, ...]] = {}
        verified_evidence_ids = verify_scenario_evidence(
            self.artifact_store,
            list(result.evidence),
            run_id=state.run_id,
            cache=ScenarioEvidenceCache(run_id=state.run_id),
            failure_reasons=failure_reasons,
        )
        verified_evidence_ids.difference_update(conflicting_evidence_ids)
        if len(verified_evidence_ids) != len(result.evidence):
            reasons = sorted({reason for values in failure_reasons.values() for reason in values})
            limitations.append(
                "reverse evidence integrity gate rejected "
                f"{len(result.evidence) - len(verified_evidence_ids)} record(s) ({','.join(reasons)})"
            )

        accepted_behaviors = self._verified_reverse_rows(
            state,
            result.behaviors,
            claim_type="reverse_static_behavior",
            verified_evidence_ids=verified_evidence_ids,
        )
        accepted_evasion = self._verified_reverse_rows(
            state,
            result.evasion,
            claim_type="reverse_anti_analysis_behavior",
            verified_evidence_ids=verified_evidence_ids,
        )
        accepted_rule_ids = {str(item.get("rule_id")) for item in accepted_behaviors}
        accepted_injection = [item for item in result.injection if str(item.get("rule_id")) in accepted_rule_ids]
        mitre_attack = sorted(
            {
                str(value)
                for row in [*accepted_behaviors, *accepted_evasion]
                for value in (row.get("behavior"), row.get("mitre_attack_id"), row.get("mitre_attack_name"))
                if value
            }
        )
        if result.behaviors and not accepted_behaviors:
            limitations.append("All deterministic reverse behavior rows failed the evidence/claim gate")
        pe_tool_completed = pe_tool_result is not None and pe_tool_result.status == ToolStatus.SUCCESS
        status = RunStatus.COMPLETED if pe_tool_completed else result.status
        if limitations or failure_reasons:
            status = RunStatus.PARTIAL
        state.status = status
        result_limitations = list(result.limitations)
        pe_tool_limitations: list[str] = []
        if pe_tool_completed and pe_tool_result is not None:
            result_limitations = [
                item for item in result_limitations if "only bounded textual C/C++ inputs are supported" not in item
            ]
            raw_tool_limitations = pe_tool_result.data.get("limitations", [])
            if isinstance(raw_tool_limitations, list):
                pe_tool_limitations = [str(item) for item in raw_tool_limitations if str(item)]
        unknowns = (
            []
            if accepted_behaviors
            else [
                "PE static structure was parsed, but no complete high-confidence process-hollowing or remote "
                "DLL-injection API chain was established."
                if pe_tool_completed
                else "No complete high-confidence process-hollowing or remote DLL-injection API chain was established."
            ]
        )
        executive_summary = (
            pe_tool_result.summary
            if pe_tool_completed and pe_tool_result is not None and pe_tool_result.summary
            else (
                f"Bounded static reverse triage identified {len(accepted_behaviors)} evidence-bound "
                f"behavior chain(s) across {len(result.checked_paths)} source file(s)."
            )
        )
        reverse_analysis: dict[str, Any] = {"observations": [], "fused_facts": {}}
        static_fact_candidates: dict[str, dict[str, Any]] = {}
        if pe_tool_completed and pe_tool_result is not None and isinstance(pe_tool_result.data, dict):
            from secmind.reverse_analysis_observation import static_pe_observation

            observation = static_pe_observation(
                pe_tool_result.data,
                [item.evidence_id for item in pe_tool_result.evidence],
            )
            static_fact_candidates = {
                "format": {
                    "value": pe_tool_result.data.get("file", {}).get("format"),
                    "evidence_refs": list(observation.evidence_refs),
                }
            }
            reverse_analysis["observations"] = [observation.model_dump(mode="json")]
        reverse_analysis["observations"].extend(dynamic_observations)
        dynamic_fact_candidates: dict[str, dict[str, Any]] = {}
        for dynamic_observation in dynamic_observations:
            profile_id = str(dynamic_observation.get("profile_id") or "")
            artifacts_value = dynamic_observation.get("artifacts")
            artifacts_payload: dict[str, Any] = artifacts_value if isinstance(artifacts_value, dict) else {}
            created_files_value = artifacts_payload.get("created_files")
            created_files = list(created_files_value) if isinstance(created_files_value, list) else []
            evidence_refs_value = dynamic_observation.get("evidence_refs")
            evidence_refs = list(evidence_refs_value) if isinstance(evidence_refs_value, list) else []
            if profile_id and dynamic_observation.get("status") == "completed":
                dynamic_fact_candidates[f"profile:{profile_id}"] = {
                    "value": {
                        "exit_code": artifacts_payload.get("exit_code"),
                        "created_files": created_files,
                    },
                    "evidence_refs": evidence_refs,
                }
        from secmind.reverse_analysis_observation import fuse_reverse_facts

        reverse_analysis["fused_facts"] = fuse_reverse_facts(static_fact_candidates, dynamic_fact_candidates)
        answer = ReverseBehaviorAnswer.model_validate(
            {
                "task_id": _answer_task_id(state),
                "execution_status": _domain_execution_status(status),
                "epistemic_status": (
                    "conclusive" if accepted_behaviors and status == RunStatus.COMPLETED else "insufficient_evidence"
                ),
                "executive_summary": executive_summary,
                "limitations": _bounded_limitations([*result_limitations, *pe_tool_limitations, *limitations]),
                "behaviors": accepted_behaviors,
                "injection": accepted_injection,
                "evasion": accepted_evasion,
                "mitre_attack": mitre_attack,
                "c2": result.c2_observation,
                "unknowns": unknowns,
                "extensions": {
                    "capability": REVERSE_TRIAGE_CAPABILITY,
                    "coverage": dict(result.coverage),
                    "checked_paths": list(result.checked_paths),
                    "verified_evidence_ids": sorted(verified_evidence_ids),
                    "rule_bundle_digest": REVERSE_RULE_BUNDLE_DIGEST,
                    "rule_bundle_version": REVERSE_RULE_BUNDLE_VERSION,
                    "raw_artifact_digests": sorted(
                        {item.sha256.lower() for item in state.input_artifacts if item.sha256}
                    ),
                    "network_requests": 0,
                    "execution_performed": False,
                    "emulation_performed": any(item.get("status") == "completed" for item in dynamic_observations),
                    "model_calls": 0,
                    "primary_is_supplemental": True,
                    "reverse_analysis": reverse_analysis,
                },
            }
        )
        output, delta = build_scenario_semantic_projection(
            state,
            answer,
            scenario="reverse_triage",
            operation="bounded_static_reverse_triage",
            evidence_by_id=evidence_by_id,
            rule_bundle_digest=REVERSE_RULE_BUNDLE_DIGEST,
            parser_id=REVERSE_TRIAGE_CAPABILITY,
            parser_version=REVERSE_RULE_BUNDLE_VERSION,
        )
        answer = _attach_semantic_delta(answer, output, delta)
        record_scenario_semantic_projection(state, answer)
        state.decisions.append(
            DecisionRecord(
                decision="bounded_static_reverse_triage_completed",
                rationale_summary=(
                    "Complete API chains were matched against manifest-bound source bytes; no sample was "
                    "executed and no network request was made."
                ),
                evidence_ids=sorted(verified_evidence_ids),
                policy_ids=["REVERSE-STATIC-READ-ONLY-V1", "EVIDENCE-REQUIRED-V1", "CAS-MANIFEST-BOUND-V1"],
                model_id="deterministic-static-reverse-triage",
                confidence=1.0,
            )
        )
        state.audit_coverage.update(result.coverage)
        state.report = AgentReport(
            run_id=state.run_id,
            status=state.status,
            executive_summary=answer.executive_summary,
            answer_type=answer.answer_kind,
            answer_payload=answer.model_dump(mode="json"),
            findings=list(state.findings),
            decisions=list(state.decisions),
            evidence=list(state.evidence),
            limitations=list(answer.limitations),
            coverage=dict(state.audit_coverage),
            claim_ids=[item.claim_id for item in state.claims if item.status == ClaimStatus.VERIFIED],
        )

    @staticmethod
    def _reverse_pe_candidate(artifacts: Sequence[InputArtifact]) -> InputArtifact | None:
        candidates = [
            artifact
            for artifact in artifacts
            if artifact.relative_path.casefold().endswith((".exe", ".dll", ".sys", ".bin"))
        ]
        if candidates:
            return sorted(candidates, key=lambda item: item.relative_path.casefold())[0]
        return None

    def _invoke_reverse_pe_tool(self, state: AgentState, artifact: InputArtifact) -> ToolResult:
        if self.broker is None:
            raise RuntimeError("reverse PE tool invocation requires a tool broker")
        invocation_id = str(uuid5(NAMESPACE_URL, f"secmind:reverse-pe:{state.run_id}:{artifact.artifact_id}"))
        context = ToolContext(
            run_id=state.run_id,
            step_id="reverse-pe-analysis",
            workspace=state.workspace,
            allowed_paths=[state.workspace],
            invocation_id=invocation_id,
            idempotency_key=f"{state.run_id}:reverse-pe:{artifact.artifact_id}",
            attempt=1,
            # This scenario runs inside the Worker-held run lease.  The broker
            # fences every durable tool transition, so a synthetic fence of 0
            # would be rejected when a real Worker lease is active.
            lease_fence=state.lease.fence,
            lease_owner_id=state.lease.owner_id or "reverse-triage",
            step_run_id=None,
            run_fence=0,
            step_fence=0,
            usage_reservation_id=None,
            dispatch_permit_id=None,
            work_contract_id=None,
        )
        return asyncio.run(
            self.broker.execute(
                "pe_reverse_analysis",
                {"target": artifact.relative_path},
                context,
                autonomy_policy="automatic",
            )
        )

    def _invoke_reverse_dynamic_tool(
        self,
        state: AgentState,
        artifact: InputArtifact,
        profile_id: str,
    ) -> ToolResult:
        if self.broker is None:
            raise RuntimeError("reverse dynamic tool invocation requires a tool broker")
        invocation_id = str(
            uuid5(NAMESPACE_URL, f"secmind:reverse-dynamic:{state.run_id}:{artifact.artifact_id}:{profile_id}")
        )
        context = ToolContext(
            run_id=state.run_id,
            step_id=f"reverse-dynamic-{profile_id}",
            workspace=state.workspace,
            allowed_paths=[state.workspace],
            invocation_id=invocation_id,
            idempotency_key=f"{state.run_id}:reverse-dynamic:{artifact.artifact_id}:{profile_id}",
            attempt=1,
            lease_fence=state.lease.fence,
            lease_owner_id=state.lease.owner_id or "reverse-triage",
        )
        return asyncio.run(
            self.broker.execute(
                "speakeasy_dynamic_analysis",
                {
                    "target": artifact.relative_path,
                    "profile_id": profile_id,
                    "timeout_seconds": 15,
                    "max_instructions": 1_000_000,
                    "max_api_count": 2_000,
                },
                context,
                autonomy_policy="automatic",
            )
        )

    @staticmethod
    def _verified_reverse_rows(
        state: AgentState,
        rows: Sequence[Mapping[str, Any]],
        *,
        claim_type: str,
        verified_evidence_ids: set[str],
    ) -> list[dict[str, Any]]:
        accepted: list[dict[str, Any]] = []
        for row in rows:
            evidence_ids = [str(item) for item in row.get("evidence_ids", []) if str(item)]
            subject_seed = json.dumps(
                [claim_type, row.get("rule_id") or row.get("behavior"), evidence_ids],
                sort_keys=True,
                separators=(",", ":"),
            )
            subject_ref = f"reverse:{hashlib.sha256(subject_seed.encode()).hexdigest()[:32]}"
            if not evidence_ids or not set(evidence_ids) <= verified_evidence_ids:
                continue
            if verify_scenario_claim(
                state,
                claim_type=claim_type,
                subject_ref=subject_ref,
                statement=str(row.get("description") or row.get("behavior") or claim_type),
                evidence_ids=evidence_ids,
                verified_evidence_ids=verified_evidence_ids,
            ):
                accepted.append(dict(row))
        return accepted

    def _extract_exact_source_candidates(
        self,
        state: AgentState,
        artifact: InputArtifact,
        cache: ScenarioEvidenceCache,
    ) -> list[dict[str, Any]]:
        """Recover bounded exact tokens directly from immutable source bytes."""

        content = self._read_input_artifact(state.run_id, artifact)
        rows: list[dict[str, Any]] = []
        known_ids = {item.evidence_id for item in state.evidence}
        observed: list[tuple[str, str, int, int]] = []
        for match in _EXACT_TOKEN_BYTES_PATTERN.finditer(content):
            try:
                value = match.group(0).decode("ascii")
            except UnicodeDecodeError:
                continue
            observed.append((value, "bounded_flag_token", match.start(), match.end() - match.start()))
        observed.extend(_contextual_exact_source_values(content))
        seen_values: set[str] = set()
        for value, match_kind, byte_offset, byte_length in observed:
            if _is_scrubbed_exact_candidate(value):
                continue
            if value in seen_values:
                continue
            seen_values.add(value)
            locator = {
                "source_ref": artifact.relative_path,
                "segment_id": "decoded-exact-token" if match_kind.startswith("decoded_") else "exact-token",
                "record_number": 0,
                "line_number": content[:byte_offset].count(b"\n") + 1,
                "byte_offset": byte_offset,
                "byte_length": byte_length,
                "locator_scope": "record",
            }
            evidence_id = str(
                uuid5(
                    NAMESPACE_URL,
                    f"secmind:exact-source:{artifact.sha256}:{byte_offset}:{value}",
                )
            )
            evidence = Evidence(
                evidence_id=evidence_id,
                source="deterministic_exact_source@1.0",
                summary="A bounded exact-answer token was observed in immutable source bytes.",
                artifact_ref=artifact.sha256.lower(),
                sha256=artifact.sha256.lower(),
                metadata={
                    "evidence_type": "exact_value_observation",
                    "source_artifact_sha256": artifact.sha256.lower(),
                    "source_locator": locator,
                    "value_sha256": hashlib.sha256(value.encode()).hexdigest(),
                },
            )
            if evidence_id not in known_ids:
                state.evidence.append(evidence)
                known_ids.add(evidence_id)
            verified = verify_scenario_evidence(
                self.artifact_store,
                [evidence],
                run_id=state.run_id,
                cache=cache,
            )
            subject_ref = f"exact:{hashlib.sha256(value.encode()).hexdigest()[:24]}"
            if verify_scenario_claim(
                state,
                claim_type="exact_value_observed",
                subject_ref=subject_ref,
                statement="A bounded exact-answer token was observed in immutable source bytes.",
                evidence_ids=[evidence_id],
                verified_evidence_ids=verified,
            ):
                rows.append(
                    {
                        "value": value,
                        "match_kind": match_kind,
                        "evidence_ids": [evidence_id],
                        "source_locator": locator,
                        "source_locators": [locator],
                        "record_locator": locator,
                    }
                )
            if len(rows) >= _MAX_EXACT_LOG_VALUES:
                break
        return rows

    def _analyze_log_input(
        self,
        state: AgentState,
        artifact: InputArtifact,
    ) -> LogAnalysisResult:
        """Read one run-bound immutable input from CAS, then analyze it."""

        if artifact.size_bytes > _MAX_LOG_INPUT_BYTES:
            raise LogLimitError("input exceeds the offline log-analysis limit")
        content = self._read_input_artifact(state.run_id, artifact)
        if self.binary_log_parsers_enabled and detect_binary_format(content) == "zip":
            archive = extract_safe_zip(
                content,
                limits=BinaryParseLimits(max_input_bytes=_MAX_LOG_INPUT_BYTES),
            )
            for member in archive.members:
                member_digest = hashlib.sha256(member.content).hexdigest()
                self.artifact_store.put(
                    member.content,
                    expected_sha256=member_digest,
                    media_type="application/octet-stream",
                    run_id=state.run_id,
                    data_view=DataView.RAW_RESTRICTED,
                    log_layer=LogLayer.RAW_SECURITY,
                )
        return analyze_offline_logs(
            content,
            source_ref=artifact.relative_path,
            artifact_ref=artifact.sha256.lower(),
            artifact_sha256=artifact.sha256.lower(),
            allow_binary=self.binary_log_parsers_enabled,
        )

    def _read_input_artifact(self, run_id: str, artifact: InputArtifact) -> bytes:
        """Read a manifest-bound CAS object without falling back to the workspace."""

        artifact_ref = artifact.sha256.lower()
        metadata = self.artifact_store.metadata_for(artifact_ref)
        if not metadata.globally_bound and run_id not in metadata.run_ids:
            raise PermissionError("input artifact is not bound to this run")
        content = self.artifact_store.read(artifact_ref)
        if len(content) != artifact.size_bytes:
            raise ArtifactStoreError("input artifact size does not match the immutable manifest")
        if hashlib.sha256(content).hexdigest() != artifact_ref:
            raise ArtifactStoreError("input artifact digest does not match the immutable manifest")
        return content

    @staticmethod
    def _merge_log_evidence(
        state: AgentState,
        result: LogAnalysisResult,
        known_evidence_ids: set[str],
    ) -> None:
        new_evidence = [item for item in result.evidence if item.evidence_id not in known_evidence_ids]
        state.evidence.extend(new_evidence)
        known_evidence_ids.update(item.evidence_id for item in new_evidence)

    @staticmethod
    def _materialize_log_claims(
        state: AgentState,
        result: LogAnalysisResult,
        verified_evidence_ids: set[str],
        limitations: list[str],
    ) -> None:
        """Convert analyzer output into findings only after evidence verification."""

        match_evidence = {
            str(item.metadata.get("match_id")): item.evidence_id
            for item in result.evidence
            if item.metadata.get("evidence_type") == "sigma_match"
        }
        ioc_evidence = {
            str(item.metadata.get("observation_id")): item.evidence_id
            for item in result.evidence
            if item.metadata.get("evidence_type") == "ioc_occurrence"
        }
        technique_evidence = _log_technique_evidence_ids(result)
        claim_requests: list[ScenarioClaimRequest] = []
        candidate_findings: dict[str, Finding] = {}
        for match in result.rule_matches:
            evidence_id = match_evidence.get(match.match_id)
            if evidence_id is None:
                limitations.append(f"Rule match {match.match_id} has no immutable evidence")
                continue
            severity = match.severity if match.severity in {"LOW", "MEDIUM", "HIGH", "CRITICAL"} else "UNKNOWN"
            finding = Finding(
                finding_id=str(uuid5(NAMESPACE_URL, f"secmind:log-finding:{match.match_id}")),
                rule_id=match.rule_id,
                severity=cast(Any, severity),
                confidence="HIGH",
                path=match.locator.source_ref,
                line=match.locator.line_number,
                title=match.title,
                description=f"Offline rule {match.rule_id} matched a normalized security event.",
                remediation="Corroborate the event and follow the evidence-bound incident dry-run playbook.",
                evidence_ids=[evidence_id],
            )
            candidate_findings[finding.finding_id] = finding
            claim_requests.append(
                ScenarioClaimRequest(
                    claim_type="suspicious_event",
                    subject_ref=finding.finding_id,
                    statement=(
                        f"Offline rule {match.rule_id} matched {match.locator.source_ref} "
                        "and is supported by immutable source evidence."
                    ),
                    evidence_ids=(evidence_id,),
                )
            )

        for observation in result.iocs:
            evidence_id = ioc_evidence.get(observation.observation_id)
            if evidence_id is not None:
                claim_requests.append(
                    ScenarioClaimRequest(
                        claim_type="ioc_observed",
                        subject_ref=f"ioc:{observation.observation_id}",
                        statement=(
                            f"An IOC was observed in {observation.locator.source_ref} "
                            "and is supported by immutable source evidence."
                        ),
                        evidence_ids=(evidence_id,),
                    )
                )
        event_evidence = _log_evidence_indexes(result)["event"]
        for event in result.events[:128]:
            evidence_id = event_evidence.get(event.event_id)
            if evidence_id is not None:
                claim_requests.append(
                    ScenarioClaimRequest(
                        claim_type="normalized_event_observed",
                        subject_ref=f"event:{event.event_id}",
                        statement="A normalized security event was observed in immutable source bytes.",
                        evidence_ids=(evidence_id,),
                    )
                )
        for mapping in result.attack_mappings:
            evidence_ids = tuple(technique_evidence.get(mapping.technique_id, []))
            if not evidence_ids:
                limitations.append(f"ATT&CK mapping {mapping.technique_id} has no immutable correlation evidence")
                continue
            claim_requests.append(
                ScenarioClaimRequest(
                    claim_type="attack_mapping_supported",
                    subject_ref=f"attack-mapping:{mapping.technique_id}",
                    statement=(
                        f"Evidence-bound event context supports ATT&CK mapping {mapping.technique_id} as a "
                        "bounded interpretation, not proof that malicious activity succeeded."
                    ),
                    evidence_ids=evidence_ids,
                )
            )
        # Exact-answer log/forensic tasks need their deterministic scalar
        # observations to survive terminal admission even if the model lane is
        # unavailable. Bind each bounded candidate to the event evidence now;
        # the renderer can then publish the same value without bypassing CAS or
        # the verifier.
        if require_resolved_task_contract(state).scoring_mode == "exact_answer_with_evidence":
            for candidate in _log_exact_candidates(result):
                evidence_ids = tuple(str(item) for item in candidate.get("evidence_ids", []) if str(item))
                if evidence_ids:
                    claim_requests.append(
                        ScenarioClaimRequest(
                            claim_type="exact_value_observed",
                            subject_ref=f"exact:{hashlib.sha256(str(candidate['value']).encode()).hexdigest()[:24]}",
                            statement="A bounded exact-answer token was observed in a normalized event.",
                            evidence_ids=evidence_ids,
                        )
                    )
        accepted_subjects = verify_scenario_claims(
            state,
            claim_requests,
            verified_evidence_ids=verified_evidence_ids,
        )
        existing_finding_ids = {item.finding_id for item in state.findings}
        for finding_id, finding in candidate_findings.items():
            if finding_id in accepted_subjects and finding_id not in existing_finding_ids:
                state.findings.append(finding)
            elif finding_id not in accepted_subjects:
                limitations.append(f"Finding {finding_id} failed the claim evidence gate")

    def _store_timeline(self, run_id: str, source_ref: str, result: LogAnalysisResult) -> StoredArtifact:
        source_digests = sorted(
            {
                str(item.metadata.get("source_artifact_sha256")).lower()
                for item in result.evidence
                if isinstance(item.metadata.get("source_artifact_sha256"), str)
                and re.fullmatch(r"[a-fA-F0-9]{64}", str(item.metadata.get("source_artifact_sha256")))
            }
        )
        payload = {
            "schema_version": SCHEMA_VERSION,
            "source": source_ref,
            "status": result.status,
            "raw_artifact_digests": source_digests,
            "process_provenance": {
                "process_id": "secmind.deterministic-scenario-analyzer",
                "process_version": SCHEMA_VERSION,
                "operation": "offline_log_analysis",
                "input_artifact_digests": source_digests,
                "network_access_performed": False,
                "model_calls": 0,
                "rule_bundle_digest": result.coverage.get("rule_bundle_digest"),
            },
            "timeline": [
                {
                    "event_id": item.event_id,
                    "timestamp_utc": item.timestamp_utc,
                    "timestamp": item.timestamp_utc,
                    "event_type": item.event_type,
                    "severity": item.severity,
                    "entities": [asdict(entity) for entity in item.entities],
                    "attributes": dict(item.attributes),
                    "message": item.message,
                    "event_content_sha256": item.content_sha256,
                    "locator": asdict(item.locator),
                }
                for item in result.events
            ],
            "rule_matches": [asdict(item) for item in result.rule_matches],
            "iocs": [asdict(item) for item in result.iocs],
            "attack_mappings": [asdict(item) for item in result.attack_mappings],
            "coverage": dict(result.coverage),
            "diagnostics": [asdict(item) for item in result.diagnostics],
        }
        return self.artifact_store.put(
            json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(),
            media_type="application/vnd.secmind.security-timeline+json",
            run_id=run_id,
            data_view=DataView.OBSERVABLE,
            log_layer=LogLayer.NORMALIZED_SECURITY,
        )

    def _record_log_observation(
        self,
        state: AgentState,
        source_ref: str,
        result: LogAnalysisResult,
        timeline: StoredArtifact,
    ) -> None:
        state.observations.append(
            ToolResult(
                status=ToolStatus.SUCCESS,
                summary=f"Offline log analysis normalized {len(result.events)} event(s).",
                artifacts=[
                    ArtifactRef(
                        artifact_id=timeline.artifact_id,
                        ref=timeline.artifact_id,
                        sha256=timeline.sha256,
                        size_bytes=timeline.size_bytes,
                        media_type=timeline.media_type,
                    )
                ],
                evidence=list(result.evidence),
                data={
                    "coverage": dict(result.coverage),
                    "source": source_ref,
                    "raw_artifact_digests": sorted(
                        {
                            str(item.metadata.get("source_artifact_sha256")).lower()
                            for item in result.evidence
                            if isinstance(item.metadata.get("source_artifact_sha256"), str)
                        }
                    ),
                    "derived_artifact_digests": [timeline.sha256.lower()],
                    "process_provenance": {
                        "process_id": "secmind.deterministic-scenario-analyzer",
                        "process_version": SCHEMA_VERSION,
                        "operation": "offline_log_analysis",
                        "output_artifact_digests": [timeline.sha256.lower()],
                        "network_access_performed": False,
                        "model_calls": 0,
                    },
                },
            )
        )

    @staticmethod
    def _finish_log_report(
        state: AgentState,
        analyzed_sources: int,
        timeline_artifact_ids: list[str],
        limitations: list[str],
        results: Sequence[LogAnalysisResult],
        *,
        exact_source_candidates: Sequence[dict[str, Any]] = (),
    ) -> None:
        state.status = RunStatus.COMPLETED if not limitations else RunStatus.PARTIAL
        merged_result = _merge_log_results(results)
        mapping_metrics = _attack_mapping_pipeline_metrics(state, results, merged_result)
        merged_result = replace(
            merged_result,
            coverage={**merged_result.coverage, "attack_mapping_pipeline": mapping_metrics},
        )
        state.audit_coverage["log_attack_mapping_pipeline"] = mapping_metrics
        exact_mode = require_resolved_task_contract(state).scoring_mode == "exact_answer_with_evidence"
        answer: ExactAnswer | TimelineAnswer
        if exact_mode:
            answer = _log_exact_answer(
                state,
                merged_result,
                limitations=limitations,
                source_candidates=exact_source_candidates,
            )
        else:
            answer = _log_timeline_answer(
                state,
                merged_result,
                timeline_artifact_ids=timeline_artifact_ids,
                limitations=limitations,
            )
        if limitations and state.status == RunStatus.COMPLETED:
            # A typed answer output bound can itself make coverage partial; do
            # not let a valid parser run masquerade as a complete report.
            state.status = RunStatus.PARTIAL
            answer = (
                _log_exact_answer(
                    state,
                    merged_result,
                    limitations=limitations,
                    source_candidates=exact_source_candidates,
                )
                if exact_mode
                else _log_timeline_answer(
                    state,
                    merged_result,
                    timeline_artifact_ids=timeline_artifact_ids,
                    limitations=limitations,
                )
            )
        record_scenario_semantic_projection(state, answer)
        state.decisions.append(
            DecisionRecord(
                decision="offline_log_analysis_completed",
                rationale_summary=(
                    "Bounded deterministic normalization, offline rules, IOC extraction and timeline correlation "
                    "ran without network or model calls."
                ),
                evidence_ids=[item.evidence_id for item in state.evidence],
                policy_ids=["LOG-OFFLINE-ONLY-1.4", "EVIDENCE-REQUIRED-V1"],
                model_id="deterministic-log-pipeline",
            )
        )
        state.report = AgentReport(
            run_id=state.run_id,
            status=state.status,
            executive_summary=(
                f"Offline log analysis processed {analyzed_sources} source(s), produced "
                f"{len(state.findings)} rule-backed finding(s), and preserved "
                f"{len(state.evidence)} evidence record(s)."
            ),
            answer_type=answer.answer_kind,
            answer_payload=answer.model_dump(mode="json"),
            findings=state.findings,
            decisions=state.decisions,
            evidence=state.evidence,
            limitations=sorted(set(limitations)),
            coverage={
                "sources_processed": analyzed_sources,
                "timeline_artifact_ids": timeline_artifact_ids,
                "network_requests": 0,
                "provider_requests": 0,
                "scenario_semantic_delta": state.audit_coverage.get("scenario_semantic_delta", {}),
                "scenario_semantic_output": state.audit_coverage.get("scenario_semantic_output", {}),
            },
            claim_ids=[item.claim_id for item in state.claims if item.status == ClaimStatus.VERIFIED],
        )

    @staticmethod
    def _finish_log_integrity_failure(
        state: AgentState,
        *,
        artifact: InputArtifact,
        analyzed_sources: int,
        limitations: list[str],
        reason_code: str,
        create_claim: bool = True,
    ) -> None:
        """Fail closed when immutable scenario evidence cannot be verified."""

        limitation = f"{artifact.relative_path}: evidence gate failed ({reason_code})"
        limitations.append(limitation)
        if create_claim:
            verify_scenario_claim(
                state,
                claim_type="evidence_integrity_failure",
                subject_ref=artifact.relative_path,
                statement="The log input could not be analyzed because its immutable CAS evidence was unavailable.",
                evidence_ids=[],
                verified_evidence_ids=set(),
            )
        state.findings = []
        state.status = RunStatus.RECOVERY_REQUIRED
        state.last_error = limitation
        integrity_answer = TimelineAnswer.model_validate(
            {
                "task_id": _answer_task_id(state),
                "execution_status": "partial",
                "epistemic_status": "insufficient_evidence",
                "executive_summary": (
                    "Log analysis stopped because immutable evidence integrity could not be established."
                ),
                "limitations": _bounded_limitations(limitations),
                "facts": [],
                "inferences": [],
                "events": [],
                "actors": [],
                "iocs": [],
                "techniques": [],
                "gaps": [
                    {
                        "code": "evidence_integrity_failure",
                        "artifact": artifact.relative_path,
                        "reason": reason_code,
                        "evidence_ids": [],
                        "raw_artifact_digests": [artifact.sha256.lower()],
                        "source_locator": {
                            "source_ref": artifact.relative_path,
                            "segment_id": "artifact",
                            "record_number": 0,
                            "line_number": 0,
                            "byte_offset": 0,
                            "byte_length": artifact.size_bytes,
                            "locator_scope": "whole_file",
                        },
                        "source_locators": [],
                    }
                ],
                "extensions": {
                    "coverage": {"sources_processed": analyzed_sources},
                    "raw_artifact_digests": [artifact.sha256.lower()],
                    "derived_artifact_digests": [],
                },
            }
        )
        semantic_output, semantic_delta = build_scenario_semantic_projection(
            state,
            integrity_answer,
            scenario="log_analysis",
            operation="offline_log_integrity_failure",
            evidence_by_id={item.evidence_id: item for item in state.evidence},
        )
        integrity_answer = _attach_semantic_delta(integrity_answer, semantic_output, semantic_delta)
        record_scenario_semantic_projection(state, integrity_answer)
        state.report = AgentReport(
            run_id=state.run_id,
            status=state.status,
            executive_summary="Log analysis stopped because immutable evidence integrity could not be established.",
            answer_type="timeline",
            answer_payload=integrity_answer.model_dump(mode="json"),
            findings=[],
            decisions=state.decisions,
            evidence=state.evidence,
            limitations=sorted(set(limitations)),
            coverage={
                "sources_processed": analyzed_sources,
                "integrity_failure_source": artifact.relative_path,
                "network_requests": 0,
                "provider_requests": 0,
            },
            claim_ids=[item.claim_id for item in state.claims if item.status == ClaimStatus.VERIFIED],
        )

    def execute_api_assessment(self, state: AgentState) -> None:
        """Run static API analysis and bind findings to preserved source bytes."""

        spec = self.task_specs.load_spec(state.run_id)
        assets = self.task_specs.parsed_assets(state.run_id)
        input_by_id = {item.artifact_id: item for item in state.input_artifacts}
        cas_inputs: dict[str, str] = {}
        for asset in assets:
            source_artifact = input_by_id.get(asset.artifact_id)
            if source_artifact is None:
                continue
            try:
                self._read_input_artifact(state.run_id, source_artifact)
            except (OSError, ValueError):
                continue
            cas_inputs[asset.artifact_id] = source_artifact.sha256.lower()

        result = assess_api_assets(spec, assets)
        state.evidence = [
            evidence.model_copy(
                update={
                    "artifact_ref": (
                        cas_inputs.get(evidence.artifact_ref, evidence.artifact_ref)
                        if evidence.artifact_ref is not None
                        else None
                    )
                }
            )
            for evidence in result.evidence
        ]
        verified_evidence_ids = verify_scenario_evidence(
            self.artifact_store,
            state.evidence,
            run_id=state.run_id,
        )
        state.findings = [
            finding
            for finding in result.findings
            if verify_scenario_claim(
                state,
                claim_type="api_security_finding",
                subject_ref=finding.finding_id,
                statement=(
                    f"Static API rule {finding.rule_id} matched {finding.path} "
                    "and is supported by immutable source evidence."
                ),
                evidence_ids=finding.evidence_ids,
                verified_evidence_ids=verified_evidence_ids,
            )
        ]
        rejected_evidence = len(state.evidence) - len(verified_evidence_ids)
        state.status = RunStatus.PARTIAL if rejected_evidence else result.status
        limitations = list(result.coverage_gaps)
        if rejected_evidence:
            limitations.append(f"{rejected_evidence} evidence record(s) failed CAS integrity verification")
        answer = _api_exact_answer(
            state,
            result,
            assets,
            input_by_id,
            {item.evidence_id: item for item in state.evidence},
            verified_evidence_ids,
            limitations,
        )
        record_scenario_semantic_projection(state, answer)
        state.decisions.append(
            DecisionRecord(
                decision="api_static_assessment_completed",
                rationale_summary=result.dynamic_probe_policy.reason_summary,
                evidence_ids=sorted(verified_evidence_ids),
                policy_ids=result.dynamic_probe_policy.policy_ids,
                confidence=1,
                model_id="deterministic-api-static-analyzer",
            )
        )
        state.report = AgentReport(
            run_id=state.run_id,
            status=state.status,
            executive_summary=(
                f"Static API assessment inventoried {len(result.asset_graph.endpoints)} endpoint(s) and produced "
                f"{len(state.findings)} CAS-verified finding(s); no network request was made."
            ),
            answer_type=answer.answer_kind,
            answer_payload=answer.model_dump(mode="json"),
            findings=state.findings,
            decisions=state.decisions,
            evidence=state.evidence,
            limitations=limitations,
            coverage={
                "asset_ids": list(result.asset_graph.asset_ids),
                "endpoint_count": len(result.asset_graph.endpoints),
                "method_counts": dict(result.asset_graph.method_counts),
                "network_requests": result.network_requests_performed,
                "dynamic_probes_enabled": result.dynamic_probes_enabled,
                "scenario_semantic_delta": state.audit_coverage.get("scenario_semantic_delta", {}),
                "scenario_semantic_output": state.audit_coverage.get("scenario_semantic_output", {}),
            },
            claim_ids=[item.claim_id for item in state.claims if item.status == ClaimStatus.VERIFIED],
        )

    def execute_incident_dry_run(self, state: AgentState) -> None:
        """Render an evidence-bound playbook without performing state changes."""

        spec = self.task_specs.load_spec(state.run_id)
        graph = EvidenceGraph(claims=state.claims, evidence=state.evidence, links=state.evidence_links)
        result = build_incident_dry_run(spec, graph)
        state.status = result.status
        answer = _incident_domain_answer(
            state,
            result,
            {item.evidence_id: item for item in state.evidence},
        )
        record_scenario_semantic_projection(state, answer)
        state.decisions.append(
            DecisionRecord(
                decision="incident_response_dry_run_completed",
                rationale_summary=(
                    "Generated an evidence-bound, non-executing playbook; R2 containment and recovery remain "
                    "approval-gated and unimplemented."
                ),
                evidence_ids=sorted({item for action in result.actions for item in action.prerequisite_evidence_ids}),
                policy_ids=["IR-DRY-RUN-ONLY-1.4", "POL-R2-STATE-CHANGE"],
                model_id="deterministic-ir-dry-run",
            )
        )
        state.report = AgentReport(
            run_id=state.run_id,
            status=result.status,
            executive_summary=(
                f"Incident dry run generated {len(result.actions)} non-executing action(s); executed action count is 0."
            ),
            answer_type=answer.answer_kind,
            answer_payload=answer.model_dump(mode="json"),
            decisions=state.decisions,
            evidence=state.evidence,
            limitations=list(result.coverage_gaps),
            coverage={
                "mode": result.mode,
                "actions": [asdict(item) for item in result.actions],
                "alternative_explanations": [asdict(item) for item in result.alternative_explanations],
                "executed_action_count": result.executed_action_count,
                "scenario_semantic_delta": state.audit_coverage.get("scenario_semantic_delta", {}),
                "scenario_semantic_output": state.audit_coverage.get("scenario_semantic_output", {}),
            },
            claim_ids=[item.claim_id for item in state.claims],
        )


def verify_scenario_evidence(
    artifact_store: ContentAddressedArtifactStore,
    evidence: list[Evidence] | tuple[Evidence, ...],
    *,
    run_id: str,
    cache: ScenarioEvidenceCache | None = None,
    failure_reasons: dict[str, tuple[str, ...]] | None = None,
) -> set[str]:
    """Verify CAS identity, digest and locator with bounded typed read caching."""

    verified: set[str] = set()
    active_cache = cache if cache is not None else ScenarioEvidenceCache(run_id=run_id)
    if active_cache.run_id != run_id:
        raise ValueError("scenario evidence cache belongs to another run")
    for item in evidence:
        reasons: list[str] = []
        content_size: int | None = None
        if item.artifact_ref is None or item.sha256 is None:
            reasons.append("CAS_REFERENCE_REQUIRED")
        else:
            outcome = active_cache.read(artifact_store, item.artifact_ref)
            content_size = outcome.size_bytes
            if outcome.error_code is not None:
                reasons.append(outcome.error_code)
            elif outcome.digest != item.sha256.lower():
                reasons.append("CAS_DIGEST_MISMATCH")
        locator = item.metadata.get("source_locator")
        if content_size is not None and isinstance(locator, dict):
            offset = locator.get("byte_offset")
            length = locator.get("byte_length")
            if (
                not isinstance(offset, int)
                or isinstance(offset, bool)
                or not isinstance(length, int)
                or isinstance(length, bool)
                or offset < 0
                or length < 0
                or offset + length > content_size
            ):
                reasons.append("SOURCE_LOCATOR_OUT_OF_BOUNDS")
        if not reasons:
            verified.add(item.evidence_id)
        elif failure_reasons is not None:
            failure_reasons[item.evidence_id] = tuple(reasons)
    return verified


def verify_scenario_claim(
    state: AgentState,
    *,
    claim_type: str,
    subject_ref: str,
    statement: str,
    evidence_ids: list[str],
    verified_evidence_ids: set[str],
) -> bool:
    """Apply one claim through the batch implementation used by large captures."""

    accepted = verify_scenario_claims(
        state,
        [
            ScenarioClaimRequest(
                claim_type=claim_type,
                subject_ref=subject_ref,
                statement=statement,
                evidence_ids=tuple(evidence_ids),
            )
        ],
        verified_evidence_ids=verified_evidence_ids,
    )
    return subject_ref in accepted


def verify_scenario_claims(
    state: AgentState,
    requests: Sequence[ScenarioClaimRequest],
    *,
    verified_evidence_ids: set[str],
) -> set[str]:
    """Verify many deterministic claims with one EvidenceGraph materialization.

    Rebuilding a graph containing thousands of packet evidence nodes for every
    IOC made large PCAP tasks quadratic. This function preserves the exact
    transition policy while committing graph state once per analyzer result.
    """

    graph = EvidenceGraph(claims=state.claims, evidence=state.evidence, links=state.evidence_links)
    existing_claims = {item.claim_id: item for item in graph.claims}
    existing_link_ids = {item.link_id for item in graph.links}
    results_by_claim = {item.claim_id: item for item in state.verification_results}
    accepted_subjects: set[str] = set()

    for request in requests:
        candidate = make_claim(
            claim_type=request.claim_type,
            statement=request.statement,
            subject_ref=request.subject_ref,
            producer="deterministic-scenario-analyzer",
            confidence=0,
        )
        existing = existing_claims.get(candidate.claim_id)
        if existing is not None and existing.status in {
            ClaimStatus.VERIFIED,
            ClaimStatus.REJECTED,
            ClaimStatus.CONFLICTED,
            ClaimStatus.INSUFFICIENT,
        }:
            if existing.status == ClaimStatus.VERIFIED:
                # A stable claim can be observed in more than one immutable
                # source (for example, an original PCAP and its attested JSON
                # view).  The old terminal-state shortcut accepted the
                # duplicate observation but never attached its evidence.  A
                # later answer could therefore reference a CAS-verified source
                # that Admission could not reach through a verified SUPPORTS
                # edge.  Extend the proof only when the *entire* new evidence
                # set has independently passed the scenario verifier; terminal
                # claims remain immutable and unverified evidence gains no
                # authority from an earlier successful observation.
                linked_ids = sorted(set(request.evidence_ids))
                if linked_ids and all(item in verified_evidence_ids for item in linked_ids):
                    for evidence_id in linked_ids:
                        link = make_link(
                            claim_id=candidate.claim_id,
                            evidence_id=evidence_id,
                            relation=EvidenceRelation.SUPPORTS,
                            grader_id="deterministic-scenario-verifier",
                        )
                        link.verifier_status = ClaimStatus.VERIFIED
                        if link.link_id not in existing_link_ids:
                            graph.add_link(link)
                            existing_link_ids.add(link.link_id)

                    previous = results_by_claim.get(candidate.claim_id)
                    verified_ids = sorted(
                        set(previous.verified_evidence_ids if previous is not None else ()) | set(linked_ids)
                    )
                    results_by_claim[candidate.claim_id] = VerificationResult(
                        claim_id=candidate.claim_id,
                        status=ClaimStatus.VERIFIED,
                        reason_summary="Claim linkage, CAS content and source locator verified.",
                        verified_evidence_ids=verified_ids,
                        rejected_evidence_ids=(list(previous.rejected_evidence_ids) if previous is not None else []),
                        confidence=max(previous.confidence if previous is not None else 0, existing.confidence),
                        grader_ids=sorted(
                            set(previous.grader_ids if previous is not None else ())
                            | {"deterministic-scenario-verifier"}
                        ),
                        # Scenario verification receipts historically omit the
                        # generic verifier's link-set digest.  Never retain an
                        # older digest after extending the evidence set.
                        evidence_set_digest=None,
                        evidence_revision=(previous.evidence_revision + 1 if previous is not None else 1),
                    )
                    accepted_subjects.add(request.subject_ref)
            continue
        if existing is None:
            graph.add_claim(candidate)
            existing_claims[candidate.claim_id] = candidate

        linked_ids = sorted(set(request.evidence_ids))
        for evidence_id in linked_ids:
            link = make_link(
                claim_id=candidate.claim_id,
                evidence_id=evidence_id,
                relation=EvidenceRelation.SUPPORTS,
                grader_id="deterministic-scenario-verifier",
            )
            if link.link_id not in existing_link_ids:
                graph.add_link(link)
                existing_link_ids.add(link.link_id)

        verified_ids = [item for item in linked_ids if item in verified_evidence_ids]
        rejected_ids = [item for item in linked_ids if item not in verified_evidence_ids]
        status = ClaimStatus.VERIFIED if linked_ids and not rejected_ids else ClaimStatus.REJECTED
        result = VerificationResult(
            claim_id=candidate.claim_id,
            status=status,
            reason_summary=(
                "Claim linkage, CAS content and source locator verified."
                if status == ClaimStatus.VERIFIED
                else "One or more supporting evidence records failed CAS integrity verification."
            ),
            verified_evidence_ids=verified_ids,
            rejected_evidence_ids=rejected_ids,
            confidence=0.9 if status == ClaimStatus.VERIFIED else 0,
            grader_ids=["deterministic-scenario-verifier"],
        )
        graph.apply_verification(result)
        existing_claims[candidate.claim_id] = graph.claim(candidate.claim_id)
        results_by_claim[candidate.claim_id] = result
        if status == ClaimStatus.VERIFIED:
            accepted_subjects.add(request.subject_ref)

    state.claims = list(graph.claims)
    state.evidence_links = list(graph.links)
    state.verification_results = sorted(results_by_claim.values(), key=lambda item: item.claim_id)
    return accepted_subjects
