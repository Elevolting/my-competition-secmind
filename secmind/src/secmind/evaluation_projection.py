"""Fail-closed projection of sealed SecMind results for external evaluation.

This module is deliberately a pure boundary. It accepts only an immutable
admission snapshot and an ``InputArtifact`` manifest. It never consults
runtime state, a database, or the workspace and it never synthesizes findings.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import unicodedata
from collections.abc import Mapping, Sequence
from pathlib import PurePosixPath
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from secmind.admission import AdmissionError, AdmissionService
from secmind.schemas import (
    DecisionRecord,
    Evidence,
    Finding,
    InputArtifact,
    RunStatus,
    SealedAdmissionSnapshot,
)

PROJECTION_SCHEMA_VERSION = "test3-sealed-projection-1.0"
V082_PROJECTION_SCHEMA_VERSION = "secmind-evaluation-projection-v0.8.2"
_SHA256_CHARACTERS = frozenset("0123456789abcdef")
_TERMINAL_STATUS: dict[RunStatus, str] = {
    RunStatus.COMPLETED: "SUCCESS",
    RunStatus.PARTIAL: "PARTIAL",
    RunStatus.DENIED: "POLICY_BLOCKED",
    RunStatus.FAILED: "CRASH",
    RunStatus.RECOVERY_REQUIRED: "RECOVERY_REQUIRED",
    RunStatus.CANCELLED: "TIMEOUT",
}
_FINDING_DETAIL_KEYS = (
    "attack_path_summary",
    "data_flow",
    "impact",
    "native_rule_id",
    "normalized_rule_id",
    "preconditions",
    "root_cause",
    "weakness_ids",
)
_EVIDENCE_METADATA_KEYS = (
    "assurance_level",
    "database_version",
    "evidence_type",
    "native_rule_id",
    "normalized_rule_id",
    "rule_bundle_digest",
    "tool_name",
    "tool_version",
    "weakness_ids",
)
_FILE_DIGEST_KEYS = ("file_sha256", "source_sha256", "input_sha256")
_PATH_KEYS = ("path", "file", "relative_path", "source_path")
_LINE_KEYS = ("line", "line_start", "start_line", "sink_line")


class EvaluationProjectionError(ValueError):
    """A sealed result cannot be projected without weakening its evidence chain."""


class _FrozenContract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ProjectionLimits(_FrozenContract):
    """Hard limits for one evaluation projection; excess input is rejected."""

    max_manifest_files: int = Field(default=10_000, ge=1, le=100_000)
    max_findings: int = Field(default=100, ge=1, le=1_000)
    max_evidence: int = Field(default=500, ge=1, le=5_000)
    max_evidence_per_finding: int = Field(default=32, ge=1, le=100)
    max_decisions: int = Field(default=100, ge=0, le=1_000)
    max_text_chars: int = Field(default=4_000, ge=256, le=32_000)
    max_total_json_bytes: int = Field(default=4 * 1024 * 1024, ge=64 * 1024, le=32 * 1024 * 1024)
    require_finding_line: bool = True


class Test3BudgetCaps(_FrozenContract):
    """Platform ceilings for untrusted benchmark budget requests."""

    wall_time_cap_seconds: int = Field(default=7_200, ge=1, le=7_200)
    provider_request_cap: int = Field(default=100, ge=0, le=1_000)
    model_token_cap: int = Field(default=2_000_000, ge=0, le=10_000_000)
    tool_call_cap: int = Field(default=100, ge=0, le=1_000)


class Test3Budget(_FrozenContract):
    wall_time_cap_seconds: int = Field(ge=1, le=7_200)
    provider_request_cap: int = Field(ge=0, le=1_000)
    model_token_cap: int = Field(ge=0, le=10_000_000)
    tool_call_cap: int = Field(ge=0, le=1_000)


class Test3FindingProjection(_FrozenContract):
    id: str = Field(min_length=1, max_length=256)
    finding_id: str = Field(min_length=1, max_length=256)
    title: str = Field(min_length=1, max_length=4_000)
    classification: str = Field(min_length=1, max_length=256)
    cwe: str | None = Field(default=None, max_length=64)
    rule_id: str = Field(min_length=1, max_length=256)
    severity: str = Field(max_length=32)
    confidence: str = Field(max_length=32)
    file: str = Field(min_length=1, max_length=1_024)
    path: str = Field(min_length=1, max_length=1_024)
    line: int | None = Field(default=None, ge=1)
    input_artifact_id: str = Field(min_length=1, max_length=256)
    input_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    # v0.8.2 scorers consume this explicit top-level alias.  It is populated
    # for the legacy projection as well, so one serialized finding cannot
    # silently drift between scorer and runtime vocabulary.
    file_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    description: str = Field(max_length=4_000)
    remediation: str = Field(max_length=4_000)
    evidence_ids: list[str] = Field(min_length=1, max_length=100)
    root_cause: Any | None = None
    data_flow: Any | None = None
    preconditions: Any | None = None
    impact: Any | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class Test3EvidenceProjection(_FrozenContract):
    id: str = Field(min_length=1, max_length=100)
    evidence_id: str = Field(min_length=1, max_length=100)
    source: str = Field(min_length=1, max_length=1_024)
    summary: str = Field(max_length=4_000)
    artifact_ref: str | None = Field(default=None, max_length=1_024)
    sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    file: str = Field(min_length=1, max_length=1_024)
    path: str = Field(min_length=1, max_length=1_024)
    line: int | None = Field(default=None, ge=1)
    input_artifact_id: str = Field(min_length=1, max_length=256)
    input_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    file_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    finding_id: str | None = Field(default=None, max_length=256)
    finding_ids: list[str] = Field(min_length=1, max_length=100)
    metadata: dict[str, Any] = Field(default_factory=dict)


class Test3AnswerProjection(_FrozenContract):
    # Domain answers are a discriminated, versioned payload.  The scorer
    # boundary keeps common aliases while preserving domain-specific fields
    # such as decision/safe_actions/blocked_actions, timelines and exact
    # evidence-gap responses instead of collapsing everything to a summary.
    model_config = ConfigDict(extra="allow", frozen=True)

    summary: str = Field(max_length=4_000)
    answer_type: str = Field(default="universal", min_length=1, max_length=128)
    coverage: dict[str, Any] = Field(default_factory=dict)


class Test3RunProof(_FrozenContract):
    source_contract: Literal["sealed_report_evidence_input_manifest"] = "sealed_report_evidence_input_manifest"
    snapshot_id: str | None = None
    report_integrity_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    input_manifest_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    input_artifact_count: int = Field(ge=1)
    finding_count: int = Field(ge=0)
    evidence_count: int = Field(ge=0)
    unused_evidence_count: int = Field(ge=0)


class Test3Projection(_FrozenContract):
    schema_version: str = PROJECTION_SCHEMA_VERSION
    projection_id: str = Field(pattern=r"^test3-projection-[a-f0-9]{64}$")
    task_id: str = Field(min_length=1, max_length=128)
    run_id: str = Field(min_length=1, max_length=256)
    status: Literal["SUCCESS", "PARTIAL", "POLICY_BLOCKED", "RECOVERY_REQUIRED", "CRASH", "TIMEOUT"]
    answer: Test3AnswerProjection
    findings: list[Test3FindingProjection]
    evidence: list[Test3EvidenceProjection]
    limitations: list[str]
    decisions: list[DecisionRecord]
    run_proof: Test3RunProof


class _ManifestEntry(_FrozenContract):
    artifact_id: str
    path: str
    comparison_path: str
    sha256: str
    size_bytes: int


def clamp_test3_budget(
    requested: Mapping[str, object] | None,
    *,
    caps: Test3BudgetCaps | None = None,
) -> Test3Budget:
    """Clamp benchmark-controlled budgets to local hard ceilings.

    Invalid scalar types fail closed instead of falling back to permissive
    defaults.  This function performs no I/O and cannot alter runtime policy.
    """

    requested = requested or {}
    caps = caps or Test3BudgetCaps()
    return Test3Budget(
        wall_time_cap_seconds=_clamped_integer(
            requested, "wall_time_cap_seconds", default=420, minimum=1, maximum=caps.wall_time_cap_seconds
        ),
        provider_request_cap=_clamped_integer(
            requested, "provider_request_cap", default=24, minimum=0, maximum=caps.provider_request_cap
        ),
        model_token_cap=_clamped_integer(
            requested, "model_token_cap", default=200_000, minimum=0, maximum=caps.model_token_cap
        ),
        tool_call_cap=_clamped_integer(requested, "tool_call_cap", default=100, minimum=0, maximum=caps.tool_call_cap),
    )


def project_test3_result(
    *,
    task_id: str,
    input_manifest: Sequence[InputArtifact],
    snapshot: SealedAdmissionSnapshot,
    limits: ProjectionLimits | None = None,
    scorer_path: bool = False,
) -> Test3Projection:
    """Create a deterministic evaluation result from sealed public objects.

    The admission snapshot is mandatory: accepting a free-standing report and
    evidence list would let a benchmark adapter manufacture an apparently
    sealed result without proving that SecMind's publication gate emitted it.
    """

    limits = limits or ProjectionLimits()
    _validate_identifier(task_id, field="task_id", maximum=128)
    try:
        source_report = AdmissionService.project(snapshot)
    except AdmissionError as exc:
        raise EvaluationProjectionError(f"admission snapshot is invalid: {exc}") from exc
    source_evidence = [item.model_copy(deep=True) for item in source_report.evidence]
    snapshot_id = snapshot.snapshot_id
    status = _TERMINAL_STATUS.get(source_report.status)
    if status is None:
        raise EvaluationProjectionError(f"report status is not terminal: {source_report.status.value}")
    if len(input_manifest) == 0 or len(input_manifest) > limits.max_manifest_files:
        raise EvaluationProjectionError("input manifest size is outside the projection limit")
    if len(source_report.findings) > limits.max_findings:
        raise EvaluationProjectionError("finding count exceeds the projection limit")
    if len(source_evidence) > limits.max_evidence:
        raise EvaluationProjectionError("evidence count exceeds the projection limit")
    if len(source_report.decisions) > limits.max_decisions:
        raise EvaluationProjectionError("decision count exceeds the projection limit")

    manifest_entries = _manifest_entries(input_manifest)
    evidence_by_id = _unique_evidence(source_evidence)
    findings_by_id = _unique_findings(source_report.findings)
    projected_findings: list[Test3FindingProjection] = []
    evidence_bindings: dict[str, tuple[Evidence, _ManifestEntry, str, int | None, set[str]]] = {}

    for finding in sorted(
        findings_by_id.values(),
        key=lambda item: (_canonical_path(item.path)[1], item.line or 0, item.rule_id, item.finding_id),
    ):
        if limits.require_finding_line and finding.line is None:
            raise EvaluationProjectionError(f"finding {finding.finding_id!r} has no source line")
        if not finding.evidence_ids:
            raise EvaluationProjectionError(f"finding {finding.finding_id!r} has no evidence reference")
        if len(finding.evidence_ids) > limits.max_evidence_per_finding:
            raise EvaluationProjectionError(f"finding {finding.finding_id!r} exceeds its evidence limit")
        if len(set(finding.evidence_ids)) != len(finding.evidence_ids):
            raise EvaluationProjectionError(f"finding {finding.finding_id!r} repeats an evidence reference")

        finding_path, _ = _canonical_path(finding.path)
        artifact = _resolve_artifact(finding_path, manifest_entries)
        for evidence_id in finding.evidence_ids:
            item = evidence_by_id.get(evidence_id)
            if item is None:
                raise EvaluationProjectionError(
                    f"finding {finding.finding_id!r} references missing evidence {evidence_id!r}"
                )
            bound_artifact, evidence_path, evidence_line = _validate_evidence_binding(
                item,
                finding=finding,
                expected_artifact=artifact,
                manifest=manifest_entries,
            )
            existing = evidence_bindings.get(evidence_id)
            if existing is None:
                evidence_bindings[evidence_id] = (
                    item,
                    bound_artifact,
                    evidence_path,
                    evidence_line,
                    {finding.finding_id},
                )
            else:
                _, prior_artifact, prior_path, prior_line, finding_ids = existing
                if (prior_artifact.artifact_id, prior_path, prior_line) != (
                    bound_artifact.artifact_id,
                    evidence_path,
                    evidence_line,
                ):
                    raise EvaluationProjectionError(f"evidence {evidence_id!r} has conflicting source bindings")
                finding_ids.add(finding.finding_id)

        projected_findings.append(_project_finding(finding, artifact=artifact, limits=limits, scorer_path=scorer_path))

    projected_evidence = [
        _project_evidence(
            item,
            artifact=artifact,
            line=line,
            finding_ids=sorted(finding_ids),
            limits=limits,
            scorer_path=scorer_path,
        )
        for _evidence_id, (item, artifact, _path, line, finding_ids) in sorted(evidence_bindings.items())
    ]
    manifest_digest = _digest(
        [
            {
                "artifact_id": item.artifact_id,
                "path": item.path,
                "sha256": item.sha256,
                "size_bytes": item.size_bytes,
            }
            for item in sorted(manifest_entries, key=lambda value: value.comparison_path)
        ]
    )
    report_digest = _digest(source_report.model_dump(mode="json", exclude={"generated_at"}))
    limitations = sorted(
        {_bounded_text(item, limits.max_text_chars, field="limitation") for item in source_report.limitations if item}
    )
    decisions = sorted(
        (item.model_copy(deep=True) for item in source_report.decisions),
        key=lambda item: (
            item.decision,
            tuple(sorted(item.evidence_ids)),
            tuple(sorted(item.policy_ids)),
            item.rationale_summary,
        ),
    )
    proof = Test3RunProof(
        snapshot_id=snapshot_id,
        report_integrity_sha256=report_digest,
        input_manifest_sha256=manifest_digest,
        input_artifact_count=len(manifest_entries),
        finding_count=len(projected_findings),
        evidence_count=len(projected_evidence),
        unused_evidence_count=len(source_evidence) - len(projected_evidence),
    )
    payload: dict[str, Any] = {
        "schema_version": V082_PROJECTION_SCHEMA_VERSION if scorer_path else PROJECTION_SCHEMA_VERSION,
        "task_id": task_id,
        "run_id": source_report.run_id,
        "status": status,
        "answer": Test3AnswerProjection.model_validate(
            {
                **source_report.answer_payload,
                "summary": _bounded_text(
                    source_report.executive_summary,
                    limits.max_text_chars,
                    field="executive_summary",
                ),
                "answer_type": source_report.answer_type,
                # Coverage is an open internal map and may contain workspace
                # paths or tool-private state. The sealed scoring boundary
                # derives auditable counts from ``run_proof`` instead.
                "coverage": {},
            }
        ).model_dump(mode="json"),
        "findings": [item.model_dump(mode="json") for item in projected_findings],
        "evidence": [item.model_dump(mode="json") for item in projected_evidence],
        "limitations": limitations,
        "decisions": [item.model_dump(mode="json") for item in decisions],
        "run_proof": proof.model_dump(mode="json"),
    }
    result = Test3Projection(projection_id=f"test3-projection-{_digest(payload)}", **payload)
    if len(_canonical_json(result.model_dump(mode="json"))) > limits.max_total_json_bytes:
        raise EvaluationProjectionError("projected result exceeds the serialized size limit")
    return result


def project_test3_v082_result(
    *,
    task_id: str,
    input_manifest: Sequence[InputArtifact],
    snapshot: SealedAdmissionSnapshot,
    limits: ProjectionLimits | None = None,
) -> Test3Projection:
    """Project the sealed runtime result using the v0.8.2 scorer contract.

    The default function remains byte-compatible in field vocabulary for
    existing Test3 consumers.  This explicit entry point turns on the
    ``input/<path>`` namespace and the top-level ``file_sha256``/``finding_id``
    aliases required by the v0.8.2 scorer.
    """

    return project_test3_result(
        task_id=task_id,
        input_manifest=input_manifest,
        snapshot=snapshot,
        limits=limits,
        scorer_path=True,
    )


def _manifest_entries(input_manifest: Sequence[InputArtifact]) -> list[_ManifestEntry]:
    entries: list[_ManifestEntry] = []
    seen_paths: set[str] = set()
    seen_artifact_ids: set[str] = set()
    for artifact in input_manifest:
        path, comparison = _canonical_path(artifact.relative_path)
        digest = _sha256(artifact.sha256, field=f"input artifact {artifact.artifact_id!r} SHA-256")
        _validate_identifier(artifact.artifact_id, field="artifact_id", maximum=256)
        if artifact.size_bytes < 0:
            raise EvaluationProjectionError(f"input artifact {artifact.artifact_id!r} has a negative size")
        if comparison in seen_paths:
            raise EvaluationProjectionError(f"input manifest repeats path {path!r}")
        if artifact.artifact_id in seen_artifact_ids:
            raise EvaluationProjectionError(f"input manifest repeats artifact ID {artifact.artifact_id!r}")
        seen_paths.add(comparison)
        seen_artifact_ids.add(artifact.artifact_id)
        entries.append(
            _ManifestEntry(
                artifact_id=artifact.artifact_id,
                path=path,
                comparison_path=comparison,
                sha256=digest,
                size_bytes=artifact.size_bytes,
            )
        )
    return entries


def _unique_evidence(items: Sequence[Evidence]) -> dict[str, Evidence]:
    result: dict[str, Evidence] = {}
    for item in items:
        _validate_identifier(item.evidence_id, field="evidence_id", maximum=100)
        if item.evidence_id in result:
            raise EvaluationProjectionError(f"evidence ID is not unique: {item.evidence_id!r}")
        result[item.evidence_id] = item
    return result


def _unique_findings(items: Sequence[Finding]) -> dict[str, Finding]:
    result: dict[str, Finding] = {}
    for item in items:
        _validate_identifier(item.finding_id, field="finding_id", maximum=256)
        if item.finding_id in result:
            raise EvaluationProjectionError(f"finding ID is not unique: {item.finding_id!r}")
        result[item.finding_id] = item
    return result


def _resolve_artifact(path: str, manifest: Sequence[_ManifestEntry]) -> _ManifestEntry:
    _, comparison = _canonical_path(path)
    exact = [item for item in manifest if item.comparison_path == comparison]
    if len(exact) == 1:
        return exact[0]
    reason = "missing" if not exact else "ambiguous"
    raise EvaluationProjectionError(f"finding/evidence path is {reason} in the input manifest: {path!r}")


def _validate_evidence_binding(
    evidence: Evidence,
    *,
    finding: Finding,
    expected_artifact: _ManifestEntry,
    manifest: Sequence[_ManifestEntry],
) -> tuple[_ManifestEntry, str, int | None]:
    metadata = evidence.metadata
    raw_path = _first_metadata_value(metadata, _PATH_KEYS)
    evidence_path = finding.path if raw_path is None else _require_string(raw_path, field="evidence path")
    canonical_evidence_path, _ = _canonical_path(evidence_path)
    artifact = _resolve_artifact(canonical_evidence_path, manifest)
    if artifact.artifact_id != expected_artifact.artifact_id:
        raise EvaluationProjectionError(f"evidence {evidence.evidence_id!r} belongs to another manifest artifact")

    declared_digests = [metadata[key] for key in _FILE_DIGEST_KEYS if metadata.get(key) not in (None, "")]
    if declared_digests:
        for value in declared_digests:
            digest = _sha256(value, field=f"evidence {evidence.evidence_id!r} input SHA-256")
            if not _constant_time_equal(digest, artifact.sha256):
                raise EvaluationProjectionError(
                    f"evidence {evidence.evidence_id!r} input SHA-256 does not match the manifest"
                )
    elif evidence.sha256 is not None:
        digest = _sha256(evidence.sha256, field=f"evidence {evidence.evidence_id!r} SHA-256")
        if not _constant_time_equal(digest, artifact.sha256):
            raise EvaluationProjectionError(f"evidence {evidence.evidence_id!r} lacks a matching input SHA-256")
    else:
        raise EvaluationProjectionError(f"evidence {evidence.evidence_id!r} has no input SHA-256 binding")

    raw_line = _first_metadata_value(metadata, _LINE_KEYS)
    evidence_line = None if raw_line is None else _positive_integer(raw_line, field="evidence line")
    if finding.line is not None and evidence_line != finding.line:
        raise EvaluationProjectionError(
            f"evidence {evidence.evidence_id!r} line does not match finding {finding.finding_id!r}"
        )
    return artifact, canonical_evidence_path, evidence_line


def _project_finding(
    finding: Finding,
    *,
    artifact: _ManifestEntry,
    limits: ProjectionLimits,
    scorer_path: bool,
) -> Test3FindingProjection:
    rule_id = _bounded_text(finding.rule_id, 256, field="rule_id")
    raw_cwe = finding.raw.get("cwe")
    cwe = rule_id if rule_id.upper().startswith("CWE-") else None
    if cwe is None and isinstance(raw_cwe, (str, int)):
        candidate = str(raw_cwe)
        cwe = candidate if candidate.upper().startswith("CWE-") else None
    details = {
        key: _bounded_value(finding.raw[key], limits=limits, field=f"finding.raw.{key}")
        for key in _FINDING_DETAIL_KEYS
        if finding.raw.get(key) not in (None, "", [])
    }
    scoring_details = {key: details.get(key) for key in ("root_cause", "data_flow", "preconditions", "impact")}
    public_artifact_path = f"input/{artifact.path}" if scorer_path else artifact.path
    return Test3FindingProjection(
        id=finding.finding_id,
        finding_id=finding.finding_id,
        title=_bounded_text(finding.title, limits.max_text_chars, field="finding title"),
        classification=rule_id,
        cwe=cwe,
        rule_id=rule_id,
        severity=finding.severity,
        confidence=finding.confidence,
        file=public_artifact_path,
        path=public_artifact_path,
        line=finding.line,
        input_artifact_id=artifact.artifact_id,
        input_sha256=artifact.sha256,
        file_sha256=artifact.sha256,
        description=_bounded_text(finding.description, limits.max_text_chars, field="finding description"),
        remediation=_bounded_text(finding.remediation or "", limits.max_text_chars, field="finding remediation"),
        evidence_ids=sorted(finding.evidence_ids),
        **scoring_details,
        details=details,
    )


def _project_evidence(
    evidence: Evidence,
    *,
    artifact: _ManifestEntry,
    line: int | None,
    finding_ids: list[str],
    limits: ProjectionLimits,
    scorer_path: bool,
) -> Test3EvidenceProjection:
    metadata = {
        key: _bounded_value(evidence.metadata[key], limits=limits, field=f"evidence.metadata.{key}")
        for key in _EVIDENCE_METADATA_KEYS
        if evidence.metadata.get(key) not in (None, "", [])
    }
    public_artifact_path = f"input/{artifact.path}" if scorer_path else artifact.path
    return Test3EvidenceProjection(
        id=evidence.evidence_id,
        evidence_id=evidence.evidence_id,
        source=_bounded_text(evidence.source, 1_024, field="evidence source"),
        summary=_bounded_text(evidence.summary, limits.max_text_chars, field="evidence summary"),
        artifact_ref=(
            None
            if evidence.artifact_ref is None
            else _bounded_text(evidence.artifact_ref, 1_024, field="evidence artifact_ref")
        ),
        sha256=None if evidence.sha256 is None else _sha256(evidence.sha256, field="evidence SHA-256"),
        file=public_artifact_path,
        path=public_artifact_path,
        line=line,
        input_artifact_id=artifact.artifact_id,
        input_sha256=artifact.sha256,
        file_sha256=artifact.sha256,
        finding_id=finding_ids[0] if len(finding_ids) == 1 else None,
        finding_ids=finding_ids,
        metadata=metadata,
    )


def _bounded_mapping(value: Mapping[str, Any], *, limits: ProjectionLimits, field: str) -> dict[str, Any]:
    if len(value) > 200:
        raise EvaluationProjectionError(f"{field} has too many keys")
    result: dict[str, Any] = {}
    for raw_key in sorted(value, key=str):
        if not isinstance(raw_key, str):
            raise EvaluationProjectionError(f"{field} contains a non-string key")
        key = _bounded_text(raw_key, 256, field=f"{field} key")
        result[key] = _bounded_value(value[raw_key], limits=limits, field=f"{field}.{key}")
    return result


def _bounded_value(value: Any, *, limits: ProjectionLimits, field: str, depth: int = 0) -> Any:
    if depth > 4:
        raise EvaluationProjectionError(f"{field} exceeds the nesting limit")
    if isinstance(value, float) and not math.isfinite(value):
        raise EvaluationProjectionError(f"{field} contains a non-finite number")
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return _bounded_text(value, limits.max_text_chars, field=field)
    if isinstance(value, Mapping):
        if len(value) > 100:
            raise EvaluationProjectionError(f"{field} has too many keys")
        result: dict[str, Any] = {}
        for raw_key in sorted(value, key=str):
            if not isinstance(raw_key, str):
                raise EvaluationProjectionError(f"{field} contains a non-string key")
            key = _bounded_text(raw_key, 256, field=f"{field} key")
            result[key] = _bounded_value(value[raw_key], limits=limits, field=f"{field}.{key}", depth=depth + 1)
        return result
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray, memoryview)):
        if len(value) > 100:
            raise EvaluationProjectionError(f"{field} has too many values")
        return [
            _bounded_value(item, limits=limits, field=f"{field}[{index}]", depth=depth + 1)
            for index, item in enumerate(value)
        ]
    raise EvaluationProjectionError(f"{field} contains an unsupported value type")


def _canonical_path(value: str) -> tuple[str, str]:
    normalized = unicodedata.normalize("NFC", _require_string(value, field="repository path").replace("\\", "/"))
    path = PurePosixPath(normalized)
    if (
        not normalized
        or len(normalized) > 1_024
        or path.is_absolute()
        or (path.parts and path.parts[0].endswith(":"))
        or any(part in {"", ".", ".."} for part in path.parts)
        or any(ord(character) < 32 or ord(character) == 127 for character in normalized)
    ):
        raise EvaluationProjectionError(f"unsafe or non-canonical repository path: {value!r}")
    canonical = path.as_posix()
    return canonical, canonical.casefold()


def _clamped_integer(
    source: Mapping[str, object],
    key: str,
    *,
    default: int,
    minimum: int,
    maximum: int,
) -> int:
    value = source.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise EvaluationProjectionError(f"budget field {key!r} must be an integer")
    return max(minimum, min(value, maximum))


def _positive_integer(value: object, *, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise EvaluationProjectionError(f"{field} must be a positive integer")
    return value


def _first_metadata_value(metadata: Mapping[str, Any], keys: Sequence[str]) -> object | None:
    for key in keys:
        value = metadata.get(key)
        if value not in (None, ""):
            return value
    return None


def _require_string(value: object, *, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise EvaluationProjectionError(f"{field} must be a non-empty string")
    return value


def _validate_identifier(value: str, *, field: str, maximum: int) -> None:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise EvaluationProjectionError(f"{field} is empty or exceeds {maximum} characters")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise EvaluationProjectionError(f"{field} contains a control character")


def _bounded_text(value: str, maximum: int, *, field: str) -> str:
    if not isinstance(value, str):
        raise EvaluationProjectionError(f"{field} must be a string")
    if len(value) > maximum:
        raise EvaluationProjectionError(f"{field} exceeds {maximum} characters")
    return value


def _sha256(value: object, *, field: str) -> str:
    if not isinstance(value, str):
        raise EvaluationProjectionError(f"{field} must be a hexadecimal string")
    normalized = value.casefold()
    if len(normalized) != 64 or any(character not in _SHA256_CHARACTERS for character in normalized):
        raise EvaluationProjectionError(f"{field} is not a SHA-256 digest")
    return normalized


def _constant_time_equal(left: str, right: str) -> bool:
    return hmac.compare_digest(left, right)


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


__all__ = [
    "EvaluationProjectionError",
    "PROJECTION_SCHEMA_VERSION",
    "V082_PROJECTION_SCHEMA_VERSION",
    "ProjectionLimits",
    "Test3Budget",
    "Test3BudgetCaps",
    "Test3Projection",
    "clamp_test3_budget",
    "project_test3_result",
    "project_test3_v082_result",
]
