"""Strict, replayable held-out calibration for scanner assurance.

The calibration boundary deliberately keeps scanner execution and metric
evaluation separate. A release job may execute a scanner and export bounded
observations, while this module verifies that observations are bound to the
frozen manifest, computes precision/recall, and applies release gates. An
unavailable external image is never converted into a passing zero-finding
observation.

The fixture and assurance fields are optional so older sealed observations
remain readable. A strict release policy can require signer/calibration
lineage explicitly.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_CALIBRATED_SECURITY_CLAIM_TOOLS = frozenset({"semgrep_sast", "gitleaks_secret_scan"})


class ToolCalibrationError(ValueError):
    """Raised when calibration input is incomplete or internally inconsistent."""


class CalibrationAssuranceLineage(BaseModel):
    """Source and signer facts needed by the single-source release gate."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_id: str = Field(min_length=1, max_length=200)
    report_id: str = Field(default="", max_length=200)
    assurance_level: Literal[
        "observation_only",
        "deterministic_rule_hit",
        "deterministic_semantic",
        "calibrated_security_claim",
    ] = "observation_only"
    signer_id: str | None = Field(default=None, max_length=200)
    signature_algorithm: Literal["Ed25519"] | None = None
    signature_valid: bool = False
    trusted_signer: bool = False
    calibration_version: str | None = Field(default=None, max_length=200)
    calibration_manifest_digest: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    calibration_report_digest: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    contract_digest: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    # The complete signed contract is retained in sealed acceptance material
    # so an independent verifier can replay the signer check. Older reports
    # omit it and remain readable for metric-only compatibility.
    assurance_contract: dict[str, Any] | None = None

    @model_validator(mode="after")
    def validate_signer_and_calibration(self) -> CalibrationAssuranceLineage:
        signed = self.signature_valid or self.trusted_signer
        if signed and (
            self.signer_id is None
            or self.signature_algorithm != "Ed25519"
            or not self.signature_valid
            or not self.trusted_signer
        ):
            raise ValueError("trusted assurance requires a valid Ed25519 signer")
        if self.assurance_level == "calibrated_security_claim" and (
            not self.calibration_version
            or not _is_sha256(self.calibration_manifest_digest)
            or not _is_sha256(self.calibration_report_digest)
        ):
            raise ValueError("calibrated assurance requires version and report digests")
        return self


class CalibrationCase(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str = Field(min_length=1, max_length=200)
    tool_name: str = Field(min_length=1, max_length=120)
    input_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    evaluation_kind: Literal["finding", "sbom"] = "finding"
    expected_rule_ids: tuple[str, ...] = ()
    expected_component_ids: tuple[str, ...] = ()
    # Fixture metadata is optional for compatibility with an already sealed
    # observation, but required by the execution script for a real run.
    fixture_path: str | None = Field(default=None, max_length=500)
    source_kind: Literal["original_authored", "public_domain", "licensed_external"] | None = None
    license_id: str | None = Field(default=None, max_length=120)
    label_commitment: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")

    @model_validator(mode="after")
    def validate_case_metadata(self) -> CalibrationCase:
        if self.fixture_path is not None:
            path = PurePosixPath(self.fixture_path.replace("\\", "/"))
            if path.is_absolute() or ".." in path.parts:
                raise ValueError("fixture_path must be a relative path inside the fixture root")
            if self.source_kind is None or not self.license_id:
                raise ValueError("fixture cases require source_kind and license_id")
        if len(self.expected_rule_ids) != len(set(self.expected_rule_ids)):
            raise ValueError("expected_rule_ids must be unique")
        if len(self.expected_component_ids) != len(set(self.expected_component_ids)):
            raise ValueError("expected_component_ids must be unique")
        if self.evaluation_kind == "sbom":
            if self.tool_name != "syft_sbom":
                raise ValueError("only syft_sbom may use sbom evaluation")
            if self.expected_rule_ids:
                raise ValueError("sbom cases cannot declare expected_rule_ids")
        elif self.expected_component_ids:
            raise ValueError("expected_component_ids require sbom evaluation")
        return self


class CalibrationManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["tool-calibration-manifest-1.0"]
    dataset_id: str = Field(min_length=1, max_length=200)
    split: Literal["heldout"]
    cases: tuple[CalibrationCase, ...]
    # These attest that the fixture set was frozen before scanner execution.
    frozen: bool = True
    qualification_only: bool = False
    dataset_license: str | None = Field(default=None, max_length=120)
    non_leakage_attestation: str | None = Field(default=None, max_length=1_000)
    fixture_tree_digest: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")

    @model_validator(mode="after")
    def unique_cases(self) -> CalibrationManifest:
        keys = [(item.case_id, item.tool_name) for item in self.cases]
        if not self.cases or len(keys) != len(set(keys)):
            raise ValueError("calibration manifest requires unique cases")
        if not self.frozen:
            raise ValueError("held-out calibration manifest must be frozen")
        fixture_cases = [item for item in self.cases if item.fixture_path is not None]
        if fixture_cases and not self.non_leakage_attestation:
            raise ValueError("fixture manifest requires a non-leakage attestation")
        return self


class CalibrationObservation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str = Field(min_length=1, max_length=200)
    tool_name: str = Field(min_length=1, max_length=120)
    tool_version: str = Field(min_length=1, max_length=120)
    input_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    evaluation_kind: Literal["finding", "sbom"] = "finding"
    found_rule_ids: tuple[str, ...] = ()
    observed_component_ids: tuple[str, ...] = ()
    parse_complete: bool
    evidence_complete: bool
    # An external image that is not present is explicit and never a pass.
    status: Literal["success", "unavailable", "error"] = "success"
    execution_source: Literal["builtin", "external_image", "sealed_observation"] = "sealed_observation"
    rule_bundle_digest: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    input_manifest_digest: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    finding_fingerprints: tuple[str, ...] = ()
    assurance_lineage: CalibrationAssuranceLineage | None = None

    @model_validator(mode="after")
    def unique_found_rules_and_fingerprints(self) -> CalibrationObservation:
        if len(self.found_rule_ids) != len(set(self.found_rule_ids)):
            raise ValueError("found_rule_ids must be unique")
        if len(self.finding_fingerprints) != len(set(self.finding_fingerprints)):
            raise ValueError("finding_fingerprints must be unique")
        if len(self.observed_component_ids) != len(set(self.observed_component_ids)):
            raise ValueError("observed_component_ids must be unique")
        if any(not _is_sha256(item) for item in self.finding_fingerprints):
            raise ValueError("finding_fingerprints must be sha256 values")
        if self.status != "success" and self.found_rule_ids:
            raise ValueError("unavailable or error observations cannot publish findings")
        if self.status != "success" and self.observed_component_ids:
            raise ValueError("unavailable or error observations cannot publish SBOM components")
        return self


class CalibrationObservations(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["tool-calibration-observations-1.0"]
    dataset_id: str = Field(min_length=1, max_length=200)
    cases: tuple[CalibrationObservation, ...]

    @model_validator(mode="after")
    def unique_cases(self) -> CalibrationObservations:
        keys = [(item.case_id, item.tool_name) for item in self.cases]
        if not self.cases or len(keys) != len(set(keys)):
            raise ValueError("calibration observations require unique cases")
        return self


class ToolCalibrationPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    required_tools: tuple[str, ...]
    minimum_cases_per_tool: int = Field(default=10, ge=1)
    minimum_positive_cases_per_tool: int = Field(default=3, ge=1)
    minimum_negative_cases_per_tool: int = Field(default=3, ge=1)
    minimum_precision: float = Field(default=0.90, ge=0, le=1)
    minimum_recall: float = Field(default=0.90, ge=0, le=1)
    minimum_component_completeness: float = Field(default=1.0, ge=0, le=1)
    minimum_component_accuracy: float = Field(default=1.0, ge=0, le=1)
    required_evidence_completeness: float = Field(default=1.0, ge=0, le=1)
    # Strict assurance admission is opt-in for compatibility with the v1
    # metric-only evaluator. The checked-in release policy enables it.
    require_trusted_signer: bool = False
    require_calibrated_security_claim: bool = False
    expected_independent_source_count: int = Field(default=0, ge=0)
    require_same_source_double_report: bool = False
    require_toolchain_complete: bool = False
    require_untouched_holdout: bool = False


def evaluate_tool_calibration(
    manifest: CalibrationManifest,
    observations: CalibrationObservations,
    policy: ToolCalibrationPolicy,
    *,
    unavailable_tools: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Evaluate a frozen manifest and its observations."""

    if observations.dataset_id != manifest.dataset_id:
        raise ToolCalibrationError("calibration dataset identity mismatch")
    manifest_rows = {(item.case_id, item.tool_name): item for item in manifest.cases}
    observation_rows = {(item.case_id, item.tool_name): item for item in observations.cases}
    if set(manifest_rows) != set(observation_rows):
        missing = sorted(set(manifest_rows) - set(observation_rows))
        extra = sorted(set(observation_rows) - set(manifest_rows))
        raise ToolCalibrationError(f"calibration coverage mismatch: missing={missing!r}, extra={extra!r}")

    grouped: dict[str, list[tuple[CalibrationCase, CalibrationObservation]]] = defaultdict(list)
    for key, case in sorted(manifest_rows.items()):
        observation = observation_rows[key]
        if observation.input_sha256 != case.input_sha256:
            raise ToolCalibrationError(f"calibration input digest mismatch for {case.case_id}")
        if observation.evaluation_kind != case.evaluation_kind:
            raise ToolCalibrationError(f"calibration evaluation kind mismatch for {case.case_id}")
        grouped[case.tool_name].append((case, observation))

    required = set(policy.required_tools)
    missing_tools = sorted(required - set(grouped))
    blockers = [f"missing required tool: {name}" for name in missing_tools]
    metrics: dict[str, dict[str, Any]] = {}
    for tool_name in sorted(grouped):
        rows = grouped[tool_name]
        evaluation_kinds = {case.evaluation_kind for case, _ in rows}
        if len(evaluation_kinds) != 1:
            raise ToolCalibrationError(f"mixed evaluation kinds for {tool_name}")
        evaluation_kind = next(iter(evaluation_kinds))
        if evaluation_kind == "sbom":
            metrics[tool_name] = _evaluate_sbom_tool(rows, policy)
            blockers.extend(f"{tool_name}:{item}" for item in metrics[tool_name]["blockers"])
            continue
        expected = [(case, set(case.expected_rule_ids)) for case, _ in rows]
        observed = [(observation, set(observation.found_rule_ids)) for _, observation in rows]
        pairs = list(zip(expected, observed, strict=True))
        true_positives = sum(len(expected_rules & found_rules) for (_, expected_rules), (_, found_rules) in pairs)
        false_positives = sum(len(found_rules - expected_rules) for (_, expected_rules), (_, found_rules) in pairs)
        false_negatives = sum(len(expected_rules - found_rules) for (_, expected_rules), (_, found_rules) in pairs)
        positive_cases = sum(bool(expected_rules) for _, expected_rules in expected)
        negative_cases = len(rows) - positive_cases
        parse_complete = sum(observation.parse_complete for observation, _ in observed)
        evidence_complete = sum(observation.evidence_complete for observation, _ in observed)
        precision = _ratio(true_positives, true_positives + false_positives)
        recall = _ratio(true_positives, true_positives + false_negatives)
        evidence_rate = _ratio(evidence_complete, len(rows))
        parse_rate = _ratio(parse_complete, len(rows))
        unavailable_count = sum(observation.status == "unavailable" for observation, _ in observed)
        error_count = sum(observation.status == "error" for observation, _ in observed)
        if unavailable_count or error_count:
            # A missing or failed scanner did not produce a denominator-backed
            # report. Keep the raw comparison counts for diagnosis, but never
            # publish synthetic precision/recall values as calibration facts.
            precision = None
            recall = None
        tool_blockers: list[str] = []
        if len(rows) < policy.minimum_cases_per_tool:
            tool_blockers.append("insufficient_cases")
        if positive_cases < policy.minimum_positive_cases_per_tool:
            tool_blockers.append("insufficient_positive_cases")
        if negative_cases < policy.minimum_negative_cases_per_tool:
            tool_blockers.append("insufficient_negative_cases")
        if precision is None or precision < policy.minimum_precision:
            tool_blockers.append("precision_below_threshold")
        if recall is None or recall < policy.minimum_recall:
            tool_blockers.append("recall_below_threshold")
        if evidence_rate is None or evidence_rate < policy.required_evidence_completeness:
            tool_blockers.append("evidence_incomplete")
        if parse_rate != 1.0:
            tool_blockers.append("parse_incomplete")
        if unavailable_count:
            tool_blockers.append("unavailable_observations")
        if error_count:
            tool_blockers.append("scanner_errors")
        lineage = _lineage_summary(rows)
        signer_required = policy.require_trusted_signer and tool_name != "syft_sbom"
        calibrated_claim_required = (
            policy.require_calibrated_security_claim and tool_name in _CALIBRATED_SECURITY_CLAIM_TOOLS
        )
        if signer_required and not lineage["all_trusted_signer"]:
            tool_blockers.append("trusted_signer_required")
        if calibrated_claim_required and not lineage["all_calibrated"]:
            tool_blockers.append("calibrated_security_claim_required")
        metrics[tool_name] = {
            "evaluation_kind": "finding",
            "metric_status": "unavailable" if unavailable_count else ("error" if error_count else "ok"),
            "tool_versions": sorted({observation.tool_version for observation, _ in observed}),
            "case_count": len(rows),
            "positive_case_count": positive_cases,
            "negative_case_count": negative_cases,
            "true_positives": true_positives,
            "false_positives": false_positives,
            "false_negatives": false_negatives,
            "precision": precision,
            "recall": recall,
            "parse_completeness": parse_rate,
            "evidence_completeness": evidence_rate,
            "unavailable_observation_count": unavailable_count,
            "error_observation_count": error_count,
            "assurance_lineage": lineage,
            "trusted_signer_required": signer_required,
            "calibrated_claim_required": calibrated_claim_required,
            "eligible": not tool_blockers,
            "blockers": tool_blockers,
        }
        blockers.extend(f"{tool_name}:{item}" for item in tool_blockers)

    unavailable = dict(unavailable_tools or {})
    for observation in observations.cases:
        if observation.status == "unavailable":
            unavailable.setdefault(
                observation.tool_name,
                "unavailable: immutable external image and sandbox runner are not configured",
            )
    unavailable = dict(sorted(unavailable.items()))
    if policy.require_toolchain_complete and unavailable:
        blockers.append("external_toolchain_incomplete")
    if policy.require_untouched_holdout and manifest.qualification_only:
        blockers.append("qualification_only_manifest")
    source_gate, source_blockers = _source_gate(observations, policy)
    blockers.extend(source_blockers)
    report: dict[str, Any] = {
        "schema_version": "tool-calibration-report-1.0",
        "dataset_id": manifest.dataset_id,
        "split": manifest.split,
        "manifest_digest": _model_digest(manifest),
        "observations_digest": _model_digest(observations),
        "manifest_metadata": {
            "frozen": manifest.frozen,
            "qualification_only": manifest.qualification_only,
            "dataset_license": manifest.dataset_license,
            "non_leakage_attestation": manifest.non_leakage_attestation,
            "fixture_tree_digest": manifest.fixture_tree_digest,
        },
        "policy": policy.model_dump(mode="json"),
        "tools": metrics,
        "unavailable_tools": unavailable,
        "toolchain_complete": not unavailable,
        "release_gate": {
            "same_source_double_report": source_gate,
            "high_assurance_single_source": _high_assurance_gate(metrics, policy),
        },
        "release_eligible": not blockers,
        "blockers": blockers,
    }
    report["report_digest"] = _mapping_digest(report)
    return report


def _evaluate_sbom_tool(
    rows: Sequence[tuple[CalibrationCase, CalibrationObservation]],
    policy: ToolCalibrationPolicy,
) -> dict[str, Any]:
    """Evaluate Syft as a component-set producer, not as a finding detector.

    ``component_completeness`` is the fraction of frozen expected components
    present in the emitted SBOM; ``component_accuracy`` is the fraction of
    emitted components that belong to that frozen set.  This keeps a Syft
    SBOM gate explicit instead of treating a component inventory as CWE
    precision/recall.
    """

    expected_sets = [set(case.expected_component_ids) for case, _ in rows]
    observed_sets = [set(observation.observed_component_ids) for _, observation in rows]
    true_components = sum(
        len(expected & observed) for expected, observed in zip(expected_sets, observed_sets, strict=True)
    )
    false_components = sum(
        len(observed - expected) for expected, observed in zip(expected_sets, observed_sets, strict=True)
    )
    missing_components = sum(
        len(expected - observed) for expected, observed in zip(expected_sets, observed_sets, strict=True)
    )
    expected_count = sum(len(item) for item in expected_sets)
    observed_count = sum(len(item) for item in observed_sets)
    component_completeness = _ratio(true_components, expected_count)
    component_accuracy = _ratio(true_components, observed_count)
    positive_cases = sum(bool(item) for item in expected_sets)
    negative_cases = len(rows) - positive_cases
    parse_rate = _ratio(sum(observation.parse_complete for _, observation in rows), len(rows))
    evidence_rate = _ratio(sum(observation.evidence_complete for _, observation in rows), len(rows))
    unavailable_count = sum(observation.status == "unavailable" for _, observation in rows)
    error_count = sum(observation.status == "error" for _, observation in rows)
    tool_blockers: list[str] = []
    if len(rows) < policy.minimum_cases_per_tool:
        tool_blockers.append("insufficient_cases")
    if positive_cases < policy.minimum_positive_cases_per_tool:
        tool_blockers.append("insufficient_positive_cases")
    if negative_cases < policy.minimum_negative_cases_per_tool:
        tool_blockers.append("insufficient_negative_cases")
    if component_completeness is None or component_completeness < policy.minimum_component_completeness:
        tool_blockers.append("component_completeness_below_threshold")
    if component_accuracy is None or component_accuracy < policy.minimum_component_accuracy:
        tool_blockers.append("component_accuracy_below_threshold")
    if evidence_rate is None or evidence_rate < policy.required_evidence_completeness:
        tool_blockers.append("evidence_incomplete")
    if parse_rate != 1.0:
        tool_blockers.append("parse_incomplete")
    if unavailable_count:
        tool_blockers.append("unavailable_observations")
    if error_count:
        tool_blockers.append("scanner_errors")
    lineage = _lineage_summary(rows)
    # Syft is an SBOM observation lane, not a security finding claim. Its
    # completeness/accuracy gate is still strict, while signer/calibrated
    # claim requirements remain scoped to security scanners.
    signer_required = False
    calibrated_claim_required = False
    return {
        "evaluation_kind": "sbom",
        "metric_status": "unavailable" if unavailable_count else ("error" if error_count else "ok"),
        "tool_versions": sorted({observation.tool_version for _, observation in rows}),
        "case_count": len(rows),
        "positive_case_count": positive_cases,
        "negative_case_count": negative_cases,
        "component_true_positives": true_components,
        "component_false_positives": false_components,
        "component_false_negatives": missing_components,
        "component_completeness": component_completeness,
        "component_accuracy": component_accuracy,
        "parse_completeness": parse_rate,
        "evidence_completeness": evidence_rate,
        "unavailable_observation_count": unavailable_count,
        "error_observation_count": error_count,
        "assurance_lineage": lineage,
        "trusted_signer_required": signer_required,
        "calibrated_claim_required": calibrated_claim_required,
        "eligible": not tool_blockers,
        "blockers": tool_blockers,
    }


def evaluate_tool_calibration_files(
    manifest_path: Path,
    observations_path: Path,
    policy: ToolCalibrationPolicy,
    *,
    unavailable_tools: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    manifest = CalibrationManifest.model_validate(_read_json_object(manifest_path))
    observations = CalibrationObservations.model_validate(_read_json_object(observations_path))
    return evaluate_tool_calibration(
        manifest,
        observations,
        policy,
        unavailable_tools=unavailable_tools,
    )


def validate_calibration_report(report: dict[str, Any]) -> None:
    """Fail closed on a changed or non-eligible calibration report."""

    if report.get("schema_version") != "tool-calibration-report-1.0":
        raise ToolCalibrationError("unsupported calibration report")
    observed_digest = report.get("report_digest")
    unsigned = {key: value for key, value in report.items() if key != "report_digest"}
    if not isinstance(observed_digest, str) or observed_digest != _mapping_digest(unsigned):
        raise ToolCalibrationError("calibration report digest mismatch")
    if report.get("release_eligible") is not True or report.get("blockers") != []:
        raise ToolCalibrationError("calibration report is not release eligible")


def _lineage_summary(
    rows: Sequence[tuple[CalibrationCase, CalibrationObservation]],
) -> dict[str, Any]:
    lineages = [observation.assurance_lineage for _, observation in rows]
    present = [item for item in lineages if item is not None]
    source_ids = sorted({item.source_id for item in present})
    signer_ids = sorted({item.signer_id for item in present if item.signer_id})
    return {
        "observed": bool(present),
        "source_ids": source_ids,
        "report_ids": sorted({item.report_id for item in present if item.report_id}),
        "signer_ids": signer_ids,
        "all_trusted_signer": bool(present) and all(item.trusted_signer and item.signature_valid for item in present),
        "all_calibrated": bool(present)
        and all(item.assurance_level == "calibrated_security_claim" for item in present),
        "records": [item.model_dump(mode="json") for item in present],
    }


def _source_gate(
    observations: CalibrationObservations,
    policy: ToolCalibrationPolicy,
) -> tuple[dict[str, Any], list[str]]:
    lineages = [item.assurance_lineage for item in observations.cases if item.assurance_lineage is not None]
    source_ids = sorted({item.source_id for item in lineages})
    report_ids = sorted({item.report_id for item in lineages if item.report_id})
    independent_count = len(source_ids)
    same_source_double = len(report_ids) >= 2 and independent_count == 1
    blockers: list[str] = []
    if policy.require_same_source_double_report and not same_source_double:
        blockers.append("same_source_double_report_required")
    if policy.expected_independent_source_count and independent_count != policy.expected_independent_source_count:
        blockers.append("independent_source_count_mismatch")
    return (
        {
            "report_count": len(report_ids),
            "source_ids": source_ids,
            "independent_source_count": independent_count,
            "same_source_double_report": same_source_double,
            "required_independent_source_count": policy.expected_independent_source_count,
            "eligible": not blockers,
            "blockers": blockers,
        },
        blockers,
    )


def _high_assurance_gate(
    metrics: Mapping[str, Mapping[str, Any]],
    policy: ToolCalibrationPolicy,
) -> dict[str, Any]:
    required = policy.require_trusted_signer or policy.require_calibrated_security_claim
    eligible_tools = []
    for tool_name, metric in sorted(metrics.items()):
        lineage = metric.get("assurance_lineage", {})
        if (
            metric.get("eligible") is True
            and (not metric.get("trusted_signer_required", True) or lineage.get("all_trusted_signer") is True)
            and (not metric.get("calibrated_claim_required", True) or lineage.get("all_calibrated") is True)
            and len(lineage.get("source_ids", [])) == 1
        ):
            eligible_tools.append(tool_name)
    blockers: list[str] = []
    if required and not eligible_tools:
        blockers.append("no_trusted_calibrated_single_source")
    return {
        "required": required,
        "eligible_tools": eligible_tools,
        "admitted": not blockers,
        "blockers": blockers,
    }


def _read_json_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ToolCalibrationError(f"cannot read calibration JSON: {path.name}") from exc
    if not isinstance(value, dict):
        raise ToolCalibrationError("calibration JSON must be an object")
    return value


def _model_digest(value: BaseModel) -> str:
    return _mapping_digest(value.model_dump(mode="json"))


def _mapping_digest(value: Mapping[str, Any]) -> str:
    payload = json.dumps(dict(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and _SHA256_RE.fullmatch(value.lower()) is not None


__all__ = [
    "CalibrationAssuranceLineage",
    "CalibrationCase",
    "CalibrationManifest",
    "CalibrationObservation",
    "CalibrationObservations",
    "ToolCalibrationError",
    "ToolCalibrationPolicy",
    "evaluate_tool_calibration",
    "evaluate_tool_calibration_files",
    "validate_calibration_report",
]
