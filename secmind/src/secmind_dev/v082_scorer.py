"""Fail-closed finding scorer used by the v0.8.2 aggregate layer."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from .v082_aggregate import TaskScore, finding_metrics
from .v082_contracts import (
    AgentReport,
    AttemptRecord,
    InputManifest,
    canonical_digest,
    terminal_status,
)


def score_findings(
    predicted: Sequence[Mapping[str, Any]],
    expected: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Score deduplicated semantic findings with verified/evidence views.

    A duplicate semantic fingerprint contributes once.  ``verified_precision``
    only includes findings explicitly verified by the runtime or a trusted
    evidence record; unverified scanner noise is reported separately instead
    of being silently converted into a false positive.
    """

    expected_fingerprints = {
        str(item.get("fingerprint") or _fingerprint(item, index))
        for index, item in enumerate(expected)
        if isinstance(item, Mapping)
    }
    rows: list[dict[str, Any]] = []
    for index, item in enumerate(predicted):
        if not isinstance(item, Mapping):
            continue
        fingerprint = str(item.get("fingerprint") or _fingerprint(item, index))
        evidence_valid = bool(item.get("evidence_valid") or item.get("evidence_complete"))
        verified = bool(item.get("verified"))
        rows.append(
            {
                "fingerprint": fingerprint,
                "expected": fingerprint in expected_fingerprints,
                "verified": verified,
                "evidence_valid": evidence_valid,
            }
        )
    metrics = finding_metrics(rows)
    if not expected_fingerprints and not rows:
        metrics["precision"] = 1.0
        metrics["recall"] = 1.0
        metrics["f1"] = 1.0
        metrics["evidence_grounded_f1"] = 1.0
    metrics["expected_fingerprints"] = len(expected_fingerprints)
    metrics["unverified_predicted"] = sum(not bool(item["verified"]) for item in _deduplicate(rows))
    return metrics


def score_report(
    report: AgentReport,
    manifest: InputManifest,
    *,
    expected_findings: Sequence[Mapping[str, Any]] = (),
    engineering_score: float | None = None,
    attempts: Sequence[AttemptRecord] = (),
    round_number: int = 1,
    block: int | None = None,
    arm: str = "unknown",
) -> TaskScore:
    """Convert a sealed report into one score row without mixing denominators."""

    validation = report.validate_evidence(manifest)
    predicted: list[dict[str, Any]] = []
    invalid = set(validation.invalid_finding_ids)
    evidence_by_id = {item.evidence_id: item for item in report.evidence}
    for finding in report.findings:
        evidence_valid = finding.finding_id not in invalid
        trusted = bool(finding.raw.get("verified"))
        trusted = trusted or any(
            evidence_by_id[evidence_id].metadata.get("assurance_level")
            in {"semantically_corroborated", "human_confirmed"}
            for evidence_id in finding.evidence_ids
            if evidence_id in evidence_by_id
        )
        predicted.append(
            {
                **finding.to_dict(),
                "fingerprint": finding.fingerprint(),
                "verified": trusted,
                "evidence_valid": evidence_valid,
            }
        )
    metrics = score_findings(predicted, expected_findings)
    outcome_score = 100.0 * float(metrics["f1"] or 0.0)
    status = terminal_status(report, validation, tuple(attempts))
    return TaskScore(
        task_id=report.task_id,
        score=outcome_score,
        outcome_score=outcome_score,
        engineering_score=engineering_score,
        outcome_correct=(metrics["f1"] == 1.0),
        status=status,
        primary_status=report.status,
        evidence_completeness=metrics["evidence_completeness"],
        precision=metrics["precision"],
        recall=metrics["recall"],
        finding_f1=metrics["f1"],
        round_number=round_number,
        block=block,
        arm=arm,
        findings=tuple(predicted),
        metadata={
            "evidence_validation": validation.to_dict(),
            "verified_precision": metrics["verified_precision"],
            "evidence_grounded_f1": metrics["evidence_grounded_f1"],
            "expected_fingerprints": metrics["expected_fingerprints"],
        },
    )


def _fingerprint(value: Mapping[str, Any], index: int) -> str:
    return canonical_digest(
        {
            "path": _normal_path(value.get("path") or value.get("file") or ""),
            "line": value.get("line"),
            "rule_id": str(value.get("rule_id") or value.get("classification") or value.get("cwe") or "").casefold(),
            "root_cause": value.get("root_cause") or value.get("data_flow") or value.get("description") or index,
        }
    )


def _normal_path(value: object) -> str:
    path = str(value).replace("\\", "/").casefold()
    return path[6:] if path.startswith("input/") else path


def _deduplicate(rows: Sequence[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    unique: dict[str, Mapping[str, Any]] = {}
    for row in rows:
        fingerprint = str(row.get("fingerprint", ""))
        if not fingerprint:
            continue
        prior = unique.get(fingerprint)
        if prior is None:
            unique[fingerprint] = row
            continue
        unique[fingerprint] = {
            **prior,
            "verified": bool(prior.get("verified") or row.get("verified")),
            "evidence_valid": bool(prior.get("evidence_valid") or row.get("evidence_valid")),
        }
    return list(unique.values())


__all__ = ["score_findings", "score_report"]
