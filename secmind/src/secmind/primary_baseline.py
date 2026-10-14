"""Immutable Primary receipt, admission, and publication helpers.

The mutable ``AgentState.report`` is a presentation object.  It must never be
the authority for whether a model-produced baseline still exists.  This module
keeps the Primary lane self-contained and provides the only compatibility
merge used while the v0.7 graph is incrementally replaced by v0.8 macro nodes.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from typing import Any

from secmind.schemas import (
    AgentReport,
    AgentState,
    BaselineAdmission,
    DecisionRecord,
    Evidence,
    Finding,
    PublishedBaselineProjection,
    RawPrimaryReceipt,
    RunStatus,
)

_VOLATILE_RAW_KEYS = {
    "canonical_primary",
    "model_id",
    "prompt_version",
    "response_sha256",
    "request_sha256",
    "prompt_artifact_id",
}
_BASELINE_RUNTIME_COVERAGE_KEYS = {
    "primary_receipt_id",
    "baseline_admission_id",
    "baseline_projection_id",
    "primary_semantic_digest",
    "primary_integrity_digest",
    "primary_preserved",
    "baseline_integrity_error",
}


def _canonical_sha256(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def baseline_semantic_digest(
    findings: Sequence[Finding],
    evidence: Sequence[Evidence],
    *,
    answer_type: str | None = None,
    answer_payload: dict[str, Any] | None = None,
) -> str:
    """Digest scoreable Primary semantics, independent of report wording."""

    semantic_findings = []
    for item in findings:
        raw = {
            key: value
            for key, value in item.raw.items()
            if key not in _VOLATILE_RAW_KEYS and not key.endswith("_id") and not key.endswith("_ids")
        }
        semantic_findings.append(
            {
                "rule_id": item.rule_id,
                "severity": item.severity,
                "confidence": item.confidence,
                "path": item.path.replace("\\", "/"),
                "line": item.line,
                "title": item.title,
                "description": item.description,
                "remediation": item.remediation,
                "raw": raw,
            }
        )
    semantic_evidence = [
        {
            "source": item.source.split(":", 2)[:2],
            "summary": item.summary,
            "path": item.metadata.get("path"),
            "line": item.metadata.get("line"),
            "fact_or_inference": item.metadata.get("fact_or_inference"),
        }
        for item in evidence
    ]
    payload: dict[str, Any] = {
        "findings": sorted(semantic_findings, key=_canonical_sha256),
        "evidence": sorted(semantic_evidence, key=_canonical_sha256),
    }
    if answer_payload:
        payload["answer_type"] = answer_type or "universal"
        payload["answer_payload"] = answer_payload
    return _canonical_sha256(payload)


def _projection_integrity_digest(
    *,
    status: RunStatus,
    executive_summary: str,
    answer_type: str,
    answer_payload: dict[str, Any],
    findings: Sequence[Finding],
    evidence: Sequence[Evidence],
    decisions: Sequence[DecisionRecord],
    limitations: Sequence[str],
    coverage: dict[str, Any],
) -> str:
    """Hash the exact published lane, including provenance and presentation."""

    return _canonical_sha256(
        {
            "status": status.value,
            "executive_summary": executive_summary,
            "answer_type": answer_type,
            "answer_payload": answer_payload,
            "findings": [item.model_dump(mode="json") for item in findings],
            "evidence": [item.model_dump(mode="json") for item in evidence],
            "decisions": [item.model_dump(mode="json") for item in decisions],
            "limitations": list(limitations),
            "coverage": coverage,
        }
    )


def _legacy_projection_integrity_digest(
    *,
    status: RunStatus,
    executive_summary: str,
    findings: Sequence[Finding],
    evidence: Sequence[Evidence],
    decisions: Sequence[DecisionRecord],
    limitations: Sequence[str],
    coverage: dict[str, Any],
) -> str:
    """Recompute the exact v0.8.2 projection digest during rolling recovery."""

    return _canonical_sha256(
        {
            "status": status.value,
            "executive_summary": executive_summary,
            "findings": [item.model_dump(mode="json") for item in findings],
            "evidence": [item.model_dump(mode="json") for item in evidence],
            "decisions": [item.model_dump(mode="json") for item in decisions],
            "limitations": list(limitations),
            "coverage": coverage,
        }
    )


def _baseline_coverage(coverage: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in coverage.items() if key not in _BASELINE_RUNTIME_COVERAGE_KEYS}


def validate_baseline_chain(state: AgentState) -> tuple[bool, str | None]:
    """Validate ownership, identities, references, semantics, and exact bytes.

    Pydantic's frozen models are shallow.  Every read therefore verifies the
    full chain before any nested object is copied back into mutable run state.
    """

    receipt = state.raw_primary_receipt
    admission = state.baseline_admission
    projection = state.published_baseline
    if receipt is None or admission is None or projection is None:
        return False, "baseline chain is incomplete"
    if {receipt.run_id, admission.run_id, projection.run_id} != {state.run_id}:
        return False, "baseline chain belongs to another run"
    receipt_payload = {
        "run_id": receipt.run_id,
        "model_id": receipt.model_id,
        "prompt_version": receipt.prompt_version,
        "prompt_artifact_id": receipt.prompt_artifact_id,
        "request_sha256": receipt.request_sha256,
        "response_sha256": receipt.response_sha256,
        "response_schema_sha256": receipt.response_schema_sha256,
        "context_sha256": receipt.context_sha256,
        "response_artifact_id": receipt.response_artifact_id,
    }
    if receipt.receipt_id != f"primary-receipt-{_canonical_sha256(receipt_payload)}":
        return False, "primary receipt identity mismatch"
    if receipt.response_artifact_id != receipt.response_sha256:
        return False, "primary receipt does not reference the raw provider response"
    finding_ids = sorted(item.finding_id for item in projection.findings)
    evidence_ids = sorted(item.evidence_id for item in projection.evidence)
    semantic_digest = baseline_semantic_digest(
        projection.findings,
        projection.evidence,
        answer_type=projection.answer_type,
        answer_payload=projection.answer_payload,
    )
    admission_payload = {
        "run_id": admission.run_id,
        "receipt_id": admission.receipt_id,
        "semantic_digest": semantic_digest,
        "finding_ids": finding_ids,
        "evidence_ids": evidence_ids,
    }
    if admission.receipt_id != receipt.receipt_id:
        return False, "baseline admission receipt mismatch"
    if admission.admission_id != f"baseline-admission-{_canonical_sha256(admission_payload)}":
        return False, "baseline admission identity mismatch"
    if admission.finding_ids != finding_ids or admission.evidence_ids != evidence_ids:
        return False, "baseline admission references mismatch"
    if admission.semantic_digest != semantic_digest or projection.semantic_digest != semantic_digest:
        return False, "baseline semantic digest mismatch"
    if projection.receipt_id != receipt.receipt_id or projection.admission_id != admission.admission_id:
        return False, "baseline projection chain mismatch"
    integrity_digest = _projection_integrity_digest(
        status=projection.status,
        executive_summary=projection.executive_summary,
        answer_type=projection.answer_type,
        answer_payload=projection.answer_payload,
        findings=projection.findings,
        evidence=projection.evidence,
        decisions=projection.decisions,
        limitations=projection.limitations,
        coverage=projection.coverage,
    )
    if projection.integrity_digest != integrity_digest:
        legacy_integrity = _legacy_projection_integrity_digest(
            status=projection.status,
            executive_summary=projection.executive_summary,
            findings=projection.findings,
            evidence=projection.evidence,
            decisions=projection.decisions,
            limitations=projection.limitations,
            coverage=projection.coverage,
        )
        if not (
            projection.answer_type == "universal"
            and not projection.answer_payload
            and projection.integrity_digest == legacy_integrity
        ):
            return False, "baseline projection integrity mismatch"
    projection_payload = {
        "run_id": projection.run_id,
        "receipt_id": projection.receipt_id,
        "admission_id": projection.admission_id,
        "semantic_digest": projection.semantic_digest,
        "integrity_digest": projection.integrity_digest,
    }
    if projection.projection_id != f"baseline-projection-{_canonical_sha256(projection_payload)}":
        return False, "baseline projection identity mismatch"
    if admission.admission_status != "baseline_admitted" or admission.provenance_status != "bound":
        return False, "baseline was not admitted"
    return True, None


def publish_primary_baseline(
    state: AgentState,
    *,
    model_id: str,
    prompt_version: str,
    prompt_artifact_id: str | None,
    request_sha256: str,
    response_sha256: str,
    response_schema_sha256: str,
    context_sha256: str,
    response_artifact_id: str,
    provider_requests: int,
    input_tokens: int,
    output_tokens: int,
    cost_units: float,
    status: RunStatus,
    executive_summary: str,
    findings: Sequence[Finding],
    evidence: Sequence[Evidence],
    decisions: Sequence[DecisionRecord],
    limitations: Sequence[str],
    coverage: dict[str, Any],
    answer_type: str = "universal",
    answer_payload: dict[str, Any] | None = None,
    bound_finding_ids: set[str] | None = None,
    bound_evidence_ids: set[str] | None = None,
) -> PublishedBaselineProjection:
    """Seal the Primary lane once and attach it to durable graph state."""

    all_finding_copies = [item.model_copy(deep=True) for item in findings]
    if bound_finding_ids is None:
        finding_copies = all_finding_copies
        unbound_finding_ids: list[str] = []
    else:
        finding_copies = [item for item in all_finding_copies if item.finding_id in bound_finding_ids]
        unbound_finding_ids = sorted(
            item.finding_id for item in all_finding_copies if item.finding_id not in bound_finding_ids
        )
    admitted_evidence_ids = {evidence_id for item in finding_copies for evidence_id in item.evidence_ids}
    # Typed non-finding answers (for example evidence-gap, timeline, and
    # policy decisions) can be supported by independently verified evidence
    # without publishing a Finding.  Keep that answer-level evidence only
    # when the caller explicitly binds its identifier; never widen this to
    # every item present in mutable graph state.
    if bound_evidence_ids is not None:
        admitted_evidence_ids.update(bound_evidence_ids)
    evidence_copies = [
        item.model_copy(deep=True)
        for item in evidence
        if bound_finding_ids is None or item.evidence_id in admitted_evidence_ids
    ]
    supplied_evidence_ids = {item.evidence_id for item in evidence}
    unbound_evidence_ids = sorted(supplied_evidence_ids - {item.evidence_id for item in evidence_copies})
    decision_copies = [item.model_copy(deep=True) for item in decisions]
    sealed_coverage = {
        **_baseline_coverage(coverage),
        "unbound_primary_candidate_count": len(unbound_finding_ids),
        "unbound_primary_finding_ids": unbound_finding_ids,
        "unbound_primary_evidence_count": len(unbound_evidence_ids),
        "unbound_primary_evidence_ids": unbound_evidence_ids,
    }
    effective_status = RunStatus.PARTIAL if unbound_finding_ids else status
    sealed_answer_payload = dict(answer_payload or {})
    sealed_limitations = list(dict.fromkeys(limitations))
    if unbound_finding_ids:
        sealed_limitations.append(
            f"{len(unbound_finding_ids)} Primary candidate(s) were kept out of the public baseline because their "
            "path/line provenance could not be bound to the immutable input snapshot."
        )
    semantic_digest = baseline_semantic_digest(
        finding_copies,
        evidence_copies,
        answer_type=answer_type,
        answer_payload=sealed_answer_payload,
    )
    receipt_payload = {
        "run_id": state.run_id,
        "model_id": model_id,
        "prompt_version": prompt_version,
        "prompt_artifact_id": prompt_artifact_id,
        "request_sha256": request_sha256,
        "response_sha256": response_sha256,
        "response_schema_sha256": response_schema_sha256,
        "context_sha256": context_sha256,
        "response_artifact_id": response_artifact_id,
    }
    receipt = RawPrimaryReceipt(
        receipt_id=f"primary-receipt-{_canonical_sha256(receipt_payload)}",
        run_id=state.run_id,
        model_id=model_id,
        prompt_version=prompt_version,
        prompt_artifact_id=prompt_artifact_id,
        request_sha256=request_sha256,
        response_sha256=response_sha256,
        response_schema_sha256=response_schema_sha256,
        context_sha256=context_sha256,
        response_artifact_id=response_artifact_id,
        provider_requests=provider_requests,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cost_units=cost_units,
    )
    evidence_ids = {item.evidence_id for item in evidence_copies}
    provenance_bound = all(
        item.evidence_ids and set(item.evidence_ids).issubset(evidence_ids) for item in finding_copies
    )
    admission_payload = {
        "run_id": state.run_id,
        "receipt_id": receipt.receipt_id,
        "semantic_digest": semantic_digest,
        "finding_ids": sorted(item.finding_id for item in finding_copies),
        "evidence_ids": sorted(evidence_ids),
    }
    admission = BaselineAdmission(
        admission_id=f"baseline-admission-{_canonical_sha256(admission_payload)}",
        run_id=state.run_id,
        receipt_id=receipt.receipt_id,
        semantic_digest=semantic_digest,
        finding_ids=sorted(item.finding_id for item in finding_copies),
        evidence_ids=sorted(evidence_ids),
        provenance_status="bound" if provenance_bound else "unbound",
        semantic_status="model_proposed",
        admission_status="baseline_admitted" if provenance_bound else "shadow",
    )
    projection_payload = {
        "run_id": state.run_id,
        "receipt_id": receipt.receipt_id,
        "admission_id": admission.admission_id,
        "semantic_digest": semantic_digest,
        "integrity_digest": _projection_integrity_digest(
            status=effective_status,
            executive_summary=executive_summary,
            answer_type=answer_type,
            answer_payload=sealed_answer_payload,
            findings=finding_copies,
            evidence=evidence_copies,
            decisions=decision_copies,
            limitations=sealed_limitations,
            coverage=sealed_coverage,
        ),
    }
    projection = PublishedBaselineProjection(
        projection_id=f"baseline-projection-{_canonical_sha256(projection_payload)}",
        run_id=state.run_id,
        receipt_id=receipt.receipt_id,
        admission_id=admission.admission_id,
        semantic_digest=semantic_digest,
        integrity_digest=str(projection_payload["integrity_digest"]),
        status=effective_status,
        executive_summary=executive_summary,
        answer_type=answer_type,
        answer_payload=sealed_answer_payload,
        findings=finding_copies,
        evidence=evidence_copies,
        decisions=decision_copies,
        limitations=sealed_limitations,
        coverage=sealed_coverage,
    )
    if state.published_baseline is not None:
        valid, reason = validate_baseline_chain(state)
        if not valid:
            raise ValueError(f"existing baseline chain is invalid: {reason}")
        if (
            state.raw_primary_receipt is not None
            and state.baseline_admission is not None
            and state.raw_primary_receipt.receipt_id == receipt.receipt_id
            and state.baseline_admission.admission_id == admission.admission_id
            and state.published_baseline.projection_id == projection.projection_id
        ):
            return state.published_baseline
        raise ValueError("Primary baseline is append-only and cannot be overwritten")
    state.raw_primary_receipt = receipt
    state.baseline_admission = admission
    state.published_baseline = projection
    state.audit_coverage.update(
        {
            "primary_receipt_id": receipt.receipt_id,
            "baseline_admission_id": admission.admission_id,
            "baseline_projection_id": projection.projection_id,
            "primary_semantic_digest": semantic_digest,
            "primary_integrity_digest": projection.integrity_digest,
        }
    )
    return projection


def baseline_report(state: AgentState) -> AgentReport | None:
    """Materialize a report view from the immutable Primary projection."""

    baseline = state.published_baseline
    if baseline is None:
        return None
    valid, _reason = validate_baseline_chain(state)
    if not valid:
        return None
    return AgentReport(
        run_id=state.run_id,
        status=baseline.status,
        executive_summary=baseline.executive_summary,
        answer_type=baseline.answer_type,
        answer_payload=dict(baseline.answer_payload),
        findings=[item.model_copy(deep=True) for item in baseline.findings],
        decisions=[item.model_copy(deep=True) for item in baseline.decisions],
        evidence=[item.model_copy(deep=True) for item in baseline.evidence],
        limitations=list(baseline.limitations),
        coverage=dict(baseline.coverage),
        audit_kernel=state.audit_kernel,
    )


def report_preserves_baseline(state: AgentState, report: AgentReport | None = None) -> bool:
    """Verify the report's Primary lane against the sealed semantic digest."""

    baseline = state.published_baseline
    current = report or state.report
    if baseline is None or current is None:
        return False
    valid, _reason = validate_baseline_chain(state)
    if not valid:
        return False
    finding_ids = {item.finding_id for item in baseline.findings}
    evidence_ids = {item.evidence_id for item in baseline.evidence}
    findings = sorted(
        (item for item in current.findings if item.finding_id in finding_ids),
        key=lambda item: item.finding_id,
    )
    evidence = sorted(
        (item for item in current.evidence if item.evidence_id in evidence_ids),
        key=lambda item: item.evidence_id,
    )
    if len(findings) != len(finding_ids) or len(evidence) != len(evidence_ids):
        return False
    if current.answer_type != baseline.answer_type or current.answer_payload != baseline.answer_payload:
        return False
    return _canonical_sha256(
        {
            "findings": [item.model_dump(mode="json") for item in findings],
            "evidence": [item.model_dump(mode="json") for item in evidence],
        }
    ) == _canonical_sha256(
        {
            "findings": [
                item.model_dump(mode="json")
                for item in sorted(baseline.findings, key=lambda candidate: candidate.finding_id)
            ],
            "evidence": [
                item.model_dump(mode="json")
                for item in sorted(baseline.evidence, key=lambda candidate: candidate.evidence_id)
            ],
        }
    )


def restore_published_baseline(state: AgentState) -> bool:
    """Merge the sealed Primary lane into state/report with baseline precedence."""

    baseline = state.published_baseline
    if baseline is None:
        return False
    valid, reason = validate_baseline_chain(state)
    if not valid:
        state.audit_coverage.update(
            {
                "primary_preserved": False,
                "baseline_integrity_error": reason,
            }
        )
        return False
    state.findings = sorted(
        {
            **{item.finding_id: item for item in state.findings},
            **{item.finding_id: item.model_copy(deep=True) for item in baseline.findings},
        }.values(),
        key=lambda item: (item.path, item.line or 0, item.rule_id, item.finding_id),
    )
    state.evidence = sorted(
        {
            **{item.evidence_id: item for item in state.evidence},
            **{item.evidence_id: item.model_copy(deep=True) for item in baseline.evidence},
        }.values(),
        key=lambda item: item.evidence_id,
    )
    state.decisions = list(
        {
            (item.decision, item.prompt_version, item.model_id): item
            for item in [*state.decisions, *[entry.model_copy(deep=True) for entry in baseline.decisions]]
        }.values()
    )
    if state.report is None:
        state.report = baseline_report(state)
    else:
        findings = {item.finding_id: item for item in state.report.findings}
        findings.update({item.finding_id: item.model_copy(deep=True) for item in baseline.findings})
        evidence = {item.evidence_id: item for item in state.report.evidence}
        evidence.update({item.evidence_id: item.model_copy(deep=True) for item in baseline.evidence})
        state.report = state.report.model_copy(
            update={
                "answer_type": baseline.answer_type,
                "answer_payload": dict(baseline.answer_payload),
                "findings": sorted(
                    findings.values(),
                    key=lambda item: (item.path, item.line or 0, item.rule_id, item.finding_id),
                ),
                "evidence": sorted(evidence.values(), key=lambda item: item.evidence_id),
                "limitations": list(dict.fromkeys([*baseline.limitations, *state.report.limitations])),
            }
        )
    preserved = report_preserves_baseline(state)
    state.audit_coverage.update(
        {
            "primary_preserved": preserved,
            "primary_semantic_digest": baseline.semantic_digest,
            "primary_integrity_digest": baseline.integrity_digest,
        }
    )
    if state.report is not None:
        state.report = state.report.model_copy(update={"coverage": dict(state.audit_coverage)})
    return preserved


__all__ = [
    "baseline_report",
    "baseline_semantic_digest",
    "publish_primary_baseline",
    "report_preserves_baseline",
    "restore_published_baseline",
    "validate_baseline_chain",
]
