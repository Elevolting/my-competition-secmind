from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal, cast
from uuid import NAMESPACE_URL, uuid5

from secmind.artifact_store import ContentAddressedArtifactStore, StoredArtifact
from secmind.audit_kernel.pipeline import AuditKernelResult
from secmind.investigation.contracts import (
    ArtifactDataClass,
    ArtifactSecurityLabel,
    ArtifactView,
)
from secmind.investigation.store import InvestigationStore
from secmind.ledger import canonical_json
from secmind.schemas import (
    SCHEMA_VERSION,
    AuditUnitResult,
    DataView,
    Evidence,
    EvidenceAssurance,
    Finding,
)


@dataclass(frozen=True, slots=True)
class AuditProjection:
    evidence: tuple[Evidence, ...]
    findings: tuple[Finding, ...]
    units: tuple[AuditUnitResult, ...]
    malformed_positive_units: tuple[str, ...]


class AuditResultProjector:
    """Materialize immutable public evidence without owning graph state."""

    def __init__(
        self,
        artifact_store: ContentAddressedArtifactStore,
        investigation_store: InvestigationStore | None,
    ) -> None:
        self._artifact_store = artifact_store
        self._investigation_store = investigation_store

    def project(
        self,
        result: AuditKernelResult,
        *,
        run_id: str,
        step_id: str,
        planner_model_id: str,
        severity_for: Callable[[int, EvidenceAssurance], Literal["MEDIUM", "HIGH"]],
    ) -> AuditProjection:
        evidence: list[Evidence] = []
        findings: list[Finding] = []
        units: list[AuditUnitResult] = []
        malformed: list[str] = []
        decision_by_unit = {item.unit_id: item for item in result.decisions}

        for unit in sorted(result.units, key=lambda item: item.unit_id):
            decision = decision_by_unit[unit.unit_id]
            primary = result.primary_verdicts[unit.unit_id]
            accepted_flow = next(
                (
                    flow
                    for flow in result.candidate_flows.get(unit.unit_id, ())
                    if flow.flow_id == decision.accepted_flow_id
                ),
                None,
            )
            sink_line = accepted_flow.sink_site.line if accepted_flow is not None else primary.sink_line
            final_cwe = decision.final_cwe
            stored = self._artifact_store.put(
                canonical_json(
                    {
                        "schema_version": SCHEMA_VERSION,
                        "run_id": run_id,
                        "kernel": f"v0.7-{result.mode}",
                        "unit": unit.model_dump(mode="json"),
                        "primary": primary.model_dump(mode="json"),
                        "decision": decision.model_dump(mode="json"),
                        "accepted_flow": (None if accepted_flow is None else accepted_flow.model_dump(mode="json")),
                        "candidate_flow_count": len(result.candidate_flows.get(unit.unit_id, ())),
                    }
                ).encode("utf-8"),
                media_type="application/vnd.secmind.audit-unit-decision+json",
                run_id=run_id,
                data_view=DataView.OBSERVABLE,
            )
            self._label_artifact(stored, run_id=run_id, step_id=step_id)
            assurance = (
                EvidenceAssurance.SEMANTICALLY_CORROBORATED
                if accepted_flow is not None
                else EvidenceAssurance.MODEL_PROPOSED
            )
            evidence_id = f"audit-{stored.sha256[:24]}"
            item_evidence = Evidence(
                evidence_id=evidence_id,
                source="secmind:v0.7-primary-agent",
                summary=(
                    f"{decision.final_verdict.value} decision for {unit.primary_path}"
                    + (f" at line {sink_line}" if sink_line is not None else "")
                ),
                artifact_ref=stored.artifact_id,
                sha256=stored.sha256,
                metadata={
                    "evidence_type": "audit_unit_decision",
                    "step_id": step_id,
                    "unit_id": unit.unit_id,
                    "path": unit.primary_path,
                    "file_sha256": unit.source_sha256,
                    "line": sink_line,
                    "baseline_verdict": decision.baseline_verdict.value,
                    "final_verdict": decision.final_verdict.value,
                    "action": decision.action.value,
                    "decision_digest": decision.decision_digest,
                    "primary_receipt_id": primary.receipt_id,
                    "kernel_mode": result.mode,
                    "assurance_level": assurance.value,
                },
            )
            evidence.append(item_evidence)
            confidence = accepted_flow.confidence if accepted_flow is not None else primary.confidence
            units.append(
                AuditUnitResult(
                    unit_id=unit.unit_id,
                    path=unit.primary_path,
                    source_sha256=unit.source_sha256,
                    baseline_verdict=decision.baseline_verdict.value,
                    final_verdict=decision.final_verdict.value,
                    action=cast(
                        Literal["keep_baseline", "accept_enhancement", "accept_correction"],
                        decision.action.value,
                    ),
                    baseline_cwe=decision.baseline_cwe,
                    cwe=final_cwe,
                    sink_line=sink_line,
                    confidence=confidence,
                    primary_receipt_id=primary.receipt_id,
                    decision_digest=decision.decision_digest,
                    evidence_ids=[evidence_id],
                    reason_codes=list(decision.reason_codes),
                )
            )
            if decision.final_verdict.value != "vulnerable":
                continue
            if final_cwe is None or sink_line is None:
                malformed.append(unit.unit_id)
                continue
            confidence_label = "HIGH" if confidence >= 0.85 else ("MEDIUM" if confidence >= 0.6 else "LOW")
            findings.append(
                Finding(
                    finding_id=str(
                        uuid5(NAMESPACE_URL, f"secmind:v07:{run_id}:{unit.unit_id}:{final_cwe}:{sink_line}")
                    ),
                    rule_id=f"CWE-{final_cwe}",
                    severity=severity_for(final_cwe, assurance),
                    confidence=cast(Any, confidence_label),
                    path=unit.primary_path,
                    line=sink_line,
                    title=f"SecMind v0.7 Primary Agent review: CWE-{final_cwe}",
                    description=(
                        "Tool evidence and an independently routed critic corroborated the primary proposal."
                        if accepted_flow is not None
                        else result.rationales.get(
                            unit.unit_id,
                            "The bounded Primary Agent proposed a source-to-sink security finding.",
                        )
                    ),
                    remediation="Validate untrusted input and use a safe API appropriate to the identified sink.",
                    evidence_ids=[evidence_id],
                    raw={
                        "model_id": planner_model_id,
                        "primary_receipt_id": primary.receipt_id,
                        "decision_digest": decision.decision_digest,
                        "gain_action": decision.action.value,
                        "assurance_level": assurance.value,
                    },
                )
            )
        return AuditProjection(tuple(evidence), tuple(findings), tuple(units), tuple(malformed))

    def _label_artifact(self, stored: StoredArtifact, *, run_id: str, step_id: str) -> None:
        if self._investigation_store is None:
            return
        self._investigation_store.label_artifact(
            ArtifactSecurityLabel(
                artifact_id=stored.artifact_id,
                owner_run_id=run_id,
                owner_step_id=step_id,
                view=ArtifactView.OBSERVABLE,
                data_class=ArtifactDataClass.MODEL_IO,
                retention_policy_id="competition-run-default",
                allowed_purposes=["analysis", "report", "download"],
                created_by="primary-audit-agent",
                content_sha256=stored.sha256,
                size=stored.size_bytes,
                media_type=stored.media_type,
            )
        )


__all__ = ["AuditProjection", "AuditResultProjector"]
