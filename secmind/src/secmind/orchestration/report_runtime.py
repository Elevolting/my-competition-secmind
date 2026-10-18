"""Deterministic report projection and terminal admission node."""

from __future__ import annotations

from typing import Any

from secmind.artifact_store import ArtifactStoreError
from secmind.direct_anchor_pipeline import (
    AnchorReport,
    DeltaDisposition,
    TypedDelta,
    build_enhanced_report,
    stable_digest,
)
from secmind.evidence_graph import EvidenceGraph
from secmind.orchestration.tool_projection_runtime import persist_projection_artifact
from secmind.orchestration.typed_answer_runtime import project_active_answer
from secmind.primary_baseline import baseline_report
from secmind.public_coverage import public_coverage_projection
from secmind.schemas import AgentReport, RunStatus, Scenario, StepStatus


def _safe_active_answer(state: Any) -> Any | None:
    try:
        return project_active_answer(state)
    except (TypeError, ValueError):
        return None


def finalize_augmentation_status(state: Any) -> None:
    current = str(state.audit_coverage.get("augmentation_status", "not_run"))
    if current not in {"pending", "running"}:
        return
    runtimes = list(state.step_runtime.values())
    if not state.plan:
        status = "not_applicable" if current == "pending" else "skipped"
    elif not runtimes or any(item.status in {StepStatus.PENDING, StepStatus.RUNNING} for item in runtimes):
        status = "partial"
    elif any(item.status in {StepStatus.FAILED, StepStatus.CANCELLED} for item in runtimes):
        status = "partial"
    else:
        status = "completed"
    state.audit_coverage["augmentation_status"] = status


async def report(host: Any, value: Any) -> Any:
    state = host._state(value)
    finalize_augmentation_status(state)
    primary_report = baseline_report(state)
    typed_active = _safe_active_answer(state)
    if state.published_baseline is not None and typed_active is None:
        state.status = RunStatus.PARTIAL
        state.last_error = "typed PublishedAnswer replay failed before report projection"
    if primary_report is None and state.audit_coverage.get("canonical_primary_completed"):
        primary_report = state.report.model_copy(deep=True) if state.report is not None else None
    try:
        state = await host.reporter.run(state)
    except Exception as exc:  # Reporting must be a total function over durable state.
        reason = f"Structured reporter degraded safely: {type(exc).__name__}."
        state.last_error = reason
        if state.status not in {RunStatus.DENIED, RunStatus.CANCELLED, RunStatus.FAILED}:
            state.status = RunStatus.PARTIAL
        existing = primary_report or state.report
        state.report = AgentReport(
            run_id=state.run_id,
            status=state.status,
            executive_summary=(
                existing.executive_summary
                if existing is not None
                else "SecMind preserved a partial result after the structured reporter failed."
            ),
            findings=list(state.findings if existing is None else existing.findings),
            decisions=list(state.decisions),
            evidence=list(state.evidence if existing is None else existing.evidence),
            limitations=list(dict.fromkeys([*(existing.limitations if existing is not None else []), reason])),
            coverage=public_coverage_projection(state.audit_coverage),
            audit_kernel=state.audit_kernel,
            audit_units=state.audit_units,
        )
    if state.published_baseline is not None and _safe_active_answer(state) is None:
        state.status = RunStatus.PARTIAL
        state.last_error = "typed PublishedAnswer replay failed after report projection"
    if state.scenario == Scenario.CODE_AUDIT and state.report is not None:
        try:
            projection = EvidenceGraph(
                claims=state.claims,
                evidence=state.evidence,
                links=state.evidence_links,
            ).verified_report_projection(state.findings)
            state.report = state.report.model_copy(
                update={
                    "findings": list(projection.findings),
                    "evidence": list(projection.evidence),
                    "claim_ids": list(projection.claim_ids),
                }
            )
        except (TypeError, ValueError) as exc:
            reason = f"Evidence projection degraded safely: {type(exc).__name__}."
            state.status = RunStatus.PARTIAL
            state.last_error = reason
            state.report = state.report.model_copy(
                update={
                    "status": state.status,
                    "limitations": list(dict.fromkeys([*state.report.limitations, reason])),
                }
            )
    if state.report is not None:
        anchor_payload = state.audit_coverage.get("anchor_report")
        raw_delta_payload = state.audit_coverage.get("typed_deltas", [])
        if isinstance(anchor_payload, dict):
            try:
                anchor = AnchorReport.model_validate(anchor_payload)
                deltas = tuple(TypedDelta.model_validate(item) for item in raw_delta_payload if isinstance(item, dict))
                precision_gate_met = not any(
                    item.disposition in {DeltaDisposition.QUARANTINED, DeltaDisposition.REJECTED} for item in deltas
                )
                enhanced = build_enhanced_report(
                    anchor=anchor,
                    deltas=deltas,
                    findings=state.report.findings,
                    evidence=state.report.evidence,
                    coverage={key: item for key, item in state.audit_coverage.items() if key != "enhanced_report"},
                    precision_gate_met=precision_gate_met,
                    publishable=precision_gate_met,
                )
                enhanced_payload = enhanced.model_dump(mode="json")
                enhanced_digest = stable_digest(enhanced)
                enhanced_artifact = persist_projection_artifact(
                    host,
                    state,
                    enhanced_payload,
                    media_type="application/vnd.secmind.enhanced-report+json",
                    reference_key="enhanced_report_artifact_id",
                )
                state.audit_coverage["enhanced_report"] = {
                    "schema_version": "secmind-enhanced-report-summary-v1",
                    "publishable": bool(enhanced_payload.get("publishable")),
                    "precision_gate_met": bool(enhanced_payload.get("precision_gate_met")),
                    "anchor_preserved": bool(enhanced_payload.get("anchor_preserved", True)),
                    "anchor_report_digest": enhanced_payload.get("anchor_report_digest"),
                    "enhanced_report_digest": enhanced_digest,
                    "artifact_id": enhanced_artifact.artifact_id,
                    "finding_count": len(enhanced_payload.get("findings", [])),
                    "evidence_count": len(enhanced_payload.get("evidence", [])),
                    "delta_count": len(enhanced_payload.get("deltas", [])),
                    "added_delta_count": len(enhanced_payload.get("added_delta_ids", [])),
                    "corrected_delta_count": len(enhanced_payload.get("corrected_delta_ids", [])),
                    "rejected_delta_count": len(enhanced_payload.get("rejected_delta_ids", [])),
                    "quarantined_delta_count": len(enhanced_payload.get("quarantined_delta_ids", [])),
                }
                state.audit_coverage["enhanced_report_digest"] = enhanced_digest
                state.audit_coverage["enhanced_report_artifact_id"] = enhanced_artifact.artifact_id
            except (ArtifactStoreError, OSError, TypeError, ValueError) as exc:
                state.audit_coverage["enhanced_report"] = {
                    "schema_version": "secmind-enhanced-report-summary-v1",
                    "publishable": False,
                    "reason": f"enhanced_report_projection_failed:{type(exc).__name__}",
                }
        state.report = state.report.model_copy(
            update={
                "coverage": public_coverage_projection(state.audit_coverage),
            }
        )
        host._seal_admission(state)
    payload = {"status": state.status, "finding_count": len(state.findings), "evidence_count": len(state.evidence)}
    return await host._checkpoint(state, "report.generated", payload)


__all__ = ["finalize_augmentation_status", "report"]
