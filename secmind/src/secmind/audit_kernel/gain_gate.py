from __future__ import annotations

import logging
from collections.abc import Iterable
from datetime import datetime

from secmind.audit_kernel.contracts import (
    AuditUnit,
    CandidateFlow,
    CriticVerdict,
    FlowVerdict,
    GainAction,
    GainPolicy,
    PrimaryVerdict,
    ReviewVerdict,
    StructuralConsistencyCertificate,
    UnitDecision,
)
from secmind.audit_kernel.patch_release import (
    EmpiricalGate,
    PatchIdentity,
    PatchReleaseRecord,
)

logger = logging.getLogger(__name__)


class GainGate:
    """Fail-safe adjudicator for independently qualified label corrections."""

    def __init__(self, empirical_gate: EmpiricalGate | None = None) -> None:
        self._empirical_gate = empirical_gate or EmpiricalGate()

    def decide(
        self,
        unit: AuditUnit,
        baseline: PrimaryVerdict,
        *,
        policy: GainPolicy | None,
        flow: CandidateFlow | None = None,
        certificate: StructuralConsistencyCertificate | None = None,
        critic: CriticVerdict | None = None,
        patch_identity: PatchIdentity | None = None,
        release: PatchReleaseRecord | None = None,
        now: datetime | None = None,
    ) -> UnitDecision:
        try:
            evidence_ids = self._evidence_union(baseline, flow, certificate, critic)
            reason = self._rejection_reason(unit, baseline, policy, flow, certificate, critic)
            if reason is not None:
                return self._keep(unit, baseline, policy, evidence_ids, reason)
            if patch_identity is None:
                return self._keep(
                    unit,
                    baseline,
                    policy,
                    evidence_ids,
                    "patch_identity_missing",
                )
            if flow is None:
                return self._keep(
                    unit,
                    baseline,
                    policy,
                    evidence_ids,
                    "enhancement_incomplete",
                )
            if not patch_identity.matches_candidate(unit, flow):
                return self._keep(
                    unit,
                    baseline,
                    policy,
                    evidence_ids,
                    "patch_identity_candidate_mismatch",
                )
            empirical = self._empirical_gate.evaluate(patch_identity, release=release, now=now)
            if not empirical.allowed:
                return self._keep(unit, baseline, policy, evidence_ids, empirical.reason)
            if policy is None or certificate is None or critic is None or empirical.patch_release_id is None:
                return self._keep(
                    unit,
                    baseline,
                    policy,
                    evidence_ids,
                    "empirical_release_incomplete",
                )
            correction = flow.verdict == FlowVerdict.CANDIDATE_NEGATIVE
            return UnitDecision.create(
                unit_id=unit.unit_id,
                action=GainAction.ACCEPT_CORRECTION if correction else GainAction.ACCEPT_ENHANCEMENT,
                baseline_verdict=baseline.verdict,
                final_verdict=ReviewVerdict.NOT_VULNERABLE if correction else ReviewVerdict.VULNERABLE,
                baseline_cwe=baseline.cwe,
                final_cwe=None if correction else flow.cwe,
                baseline_receipt_id=baseline.receipt_id,
                accepted_flow_id=flow.flow_id,
                patch_release_id=empirical.patch_release_id,
                critic_receipt_id=critic.receipt_id,
                semantic_certificate_digest=certificate.certificate_digest,
                policy_digest=policy.policy_digest,
                evidence_ids=evidence_ids,
                reason_codes=(
                    "authoritative_patch_release_matched",
                    (
                        "independent_semantic_correction_accepted"
                        if correction
                        else "independent_semantic_enhancement_accepted"
                    ),
                    f"patch_release:{empirical.patch_release_id}",
                ),
            )
        except Exception as exc:
            # Optional augmentation is a fault domain: never erase the durable
            # baseline, but make unexpected implementation faults observable.
            logger.warning("gain gate augmentation failed closed", extra={"error_type": type(exc).__name__})
            return self._keep(
                unit,
                baseline,
                policy,
                tuple(sorted(set(baseline.evidence_ids))),
                "enhancement_error",
            )

    @staticmethod
    def _rejection_reason(
        unit: AuditUnit,
        baseline: PrimaryVerdict,
        policy: GainPolicy | None,
        flow: CandidateFlow | None,
        certificate: StructuralConsistencyCertificate | None,
        critic: CriticVerdict | None,
    ) -> str | None:
        if baseline.unit_id != unit.unit_id:
            return "baseline_unit_mismatch"
        if baseline.verdict not in {ReviewVerdict.VULNERABLE, ReviewVerdict.NOT_VULNERABLE}:
            return "baseline_not_scoreable"
        if policy is None or not policy.digest_valid():
            return "policy_missing_or_invalid"
        if not policy.enabled:
            return "policy_disabled"
        if flow is None or certificate is None or critic is None:
            return "enhancement_incomplete"
        if flow.unit_id != unit.unit_id or certificate.unit_id != unit.unit_id or critic.unit_id != unit.unit_id:
            return "enhancement_unit_mismatch"
        if certificate.flow_id != flow.flow_id:
            return "certificate_flow_mismatch"
        correction = baseline.verdict == ReviewVerdict.VULNERABLE
        expected_flow = FlowVerdict.CANDIDATE_NEGATIVE if correction else FlowVerdict.CANDIDATE_POSITIVE
        if flow.verdict != expected_flow or flow.source_site is None:
            return "tool_flow_direction_mismatch"
        if correction and (baseline.cwe is None or flow.cwe != baseline.cwe):
            return "correction_cwe_mismatch"
        if flow.cwe not in unit.target_cwes or (policy.allowed_cwes and flow.cwe not in policy.allowed_cwes):
            return "cwe_outside_policy"
        if flow.tool_name not in policy.approved_tool_names:
            return "tool_not_approved"
        if flow.rule_bundle_digest not in policy.approved_rule_bundle_digests:
            return "rule_bundle_not_approved"
        minimum_tool_confidence = (
            policy.minimum_correction_tool_confidence if correction else policy.minimum_tool_confidence
        )
        if flow.confidence < minimum_tool_confidence or not flow.evidence_ids:
            return "tool_evidence_insufficient"
        if (
            not certificate.valid
            or not certificate.digest_valid()
            or not all(check.passed for check in certificate.checks)
            or not set(flow.evidence_ids).issubset(certificate.evidence_ids)
        ):
            return "semantic_certificate_invalid"
        expected_critic = ReviewVerdict.NOT_VULNERABLE if correction else ReviewVerdict.VULNERABLE
        if critic.verdict != expected_critic:
            return "critic_did_not_confirm"
        minimum_critic_confidence = (
            policy.minimum_correction_critic_confidence if correction else policy.minimum_critic_confidence
        )
        if critic.confidence < minimum_critic_confidence or not critic.evidence_ids:
            return "critic_evidence_insufficient"
        if baseline.model_id is None or critic.model_id is None:
            return "critic_model_lineage_missing"
        if baseline.model_id == critic.model_id:
            return "critic_model_not_independent"
        if not correction:
            if critic.cwe != flow.cwe:
                return "critic_cwe_mismatch"
            if critic.source_node_id != flow.source_site.node_id or critic.sink_node_id != flow.sink_site.node_id:
                return "critic_path_mismatch"
        if critic.lineage_id == flow.lineage_id or critic.lineage_id.startswith("tool:"):
            return "lineage_not_independent"
        return None

    @staticmethod
    def _keep(
        unit: AuditUnit,
        baseline: PrimaryVerdict,
        policy: GainPolicy | None,
        evidence_ids: tuple[str, ...],
        reason: str,
    ) -> UnitDecision:
        return UnitDecision.create(
            unit_id=unit.unit_id,
            action=GainAction.KEEP_BASELINE,
            baseline_verdict=baseline.verdict,
            final_verdict=baseline.verdict,
            baseline_cwe=baseline.cwe,
            final_cwe=baseline.cwe,
            baseline_receipt_id=baseline.receipt_id,
            policy_digest=None if policy is None else policy.policy_digest,
            evidence_ids=evidence_ids,
            reason_codes=(reason,),
        )

    @staticmethod
    def _evidence_union(
        baseline: PrimaryVerdict,
        flow: CandidateFlow | None,
        certificate: StructuralConsistencyCertificate | None,
        critic: CriticVerdict | None,
    ) -> tuple[str, ...]:
        groups: Iterable[tuple[str, ...]] = (
            baseline.evidence_ids,
            () if flow is None else flow.evidence_ids,
            () if certificate is None else certificate.evidence_ids,
            () if critic is None else critic.evidence_ids,
        )
        return tuple(sorted({evidence_id for group in groups for evidence_id in group if evidence_id}))
