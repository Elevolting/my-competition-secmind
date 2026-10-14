from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Literal
from uuid import NAMESPACE_URL, uuid5

from secmind.evidence_graph import EvidenceGraph
from secmind.ledger import canonical_json
from secmind.policy import PolicyError, resource_in_scope
from secmind.schemas import (
    ClaimStatus,
    Evidence,
    EvidenceRelation,
    PolicyAction,
    PolicyDecision,
    RiskLevel,
    RunStatus,
    Scenario,
    TaskSpec,
)
from secmind.secret_scrubber import scrub_text

_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
DryRunPhase = Literal["investigation", "containment", "recovery", "validation"]
_PHASES: tuple[tuple[DryRunPhase, str, str, RiskLevel, PolicyAction, str, str, str], ...] = (
    (
        "investigation",
        "Validate the affected subject and time window",
        "Review the preserved evidence and corroborate the subject, account and time window without changing state.",
        RiskLevel.R0,
        PolicyAction.ALLOW,
        "Read-only review may narrow or reject the current incident hypothesis.",
        "Stop and retain the original hypothesis if evidence integrity or scope cannot be confirmed.",
        "incident-investigator",
    ),
    (
        "containment",
        "Prepare a reversible containment option",
        "Document a least-impact containment option for operator review; do not isolate, block or disable anything.",
        RiskLevel.R2,
        PolicyAction.REQUIRE_APPROVAL,
        "A future approved action could reduce exposure but may interrupt the affected service or account.",
        "Require a tested restoration path and abort if the affected subject or blast radius differs from evidence.",
        "incident-commander",
    ),
    (
        "recovery",
        "Prepare restoration from a known-good state",
        "Document restoration prerequisites and integrity checks; do not delete data or modify the affected system.",
        RiskLevel.R2,
        PolicyAction.REQUIRE_APPROVAL,
        "A future approved restoration may replace affected state and must preserve forensic evidence.",
        "Abort if backups, ownership, integrity hashes or a reversible restoration method are unavailable.",
        "recovery-operator",
    ),
    (
        "validation",
        "Define post-action verification criteria",
        "Compare fresh read-only observations with the preserved baseline and record any unresolved indicators.",
        RiskLevel.R0,
        PolicyAction.ALLOW,
        "Read-only validation determines whether the proposed playbook would meet its success criteria.",
        "Reopen investigation when indicators persist or new evidence contradicts the current hypothesis.",
        "evidence-verifier",
    ),
)


class IncidentDryRunError(ValueError):
    """The requested dry run violates the scenario or evidence boundary."""


@dataclass(frozen=True)
class DryRunAction:
    action_id: str
    phase: DryRunPhase
    title: str
    description: str
    subject_ref: str
    prerequisite_evidence_ids: tuple[str, ...]
    policy_decision: PolicyDecision
    expected_impact: str
    rollback_condition: str
    human_role: str
    execution_enabled: bool = False


@dataclass(frozen=True)
class AlternativeExplanation:
    claim_id: str
    evidence_ids: tuple[str, ...]
    explanation: str
    treated_as_fact: bool = False


@dataclass(frozen=True)
class IncidentDryRunResult:
    run_id: str
    task_spec_digest: str
    status: RunStatus
    actions: tuple[DryRunAction, ...]
    alternative_explanations: tuple[AlternativeExplanation, ...]
    coverage_gaps: tuple[str, ...]
    executed_action_count: int = 0
    mode: Literal["dry_run"] = "dry_run"
    source_content_trust: Literal["untrusted_data"] = "untrusted_data"


def build_incident_dry_run(task_spec: TaskSpec, evidence_graph: EvidenceGraph) -> IncidentDryRunResult:
    """Build an evidence-bound operator playbook without executing any action.

    Evidence statements and metadata are never interpreted as instructions.  Only
    verifier-owned graph state, immutable evidence references and platform templates
    influence the returned recommendation portfolio.
    """

    if task_spec.primary_scenario != Scenario.INCIDENT_RESPONSE:
        raise IncidentDryRunError("TaskSpec is not an incident-response task")

    actions: list[DryRunAction] = []
    alternatives: list[AlternativeExplanation] = []
    gaps: list[str] = []
    for claim in evidence_graph.claims:
        if claim.status == ClaimStatus.CONFLICTED:
            alternative_evidence = _integrity_evidence_for_claim(
                evidence_graph,
                claim.claim_id,
                accepted_statuses=frozenset({ClaimStatus.CONFLICTED}),
            )
            alternatives.append(
                AlternativeExplanation(
                    claim_id=claim.claim_id,
                    evidence_ids=tuple(item.evidence_id for item in alternative_evidence),
                    explanation=(
                        "The evidence graph marks this hypothesis as conflicting. "
                        "It requires operator investigation and is not promoted to fact."
                    ),
                )
            )
            continue
        if claim.status != ClaimStatus.VERIFIED:
            continue
        integrity_evidence = _integrity_evidence_for_claim(evidence_graph, claim.claim_id)
        evidence_ids = tuple(item.evidence_id for item in integrity_evidence)
        if not _subject_is_in_scope(claim.subject_ref, task_spec.authorized_scope):
            gaps.append(f"verified claim {claim.claim_id} is outside the explicit TaskSpec scope")
            continue
        if not evidence_ids:
            gaps.append(f"verified claim {claim.claim_id} lacks integrity-bearing verifier-approved evidence")
            continue
        safe_subject = scrub_text(claim.subject_ref)[:1_024]
        for phase, title, description, risk, policy_action, impact, rollback, role in _PHASES:
            actions.append(
                DryRunAction(
                    action_id=_stable_id(
                        "ir-action",
                        {
                            "run_id": task_spec.run_id,
                            "claim_id": claim.claim_id,
                            "phase": phase,
                            "evidence_ids": evidence_ids,
                        },
                    ),
                    phase=phase,
                    title=title,
                    description=description,
                    subject_ref=safe_subject,
                    prerequisite_evidence_ids=evidence_ids,
                    policy_decision=_policy_classification(
                        task_spec,
                        action_key=f"{claim.claim_id}:{phase}",
                        risk=risk,
                        action=policy_action,
                    ),
                    expected_impact=impact,
                    rollback_condition=rollback,
                    human_role=role,
                )
            )

    if not actions:
        gaps.append("no in-scope verified incident hypothesis can support a playbook")
    status = RunStatus.COMPLETED if actions and not gaps else RunStatus.PARTIAL
    return IncidentDryRunResult(
        run_id=task_spec.run_id,
        task_spec_digest=task_spec.content_digest,
        status=status,
        actions=tuple(sorted(actions, key=lambda item: (item.subject_ref, item.phase, item.action_id))),
        alternative_explanations=tuple(sorted(alternatives, key=lambda item: item.claim_id)),
        coverage_gaps=tuple(sorted(set(gaps))),
    )


def _integrity_evidence_for_claim(
    graph: EvidenceGraph,
    claim_id: str,
    *,
    accepted_statuses: frozenset[ClaimStatus] = frozenset({ClaimStatus.VERIFIED}),
) -> tuple[Evidence, ...]:
    evidence = {item.evidence_id: item for item in graph.evidence_for_claim(claim_id)}
    identifiers = {
        link.evidence_id
        for link in graph.links_for_claim(claim_id)
        if link.relation in {EvidenceRelation.SUPPORTS, EvidenceRelation.CONTRADICTS}
        and link.verifier_status in accepted_statuses
    }
    return tuple(
        evidence[evidence_id]
        for evidence_id in sorted(identifiers)
        if evidence_id in evidence
        and evidence[evidence_id].artifact_ref
        and evidence[evidence_id].sha256
        and _SHA256.fullmatch(str(evidence[evidence_id].sha256))
    )


def _subject_is_in_scope(subject_ref: str, authorized_scope: list[str]) -> bool:
    try:
        return resource_in_scope(subject_ref, authorized_scope)
    except PolicyError:
        return False


def _policy_classification(
    task_spec: TaskSpec,
    *,
    action_key: str,
    risk: RiskLevel,
    action: PolicyAction,
) -> PolicyDecision:
    material = {
        "run_id": task_spec.run_id,
        "task_spec_digest": task_spec.content_digest,
        "action_key": action_key,
        "risk": int(risk),
        "action": action.value,
        "execution_enabled": False,
    }
    digest = hashlib.sha256(canonical_json(material).encode()).hexdigest()
    return PolicyDecision(
        decision_id=_stable_id("ir-policy", material),
        action=action,
        effective_risk=risk,
        policy_ids=["IR-DRY-RUN-ONLY-1.4", "POL-R2-STATE-CHANGE" if risk == RiskLevel.R2 else "POL-R0-READ"],
        reason_summary=(
            "This is a read-only dry-run classification. R2 state-changing actions remain unimplemented and require "
            "a separate Broker/PDP approval path."
            if risk == RiskLevel.R2
            else "This read-only planning or verification action does not cross an execution boundary."
        ),
        decision_input_hash=digest,
    )


def _stable_id(namespace: str, value: object) -> str:
    return str(uuid5(NAMESPACE_URL, f"secmind:{namespace}:{canonical_json(value)}"))


__all__ = [
    "AlternativeExplanation",
    "DryRunAction",
    "IncidentDryRunError",
    "IncidentDryRunResult",
    "build_incident_dry_run",
]
