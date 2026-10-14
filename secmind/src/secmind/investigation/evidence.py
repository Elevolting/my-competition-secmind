"""Pure evidence evaluation for bounded investigations.

The types in this module derive evidence matrices, gaps, replan decisions, and
completion evaluations from immutable contracts. They perform no I/O; storage,
tool execution, and graph routing remain outside this domain layer.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from secmind.evidence_graph import EvidenceGraph, EvidenceGraphError
from secmind.investigation.contracts import (
    CompletionOutcome,
    CompletionSnapshotV2,
    Hypothesis,
    HypothesisStatus,
    ObligationStatus,
    RequirementObligation,
    canonical_content_digest,
)
from secmind.schemas import ClaimStatus, Evidence, EvidenceRelation, Finding, ReplanTrigger


class EvidenceEvaluationError(ValueError):
    """The investigation evidence input is internally inconsistent."""


class RequirementDisposition(StrEnum):
    PROVEN = "proven"
    REFUTED = "refuted"
    INCOMPLETE = "incomplete"
    UNVERIFIED = "unverified"
    MISSING = "missing"
    WAIVED = "waived"


class EvidenceGapKind(StrEnum):
    MISSING_EVIDENCE = "missing_evidence"
    INVALID_EVIDENCE_REFERENCE = "invalid_evidence_reference"
    MISSING_EVIDENCE_TYPE = "missing_evidence_type"
    NON_INDEPENDENT_EVIDENCE = "non_independent_evidence"
    UNVERIFIED_EVIDENCE = "unverified_evidence"
    MISSING_VERIFIER_RECEIPT = "missing_verifier_receipt"
    CONTRADICTED_REQUIREMENT = "contradicted_requirement"
    INCOMPLETE_REQUIREMENT = "incomplete_requirement"
    INVALID_WAIVER = "invalid_waiver"
    HIGH_RISK_ATTACK_PATH = "high_risk_attack_path"
    HIGH_RISK_PRECONDITIONS = "high_risk_preconditions"
    HIGH_RISK_IMPACT = "high_risk_impact"
    HIGH_RISK_INDEPENDENT_VALIDATION = "high_risk_independent_validation"


_VERSIONED_SOURCE_SUFFIX = re.compile(r"(?::|@|/v)\d+(?:[._-]\d+)*$", re.IGNORECASE)
_PASSING_GRADES = frozenset({"complete", "passed", "proven", "satisfied", "verified"})


def _non_empty_string(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    return normalized or None


def _metadata_string(metadata: Mapping[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = _non_empty_string(metadata.get(key))
        if value is not None:
            return value
    return None


def _source_family(evidence: Evidence) -> str:
    configured = _metadata_string(
        evidence.metadata,
        "original_source_family",
        "original_source_id",
        "source_family",
        "source_id",
    )
    source = configured or evidence.source
    normalized = " ".join(source.strip().casefold().split())
    return _VERSIONED_SOURCE_SUFFIX.sub("", normalized) or "unknown-source"


def _evidence_types(evidence: Evidence) -> frozenset[str]:
    raw = evidence.metadata.get("evidence_types", evidence.metadata.get("evidence_type"))
    if isinstance(raw, str):
        values = [raw]
    elif isinstance(raw, Sequence) and not isinstance(raw, (bytes, bytearray, str)):
        values = [item for item in raw if isinstance(item, str)]
    else:
        values = []
    return frozenset(item.strip().casefold() for item in values if item.strip())


def _semantic_evidence_key(evidence: Evidence) -> str:
    explicit = _metadata_string(evidence.metadata, "semantic_evidence_key", "semantic_key")
    if explicit is not None:
        return explicit.casefold()
    metadata = evidence.metadata
    locator = metadata.get("normalized_locator", metadata.get("locator"))
    arguments = metadata.get("normalized_args", metadata.get("arguments"))
    inputs = metadata.get("input_artifact_digests", metadata.get("input_digests", []))
    relation = metadata.get("claim_relation", "supports")
    payload = {
        "tool": _metadata_string(metadata, "tool_name", "tool_family") or "unknown-tool",
        "tool_version": _metadata_string(metadata, "tool_version") or "unknown-version",
        "arguments": arguments if isinstance(arguments, (dict, list, str, int, float, bool)) else None,
        "inputs": inputs if isinstance(inputs, (dict, list, str)) else None,
        "locator": locator if isinstance(locator, (dict, list, str, int)) else None,
        "relation": str(relation).casefold(),
        "source_family": _source_family(evidence),
        "summary": " ".join(evidence.summary.casefold().split()),
    }
    return canonical_content_digest(payload)


@dataclass(frozen=True)
class EvidenceGraphView:
    """A verified graph fragment with an explicit provenance lineage."""

    graph_id: str
    graph: EvidenceGraph

    def __post_init__(self) -> None:
        if not self.graph_id.strip():
            raise ValueError("graph_id must not be empty")


@dataclass(frozen=True)
class EvidenceNode:
    evidence: Evidence
    graph_ids: frozenset[str]
    source_family: str
    semantic_key: str
    invocation_id: str | None
    tool_family: str | None
    rule_family: str | None
    agent_session_id: str | None
    verified: bool
    verified_claim_ids: frozenset[str]
    subject_refs: frozenset[str]
    evidence_types: frozenset[str]


class InvestigationEvidenceGraph:
    """Read-only union of evidence graphs with conservative provenance semantics.

    Evidence that is merely copied into another graph remains one node because the
    evidence id and semantic key are deduplicated.  Independence additionally
    requires disjoint original-source and graph lineages.
    """

    def __init__(self, views: Iterable[EvidenceGraphView]) -> None:
        selected = tuple(sorted(views, key=lambda item: item.graph_id))
        self._views = selected
        self._nodes = self._build_nodes(selected)
        self._claims = self._build_claim_index(selected)

    @property
    def nodes(self) -> tuple[EvidenceNode, ...]:
        return tuple(self._nodes[key] for key in sorted(self._nodes))

    @property
    def evidence_ids(self) -> frozenset[str]:
        return frozenset(self._nodes)

    @property
    def claim_ids(self) -> frozenset[str]:
        return frozenset(self._claims)

    def node(self, evidence_id: str) -> EvidenceNode:
        try:
            return self._nodes[evidence_id]
        except KeyError as exc:
            raise EvidenceEvaluationError(f"unknown evidence {evidence_id}") from exc

    def verified_claim(self, claim_id: str) -> bool:
        return self._claims.get(claim_id) == ClaimStatus.VERIFIED

    def verified_evidence_for_subject(self, subject_ref: str) -> tuple[str, ...]:
        return tuple(
            node.evidence.evidence_id for node in self.nodes if node.verified and subject_ref in node.subject_refs
        )

    def independent_evidence(self, evidence_ids: Iterable[str]) -> tuple[EvidenceNode, ...]:
        """Return a deterministic, fail-closed set of independent evidence.

        A candidate is rejected when it shares a semantic key, original source,
        or EvidenceGraph lineage with an already selected candidate.  Different
        ids, hashes, agent names, or serializations alone therefore cannot create
        a second independent result.
        """

        candidates = [self._nodes[item] for item in sorted(set(evidence_ids)) if item in self._nodes]
        candidates.sort(
            key=lambda item: (
                item.semantic_key,
                item.source_family,
                tuple(sorted(item.graph_ids)),
                item.evidence.evidence_id,
            )
        )
        selected: list[EvidenceNode] = []
        semantic_keys: set[str] = set()
        sources: set[str] = set()
        graph_ids: set[str] = set()
        for candidate in candidates:
            if not candidate.verified:
                continue
            if candidate.semantic_key in semantic_keys:
                continue
            if candidate.source_family in sources:
                continue
            if candidate.graph_ids & graph_ids:
                continue
            selected.append(candidate)
            semantic_keys.add(candidate.semantic_key)
            sources.add(candidate.source_family)
            graph_ids.update(candidate.graph_ids)
        return tuple(selected)

    @staticmethod
    def _build_claim_index(views: Sequence[EvidenceGraphView]) -> dict[str, ClaimStatus]:
        claims: dict[str, ClaimStatus] = {}
        for view in views:
            for claim in view.graph.claims:
                current = claims.get(claim.claim_id)
                if current is not None and current != claim.status:
                    raise EvidenceEvaluationError(f"claim {claim.claim_id} has conflicting graph states")
                claims[claim.claim_id] = claim.status
        return claims

    @staticmethod
    def _build_nodes(views: Sequence[EvidenceGraphView]) -> dict[str, EvidenceNode]:
        nodes: dict[str, EvidenceNode] = {}
        graph_ids_by_evidence: dict[str, set[str]] = {}
        verified_claims_by_evidence: dict[str, set[str]] = {}
        subjects_by_evidence: dict[str, set[str]] = {}

        for view in views:
            claims = {claim.claim_id: claim for claim in view.graph.claims}
            for evidence in view.graph.evidence:
                existing = nodes.get(evidence.evidence_id)
                if existing is not None and existing.evidence != evidence:
                    raise EvidenceEvaluationError(
                        f"evidence {evidence.evidence_id} has conflicting content across graphs"
                    )
                graph_ids_by_evidence.setdefault(evidence.evidence_id, set()).add(view.graph_id)
                nodes.setdefault(
                    evidence.evidence_id,
                    EvidenceNode(
                        evidence=evidence.model_copy(deep=True),
                        graph_ids=frozenset(),
                        source_family=_source_family(evidence),
                        semantic_key=_semantic_evidence_key(evidence),
                        invocation_id=_metadata_string(evidence.metadata, "invocation_id"),
                        tool_family=_metadata_string(evidence.metadata, "tool_family", "tool_name"),
                        rule_family=_metadata_string(evidence.metadata, "rule_family", "rule_id"),
                        agent_session_id=_metadata_string(
                            evidence.metadata, "agent_session_id", "thread_id", "delegation_id"
                        ),
                        verified=False,
                        verified_claim_ids=frozenset(),
                        subject_refs=frozenset(),
                        evidence_types=_evidence_types(evidence),
                    ),
                )
            for link in view.graph.links:
                claim = claims.get(link.claim_id)
                if claim is None:
                    raise EvidenceGraphError(f"Evidence link references unknown claim {link.claim_id}")
                is_verified_support = (
                    claim.status == ClaimStatus.VERIFIED
                    and link.relation == EvidenceRelation.SUPPORTS
                    and link.verifier_status == ClaimStatus.VERIFIED
                    and view.graph.evidence_is_publishable(link.evidence_id)
                )
                if not is_verified_support:
                    continue
                verified_claims_by_evidence.setdefault(link.evidence_id, set()).add(claim.claim_id)
                subjects_by_evidence.setdefault(link.evidence_id, set()).add(claim.subject_ref)

        return {
            evidence_id: EvidenceNode(
                evidence=node.evidence,
                graph_ids=frozenset(graph_ids_by_evidence[evidence_id]),
                source_family=node.source_family,
                semantic_key=node.semantic_key,
                invocation_id=node.invocation_id,
                tool_family=node.tool_family,
                rule_family=node.rule_family,
                agent_session_id=node.agent_session_id,
                verified=bool(verified_claims_by_evidence.get(evidence_id)),
                verified_claim_ids=frozenset(verified_claims_by_evidence.get(evidence_id, set())),
                subject_refs=frozenset(subjects_by_evidence.get(evidence_id, set())),
                evidence_types=node.evidence_types,
            )
            for evidence_id, node in nodes.items()
        }


@dataclass(frozen=True)
class RequirementEvidenceRow:
    obligation_id: str
    disposition: RequirementDisposition
    referenced_evidence_ids: tuple[str, ...]
    unknown_evidence_ids: tuple[str, ...]
    verified_evidence_ids: tuple[str, ...]
    independent_evidence_ids: tuple[str, ...]
    required_independence: int
    observed_independence: int
    missing_evidence_types: tuple[str, ...]
    reasons: tuple[str, ...]
    verifier_receipt_id: str | None

    @property
    def satisfied(self) -> bool:
        return self.disposition in {RequirementDisposition.PROVEN, RequirementDisposition.WAIVED}


@dataclass(frozen=True)
class RequirementEvidenceMatrix:
    rows: tuple[RequirementEvidenceRow, ...]

    @property
    def satisfied_obligation_ids(self) -> tuple[str, ...]:
        return tuple(row.obligation_id for row in self.rows if row.satisfied)

    @property
    def unsatisfied_obligation_ids(self) -> tuple[str, ...]:
        return tuple(row.obligation_id for row in self.rows if not row.satisfied)

    @property
    def complete(self) -> bool:
        return bool(self.rows) and not self.unsatisfied_obligation_ids

    @classmethod
    def build(
        cls,
        obligations: Iterable[RequirementObligation],
        graph: InvestigationEvidenceGraph,
    ) -> RequirementEvidenceMatrix:
        selected = tuple(sorted(obligations, key=lambda item: item.obligation_id))
        identifiers = [item.obligation_id for item in selected]
        if len(identifiers) != len(set(identifiers)):
            raise EvidenceEvaluationError("duplicate requirement obligation id")
        return cls(rows=tuple(_evaluate_obligation(item, graph) for item in selected))


def _evaluate_obligation(
    obligation: RequirementObligation,
    graph: InvestigationEvidenceGraph,
) -> RequirementEvidenceRow:
    evidence_ids = tuple(sorted(set(obligation.satisfied_by_evidence_ids)))
    known_ids = tuple(item for item in evidence_ids if item in graph.evidence_ids)
    unknown_ids = tuple(item for item in evidence_ids if item not in graph.evidence_ids)
    verified_ids = tuple(item for item in known_ids if graph.node(item).verified)
    independent = graph.independent_evidence(verified_ids)
    actual_types = frozenset(kind for item in verified_ids for kind in graph.node(item).evidence_types)
    required_types = frozenset(item.strip().casefold() for item in obligation.required_evidence_types if item.strip())
    missing_types = tuple(sorted(required_types - actual_types))
    reasons: list[str] = []

    if obligation.status == ObligationStatus.WAIVED:
        if obligation.waiver_approval_id:
            disposition = RequirementDisposition.WAIVED
        else:
            disposition = RequirementDisposition.UNVERIFIED
            reasons.append("waived obligation has no authenticated approval")
    elif obligation.status == ObligationStatus.CONTRADICTED:
        disposition = RequirementDisposition.REFUTED
        reasons.append("authoritative obligation state is contradicted")
    elif not evidence_ids:
        disposition = RequirementDisposition.MISSING
        reasons.append("obligation has no evidence references")
    elif unknown_ids:
        disposition = RequirementDisposition.MISSING
        reasons.append(f"unknown evidence references: {', '.join(unknown_ids)}")
    elif not verified_ids:
        disposition = RequirementDisposition.UNVERIFIED
        reasons.append("referenced evidence has no verified supporting claim")
    elif missing_types:
        disposition = RequirementDisposition.INCOMPLETE
        reasons.append(f"missing evidence types: {', '.join(missing_types)}")
    elif len(independent) < obligation.minimum_independence_level:
        disposition = RequirementDisposition.INCOMPLETE
        reasons.append(
            f"independent evidence requirement is not met: {len(independent)}/{obligation.minimum_independence_level}"
        )
    elif not obligation.verifier_receipt_id:
        disposition = RequirementDisposition.UNVERIFIED
        reasons.append("obligation has no verifier receipt")
    elif obligation.status != ObligationStatus.SATISFIED:
        disposition = RequirementDisposition.INCOMPLETE
        reasons.append(f"authoritative obligation state is {obligation.status.value}")
    else:
        disposition = RequirementDisposition.PROVEN

    return RequirementEvidenceRow(
        obligation_id=obligation.obligation_id,
        disposition=disposition,
        referenced_evidence_ids=evidence_ids,
        unknown_evidence_ids=unknown_ids,
        verified_evidence_ids=verified_ids,
        independent_evidence_ids=tuple(item.evidence.evidence_id for item in independent),
        required_independence=obligation.minimum_independence_level,
        observed_independence=len(independent),
        missing_evidence_types=missing_types,
        reasons=tuple(reasons),
        verifier_receipt_id=obligation.verifier_receipt_id,
    )


@dataclass(frozen=True)
class EvidenceGap:
    gap_id: str
    kind: EvidenceGapKind
    target_type: str
    target_id: str
    reason: str
    evidence_ids: tuple[str, ...] = ()
    required_count: int | None = None
    observed_count: int | None = None
    requested_evidence_types: tuple[str, ...] = ()


def _gap(
    *,
    kind: EvidenceGapKind,
    target_type: str,
    target_id: str,
    reason: str,
    evidence_ids: Iterable[str] = (),
    required_count: int | None = None,
    observed_count: int | None = None,
    requested_evidence_types: Iterable[str] = (),
) -> EvidenceGap:
    normalized_evidence = tuple(sorted(set(evidence_ids)))
    normalized_types = tuple(sorted(set(requested_evidence_types)))
    digest = canonical_content_digest(
        {
            "kind": kind.value,
            "target_type": target_type,
            "target_id": target_id,
            "reason": reason,
            "evidence_ids": normalized_evidence,
            "required_count": required_count,
            "observed_count": observed_count,
            "requested_evidence_types": normalized_types,
        }
    )
    return EvidenceGap(
        gap_id=f"gap-{digest[:24]}",
        kind=kind,
        target_type=target_type,
        target_id=target_id,
        reason=reason,
        evidence_ids=normalized_evidence,
        required_count=required_count,
        observed_count=observed_count,
        requested_evidence_types=normalized_types,
    )


class EvidenceGapEngine:
    """Deterministically derive actionable gaps from obligations and high-risk findings."""

    def assess(
        self,
        matrix: RequirementEvidenceMatrix,
        graph: InvestigationEvidenceGraph,
        *,
        findings: Iterable[Finding] = (),
        hypotheses: Iterable[Hypothesis] = (),
    ) -> tuple[EvidenceGap, ...]:
        gaps = [gap for row in matrix.rows for gap in self._obligation_gaps(row)]
        hypotheses_by_subject: dict[str, list[Hypothesis]] = {}
        for hypothesis in hypotheses:
            hypotheses_by_subject.setdefault(hypothesis.subject_ref, []).append(hypothesis)
        for finding in sorted(findings, key=lambda item: item.finding_id):
            if finding.severity not in {"HIGH", "CRITICAL"}:
                continue
            gaps.extend(self._high_risk_gaps(finding, hypotheses_by_subject.get(finding.finding_id, []), graph))
        return tuple(sorted(gaps, key=lambda item: (item.kind.value, item.target_type, item.target_id, item.gap_id)))

    @staticmethod
    def _obligation_gaps(row: RequirementEvidenceRow) -> tuple[EvidenceGap, ...]:
        if row.satisfied:
            return ()
        gaps: list[EvidenceGap] = []
        reason = "; ".join(row.reasons) or f"requirement is {row.disposition.value}"
        if row.disposition == RequirementDisposition.REFUTED:
            gaps.append(
                _gap(
                    kind=EvidenceGapKind.CONTRADICTED_REQUIREMENT,
                    target_type="requirement",
                    target_id=row.obligation_id,
                    reason=reason,
                    evidence_ids=row.referenced_evidence_ids,
                )
            )
        elif not row.referenced_evidence_ids:
            gaps.append(
                _gap(
                    kind=EvidenceGapKind.MISSING_EVIDENCE,
                    target_type="requirement",
                    target_id=row.obligation_id,
                    reason=reason,
                )
            )
        elif row.unknown_evidence_ids:
            gaps.append(
                _gap(
                    kind=EvidenceGapKind.INVALID_EVIDENCE_REFERENCE,
                    target_type="requirement",
                    target_id=row.obligation_id,
                    reason=reason,
                    evidence_ids=row.unknown_evidence_ids,
                )
            )
        elif row.referenced_evidence_ids and not row.verified_evidence_ids:
            gaps.append(
                _gap(
                    kind=EvidenceGapKind.UNVERIFIED_EVIDENCE,
                    target_type="requirement",
                    target_id=row.obligation_id,
                    reason=reason,
                    evidence_ids=row.referenced_evidence_ids,
                )
            )
        if row.missing_evidence_types:
            gaps.append(
                _gap(
                    kind=EvidenceGapKind.MISSING_EVIDENCE_TYPE,
                    target_type="requirement",
                    target_id=row.obligation_id,
                    reason=reason,
                    evidence_ids=row.verified_evidence_ids,
                    requested_evidence_types=row.missing_evidence_types,
                )
            )
        if row.observed_independence < row.required_independence:
            gaps.append(
                _gap(
                    kind=EvidenceGapKind.NON_INDEPENDENT_EVIDENCE,
                    target_type="requirement",
                    target_id=row.obligation_id,
                    reason=reason,
                    evidence_ids=row.verified_evidence_ids,
                    required_count=row.required_independence,
                    observed_count=row.observed_independence,
                )
            )
        if row.verifier_receipt_id is None and row.verified_evidence_ids:
            gaps.append(
                _gap(
                    kind=EvidenceGapKind.MISSING_VERIFIER_RECEIPT,
                    target_type="requirement",
                    target_id=row.obligation_id,
                    reason=reason,
                    evidence_ids=row.verified_evidence_ids,
                )
            )
        if "waived obligation has no authenticated approval" in reason:
            gaps.append(
                _gap(
                    kind=EvidenceGapKind.INVALID_WAIVER,
                    target_type="requirement",
                    target_id=row.obligation_id,
                    reason=reason,
                )
            )
        if not gaps:
            gaps.append(
                _gap(
                    kind=EvidenceGapKind.INCOMPLETE_REQUIREMENT,
                    target_type="requirement",
                    target_id=row.obligation_id,
                    reason=reason,
                    evidence_ids=row.referenced_evidence_ids,
                )
            )
        return tuple(gaps)

    @staticmethod
    def _high_risk_gaps(
        finding: Finding,
        hypotheses: Sequence[Hypothesis],
        graph: InvestigationEvidenceGraph,
    ) -> tuple[EvidenceGap, ...]:
        verified_hypotheses = tuple(
            hypothesis for hypothesis in hypotheses if hypothesis.status == HypothesisStatus.VERIFIED
        )
        attack_path = _non_empty_string(finding.raw.get("attack_path_summary")) or _non_empty_string(
            finding.raw.get("attack_path")
        )
        attack_path = attack_path or next(
            (item.attack_path_summary for item in verified_hypotheses if item.attack_path_summary), None
        )
        raw_preconditions = finding.raw.get("preconditions")
        preconditions = (
            tuple(item for item in raw_preconditions if _non_empty_string(item))
            if isinstance(raw_preconditions, list)
            else ()
        )
        if not preconditions:
            preconditions = next((tuple(item.preconditions) for item in verified_hypotheses if item.preconditions), ())
        impact = _non_empty_string(finding.raw.get("expected_impact")) or _non_empty_string(finding.raw.get("impact"))
        impact = impact or next((item.expected_impact for item in verified_hypotheses if item.expected_impact), None)
        verified_ids = set(graph.verified_evidence_for_subject(finding.finding_id))
        verified_ids.update(
            evidence_id
            for hypothesis in verified_hypotheses
            for evidence_id in hypothesis.supporting_evidence_ids
            if evidence_id in graph.evidence_ids and graph.node(evidence_id).verified
        )
        independent = graph.independent_evidence(verified_ids)
        gaps: list[EvidenceGap] = []
        if not attack_path:
            gaps.append(
                _gap(
                    kind=EvidenceGapKind.HIGH_RISK_ATTACK_PATH,
                    target_type="finding",
                    target_id=finding.finding_id,
                    reason="high-risk finding has no verified attack path",
                    evidence_ids=verified_ids,
                )
            )
        if not preconditions:
            gaps.append(
                _gap(
                    kind=EvidenceGapKind.HIGH_RISK_PRECONDITIONS,
                    target_type="finding",
                    target_id=finding.finding_id,
                    reason="high-risk finding has no explicit preconditions",
                    evidence_ids=verified_ids,
                )
            )
        if not impact:
            gaps.append(
                _gap(
                    kind=EvidenceGapKind.HIGH_RISK_IMPACT,
                    target_type="finding",
                    target_id=finding.finding_id,
                    reason="high-risk finding has no explicit impact",
                    evidence_ids=verified_ids,
                )
            )
        if len(independent) < 2:
            gaps.append(
                _gap(
                    kind=EvidenceGapKind.HIGH_RISK_INDEPENDENT_VALIDATION,
                    target_type="finding",
                    target_id=finding.finding_id,
                    reason="high-risk finding requires a primary result and an independent validation",
                    evidence_ids=verified_ids,
                    required_count=2,
                    observed_count=len(independent),
                )
            )
        return tuple(gaps)


@dataclass(frozen=True)
class ReplanContext:
    plan_revision: int = 0
    max_plan_revisions: int = 2
    supplement_round: int = 0
    max_supplement_rounds: int = 2
    semantic_stagnation_rounds: int = 0
    stagnation_replans: int = 0
    budget_available: bool = True
    approved_independent_source_available: bool = True
    uncertain_side_effects: bool = False

    def __post_init__(self) -> None:
        for name in (
            "plan_revision",
            "max_plan_revisions",
            "supplement_round",
            "max_supplement_rounds",
            "semantic_stagnation_rounds",
            "stagnation_replans",
        ):
            if getattr(self, name) < 0:
                raise ValueError(f"{name} cannot be negative")
        if self.plan_revision > self.max_plan_revisions:
            raise ValueError("plan_revision exceeds max_plan_revisions")
        if self.max_plan_revisions > 2:
            raise ValueError("max_plan_revisions cannot exceed the platform limit of 2")
        if self.max_supplement_rounds > 2:
            raise ValueError("max_supplement_rounds cannot exceed the platform limit of 2")


@dataclass(frozen=True)
class ReplanDecision:
    outcome: CompletionOutcome
    trigger: ReplanTrigger | None
    gap_ids: tuple[str, ...]
    next_actions: tuple[str, ...]
    rationale: str


class BoundedReplanPolicy:
    """Select supplement/replan/partial without permitting open-ended loops."""

    def decide(self, gaps: Iterable[EvidenceGap], context: ReplanContext) -> ReplanDecision:
        selected = tuple(sorted(gaps, key=lambda item: item.gap_id))
        gap_ids = tuple(item.gap_id for item in selected)
        if not selected:
            return ReplanDecision(
                outcome=CompletionOutcome.CONTINUE,
                trigger=None,
                gap_ids=(),
                next_actions=(),
                rationale="no evidence gap requires replanning",
            )
        if context.uncertain_side_effects:
            return ReplanDecision(
                outcome=CompletionOutcome.RECOVERY_REQUIRED,
                trigger=None,
                gap_ids=gap_ids,
                next_actions=("reconcile uncertain side effects with an operator",),
                rationale="automatic supplement or replan is unsafe while side effects are uncertain",
            )
        if context.semantic_stagnation_rounds >= 3:
            if (
                context.budget_available
                and context.approved_independent_source_available
                and context.plan_revision < context.max_plan_revisions
                and context.stagnation_replans < 1
            ):
                return ReplanDecision(
                    outcome=CompletionOutcome.REPLAN,
                    trigger=ReplanTrigger.EVIDENCE_INSUFFICIENT,
                    gap_ids=gap_ids,
                    next_actions=("replace the exhausted evidence route with one approved independent source",),
                    rationale="semantic progress stalled for three coordination epochs; one bounded replan remains",
                )
            return ReplanDecision(
                outcome=CompletionOutcome.PARTIAL,
                trigger=None,
                gap_ids=gap_ids,
                next_actions=("emit a partial report with unresolved evidence gaps",),
                rationale="semantic progress stalled and no safe bounded replan remains",
            )
        contradiction = any(item.kind == EvidenceGapKind.CONTRADICTED_REQUIREMENT for item in selected)
        if contradiction:
            if context.budget_available and context.plan_revision < context.max_plan_revisions:
                return ReplanDecision(
                    outcome=CompletionOutcome.REPLAN,
                    trigger=ReplanTrigger.EVIDENCE_CONTRADICTION,
                    gap_ids=gap_ids,
                    next_actions=("revise the invalidated assumptions without expanding immutable scope",),
                    rationale="authoritative evidence contradicts a requirement and a bounded revision remains",
                )
            return ReplanDecision(
                outcome=CompletionOutcome.PARTIAL,
                trigger=None,
                gap_ids=gap_ids,
                next_actions=("report the contradiction and preserve both evidence branches",),
                rationale="contradiction cannot be resolved within the remaining revision budget",
            )
        if (
            context.budget_available
            and context.approved_independent_source_available
            and context.supplement_round < context.max_supplement_rounds
        ):
            return ReplanDecision(
                outcome=CompletionOutcome.SUPPLEMENT,
                trigger=ReplanTrigger.EVIDENCE_INSUFFICIENT,
                gap_ids=gap_ids,
                next_actions=("materialize deduplicated evidence requests for the unresolved obligations",),
                rationale="evidence is insufficient and a bounded independent supplement remains",
            )
        return ReplanDecision(
            outcome=CompletionOutcome.PARTIAL,
            trigger=None,
            gap_ids=gap_ids,
            next_actions=("emit a partial report without weakening required evidence",),
            rationale="supplement budget or an approved independent source is unavailable",
        )


@dataclass(frozen=True)
class CompletionEvaluation:
    snapshot: CompletionSnapshotV2
    outcome: CompletionOutcome
    matrix: RequirementEvidenceMatrix
    gaps: tuple[EvidenceGap, ...]
    replan_decision: ReplanDecision | None
    satisfied_obligation_ids: tuple[str, ...]
    unsatisfied_obligation_ids: tuple[str, ...]
    rationale: str


class DeterministicCompletionEvaluator:
    """Fail-closed completion gate over one immutable CompletionSnapshotV2."""

    def __init__(
        self,
        *,
        gap_engine: EvidenceGapEngine | None = None,
        replan_policy: BoundedReplanPolicy | None = None,
    ) -> None:
        self.gap_engine = gap_engine or EvidenceGapEngine()
        self.replan_policy = replan_policy or BoundedReplanPolicy()

    @staticmethod
    def build_snapshot(**values: Any) -> CompletionSnapshotV2:
        """Build a snapshot whose digest binds every non-volatile gate input."""

        draft = CompletionSnapshotV2(snapshot_digest="0" * 64, **values)
        return draft.model_copy(
            update={"snapshot_digest": canonical_content_digest(draft, exclude={"snapshot_digest"})}
        )

    def evaluate(
        self,
        snapshot: CompletionSnapshotV2,
        *,
        obligations: Iterable[RequirementObligation],
        evidence_graph: InvestigationEvidenceGraph,
        findings: Iterable[Finding] = (),
        hypotheses: Iterable[Hypothesis] = (),
        replan_context: ReplanContext | None = None,
    ) -> CompletionEvaluation:
        selected_obligations = tuple(obligations)
        matrix = RequirementEvidenceMatrix.build(selected_obligations, evidence_graph)
        gaps = self.gap_engine.assess(matrix, evidence_graph, findings=findings, hypotheses=hypotheses)
        obligation_ids = tuple(sorted(item.obligation_id for item in selected_obligations))
        expected_digest = canonical_content_digest(snapshot, exclude={"snapshot_digest"})

        def result(
            outcome: CompletionOutcome,
            rationale: str,
            *,
            decision: ReplanDecision | None = None,
        ) -> CompletionEvaluation:
            return CompletionEvaluation(
                snapshot=snapshot,
                outcome=outcome,
                matrix=matrix,
                gaps=gaps,
                replan_decision=decision,
                satisfied_obligation_ids=matrix.satisfied_obligation_ids,
                unsatisfied_obligation_ids=matrix.unsatisfied_obligation_ids,
                rationale=rationale,
            )

        if snapshot.cancel_intent:
            return result(CompletionOutcome.CANCELLED, "the immutable snapshot contains a cancel intent")
        if snapshot.pending_approvals:
            return result(CompletionOutcome.AWAITING_APPROVAL, "required approvals are unresolved")
        if snapshot.pending_clarifications:
            return result(CompletionOutcome.AWAITING_USER_DECISION, "required user decisions are unresolved")
        if snapshot.snapshot_digest != expected_digest:
            return result(CompletionOutcome.RECOVERY_REQUIRED, "completion snapshot digest does not match its content")
        if any(
            not integrity
            for integrity in (
                snapshot.input_integrity,
                snapshot.artifact_integrity,
                snapshot.evidence_integrity,
                snapshot.ledger_integrity,
            )
        ):
            return result(CompletionOutcome.RECOVERY_REQUIRED, "one or more integrity gates failed")
        if any(item.run_id != snapshot.run_id for item in selected_obligations):
            return result(CompletionOutcome.RECOVERY_REQUIRED, "snapshot includes obligations from another run")
        if len(snapshot.requirement_obligations) != len(set(snapshot.requirement_obligations)):
            return result(CompletionOutcome.RECOVERY_REQUIRED, "snapshot contains duplicate obligation ids")
        if tuple(sorted(snapshot.requirement_obligations)) != obligation_ids:
            return result(CompletionOutcome.RECOVERY_REQUIRED, "snapshot obligation set is incomplete or stale")
        invalid_report_claims = tuple(
            claim_id for claim_id in snapshot.report_claim_ids if not evidence_graph.verified_claim(claim_id)
        )
        if invalid_report_claims:
            return result(
                CompletionOutcome.RECOVERY_REQUIRED,
                f"report references unverified claims: {', '.join(sorted(invalid_report_claims))}",
            )
        if snapshot.pending_replan:
            context = replan_context or ReplanContext()
            if not context.budget_available or context.plan_revision >= context.max_plan_revisions:
                return result(CompletionOutcome.PARTIAL, "pending replan exceeds the bounded revision budget")
            return result(CompletionOutcome.REPLAN, "a validated plan revision is pending application")
        if snapshot.open_evidence_requests:
            return result(CompletionOutcome.CONTINUE, "authoritative evidence requests remain open")
        active_work = any(
            (
                snapshot.active_sessions,
                snapshot.active_step_leases,
                snapshot.active_invocations,
                snapshot.unsettled_reservations,
                snapshot.unprojected_outbox_ordinals,
            )
        )
        if active_work:
            return result(CompletionOutcome.CONTINUE, "the completion snapshot is not quiescent")
        failed_grades = tuple(
            key
            for key, value in sorted(snapshot.outcome_grades.items())
            if value.strip().casefold() not in _PASSING_GRADES
        )
        if failed_grades:
            return result(
                CompletionOutcome.PARTIAL,
                f"outcome grades are not satisfied: {', '.join(failed_grades)}",
            )
        if gaps:
            decision = self.replan_policy.decide(gaps, replan_context or ReplanContext())
            return result(decision.outcome, decision.rationale, decision=decision)
        if snapshot.unscanned_scope or snapshot.limitations:
            return result(CompletionOutcome.PARTIAL, "declared unscanned scope or limitations prevent completeness")
        if not matrix.complete:
            return result(CompletionOutcome.PARTIAL, "not every requirement obligation is proven or waived")
        return result(CompletionOutcome.COMPLETE, "snapshot is quiet and every requirement is independently proven")


__all__ = [
    "BoundedReplanPolicy",
    "CompletionEvaluation",
    "DeterministicCompletionEvaluator",
    "EvidenceEvaluationError",
    "EvidenceGap",
    "EvidenceGapEngine",
    "EvidenceGapKind",
    "EvidenceGraphView",
    "EvidenceNode",
    "InvestigationEvidenceGraph",
    "ReplanContext",
    "ReplanDecision",
    "RequirementDisposition",
    "RequirementEvidenceMatrix",
    "RequirementEvidenceRow",
]
