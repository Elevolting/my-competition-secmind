from __future__ import annotations

from collections.abc import Iterable

import pytest

from secmind.evidence_graph import EvidenceGraph, make_claim, make_link
from secmind.investigation.contracts import (
    CompletionOutcome,
    Hypothesis,
    HypothesisStatus,
    ObligationStatus,
    RequirementObligation,
)
from secmind.investigation.evidence import (
    BoundedReplanPolicy,
    DeterministicCompletionEvaluator,
    EvidenceGapEngine,
    EvidenceGapKind,
    EvidenceGraphView,
    InvestigationEvidenceGraph,
    ReplanContext,
    RequirementDisposition,
    RequirementEvidenceMatrix,
)
from secmind.schemas import ClaimStatus, Evidence, Finding, VerificationResult

DIGEST = "a" * 64


def verified_graph(
    graph_id: str,
    evidence_id: str,
    *,
    source: str,
    subject_ref: str = "finding-1",
    semantic_key: str | None = None,
) -> EvidenceGraphView:
    evidence = Evidence(
        evidence_id=evidence_id,
        source=source,
        summary=f"verified evidence {evidence_id}",
        sha256=DIGEST,
        metadata={
            "evidence_type": "location",
            "semantic_evidence_key": semantic_key or f"semantic-{evidence_id}",
            "invocation_id": f"invocation-{evidence_id}",
            "tool_family": source,
        },
    )
    claim = make_claim(
        claim_type="vulnerability",
        statement=f"verified claim {evidence_id}",
        subject_ref=subject_ref,
        producer=f"producer-{evidence_id}",
        severity="HIGH",
        confidence=1,
    )
    graph = EvidenceGraph(
        claims=[claim],
        evidence=[evidence],
        links=[make_link(claim_id=claim.claim_id, evidence_id=evidence_id)],
    )
    graph.apply_verification(
        VerificationResult(
            claim_id=claim.claim_id,
            status=ClaimStatus.VERIFIED,
            reason_summary="integrity checked",
            verified_evidence_ids=[evidence_id],
            confidence=1,
        )
    )
    return EvidenceGraphView(graph_id=graph_id, graph=graph)


def obligation(
    evidence_ids: Iterable[str],
    *,
    obligation_id: str = "requirement-1",
    run_id: str = "run-1",
    independence: int = 2,
    status: ObligationStatus = ObligationStatus.SATISFIED,
    verifier_receipt_id: str | None = "verification-1",
) -> RequirementObligation:
    return RequirementObligation(
        obligation_id=obligation_id,
        run_id=run_id,
        source_type="task_spec",
        source_ref="task-spec-1",
        requirement_summary="Prove the security result",
        immutable_scope=["src/"],
        satisfaction_rule_id="verified-independent-evidence",
        required_evidence_types=["location"],
        minimum_independence_level=independence,
        status=status,
        satisfied_by_evidence_ids=list(evidence_ids),
        verifier_receipt_id=verifier_receipt_id,
        content_digest=DIGEST,
    )


def test_independence_rejects_same_source_same_graph_and_semantic_duplicates() -> None:
    first = verified_graph("graph-a", "evidence-1", source="bandit:1")
    same_graph = verified_graph("graph-a-part", "evidence-2", source="semgrep")
    same_source = verified_graph("graph-b", "evidence-3", source="bandit:2")
    independent = verified_graph("graph-c", "evidence-4", source="gitleaks")
    semantic_duplicate = verified_graph(
        "graph-d",
        "evidence-5",
        source="osv",
        semantic_key="semantic-evidence-4",
    )
    # Model two evidence items originating in one EvidenceGraph lineage.
    same_graph = EvidenceGraphView(graph_id="graph-a", graph=same_graph.graph)
    graph = InvestigationEvidenceGraph([first, same_graph, same_source, independent, semantic_duplicate])

    selected = graph.independent_evidence(["evidence-1", "evidence-2", "evidence-3", "evidence-4", "evidence-5"])
    assert [item.evidence.evidence_id for item in selected] == ["evidence-1", "evidence-4"]


def test_requirement_matrix_is_fail_closed_for_independence_and_receipts() -> None:
    graph = InvestigationEvidenceGraph(
        [
            verified_graph("graph-a", "evidence-1", source="bandit"),
            verified_graph("graph-a", "evidence-2", source="semgrep"),
        ]
    )
    matrix = RequirementEvidenceMatrix.build(
        [obligation(["evidence-1", "evidence-2"])],
        graph,
    )
    row = matrix.rows[0]
    assert row.disposition == RequirementDisposition.INCOMPLETE
    assert row.observed_independence == 1
    assert not matrix.complete
    assert EvidenceGapKind.NON_INDEPENDENT_EVIDENCE in {gap.kind for gap in EvidenceGapEngine().assess(matrix, graph)}

    no_receipt = RequirementEvidenceMatrix.build(
        [obligation(["evidence-1"], independence=1, verifier_receipt_id=None)],
        graph,
    )
    assert no_receipt.rows[0].disposition == RequirementDisposition.UNVERIFIED
    assert EvidenceGapKind.MISSING_VERIFIER_RECEIPT in {
        gap.kind for gap in EvidenceGapEngine().assess(no_receipt, graph)
    }

    unknown = RequirementEvidenceMatrix.build(
        [obligation(["evidence-1", "invented-evidence"], independence=1)],
        graph,
    )
    assert EvidenceGapKind.INVALID_EVIDENCE_REFERENCE in {
        gap.kind for gap in EvidenceGapEngine().assess(unknown, graph)
    }


def test_high_risk_finding_requires_attack_path_preconditions_impact_and_independent_validation() -> None:
    graph = InvestigationEvidenceGraph([verified_graph("graph-a", "evidence-1", source="bandit")])
    matrix = RequirementEvidenceMatrix.build(
        [obligation(["evidence-1"], independence=1)],
        graph,
    )
    finding = Finding(
        finding_id="finding-1",
        rule_id="CMD-1",
        severity="HIGH",
        path="src/app.py",
        line=10,
        title="Command injection",
        description="Untrusted data reaches a shell.",
        evidence_ids=["evidence-1"],
    )
    kinds = {gap.kind for gap in EvidenceGapEngine().assess(matrix, graph, findings=[finding])}
    assert kinds == {
        EvidenceGapKind.HIGH_RISK_ATTACK_PATH,
        EvidenceGapKind.HIGH_RISK_PRECONDITIONS,
        EvidenceGapKind.HIGH_RISK_IMPACT,
        EvidenceGapKind.HIGH_RISK_INDEPENDENT_VALIDATION,
    }


def test_verified_hypothesis_and_two_independent_graphs_satisfy_high_risk_policy() -> None:
    graph = InvestigationEvidenceGraph(
        [
            verified_graph("graph-a", "evidence-1", source="bandit"),
            verified_graph("graph-b", "evidence-2", source="semgrep"),
        ]
    )
    matrix = RequirementEvidenceMatrix.build(
        [obligation(["evidence-1", "evidence-2"])],
        graph,
    )
    finding = Finding(
        finding_id="finding-1",
        rule_id="CMD-1",
        severity="CRITICAL",
        path="src/app.py",
        line=10,
        title="Command injection",
        description="Untrusted data reaches a shell.",
        evidence_ids=["evidence-1", "evidence-2"],
    )
    hypothesis = Hypothesis(
        run_id="run-1",
        subject_ref="finding-1",
        statement="The shell invocation is reachable from an HTTP parameter.",
        attack_path_summary="request parameter -> command builder -> shell",
        preconditions=["attacker controls the request parameter"],
        expected_impact="arbitrary command execution in the sandboxed service account",
        confidence=0.95,
        supporting_evidence_ids=["evidence-1", "evidence-2"],
        status=HypothesisStatus.VERIFIED,
        producer="correlator",
        fingerprint=DIGEST,
        content_digest=DIGEST,
    )
    assert not EvidenceGapEngine().assess(
        matrix,
        graph,
        findings=[finding],
        hypotheses=[hypothesis],
    )


def test_bounded_replan_policy_supplements_replans_once_and_then_converges() -> None:
    graph = InvestigationEvidenceGraph([verified_graph("graph-a", "evidence-1", source="bandit")])
    missing = RequirementEvidenceMatrix.build(
        [obligation([], independence=1, status=ObligationStatus.OPEN, verifier_receipt_id=None)],
        graph,
    )
    gaps = EvidenceGapEngine().assess(missing, graph)
    policy = BoundedReplanPolicy()
    assert policy.decide(gaps, ReplanContext()).outcome == CompletionOutcome.SUPPLEMENT
    assert (
        policy.decide(gaps, ReplanContext(semantic_stagnation_rounds=3, stagnation_replans=0)).outcome
        == CompletionOutcome.REPLAN
    )
    assert (
        policy.decide(gaps, ReplanContext(semantic_stagnation_rounds=3, stagnation_replans=1)).outcome
        == CompletionOutcome.PARTIAL
    )
    assert (
        policy.decide(gaps, ReplanContext(uncertain_side_effects=True)).outcome == CompletionOutcome.RECOVERY_REQUIRED
    )
    with pytest.raises(ValueError, match="platform limit"):
        ReplanContext(max_plan_revisions=3)


def test_completion_evaluator_completes_only_a_quiet_integrity_checked_snapshot() -> None:
    first = verified_graph("graph-a", "evidence-1", source="bandit")
    second = verified_graph("graph-b", "evidence-2", source="semgrep")
    graph = InvestigationEvidenceGraph([first, second])
    requirement = obligation(["evidence-1", "evidence-2"])
    claim_ids = [first.graph.claims[0].claim_id]
    evaluator = DeterministicCompletionEvaluator()
    snapshot = evaluator.build_snapshot(
        run_id="run-1",
        run_state_version=9,
        run_fence=3,
        quiet_epoch=2,
        input_integrity=True,
        artifact_integrity=True,
        evidence_integrity=True,
        ledger_integrity=True,
        requirement_obligations=[requirement.obligation_id],
        outcome_grades={"contract-1": "passed"},
        report_claim_ids=claim_ids,
    )
    result = evaluator.evaluate(snapshot, obligations=[requirement], evidence_graph=graph)
    assert result.outcome == CompletionOutcome.COMPLETE
    assert result.satisfied_obligation_ids == (requirement.obligation_id,)

    active = evaluator.build_snapshot(
        **{
            **snapshot.model_dump(exclude={"snapshot_id", "snapshot_digest", "created_at"}),
            "active_invocations": ["invocation-1"],
        }
    )
    assert (
        evaluator.evaluate(active, obligations=[requirement], evidence_graph=graph).outcome
        == CompletionOutcome.CONTINUE
    )

    tampered = snapshot.model_copy(update={"ledger_integrity": False})
    assert (
        evaluator.evaluate(tampered, obligations=[requirement], evidence_graph=graph).outcome
        == CompletionOutcome.RECOVERY_REQUIRED
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("active_sessions", ["thread-1"]),
        ("active_step_leases", ["step-run-1"]),
        ("active_invocations", ["invocation-1"]),
        ("unsettled_reservations", ["reservation-1"]),
        ("unprojected_outbox_ordinals", [17]),
    ],
)
def test_completion_evaluator_never_completes_with_durable_work_in_flight(field: str, value: list) -> None:
    first = verified_graph("graph-a", "evidence-1", source="bandit")
    second = verified_graph("graph-b", "evidence-2", source="semgrep")
    graph = InvestigationEvidenceGraph([first, second])
    requirement = obligation(["evidence-1", "evidence-2"])
    evaluator = DeterministicCompletionEvaluator()
    snapshot = evaluator.build_snapshot(
        run_id="run-1",
        run_state_version=9,
        run_fence=3,
        quiet_epoch=2,
        input_integrity=True,
        artifact_integrity=True,
        evidence_integrity=True,
        ledger_integrity=True,
        requirement_obligations=[requirement.obligation_id],
        outcome_grades={"contract-1": "passed"},
        report_claim_ids=[first.graph.claims[0].claim_id],
        **{field: value},
    )

    result = evaluator.evaluate(snapshot, obligations=[requirement], evidence_graph=graph)

    assert result.outcome == CompletionOutcome.CONTINUE
    assert result.rationale == "the completion snapshot is not quiescent"


@pytest.mark.parametrize(
    "failed_integrity",
    ["input_integrity", "artifact_integrity", "evidence_integrity", "ledger_integrity"],
)
def test_completion_evaluator_rejects_a_validly_sealed_integrity_failure(failed_integrity: str) -> None:
    first = verified_graph("graph-a", "evidence-1", source="bandit")
    second = verified_graph("graph-b", "evidence-2", source="semgrep")
    graph = InvestigationEvidenceGraph([first, second])
    requirement = obligation(["evidence-1", "evidence-2"])
    evaluator = DeterministicCompletionEvaluator()
    integrity = {
        "input_integrity": True,
        "artifact_integrity": True,
        "evidence_integrity": True,
        "ledger_integrity": True,
    }
    integrity[failed_integrity] = False
    snapshot = evaluator.build_snapshot(
        run_id="run-1",
        run_state_version=9,
        run_fence=3,
        quiet_epoch=2,
        requirement_obligations=[requirement.obligation_id],
        outcome_grades={"contract-1": "passed"},
        report_claim_ids=[first.graph.claims[0].claim_id],
        **integrity,
    )

    result = evaluator.evaluate(snapshot, obligations=[requirement], evidence_graph=graph)

    assert result.outcome == CompletionOutcome.RECOVERY_REQUIRED
    assert result.rationale == "one or more integrity gates failed"


def test_completion_evaluator_prioritizes_wait_states_and_high_risk_gaps() -> None:
    graph = InvestigationEvidenceGraph([verified_graph("graph-a", "evidence-1", source="bandit")])
    requirement = obligation(["evidence-1"], independence=1)
    evaluator = DeterministicCompletionEvaluator()
    pending = evaluator.build_snapshot(
        run_id="run-1",
        run_state_version=1,
        run_fence=1,
        quiet_epoch=1,
        pending_approvals=["approval-1"],
        input_integrity=True,
        artifact_integrity=True,
        evidence_integrity=True,
        ledger_integrity=True,
        requirement_obligations=[requirement.obligation_id],
    )
    assert (
        evaluator.evaluate(pending, obligations=[requirement], evidence_graph=graph).outcome
        == CompletionOutcome.AWAITING_APPROVAL
    )

    quiet = evaluator.build_snapshot(
        **{
            **pending.model_dump(exclude={"snapshot_id", "snapshot_digest", "created_at"}),
            "pending_approvals": [],
        }
    )
    finding = Finding(
        finding_id="finding-1",
        rule_id="CMD-1",
        severity="HIGH",
        path="src/app.py",
        title="Command injection",
        description="Untrusted data reaches a shell.",
        evidence_ids=["evidence-1"],
    )
    result = evaluator.evaluate(
        quiet,
        obligations=[requirement],
        evidence_graph=graph,
        findings=[finding],
    )
    assert result.outcome == CompletionOutcome.SUPPLEMENT
    assert EvidenceGapKind.HIGH_RISK_INDEPENDENT_VALIDATION in {gap.kind for gap in result.gaps}
