from __future__ import annotations

from conftest import seal_execution_contract

from secmind.completion_gate import CompletionGate, CompletionSnapshot
from secmind.evidence_graph import EvidenceGraph, make_claim, make_link
from secmind.investigation.contracts import CompletionOutcome, ObligationStatus
from secmind.investigation.evidence import DeterministicCompletionEvaluator
from secmind.investigation.supplement import EvidenceGapSupplementPlanner
from secmind.orchestration.evidence_projection import seal_canonical_primary_policy
from secmind.orchestration.obligation_runtime import (
    critical_investigation_requirements,
    refresh_obligation_set,
)
from secmind.orchestrator import SecMindOrchestrator
from secmind.outcomes import OutcomeContractCompiler
from secmind.schemas import (
    AgentState,
    AuditUnitResult,
    ClaimStatus,
    Evidence,
    Finding,
    PlanStep,
    RunStatus,
    Scenario,
    TaskRequest,
)
from secmind.verifier import RepositoryFile, SkepticalVerifier, VerificationContext


def test_complete_direct_first_units_need_no_tool_plan_or_supplement() -> None:
    run_id = "run-v07-fast-path"
    positive_source = "1" * 64
    negative_source = "2" * 64
    positive_evidence = Evidence(
        evidence_id="audit-positive",
        source="secmind:v0.7-direct-first",
        summary="vulnerable decision for Positive.java at line 7",
        artifact_ref="artifact-positive",
        sha256="a" * 64,
        metadata={
            "evidence_type": "audit_unit_decision",
            "step_id": "model-source-review",
            "path": "src/Positive.java",
            "file_sha256": positive_source,
            "line": 7,
            "assurance_level": "semantically_corroborated",
        },
    )
    negative_evidence = Evidence(
        evidence_id="audit-negative",
        source="secmind:v0.7-direct-first",
        summary="not_vulnerable decision for Negative.java",
        artifact_ref="artifact-negative",
        sha256="b" * 64,
        metadata={
            "evidence_type": "audit_unit_decision",
            "step_id": "model-source-review",
            "path": "src/Negative.java",
            "file_sha256": negative_source,
        },
    )
    finding = Finding(
        finding_id="finding-positive",
        rule_id="CWE-89",
        severity="MEDIUM",
        confidence="HIGH",
        path="src/Positive.java",
        line=7,
        title="Direct-first SQL injection",
        description="A bounded Direct review identified the source-to-sink path.",
        evidence_ids=[positive_evidence.evidence_id],
        raw={"model_id": "mock-5.4"},
    )
    claims = [
        make_claim(
            claim_type="model_source_review.coverage",
            statement="Positive.java has an explicit vulnerable verdict.",
            subject_ref="audit-unit:positive",
            producer="model-source-review",
            confidence=0.93,
        ),
        make_claim(
            claim_type="model_source_review.coverage",
            statement="Negative.java has an explicit not_vulnerable verdict.",
            subject_ref="audit-unit:negative",
            producer="model-source-review",
            confidence=0.91,
        ),
        make_claim(
            claim_type="model_source_review.finding",
            statement="Direct-first SQL injection is present.",
            subject_ref=finding.finding_id,
            producer="model-source-review",
            severity="MEDIUM",
            confidence=0.93,
        ),
    ]
    links = [
        make_link(
            claim_id=claims[0].claim_id,
            evidence_id=positive_evidence.evidence_id,
        ),
        make_link(
            claim_id=claims[1].claim_id,
            evidence_id=negative_evidence.evidence_id,
        ),
        make_link(
            claim_id=claims[2].claim_id,
            evidence_id=positive_evidence.evidence_id,
        ),
    ]
    contract = OutcomeContractCompiler().compile(
        PlanStep(
            step_id="model-source-review",
            objective="Produce one immutable Direct verdict for each Java audit unit.",
            agent_role="sast_specialist",
            capability="model_source_review",
            tool_candidates=[],
            success_criteria=["Every Java unit has an explicit bounded verdict."],
            estimated_tool_calls=0,
        ),
        expected_claim_types=[
            "model_source_review.coverage",
            "model_source_review.finding",
        ],
        required_evidence_types=["audit_unit_decision"],
        grader_ids=["claim-confidence", "evidence-integrity", "evidence-types"],
        confidence_threshold=0.0,
        allow_partial=True,
    )
    verifier = SkepticalVerifier()
    batch = verifier.verify(
        EvidenceGraph(
            claims=claims,
            evidence=[positive_evidence, negative_evidence],
            links=links,
        ),
        (contract,),
        VerificationContext(
            repository_files={
                "src/Positive.java": RepositoryFile(path="src/Positive.java", sha256=positive_source, line_count=20),
                "src/Negative.java": RepositoryFile(path="src/Negative.java", sha256=negative_source, line_count=20),
            },
            findings=(finding,),
            artifact_hashes={
                positive_evidence.artifact_ref: positive_evidence.sha256,
                negative_evidence.artifact_ref: negative_evidence.sha256,
            },
        ),
    )
    assert all(result.status == ClaimStatus.VERIFIED for result in batch.results)

    state = seal_execution_contract(
        AgentState(
            run_id=run_id,
            task=TaskRequest(objective="Audit the Java fixtures."),
            scenario=Scenario.CODE_AUDIT,
            status=RunStatus.RUNNING,
            # The Direct-first node is deliberately outside the optional tool DAG.
            plan=[],
            outcome_contracts=[contract],
            claims=list(batch.graph.claims),
            evidence=[positive_evidence, negative_evidence],
            evidence_links=list(batch.graph.links),
            verification_results=list(batch.results),
            contract_grades={
                contract_id: [
                    {
                        "grader_id": grade.grader_id,
                        "status": grade.status.value,
                        "reason": grade.reason,
                        "requested_evidence_types": list(grade.requested_evidence_types),
                    }
                    for grade in grades
                ]
                for contract_id, grades in batch.contract_grade_results.items()
            },
            findings=[finding],
            audit_kernel="v0.7-authoritative",
            audit_units=[
                AuditUnitResult(
                    unit_id="unit-" + "1" * 64,
                    path="src/Positive.java",
                    source_sha256=positive_source,
                    baseline_verdict="vulnerable",
                    final_verdict="vulnerable",
                    action="keep_baseline",
                    cwe=89,
                    sink_line=7,
                    confidence=0.93,
                    primary_receipt_id="primary-positive",
                    decision_digest="c" * 64,
                    evidence_ids=[positive_evidence.evidence_id],
                ),
                AuditUnitResult(
                    unit_id="unit-" + "2" * 64,
                    path="src/Negative.java",
                    source_sha256=negative_source,
                    baseline_verdict="not_vulnerable",
                    final_verdict="not_vulnerable",
                    action="keep_baseline",
                    confidence=0.91,
                    primary_receipt_id="primary-negative",
                    decision_digest="d" * 64,
                    evidence_ids=[negative_evidence.evidence_id],
                ),
            ],
            audit_coverage={
                "total_units": 2,
                "covered_units": 2,
                "positive_units": 1,
                "negative_units": 1,
                "inconclusive_units": 0,
                "coverage": 1.0,
            },
        )
    )
    seal_canonical_primary_policy(state, network_enabled=False)
    refresh_obligation_set(
        state,
        {
            "findings": [finding.model_dump(mode="json")],
            "checked_paths": ["src/Positive.java", "src/Negative.java"],
            "negative_evidence": ["src/Negative.java received an explicit not_vulnerable verdict"],
        },
        evidence_ids=[positive_evidence.evidence_id, negative_evidence.evidence_id],
    )
    evidence_graph = SecMindOrchestrator._investigation_evidence_graph(state, batch.graph)
    orchestrator = object.__new__(SecMindOrchestrator)
    obligations = orchestrator._requirement_obligations(state, evidence_graph)

    outcome_obligation = next(item for item in obligations if item.source_ref == contract.contract_id)
    assert outcome_obligation.required_evidence_types == ["audit_unit_decision"]
    assert outcome_obligation.status == ObligationStatus.SATISFIED
    assert set(outcome_obligation.satisfied_by_evidence_ids) == {
        positive_evidence.evidence_id,
        negative_evidence.evidence_id,
    }
    critical_obligations = critical_investigation_requirements(state, obligations)
    assert len(critical_obligations) == 1
    assert critical_obligations[0].source_type == "task_obligation_set_receipt"
    assert critical_obligations[0].status == ObligationStatus.SATISFIED

    compatibility_result = CompletionGate().evaluate(
        CompletionSnapshot(
            graph=batch.graph,
            findings=(finding,),
            contracts=(contract,),
            contract_grades=batch.contract_grade_results,
        )
    )
    assert compatibility_result.status == RunStatus.COMPLETED

    evaluator = DeterministicCompletionEvaluator()
    snapshot = evaluator.build_snapshot(
        snapshot_id="snapshot-v07-fast-path",
        run_id=run_id,
        run_state_version=1,
        run_fence=1,
        quiet_epoch=1,
        input_integrity=True,
        artifact_integrity=True,
        evidence_integrity=True,
        ledger_integrity=True,
        requirement_obligations=[item.obligation_id for item in critical_obligations],
        outcome_grades={},
        report_claim_ids=[claim.claim_id for claim in batch.graph.claims],
    )
    evaluation = evaluator.evaluate(
        snapshot,
        obligations=critical_obligations,
        evidence_graph=evidence_graph,
        # Orchestrator excludes verified Direct-first findings here because the
        # immutable unit contract is their governing completion obligation.
        findings=[],
    )
    assert evaluation.outcome == CompletionOutcome.COMPLETE
    assert evaluation.gaps == ()
    assert (
        EvidenceGapSupplementPlanner().propose(
            evaluation.gaps,
            claims=state.claims,
            plan=state.plan,
            manifests=(),
            scenario=state.scenario,
            supplement_round=state.verification_rounds,
        )
        == ()
    )
