from __future__ import annotations

from secmind.completion_gate import CompletionGate, CompletionSnapshot
from secmind.evidence_graph import EvidenceGraph, make_claim, make_link
from secmind.outcomes import GradeResult, GradeStatus, OutcomeContractCompiler
from secmind.schemas import (
    ClaimStatus,
    Evidence,
    Finding,
    InvocationStatus,
    PlanStep,
    RunStatus,
    StepStatus,
    VerificationResult,
)


def completed_fixture(*, allow_partial: bool = True):
    step = PlanStep(
        step_id="scan",
        objective="Audit code",
        agent_role="sast_specialist",
        capability="sast",
        tool_candidates=["scanner"],
        success_criteria=["All indexed code files are covered by verified findings"],
    )
    contract = OutcomeContractCompiler().compile(
        step,
        expected_claim_types=["vulnerability"],
        grader_ids=["evidence-integrity"],
        allow_partial=allow_partial,
    )
    finding = Finding(
        finding_id="finding-1",
        rule_id="RULE-1",
        path="src/app.py",
        line=1,
        title="Issue",
        description="Issue description",
        evidence_ids=["evidence-1"],
    )
    evidence = Evidence(evidence_id="evidence-1", source="scanner:1", summary="proof")
    claim = make_claim(
        claim_type="vulnerability",
        statement="Issue is reachable",
        subject_ref=finding.finding_id,
        producer="scan",
        confidence=1,
    )
    graph = EvidenceGraph(
        claims=[claim],
        evidence=[evidence],
        links=[make_link(claim_id=claim.claim_id, evidence_id=evidence.evidence_id)],
    )
    graph.apply_verification(
        VerificationResult(
            claim_id=claim.claim_id,
            status=ClaimStatus.VERIFIED,
            reason_summary="verified",
            verified_evidence_ids=[evidence.evidence_id],
            confidence=1,
        )
    )
    grades = {contract.contract_id: (GradeResult("evidence-integrity", GradeStatus.PASSED, "passed"),)}
    return contract, finding, claim, graph, grades


def test_completion_gate_completes_only_verified_contracts() -> None:
    contract, finding, claim, graph, grades = completed_fixture()
    result = CompletionGate().evaluate(
        CompletionSnapshot(
            graph=graph,
            findings=(finding,),
            contracts=(contract,),
            contract_grades=grades,
            step_statuses={"scan": StepStatus.SUCCEEDED},
            report_claim_ids=(claim.claim_id,),
        )
    )
    assert result.status == RunStatus.COMPLETED
    assert result.projection.claim_ids == (claim.claim_id,)
    assert [item.finding_id for item in result.projection.findings] == [finding.finding_id]


def test_clean_project_completes_with_verified_negative_coverage_claim() -> None:
    step = PlanStep(
        step_id="scan",
        objective="Audit code",
        agent_role="sast_specialist",
        capability="sast",
        tool_candidates=["scanner"],
        success_criteria=["All indexed source files were scanned and no findings were emitted"],
    )
    contract = OutcomeContractCompiler().compile(
        step,
        expected_claim_types=["coverage"],
        grader_ids=["coverage"],
    )
    evidence = Evidence(evidence_id="coverage-evidence", source="scanner:1", summary="all files scanned")
    claim = make_claim(
        claim_type="coverage",
        statement="All indexed source files were scanned without findings",
        subject_ref="repository-index",
        producer="scan",
        confidence=1,
    )
    graph = EvidenceGraph(
        claims=[claim],
        evidence=[evidence],
        links=[make_link(claim_id=claim.claim_id, evidence_id=evidence.evidence_id)],
    )
    graph.apply_verification(
        VerificationResult(
            claim_id=claim.claim_id,
            status=ClaimStatus.VERIFIED,
            reason_summary="coverage verified",
            verified_evidence_ids=[evidence.evidence_id],
            confidence=1,
        )
    )
    result = CompletionGate().evaluate(
        CompletionSnapshot(
            graph=graph,
            findings=(),
            contracts=(contract,),
            contract_grades={contract.contract_id: (GradeResult("coverage", GradeStatus.PASSED, "passed"),)},
            step_statuses={"scan": StepStatus.SUCCEEDED},
        )
    )
    assert result.status == RunStatus.COMPLETED
    assert not result.projection.findings


def test_successful_tool_with_unsatisfied_coverage_is_partial() -> None:
    contract, finding, _, graph, _ = completed_fixture()
    failed_grades = {contract.contract_id: (GradeResult("coverage", GradeStatus.FAILED, "coverage missing"),)}
    result = CompletionGate().evaluate(
        CompletionSnapshot(
            graph=graph,
            findings=(finding,),
            contracts=(contract,),
            contract_grades=failed_grades,
            step_statuses={"scan": StepStatus.SUCCEEDED},
            unscanned_scope=("generated/",),
        )
    )
    assert result.status == RunStatus.PARTIAL
    assert result.unsatisfied_contract_ids == (contract.contract_id,)


def test_unverified_report_claim_and_hash_failure_are_hard_failures() -> None:
    contract, finding, _, graph, grades = completed_fixture()
    unverified = CompletionGate().evaluate(
        CompletionSnapshot(
            graph=graph,
            findings=(finding,),
            contracts=(contract,),
            contract_grades=grades,
            step_statuses={"scan": StepStatus.SUCCEEDED},
            report_claim_ids=("unverified-claim",),
        )
    )
    assert unverified.status == RunStatus.FAILED

    corrupt = CompletionGate().evaluate(
        CompletionSnapshot(
            graph=graph,
            findings=(finding,),
            contracts=(contract,),
            contract_grades=grades,
            artifact_hashes_valid=False,
        )
    )
    assert corrupt.status == RunStatus.FAILED


def test_pending_approval_or_uncertain_invocation_requires_recovery() -> None:
    contract, finding, _, graph, grades = completed_fixture()
    for snapshot in (
        CompletionSnapshot(
            graph=graph,
            findings=(finding,),
            contracts=(contract,),
            contract_grades=grades,
            pending_approval_ids=("approval-1",),
        ),
        CompletionSnapshot(
            graph=graph,
            findings=(finding,),
            contracts=(contract,),
            contract_grades=grades,
            invocation_statuses=(InvocationStatus.RECOVERY_REQUIRED,),
        ),
    ):
        assert CompletionGate().evaluate(snapshot).status == RunStatus.RECOVERY_REQUIRED


def test_non_partial_contract_failure_cannot_be_softened() -> None:
    contract, finding, _, graph, _ = completed_fixture(allow_partial=False)
    result = CompletionGate().evaluate(
        CompletionSnapshot(
            graph=graph,
            findings=(finding,),
            contracts=(contract,),
            contract_grades={},
            step_statuses={"scan": StepStatus.SUCCEEDED},
        )
    )
    assert result.status == RunStatus.FAILED


def test_optional_contract_and_step_failure_remain_auditable_without_downgrading_answer() -> None:
    contract, finding, _, graph, _ = completed_fixture(allow_partial=True)
    result = CompletionGate().evaluate(
        CompletionSnapshot(
            graph=graph,
            findings=(finding,),
            contracts=(contract,),
            contract_grades={},
            step_statuses={"scan": StepStatus.FAILED},
            tool_failures=("scan",),
        )
    )

    assert result.status == RunStatus.COMPLETED
    assert result.unsatisfied_contract_ids == (contract.contract_id,)
    assert not result.reasons


def test_candidate_claim_cannot_be_reported_before_verification_finishes() -> None:
    contract, finding, claim, graph, grades = completed_fixture()
    pending = EvidenceGraph(
        claims=[claim.model_copy(update={"status": ClaimStatus.CANDIDATE})],
        evidence=graph.evidence,
        links=[link.model_copy(update={"verifier_status": ClaimStatus.CANDIDATE}) for link in graph.links],
    )
    result = CompletionGate().evaluate(
        CompletionSnapshot(
            graph=pending,
            findings=(finding,),
            contracts=(contract,),
            contract_grades=grades,
            step_statuses={"scan": StepStatus.SUCCEEDED},
        )
    )
    assert result.status == RunStatus.RECOVERY_REQUIRED
    assert not result.projection.findings
