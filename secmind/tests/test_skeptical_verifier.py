from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from secmind.evidence_graph import EvidenceGraph, make_claim, make_link
from secmind.outcomes import OutcomeContractCompiler
from secmind.schemas import ClaimStatus, Evidence, EvidenceRelation, Finding, PlanStep
from secmind.verifier import RepositoryFile, SkepticalVerifier, VerificationContext

FILE_HASH = "1" * 64
EVIDENCE_HASH = "2" * 64
RULE_DIGEST = "3" * 64


def contract():
    step = PlanStep(
        step_id="scan",
        objective="Scan indexed source",
        agent_role="sast_specialist",
        capability="sast",
        tool_candidates=["scanner"],
        success_criteria=["Every indexed Python file is covered and findings contain location evidence"],
    )
    return OutcomeContractCompiler().compile(
        step,
        expected_claim_types=["vulnerability"],
        required_evidence_types=["sast_finding"],
        required_tool_versions={"scanner": "1"},
        required_coverage={"ratio": 1.0},
        confidence_threshold=0.8,
    )


def finding() -> Finding:
    return Finding(
        finding_id="finding-1",
        rule_id="SQL-1",
        path="src/app.py",
        line=2,
        title="SQL injection",
        description="User input reaches a query.",
        evidence_ids=["evidence-1"],
    )


def evidence(**metadata_updates) -> Evidence:
    metadata = {
        "evidence_type": "sast_finding",
        "tool_name": "scanner",
        "tool_version": "1",
        "rule_bundle_digest": RULE_DIGEST,
        "path": "src/app.py",
        "file_sha256": FILE_HASH,
    }
    metadata.update(metadata_updates)
    return Evidence(
        evidence_id="evidence-1",
        source="scanner:1",
        summary="SQL-1 at src/app.py:2",
        sha256=EVIDENCE_HASH,
        metadata=metadata,
    )


def graph_with_evidence(item: Evidence | None = None, *, relation=EvidenceRelation.SUPPORTS) -> EvidenceGraph:
    item = item or evidence()
    candidate = make_claim(
        claim_type="vulnerability",
        statement="The SQL injection is reachable",
        subject_ref="finding-1",
        producer="scan",
        confidence=0.95,
    )
    return EvidenceGraph(
        claims=[candidate],
        evidence=[item],
        links=[make_link(claim_id=candidate.claim_id, evidence_id=item.evidence_id, relation=relation)],
    )


def context(**updates) -> VerificationContext:
    values = {
        "repository_files": {
            "src/app.py": RepositoryFile("src/app.py", FILE_HASH, 10),
        },
        "findings": (finding(),),
        "evidence_hashes": {"evidence-1": EVIDENCE_HASH},
        "coverage_by_step": {"scan": {"ratio": 1.0}},
        "approved_rule_digests": frozenset({RULE_DIGEST}),
    }
    values.update(updates)
    return VerificationContext(**values)


def test_skeptical_verifier_verifies_environment_backed_claim() -> None:
    batch = SkepticalVerifier().verify(graph_with_evidence(), (contract(),), context())
    result = batch.results[0]
    assert result.status == ClaimStatus.VERIFIED
    assert result.verified_evidence_ids == ["evidence-1"]
    assert batch.graph.claim(result.claim_id).status == ClaimStatus.VERIFIED
    assert not batch.needs_supplement
    assert all(item.passed for item in batch.contract_grade_results[contract().contract_id])


@pytest.mark.parametrize(
    ("graph", "verification_context", "reason"),
    [
        (
            graph_with_evidence(),
            context(evidence_hashes={"evidence-1": "9" * 64}),
            "hash does not match",
        ),
        (
            graph_with_evidence(evidence(expires_at=(datetime.now(UTC) - timedelta(seconds=1)).isoformat())),
            context(),
            "expired",
        ),
        (
            graph_with_evidence(),
            context(repository_files={"other.py": RepositoryFile("other.py", FILE_HASH, 10)}),
            "absent from",
        ),
    ],
)
def test_integrity_location_and_freshness_fail_closed(graph, verification_context, reason) -> None:
    result = SkepticalVerifier().verify(graph, (contract(),), verification_context).results[0]
    assert result.status == ClaimStatus.REJECTED
    assert reason in result.reason_summary


def test_contradiction_is_conflicted_before_semantic_acceptance() -> None:
    batch = SkepticalVerifier().verify(
        graph_with_evidence(relation=EvidenceRelation.CONTRADICTS),
        (contract(),),
        context(),
    )
    assert batch.results[0].status == ClaimStatus.CONFLICTED


def test_supplement_requests_are_bounded_to_two_rounds() -> None:
    candidate = make_claim(
        claim_type="vulnerability",
        statement="Potential issue",
        subject_ref="finding-1",
        producer="scan",
        confidence=0.9,
    )
    empty = EvidenceGraph(claims=[candidate])
    verifier = SkepticalVerifier(max_supplement_rounds=2)

    initial = verifier.verify(empty, (contract(),), context(supplement_round=0))
    assert initial.needs_supplement
    assert initial.graph.claim(candidate.claim_id).status == ClaimStatus.CANDIDATE
    second = verifier.verify(empty, (contract(),), context(supplement_round=1))
    assert second.needs_supplement
    exhausted = verifier.verify(empty, (contract(),), context(supplement_round=2))
    assert exhausted.supplement_exhausted
    assert not exhausted.needs_supplement
    assert exhausted.graph.claim(candidate.claim_id).status == ClaimStatus.INSUFFICIENT


def test_verifier_rejects_invalid_configuration_and_repository_metadata() -> None:
    with pytest.raises(ValueError, match="supplement_round"):
        VerificationContext(supplement_round=-1)
    with pytest.raises(ValueError, match="max_supplement_rounds"):
        SkepticalVerifier(max_supplement_rounds=-1)
    with pytest.raises(ValueError, match="Unsafe repository path"):
        RepositoryFile("../escape.py", FILE_HASH, 1)
    with pytest.raises(ValueError, match="SHA-256"):
        RepositoryFile("src/app.py", "invalid", 1)
    with pytest.raises(ValueError, match="negative"):
        RepositoryFile("src/app.py", FILE_HASH, -1)


@pytest.mark.parametrize(
    ("graph", "verification_context", "reason"),
    [
        (
            graph_with_evidence(),
            context(findings=(finding().model_copy(update={"path": "../escape.py"}),)),
            "unsafe",
        ),
        (
            graph_with_evidence(),
            context(findings=(finding().model_copy(update={"line": 99}),)),
            "outside",
        ),
        (
            graph_with_evidence(evidence().model_copy(update={"sha256": None})),
            context(),
            "no valid SHA-256",
        ),
        (
            graph_with_evidence(evidence(rule_bundle_digest="4" * 64)),
            context(),
            "unapproved rule bundle",
        ),
        (
            graph_with_evidence(evidence(advisory_db_digest="5" * 64)),
            context(approved_advisory_digests=frozenset({"6" * 64})),
            "unapproved advisory database",
        ),
        (
            graph_with_evidence(evidence(file_sha256="7" * 64)),
            context(),
            "does not match the indexed source file",
        ),
    ],
)
def test_verifier_fail_closes_on_location_and_provenance_variants(graph, verification_context, reason) -> None:
    result = SkepticalVerifier().verify(graph, (contract(),), verification_context).results[0]
    assert result.status == ClaimStatus.REJECTED
    assert reason in result.reason_summary


def test_verifier_rejects_missing_invalid_or_mismatched_contracts_and_preserves_terminal_claims() -> None:
    graph = graph_with_evidence()
    claim = graph.claims[0]

    missing = SkepticalVerifier().verify(graph, (), context()).results[0]
    assert missing.status == ClaimStatus.REJECTED
    assert "no immutable outcome contract" in missing.reason_summary

    wrong_type_graph = EvidenceGraph(
        claims=[claim.model_copy(update={"claim_type": "coverage"})],
        evidence=graph.evidence,
        links=graph.links,
    )
    wrong_type = SkepticalVerifier().verify(wrong_type_graph, (contract(),), context()).results[0]
    assert wrong_type.status == ClaimStatus.REJECTED
    assert "outside its outcome contract" in wrong_type.reason_summary

    invalid_contract = contract().model_copy(update={"grader_ids": ["unknown-grader"]})
    invalid = SkepticalVerifier().verify(graph, (invalid_contract,), context()).results[0]
    assert invalid.status == ClaimStatus.REJECTED
    assert "digest does not match" in invalid.reason_summary

    terminal_graph = EvidenceGraph(
        claims=[claim.model_copy(update={"status": ClaimStatus.VERIFIED})],
        evidence=graph.evidence,
        links=graph.links,
    )
    terminal = SkepticalVerifier().verify(terminal_graph, (contract(),), context()).results[0]
    assert terminal.status == ClaimStatus.VERIFIED
    assert terminal.verified_evidence_ids == ["evidence-1"]
