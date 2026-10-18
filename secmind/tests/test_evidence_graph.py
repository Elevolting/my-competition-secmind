from __future__ import annotations

from uuid import UUID

import pytest

from secmind.evidence_graph import (
    EvidenceGraph,
    EvidenceGraphError,
    make_claim,
    make_link,
    stable_claim_id,
)
from secmind.schemas import (
    ClaimStatus,
    Evidence,
    Finding,
    VerificationResult,
)


def test_stable_claim_and_link_ids_are_replay_safe() -> None:
    values = {
        "claim_type": "vulnerability",
        "statement": "A shell command is injectable",
        "subject_ref": "finding-1",
        "producer": "scan",
        "version": "1.5",
    }
    first = stable_claim_id(**values)
    second = stable_claim_id(**dict(reversed(list(values.items()))))
    assert first == second
    assert len(first) == 36
    assert str(UUID(first)) == first
    claim = make_claim(**values, confidence=0.9)
    link_a = make_link(claim_id=claim.claim_id, evidence_id="evidence-1")
    link_b = make_link(claim_id=claim.claim_id, evidence_id="evidence-1")
    assert link_a.link_id == link_b.link_id
    assert len(link_a.link_id) == 36
    assert str(UUID(link_a.link_id)) == link_a.link_id


def test_graph_rejects_broken_references_and_conflicting_ids() -> None:
    claim = make_claim(
        claim_type="vulnerability",
        statement="Unsafe command",
        subject_ref="finding-1",
        producer="scan",
    )
    evidence = Evidence(evidence_id="evidence-1", source="scanner:1", summary="proof")
    graph = EvidenceGraph(claims=[claim], evidence=[evidence])
    graph.add_link(make_link(claim_id=claim.claim_id, evidence_id=evidence.evidence_id))

    with pytest.raises(EvidenceGraphError, match="unknown evidence"):
        graph.add_link(make_link(claim_id=claim.claim_id, evidence_id="missing"))
    with pytest.raises(EvidenceGraphError, match="different content"):
        graph.add_evidence(Evidence(evidence_id="evidence-1", source="tampered", summary="proof"))


def test_verifier_transition_and_verified_report_projection() -> None:
    finding = Finding(
        finding_id="finding-1",
        rule_id="CMD-1",
        path="src/app.py",
        line=4,
        title="Command injection",
        description="Untrusted input reaches a shell.",
        evidence_ids=["evidence-1"],
    )
    unverified = finding.model_copy(update={"finding_id": "finding-2"})
    claim = make_claim(
        claim_type="vulnerability",
        statement="The command injection is reachable",
        subject_ref=finding.finding_id,
        producer="scan",
        confidence=0.95,
    )
    evidence = Evidence(evidence_id="evidence-1", source="scanner:1", summary="proof")
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
            confidence=0.95,
        )
    )
    assert graph.claim(claim.claim_id).status == ClaimStatus.VERIFIED
    projection = graph.verified_report_projection([unverified, finding])
    assert [item.finding_id for item in projection.findings] == ["finding-1"]
    assert projection.claim_ids == (claim.claim_id,)
    assert projection.excluded_finding_ids == ("finding-2",)

    with pytest.raises(EvidenceGraphError, match="Invalid claim transition"):
        graph.apply_verification(
            VerificationResult(
                claim_id=claim.claim_id,
                status=ClaimStatus.REJECTED,
                reason_summary="late mutation",
            )
        )


def test_verified_report_projection_preserves_clean_audit_coverage() -> None:
    coverage_claim = make_claim(
        claim_type="sast.coverage",
        statement="The bounded SAST step completed over its immutable input.",
        subject_ref="coverage:scan-sast",
        producer="scan-sast",
        confidence=0.99,
    )
    coverage_evidence = Evidence(
        evidence_id="coverage-evidence",
        source="scanner:1",
        summary="bounded execution coverage",
    )
    graph = EvidenceGraph(
        claims=[coverage_claim],
        evidence=[coverage_evidence],
        links=[make_link(claim_id=coverage_claim.claim_id, evidence_id=coverage_evidence.evidence_id)],
    )
    graph.apply_verification(
        VerificationResult(
            claim_id=coverage_claim.claim_id,
            status=ClaimStatus.VERIFIED,
            reason_summary="verified coverage",
            verified_evidence_ids=[coverage_evidence.evidence_id],
            confidence=0.99,
        )
    )

    projection = graph.verified_report_projection([])

    assert projection.findings == ()
    assert projection.claim_ids == (coverage_claim.claim_id,)
    assert [item.evidence_id for item in projection.evidence] == [coverage_evidence.evidence_id]


def test_invalid_verification_reference_does_not_partially_mutate_claim() -> None:
    claim = make_claim(
        claim_type="vulnerability",
        statement="Unsafe command",
        subject_ref="finding-1",
        producer="scan",
    )
    evidence = Evidence(evidence_id="evidence-1", source="scanner:1", summary="proof")
    graph = EvidenceGraph(
        claims=[claim],
        evidence=[evidence],
        links=[make_link(claim_id=claim.claim_id, evidence_id=evidence.evidence_id)],
    )
    with pytest.raises(EvidenceGraphError, match="not linked"):
        graph.apply_verification(
            VerificationResult(
                claim_id=claim.claim_id,
                status=ClaimStatus.VERIFIED,
                reason_summary="invalid",
                verified_evidence_ids=["unlinked"],
                confidence=1,
            )
        )
    assert graph.claim(claim.claim_id).status == ClaimStatus.CANDIDATE


def test_unverified_supplemental_evidence_does_not_hide_verified_finding() -> None:
    finding = Finding(
        finding_id="finding-supplemental",
        rule_id="CWE-78",
        path="src/app.py",
        line=4,
        title="Command injection",
        description="Untrusted input reaches a shell.",
        evidence_ids=["support", "supplemental"],
    )
    claim = make_claim(
        claim_type="vulnerability",
        statement="The command injection is reachable",
        subject_ref=finding.finding_id,
        producer="scan",
    )
    graph = EvidenceGraph(
        claims=[claim],
        evidence=[
            Evidence(evidence_id="support", source="scanner", summary="verified support"),
            Evidence(
                evidence_id="supplemental",
                source="scout",
                summary="unverified context",
                metadata={"evidence_role": "supplemental"},
            ),
        ],
        links=[
            make_link(claim_id=claim.claim_id, evidence_id="support"),
            make_link(claim_id=claim.claim_id, evidence_id="supplemental"),
        ],
    )
    graph.apply_verification(
        VerificationResult(
            claim_id=claim.claim_id,
            status=ClaimStatus.VERIFIED,
            reason_summary="verified support only",
            verified_evidence_ids=["support"],
            confidence=0.9,
        )
    )

    projection = graph.verified_report_projection([finding])

    assert [item.finding_id for item in projection.findings] == [finding.finding_id]
    assert [item.evidence_id for item in projection.evidence] == ["support"]
    assert "supplemental_unverified:supplemental" in projection.notes[finding.finding_id]


def test_expected_input_binding_marks_stale_evidence_and_blocks_verification() -> None:
    claim = make_claim(
        claim_type="vulnerability",
        statement="The input reaches a sink",
        subject_ref="finding-stale",
        producer="scan",
    )
    evidence = Evidence(
        evidence_id="stale-evidence",
        source="scanner",
        summary="old snapshot",
        metadata={
            "path": "src/app.py",
            "file_sha256": "b" * 64,
            "input_manifest_digest": "b" * 64,
        },
    )
    graph = EvidenceGraph(
        claims=[claim],
        evidence=[evidence],
        links=[make_link(claim_id=claim.claim_id, evidence_id=evidence.evidence_id)],
        expected_input_manifest_digest="a" * 64,
        expected_file_sha256_by_path={"src/app.py": "b" * 64},
    )

    assert graph.validate_evidence(evidence.evidence_id).status == "stale"
    with pytest.raises(EvidenceGraphError, match="stale"):
        graph.apply_verification(
            VerificationResult(
                claim_id=claim.claim_id,
                status=ClaimStatus.VERIFIED,
                reason_summary="stale input",
                verified_evidence_ids=[evidence.evidence_id],
                confidence=0.8,
            )
        )
