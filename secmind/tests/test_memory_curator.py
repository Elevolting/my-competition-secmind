from conftest import seal_execution_contract

from secmind.memory_curator import curate_episodic_memory
from secmind.schemas import AgentReport, AgentState, Claim, ClaimStatus, Evidence, Finding, RunStatus, TaskRequest


def _completed_state() -> AgentState:
    evidence = Evidence(evidence_id="evidence-1", source="tool:1", summary="bounded", sha256="a" * 64)
    finding = Finding(
        rule_id="RULE-1",
        severity="HIGH",
        confidence="HIGH",
        path="app.py",
        title="Finding",
        description="Evidence-backed finding",
        evidence_ids=[evidence.evidence_id],
    )
    return seal_execution_contract(
        AgentState(
            run_id="run-memory-curator",
            task=TaskRequest(objective="audit API_KEY=secret-value"),
            status=RunStatus.COMPLETED,
            evidence=[evidence],
            findings=[finding],
            claims=[
                Claim(
                    claim_type="sast.finding",
                    statement="The evidence-backed finding is present.",
                    subject_ref=finding.finding_id,
                    status=ClaimStatus.VERIFIED,
                    producer="sast-step",
                    confidence=0.95,
                )
            ],
            report=AgentReport(
                run_id="run-memory-curator",
                status=RunStatus.COMPLETED,
                executive_summary="Completed with authorization: Bearer synthetic-secret-token",
            ),
        )
    )


def test_curator_scrubs_verified_evidence_complete_memory() -> None:
    candidate = curate_episodic_memory(_completed_state())
    assert candidate.accepted
    assert candidate.content is not None
    assert "secret-value" not in candidate.content
    assert "synthetic-secret-token" not in candidate.content
    assert "[REDACTED]" in candidate.content


def test_curator_rejects_broken_evidence_and_non_terminal_run() -> None:
    broken = _completed_state()
    broken.evidence = []
    assert not curate_episodic_memory(broken).accepted

    pending = _completed_state()
    pending.status = RunStatus.PARTIAL
    assert not curate_episodic_memory(pending).accepted
