from secmind.reporting import render_markdown, render_sarif
from secmind.admission import _align_admitted_report
from secmind.schemas import AgentReport, AgentState, Evidence, Finding, InputArtifact, RunStatus, Scenario, TaskRequest


def report() -> AgentReport:
    evidence = Evidence(evidence_id="evidence-1", source="tool", summary="proof")
    finding = Finding(
        rule_id="RULE-1",
        severity="HIGH",
        confidence="HIGH",
        path="app.py",
        line=7,
        title="Unsafe behavior",
        description="Unsafe behavior was detected.",
        remediation="Use the safe API.",
        evidence_ids=[evidence.evidence_id],
    )
    return AgentReport(
        run_id="run-report",
        status=RunStatus.COMPLETED,
        executive_summary="One finding.",
        findings=[finding],
        evidence=[evidence],
    )


def test_markdown_and_sarif_preserve_findings_and_evidence() -> None:
    markdown = render_markdown(report())
    assert "RULE-1" in markdown
    assert "evidence-1" in markdown
    sarif = render_sarif(report())
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["ruleId"] == "RULE-1"


def test_public_code_audit_summary_counts_admitted_evidence() -> None:
    state = AgentState(run_id="audit-summary", task=TaskRequest(objective="Audit the source"), scenario=Scenario.CODE_AUDIT)
    candidate = report().model_copy(update={
        "run_id": state.run_id,
        "executive_summary": "The report preserves 10 evidence record(s).",
    })

    public = _align_admitted_report(state, candidate)

    assert public.executive_summary == "The report preserves 1 evidence record(s)."


def test_public_reverse_summary_uses_verified_pe_sample_hash_and_structure() -> None:
    sample_hash = "a" * 64
    state = AgentState(
        run_id="reverse-summary",
        task=TaskRequest(objective="Analyze the PE sample"),
        scenario=Scenario.REVERSE_TRIAGE,
        input_artifacts=[InputArtifact(
            artifact_id="input-pe", original_name="sample.exe", relative_path="sample.exe",
            sha256=sample_hash, size_bytes=128, media_type="application/octet-stream",
        )],
    )
    state.audit_coverage["pre_primary_scenario_projection"] = {"answer_payload": {
        "answer_kind": "reverse_behavior", "unknowns": ["Behavior is not proven by static structure alone."],
        "limitations": ["Dynamic execution was disabled."],
    }}
    pe_evidence = Evidence(
        evidence_id="pe-evidence", source="pe_reverse_analysis:1", summary="Verified PE structure",
        sha256="b" * 64,
        metadata={
            "verification_status": "verified_support", "sample_name": "sample.exe",
            "sample_sha256": sample_hash, "architecture": "x86-64", "section_count": 10,
            "import_libraries": 2,
        },
    )
    candidate = AgentReport(
        run_id=state.run_id, status=RunStatus.COMPLETED,
        executive_summary="SHA256 is all zeros and no section table is available.",
        answer_type="reverse_behavior",
        answer_payload={
            "answer_kind": "reverse_behavior", "executive_summary": "SHA256 is all zeros.",
            "unknowns": ["No section table is available."],
            "limitations": ["Only binary strings were supplied."],
            "extensions": {"unknown_fields": ["The artifact hash is unknown."]},
        },
        evidence=[pe_evidence],
        limitations=["Only binary strings were supplied."],
    )

    public = _align_admitted_report(state, candidate)

    assert sample_hash in public.executive_summary
    assert "x86-64, 10 section(s), 2 import library/libraries" in public.executive_summary
    assert public.answer_payload["executive_summary"] == public.executive_summary
    assert public.answer_payload["unknowns"] == ["Behavior is not proven by static structure alone."]
    assert public.limitations == ["Dynamic execution was disabled."]
    assert "unknown_fields" not in public.answer_payload["extensions"]
