from __future__ import annotations

from secmind.evidence_gap import EvidenceGapCompiler
from secmind.primary_baseline import publish_primary_baseline
from secmind.schemas import (
    AgentState,
    Evidence,
    Finding,
    PlanStep,
    RepositoryIndexRef,
    RunStatus,
    Scenario,
    TaskRequest,
    ToolHealth,
)
from secmind.tools import default_registry


def _state(
    findings: list[Finding],
    evidence: list[Evidence],
    *,
    answer_status: str,
    dependency_files: list[str] | None = None,
    affinity_signals: list[str] | None = None,
    affinity_scores: dict[str, int] | None = None,
    languages: list[str] | None = None,
) -> AgentState:
    state = AgentState(
        run_id="run-gap-v08",
        task=TaskRequest(objective="Audit Python source", autonomy_policy="automatic"),
        scenario=Scenario.CODE_AUDIT,
        status=RunStatus.RUNNING,
        findings=findings,
        evidence=evidence,
        repository_index=RepositoryIndexRef(
            index_id="index",
            run_id="run-gap-v08",
            artifact_id="a" * 64,
            digest="a" * 64,
            file_count=1,
            languages=languages or ["python"],
            dependency_files=dependency_files or [],
        ),
        audit_coverage={
            "primary_answer_status": answer_status,
            "tool_affinity": {
                "signals": affinity_signals or [],
                "scores": affinity_scores or {},
            },
        },
    )
    publish_primary_baseline(
        state,
        model_id="deepseek-v4-flash",
        prompt_version="canonical-primary-v2",
        prompt_artifact_id="b" * 64,
        request_sha256="c" * 64,
        response_sha256="d" * 64,
        response_schema_sha256="e" * 64,
        context_sha256="f" * 64,
        response_artifact_id="d" * 64,
        provider_requests=1,
        input_tokens=1,
        output_tokens=1,
        cost_units=0,
        status=RunStatus.COMPLETED,
        executive_summary="Primary result",
        findings=findings,
        evidence=evidence,
        decisions=[],
        limitations=[],
        coverage=state.audit_coverage,
    )
    return state


def _steps() -> list[PlanStep]:
    return [
        PlanStep(
            step_id=f"scan-{tool}",
            objective=f"Run {tool}",
            agent_role="sast_specialist",
            capability="sast",
            tool_candidates=[tool],
            inputs={"target": "."},
            success_criteria=["Evidence is captured"],
        )
        for tool in ("bandit_python_audit", "python_taint_audit")
    ]


def test_closed_primary_gap_dispatches_zero_workers() -> None:
    evidence = Evidence(
        evidence_id="primary-evidence",
        source="canonical-primary",
        summary="Exact flow",
        artifact_ref="2" * 64,
        sha256="2" * 64,
    )
    finding = Finding(
        finding_id="primary-finding",
        rule_id="CWE-95",
        path="app.py",
        line=3,
        title="Unsafe eval",
        description="Untrusted input reaches eval.",
        evidence_ids=[evidence.evidence_id],
        raw={"data_flow": "request -> eval", "root_cause": "eval accepts input"},
    )
    state = _state([finding], [evidence], answer_status="completed")

    compiled = EvidenceGapCompiler().compile(state, _steps(), default_registry().manifests())

    assert compiled.gap_codes == ()
    assert compiled.tickets == ()
    assert compiled.steps == ()


def test_empty_primary_releases_one_authoritative_and_one_shadow_worker() -> None:
    state = _state([], [], answer_status="insufficient_evidence")

    compiled = EvidenceGapCompiler().compile(state, _steps(), default_registry().manifests())

    assert compiled.gap_codes == ("empty_or_inconclusive_primary",)
    assert [item.tool_name for item in compiled.tickets] == [
        "python_taint_audit",
        "bandit_python_audit",
    ]
    assert [item.release_policy for item in compiled.tickets] == ["authoritative", "shadow"]
    assert len(compiled.steps) == 2
    assert all(step.context_requirements["evidence_gap_ticket_id"] for step in compiled.steps)


def test_no_gap_can_force_bounded_shadow_scouts_without_claiming_a_gap() -> None:
    evidence = Evidence(
        evidence_id="primary-evidence",
        source="canonical-primary",
        summary="Exact flow",
        artifact_ref="2" * 64,
        sha256="2" * 64,
    )
    finding = Finding(
        finding_id="primary-finding",
        rule_id="CWE-95",
        path="app.py",
        line=3,
        title="Unsafe eval",
        description="Untrusted input reaches eval.",
        evidence_ids=[evidence.evidence_id],
        raw={"data_flow": "request -> eval", "root_cause": "eval accepts input"},
    )
    state = _state([finding], [evidence], answer_status="completed")

    compiled = EvidenceGapCompiler().compile(
        state,
        _steps(),
        default_registry().manifests(),
        force_scouts=True,
    )

    assert compiled.gap_codes == ()
    assert compiled.scout_mode is True
    assert compiled.steps
    assert all(item.release_policy == "shadow" for item in compiled.tickets)


def test_completed_primary_cannot_suppress_high_affinity_php_workflow_observation() -> None:
    evidence = Evidence(
        evidence_id="primary-evidence",
        source="canonical-primary",
        summary="Password hashing configuration",
        artifact_ref="2" * 64,
        sha256="2" * 64,
    )
    unrelated = Finding(
        finding_id="primary-finding",
        rule_id="CWE-916",
        path="subject.php",
        line=42,
        title="Weak password hashing configuration",
        description="The model reported a hashing concern but did not inspect the workflow transition.",
        evidence_ids=[evidence.evidence_id],
        raw={"data_flow": "request -> password hash", "root_cause": "weak work factor"},
    )
    state = _state(
        [unrelated],
        [evidence],
        answer_status="completed",
        affinity_scores={"web_workflow_audit": 90},
        languages=["php"],
    )
    step = PlanStep(
        step_id="web-workflow",
        objective="Verify client-controlled security workflow transitions",
        agent_role="sast_specialist",
        capability="sast",
        tool_candidates=["web_workflow_audit"],
        inputs={"target": "."},
        success_criteria=["Evidence is captured"],
    )

    compiled = EvidenceGapCompiler().compile(state, [step], default_registry().manifests())

    assert compiled.gap_codes == ("missing_web_workflow_coverage",)
    assert [ticket.tool_name for ticket in compiled.tickets] == ["web_workflow_audit"]
    assert compiled.tickets[0].release_policy == "shadow"
    assert compiled.steps[0].context_requirements["evidence_gap_code"] == "missing_web_workflow_coverage"


def test_php_workflow_model_claim_cannot_close_deterministic_coverage_gap() -> None:
    evidence = Evidence(
        evidence_id="primary-evidence",
        source="canonical-primary",
        summary="Client-selected transition reaches state change",
        artifact_ref="2" * 64,
        sha256="2" * 64,
    )
    workflow = Finding(
        finding_id="primary-finding",
        rule_id="CWE-840",
        path="subject.php",
        line=37,
        title="Workflow bypass",
        description="The final step does not verify the prior challenge.",
        evidence_ids=[evidence.evidence_id],
        raw={"data_flow": "step=2 -> update", "root_cause": "client-controlled workflow state"},
    )
    state = _state(
        [workflow],
        [evidence],
        answer_status="completed",
        affinity_scores={"web_workflow_audit": 90},
        languages=["php"],
    )

    compiled = EvidenceGapCompiler().compile(state, [], default_registry().manifests())

    assert compiled.gap_codes == ("missing_web_workflow_coverage",)


def test_php_workflow_coverage_gap_closes_only_after_successful_tool_receipt() -> None:
    evidence = Evidence(
        evidence_id="primary-evidence",
        source="canonical-primary",
        summary="Client-selected transition reaches state change",
        artifact_ref="2" * 64,
        sha256="2" * 64,
    )
    workflow = Finding(
        finding_id="primary-finding",
        rule_id="CWE-840",
        path="subject.php",
        line=37,
        title="Workflow bypass",
        description="The final step does not verify the prior challenge.",
        evidence_ids=[evidence.evidence_id],
        raw={"data_flow": "step=2 -> update", "root_cause": "client-controlled workflow state"},
    )
    state = _state(
        [workflow],
        [evidence],
        answer_status="completed",
        affinity_scores={"web_workflow_audit": 90},
        languages=["php"],
    )
    state.audit_coverage["tool_routing"] = {"succeeded": ["web_workflow_audit"]}

    compiled = EvidenceGapCompiler().compile(state, [], default_registry().manifests())

    assert compiled.gap_codes == ()


def test_completed_java_primary_cannot_suppress_semantic_scanner_observation() -> None:
    evidence = Evidence(
        evidence_id="primary-evidence",
        source="canonical-primary",
        summary="Provider found an unrelated authorization issue",
        artifact_ref="2" * 64,
        sha256="2" * 64,
    )
    unrelated = Finding(
        finding_id="primary-finding",
        rule_id="CWE-862",
        path="subject.java",
        line=10,
        title="Missing authorization",
        description="A public method does not show an authorization check.",
        evidence_ids=[evidence.evidence_id],
        raw={"data_flow": "request -> method", "root_cause": "authorization is absent"},
    )
    state = _state(
        [unrelated],
        [evidence],
        answer_status="completed",
        affinity_scores={"java_semantic_sast": 75, "semgrep_sast": 80},
        languages=["java"],
    )
    java_step = PlanStep(
        step_id="java-semantic",
        objective="Run bounded Java semantic checks",
        agent_role="sast_specialist",
        capability="sast",
        tool_candidates=["java_semantic_sast"],
        inputs={"target": "."},
        success_criteria=["Evidence is captured"],
    )
    semgrep_step = java_step.model_copy(
        update={"step_id": "semgrep", "tool_candidates": ["semgrep_sast"]},
        deep=True,
    )

    compiled = EvidenceGapCompiler().compile(
        state,
        [semgrep_step, java_step],
        default_registry().manifests(),
    )

    assert compiled.gap_codes == ("missing_java_semantic_coverage",)
    assert [ticket.tool_name for ticket in compiled.tickets] == ["java_semantic_sast"]
    assert compiled.tickets[0].release_policy == "shadow"
    assert compiled.steps[0].context_requirements["evidence_gap_code"] == "missing_java_semantic_coverage"


def test_java_semantic_coverage_closes_only_after_successful_tool_receipt() -> None:
    evidence = Evidence(
        evidence_id="primary-evidence",
        source="canonical-primary",
        summary="Provider found an unrelated authorization issue",
        artifact_ref="2" * 64,
        sha256="2" * 64,
    )
    unrelated = Finding(
        finding_id="primary-finding",
        rule_id="CWE-862",
        path="subject.java",
        line=10,
        title="Missing authorization",
        description="A public method does not show an authorization check.",
        evidence_ids=[evidence.evidence_id],
        raw={"data_flow": "request -> method", "root_cause": "authorization is absent"},
    )
    state = _state(
        [unrelated],
        [evidence],
        answer_status="completed",
        affinity_scores={"java_semantic_sast": 75},
        languages=["java"],
    )
    state.audit_coverage["tool_routing"] = {"succeeded": ["java_semantic_sast"]}

    assert EvidenceGapCompiler().gap_codes(state) == ()


def test_coverage_gap_tickets_follow_capability_domain_not_step_order() -> None:
    evidence = Evidence(
        evidence_id="primary-evidence",
        source="canonical-primary",
        summary="Exact flow",
        artifact_ref="2" * 64,
        sha256="2" * 64,
    )
    finding = Finding(
        finding_id="primary-finding",
        rule_id="CWE-95",
        path="app.py",
        line=3,
        title="Unsafe eval",
        description="Untrusted input reaches eval.",
        evidence_ids=[evidence.evidence_id],
        raw={"data_flow": "request -> eval", "root_cause": "eval accepts input"},
    )
    state = _state(
        [finding],
        [evidence],
        answer_status="completed",
        dependency_files=["package-lock.json"],
        affinity_signals=["secret_material"],
    )
    manifests = {item.name: item for item in default_registry().manifests()}
    manifests["syft_sbom"] = manifests["syft_sbom"].model_copy(update={"health_status": ToolHealth.HEALTHY})
    steps = [
        PlanStep(
            step_id="dependency",
            objective="dependency",
            agent_role="dependency_specialist",
            capability="sbom",
            tool_candidates=["syft_sbom"],
            inputs={"target": "."},
            success_criteria=["done"],
        ),
        PlanStep(
            step_id="secrets",
            objective="secrets",
            agent_role="secret_specialist",
            capability="secret_scan",
            tool_candidates=["secret_pattern_scan"],
            inputs={"target": "."},
            success_criteria=["done"],
        ),
    ]

    first = EvidenceGapCompiler().compile(state, steps, manifests.values())
    second = EvidenceGapCompiler().compile(state, list(reversed(steps)), manifests.values())

    assert first.gap_codes == ("missing_dependency_coverage", "missing_secret_coverage")
    assert {ticket.tool_name: ticket.gap_code for ticket in first.tickets} == {
        "syft_sbom": "missing_dependency_coverage",
        "secret_pattern_scan": "missing_secret_coverage",
    }
    assert {ticket.tool_name: ticket.gap_code for ticket in second.tickets} == {
        "syft_sbom": "missing_dependency_coverage",
        "secret_pattern_scan": "missing_secret_coverage",
    }
    assert all(ticket.release_policy == "shadow" for ticket in first.tickets)


def test_degraded_primary_keeps_independent_secret_and_dependency_routes() -> None:
    state = _state(
        [],
        [],
        answer_status="insufficient_evidence",
        dependency_files=["package-lock.json"],
        affinity_signals=["secret_candidate"],
    )
    manifests = {item.name: item for item in default_registry().manifests()}
    manifests["syft_sbom"] = manifests["syft_sbom"].model_copy(update={"health_status": ToolHealth.HEALTHY})
    steps = [
        PlanStep(
            step_id="sast",
            objective="sast",
            agent_role="sast_specialist",
            capability="sast",
            tool_candidates=["python_taint_audit"],
            inputs={"target": "."},
            success_criteria=["done"],
        ),
        PlanStep(
            step_id="secret",
            objective="secret",
            agent_role="secret_specialist",
            capability="secret_scan",
            tool_candidates=["secret_pattern_scan"],
            inputs={"target": "."},
            success_criteria=["done"],
        ),
        PlanStep(
            step_id="sbom",
            objective="sbom",
            agent_role="dependency_specialist",
            capability="sbom",
            tool_candidates=["syft_sbom"],
            inputs={"target": "."},
            success_criteria=["done"],
        ),
    ]

    state.raw_primary_receipt = None
    state.baseline_admission = None
    state.published_baseline = None
    compiled = EvidenceGapCompiler().compile(state, steps, manifests.values())

    assert compiled.gap_codes == (
        "empty_or_inconclusive_primary",
        "missing_dependency_coverage",
        "missing_secret_coverage",
    )
    assert {ticket.tool_name: ticket.gap_code for ticket in compiled.tickets} == {
        "python_taint_audit": "empty_or_inconclusive_primary",
        "secret_pattern_scan": "missing_secret_coverage",
        "syft_sbom": "missing_dependency_coverage",
    }
    assert [ticket.release_policy for ticket in compiled.tickets] == ["authoritative", "shadow", "shadow"]
