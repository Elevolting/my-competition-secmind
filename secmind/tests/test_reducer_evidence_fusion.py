from secmind.dag import DeterministicReducer
from secmind.schemas import (
    AgentState,
    Evidence,
    Finding,
    StepPatch,
    StepRuntime,
    StepStatus,
    TaskRequest,
)


def test_reducer_merges_same_location_and_preserves_independent_tool_evidence() -> None:
    model_evidence = Evidence(
        evidence_id="model-evidence",
        source="model:5.4",
        summary="model proposal",
        sha256="a" * 64,
        metadata={"assurance_level": "model_proposed"},
    )
    tool_evidence = Evidence(
        evidence_id="tool-evidence",
        source="semgrep:1.0",
        summary="rule-backed flow",
        sha256="b" * 64,
        metadata={"evidence_type": "sast_flow"},
    )
    model_finding = Finding(
        rule_id="CWE-89",
        severity="MEDIUM",
        confidence="MEDIUM",
        path="src/A.java",
        line=9,
        title="Model SQL injection",
        description="proposed",
        evidence_ids=[model_evidence.evidence_id],
        raw={"model_id": "mock-5.4"},
    )
    tool_finding = Finding(
        rule_id="CWE-89",
        severity="HIGH",
        confidence="HIGH",
        path="src/A.java",
        line=9,
        title="Semgrep SQL injection",
        description="corroborated",
        evidence_ids=[tool_evidence.evidence_id],
    )
    state = AgentState(
        run_id="run-fusion",
        task=TaskRequest(objective="audit"),
        evidence=[model_evidence],
        findings=[model_finding],
        step_runtime={
            "sast-semgrep": StepRuntime(
                step_id="sast-semgrep",
                status=StepStatus.RUNNING,
                transition_id="transition-1",
            )
        },
    )
    patch = StepPatch(
        step_id="sast-semgrep",
        transition_id="transition-1",
        status=StepStatus.SUCCEEDED,
        findings=[tool_finding],
        evidence=[tool_evidence],
        actual_tool_name="semgrep",
        actual_tool_version="1.0",
        actual_tool_calls=1,
    )

    merged = DeterministicReducer.apply(state, [patch])

    assert len(merged.findings) == 1
    assert merged.findings[0].evidence_ids == ["model-evidence", "tool-evidence"]
    assert merged.findings[0].severity == "HIGH"
    assert merged.findings[0].raw["corroborated_by_tools"] == ["semgrep"]
    evidence = next(item for item in merged.evidence if item.evidence_id == "tool-evidence")
    assert evidence.metadata["assurance_level"] == "semantically_corroborated"


def test_reducer_preserves_all_native_rule_provenance_when_tools_correlate() -> None:
    bandit = Finding(
        rule_id="CWE-78",
        severity="HIGH",
        confidence="HIGH",
        path="app.py",
        line=7,
        title="Bandit command injection",
        description="Bandit finding",
        raw={
            "tool_name": "bandit_python_audit",
            "test_id": "B602",
            "native_rule_id": "B602",
        },
    )
    semgrep = bandit.model_copy(
        update={
            "title": "Semgrep command injection",
            "raw": {
                "tool_name": "semgrep_sast",
                "native_rule_id": "secmind.python.flask-shell-command-injection",
            },
        },
        deep=True,
    )
    state = AgentState(
        run_id="run-native-provenance",
        task=TaskRequest(objective="audit"),
        findings=[bandit],
        step_runtime={
            "sast-semgrep": StepRuntime(
                step_id="sast-semgrep",
                status=StepStatus.RUNNING,
                transition_id="transition-native",
            )
        },
    )
    patch = StepPatch(
        step_id="sast-semgrep",
        transition_id="transition-native",
        status=StepStatus.SUCCEEDED,
        findings=[semgrep],
        actual_tool_name="semgrep_sast",
        actual_tool_calls=1,
    )

    merged = DeterministicReducer.apply(state, [patch])

    assert merged.findings[0].raw["corroborating_native_rule_ids"] == [
        "B602",
        "secmind.python.flask-shell-command-injection",
    ]
    assert merged.findings[0].raw["corroborated_by_tools"] == [
        "bandit_python_audit",
        "semgrep_sast",
    ]
