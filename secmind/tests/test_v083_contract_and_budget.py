from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from secmind.canonical_primary import (
    CanonicalAnalysisContract,
    UniversalPrimaryAnswer,
    canonical_user_prompt,
    select_analysis_profile,
    source_context_budget,
)
from secmind.canonical_primary import (
    _build_canonical_context_legacy as build_canonical_context,
)
from secmind.config import Settings
from secmind.domain_answers import (
    EvidenceGapAnswer,
    PolicyDecisionAnswer,
    normalize_domain_answer,
    primary_answer_run_status,
)
from secmind.llm import QwenGateway, estimate_prompt_tokens
from secmind.primary_baseline import publish_primary_baseline, restore_published_baseline, validate_baseline_chain
from secmind.schemas import AgentReport, AgentState, InputArtifact, RunStatus, Scenario, TaskRequest
from secmind.task_specs import TaskSpecCompiler
from secmind.tools import sanitized_tool_environment


def test_model_reservations_are_conservative_without_overselling_parent_output() -> None:
    settings = Settings(
        model_mode="offline",
        model_max_output_tokens=16_000,
        model_fallback_max_output_tokens=16_000,
        max_output_tokens=12_800,
    )
    gateway = QwenGateway(settings)

    assert gateway._max_output_tokens("primary-strong") == 12_800  # noqa: SLF001
    assert gateway._max_output_tokens("fallback-bounded") == 12_799  # noqa: SLF001
    assert estimate_prompt_tokens(240_000) == 120_256
    assert estimate_prompt_tokens(12_000_000) < 12_000_000
    small = source_context_budget(64_000, advisory_bytes=32_000)
    large = source_context_budget(640_000)

    assert 0 < small < 64_000
    assert large < 2_000_000
    assert estimate_prompt_tokens(small + 32_000 + 32_000) <= 64_000
    assert estimate_prompt_tokens(large + 256_000) <= 640_000


def test_provider_contract_compacts_large_manifest_but_keeps_its_digest() -> None:
    inputs = [
        {
            "path": f"src/file-{index:04d}.py",
            "sha256": hashlib.sha256(str(index).encode()).hexdigest(),
            "size_bytes": index + 1,
            "media_type": "text/x-python",
        }
        for index in range(3_515)
    ]
    contract = CanonicalAnalysisContract(
        task_id="T3S-large",
        objective="Audit the repository",
        scenario="code_audit_and_patch",
        analysis_profile="source_code_security",
        interaction_mode="unattended",
        primary_domain="code_audit_and_patch",
        secondary_capabilities=["secure_patch", "repository_audit"],
        scoring_mode="patch_validator",
        output_contract={"required_fields": ["answer"]},
        target_scope=["."],
        constraints=[],
        expected_outputs=["security_report"],
        autonomy_policy="graded",
        inputs=inputs,
        viewed_paths=[inputs[0]["path"]],
        omitted_paths=[item["path"] for item in inputs[1:]],
        context_sha256="a" * 64,
    )

    rendered = canonical_user_prompt(contract, [])

    assert inputs[0]["path"] in rendered
    assert inputs[-1]["path"] not in rendered
    assert '"entry_count":3515' in rendered
    assert '"answer_type":"patch_validator"' in rendered


def test_universal_provider_schema_names_every_domain_answer_field() -> None:
    properties = UniversalPrimaryAnswer.model_json_schema()["properties"]

    for field in (
        "decision",
        "events",
        "unknown_fields",
        "values",
        "fixed",
        "behaviors",
    ):
        assert field in properties


def test_large_source_uses_original_line_windows_and_keeps_tail_risk(tmp_path: Path) -> None:
    lines = [f"safe_value_{index} = {index}\n" for index in range(5_000)]
    lines[4_750] = "result = eval(untrusted_payload)\n"
    content = "".join(lines).encode()
    source = tmp_path / "large.py"
    source.write_bytes(content)
    artifact = InputArtifact(
        artifact_id="large-source",
        original_name="large.py",
        relative_path="large.py",
        sha256=hashlib.sha256(content).hexdigest(),
        size_bytes=len(content),
        media_type="text/x-python",
    )

    _contract, views = build_canonical_context(
        task_id="large-source",
        task=TaskRequest(objective="Audit code execution risk", autonomy_policy="automatic"),
        scenario=Scenario.CODE_AUDIT,
        workspace=tmp_path,
        artifacts=[artifact],
        max_context_bytes=4_096,
    )

    assert len(views) == 1
    assert views[0].view_strategy == "risk_windows"
    assert "eval(untrusted_payload)" in views[0].content
    assert any(start <= 4_751 <= end for start, end in views[0].source_line_ranges)


def test_minified_forensic_view_keeps_exact_value_outside_prefix(tmp_path: Path) -> None:
    content = b'{"packets":["' + b"A" * 700_000 + b'","flag":"HTB{tail_value}"],"end":true}'
    source = tmp_path / "packets.json"
    source.write_bytes(content)
    artifact = InputArtifact(
        artifact_id="minified-forensic",
        original_name="packets.json",
        relative_path="packets.json",
        sha256=hashlib.sha256(content).hexdigest(),
        size_bytes=len(content),
        media_type="application/json",
    )

    _contract, views = build_canonical_context(
        task_id="minified-forensic",
        task=TaskRequest(
            objective="Recover the flag from the supplied packet view",
            primary_domain="logs_ir_hunting",
            scoring_mode="exact_answer_with_evidence",
        ),
        scenario=Scenario.LOG_ANALYSIS,
        workspace=tmp_path,
        artifacts=[artifact],
        max_context_bytes=32_000,
    )

    assert views[0].view_strategy == "risk_windows"
    assert "HTB{tail_value}" in views[0].content


def test_trusted_domain_removes_unattended_scenario_guessing() -> None:
    task = TaskRequest(
        objective="Summarize the permitted actions from the supplied context",
        interaction_mode="unattended",
        primary_domain="agent_safety",
        secondary_capabilities=["prompt_injection_resistance"],
        scoring_mode="agent_policy_compliance",
    )

    spec = TaskSpecCompiler().compile("trusted-domain", task, [], [])

    assert spec.primary_scenario == Scenario.UNKNOWN
    assert spec.ambiguities == []
    assert spec.primary_domain == "agent_safety"
    assert spec.interaction_mode == "unattended"
    assert (
        select_analysis_profile(
            task.objective,
            spec.primary_scenario,
            [],
            task.secondary_capabilities,
            task.scoring_mode,
        )
        == "prompt_injection_policy"
    )


@pytest.mark.parametrize(
    ("domain", "mode", "capabilities", "expected_scenario", "expected_profile"),
    [
        (
            "agent_safety",
            "agent_policy_compliance",
            ["prompt_injection_resistance"],
            Scenario.UNKNOWN,
            "prompt_injection_policy",
        ),
        ("code_audit_and_patch", "security_finding", ["code_audit"], Scenario.CODE_AUDIT, "source_code_security"),
        (
            "code_audit_and_patch",
            "patch_validator",
            ["secure_patch", "repository_audit"],
            Scenario.CODE_AUDIT,
            "patch_validation",
        ),
        (
            "complex_input_understanding",
            "security_finding",
            ["firmware_static_audit"],
            Scenario.LOG_ANALYSIS,
            "forensics_and_logs",
        ),
        (
            "forensics_static_reverse",
            "reverse_behavior",
            ["static_malware_reasoning"],
            Scenario.REVERSE_TRIAGE,
            "binary_firmware_reverse",
        ),
        (
            "logs_ir_hunting",
            "forensic_attribution",
            ["windows_event_forensics"],
            Scenario.LOG_ANALYSIS,
            "forensics_and_logs",
        ),
        (
            "logs_ir_hunting",
            "exact_answer_with_evidence",
            ["complex_input_understanding", "digital_forensics"],
            Scenario.LOG_ANALYSIS,
            "exact_answer",
        ),
        (
            "orchestration_recovery_uncertainty",
            "evidence_gap",
            ["evidence_gap_handling"],
            Scenario.UNKNOWN,
            "evidence_gap",
        ),
    ],
)
def test_full60_trusted_contract_matrix_routes_without_heuristic_override(
    domain: str,
    mode: str,
    capabilities: list[str],
    expected_scenario: Scenario,
    expected_profile: str,
) -> None:
    task = TaskRequest(
        objective="Analyze the supplied immutable input",
        interaction_mode="unattended",
        primary_domain=domain,
        secondary_capabilities=capabilities,
        scoring_mode=mode,
    )

    spec = TaskSpecCompiler().compile(f"matrix-{mode}", task, [], [])

    assert spec.primary_scenario == expected_scenario
    assert spec.ambiguities == []
    assert (
        select_analysis_profile(
            task.objective,
            spec.primary_scenario,
            [],
            capabilities,
            mode,
        )
        == expected_profile
    )


def test_domain_answer_normalization_keeps_safety_and_uncertainty_semantics() -> None:
    policy = normalize_domain_answer(
        "agent_policy_compliance",
        {
            "task_id": "task-policy",
            "status": "completed",
            "decision": "summarize_only",
            "safe_actions": ["read supplied records"],
            "blocked_actions": ["modify payments"],
            "evidence": [{"path": "context.txt", "line": 1}],
        },
    )
    gap = normalize_domain_answer(
        "evidence_gap",
        {
            "task_id": "task-gap",
            "status": "insufficient_evidence",
            "known": ["Git LFS pointer is present"],
            "unknown_fields": ["referenced object bytes"],
            "next_evidence": ["materialize the referenced object"],
        },
    )

    assert isinstance(policy, PolicyDecisionAnswer)
    assert policy.decision == "deny_unauthorized_action; DENY/BLOCK: summarize_only"
    assert policy.epistemic_status == "conclusive"
    assert isinstance(gap, EvidenceGapAnswer)
    assert gap.execution_status == "success"
    assert gap.epistemic_status == "insufficient_evidence"


def test_partial_gap_with_explicit_blocked_claims_has_stable_epistemic_status() -> None:
    gap = normalize_domain_answer(
        "evidence_gap",
        {
            "task_id": "task-gap-partial",
            "status": "partial",
            "known": ["The supplied artifact is a Git LFS pointer."],
            "unknown_fields": ["The referenced object bytes"],
            "blocked_claims": [
                {
                    "claim": "Attack attribution can be completed.",
                    "reason": "The underlying telemetry object is absent.",
                }
            ],
            "conflicts": ["The filename suggests telemetry, but the supplied bytes are only a pointer."],
            "next_evidence": ["Provide the referenced Git LFS object."],
        },
    )

    assert isinstance(gap, EvidenceGapAnswer)
    assert gap.execution_status == "partial"
    assert gap.epistemic_status == "insufficient_evidence"


def test_non_finding_completion_does_not_require_a_vulnerability() -> None:
    assert (
        primary_answer_run_status(
            "evidence_gap",
            "insufficient_evidence",
            has_findings=False,
            negative_coverage_complete=False,
        )
        == RunStatus.COMPLETED
    )
    assert (
        primary_answer_run_status(
            "agent_policy_compliance",
            "blocked",
            has_findings=False,
            negative_coverage_complete=False,
        )
        == RunStatus.COMPLETED
    )
    assert (
        primary_answer_run_status(
            "agent_policy_compliance",
            "insufficient_evidence",
            has_findings=False,
            negative_coverage_complete=False,
        )
        == RunStatus.COMPLETED
    )
    assert (
        primary_answer_run_status(
            "security_finding",
            "completed",
            has_findings=False,
            negative_coverage_complete=False,
        )
        == RunStatus.PARTIAL
    )
    for mode in ("forensic_attribution", "reverse_behavior", "exact_answer_with_evidence", "patch_validator"):
        assert (
            primary_answer_run_status(
                mode,
                "insufficient_evidence",
                has_findings=False,
                negative_coverage_complete=False,
            )
            == RunStatus.COMPLETED
        )


def test_primary_typed_answer_is_integrity_bound_and_restored() -> None:
    state = AgentState(
        run_id="typed-primary",
        task=TaskRequest(objective="Summarize allowed actions"),
        status=RunStatus.RUNNING,
    )
    answer = {
        "answer_kind": "policy_decision",
        "task_id": "typed-primary",
        "execution_status": "success",
        "epistemic_status": "conclusive",
        "decision": "summarize_only",
        "safe_actions": ["read"],
        "blocked_actions": ["write"],
    }
    publish_primary_baseline(
        state,
        model_id="deepseek-v4-flash",
        prompt_version="v0.8.3-test",
        prompt_artifact_id=None,
        request_sha256="a" * 64,
        response_sha256="b" * 64,
        response_schema_sha256="c" * 64,
        context_sha256="d" * 64,
        response_artifact_id="b" * 64,
        provider_requests=1,
        input_tokens=100,
        output_tokens=50,
        cost_units=0.0,
        status=RunStatus.COMPLETED,
        executive_summary="Only a summary is authorized.",
        answer_type="policy_decision",
        answer_payload=answer,
        findings=[],
        evidence=[],
        decisions=[],
        limitations=[],
        coverage={},
    )
    state.report = AgentReport(
        run_id=state.run_id,
        status=RunStatus.COMPLETED,
        executive_summary="downstream replacement",
        answer_type="universal",
        answer_payload={"decision": "write"},
    )

    assert restore_published_baseline(state) is True
    assert state.report is not None
    assert state.report.answer_type == "policy_decision"
    assert state.report.answer_payload == answer
    assert validate_baseline_chain(state) == (True, None)


def test_tool_subprocess_environment_never_inherits_model_credentials(monkeypatch) -> None:
    monkeypatch.setenv("SECMIND_DEEPSEEK_API_KEY", "must-not-cross-boundary")
    monkeypatch.setenv("SECMIND_QWEN_API_KEY", "must-not-cross-boundary")
    monkeypatch.setenv("SAFE_TOOL_SETTING", "kept")

    environment = sanitized_tool_environment({"SEMGREP_SEND_METRICS": "off"})

    assert "SECMIND_DEEPSEEK_API_KEY" not in environment
    assert "SECMIND_QWEN_API_KEY" not in environment
    assert "SAFE_TOOL_SETTING" not in environment
    assert "PATH" in environment
    assert environment["SEMGREP_SEND_METRICS"] == "off"
