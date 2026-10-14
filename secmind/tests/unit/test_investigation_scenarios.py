from __future__ import annotations

from typing import Any

import pytest

from secmind.investigation.contracts import StrategyLevel
from secmind.investigation.scenarios import (
    ExecutionMode,
    PenetrationScenarioRejected,
    ReleaseDisabledError,
    ScenarioCompilationError,
    ScenarioCompiler,
    ScenarioCompileRequest,
    UnsupportedScenarioError,
    default_scenario_adapters,
)
from secmind.schemas import RiskLevel, Scenario


def _request(
    scenario: Scenario,
    *,
    dry_run: bool = False,
    strategy: StrategyLevel = StrategyLevel.BALANCED,
) -> ScenarioCompileRequest:
    return ScenarioCompileRequest(
        run_id="run-scenario-1",
        scenario=scenario,
        objective="Produce an evidence-backed static security assessment",
        immutable_scope=("artifact://source/z", "artifact://source/a"),
        asset_refs=("asset-z", "asset-a"),
        constraints=("offline only", "do not modify inputs"),
        expected_outputs=("json", "markdown"),
        strategy=strategy,
        dry_run=dry_run,
    )


def _all_keys(value: Any) -> set[str]:
    if isinstance(value, dict):
        return set(value) | {key for item in value.values() for key in _all_keys(item)}
    if isinstance(value, (list, tuple)):
        return {key for item in value for key in _all_keys(item)}
    return set()


@pytest.mark.parametrize(
    ("scenario", "expected_capabilities"),
    [
        (
            Scenario.CODE_AUDIT,
            {
                "project_inventory",
                "sast",
                "secret_scan",
                "sbom",
                "dependency_audit",
                "evidence_correlation",
                "evidence_verification",
            },
        ),
        (
            Scenario.LOG_ANALYSIS,
            {
                "log_inventory",
                "log_normalization",
                "static_log_detection",
                "static_timeline",
                "evidence_correlation",
                "evidence_verification",
            },
        ),
        (
            Scenario.API_ASSESSMENT,
            {
                "api_inventory",
                "api_schema_review",
                "api_authorization_review",
                "api_data_exposure_review",
                "evidence_correlation",
                "evidence_verification",
            },
        ),
    ],
)
def test_static_scenarios_compile_to_common_governed_plan_proposals(
    scenario: Scenario,
    expected_capabilities: set[str],
) -> None:
    compiler = ScenarioCompiler()
    result = compiler.compile(_request(scenario))

    assert result.execution_mode == ExecutionMode.STATIC
    assert result.release_enabled is True
    assert result.requires_plan_contract is True
    assert result.requires_verifier is True
    assert result.requires_completion_receipt is True
    assert {item.capability for item in result.capability_templates} == expected_capabilities
    assert {step.capability for step in result.plan_proposal.proposed_steps} == expected_capabilities
    assert result.plan_proposal.estimated_usage.provider_requests == 0
    assert result.plan_proposal.estimated_usage.cost_units == 0
    assert all(
        step.inputs["immutable_scope"] == ["artifact://source/a", "artifact://source/z"]
        for step in result.plan_proposal.proposed_steps
    )
    assert all(step.output_contract["required_evidence_types"] for step in result.plan_proposal.proposed_steps)
    assert all(item.requires_independent_verification and item.blocks_completion for item in result.obligations)

    forbidden_runtime_writes = {"status", "findings", "report", "memory", "run_status"}
    assert not (_all_keys(result.model_dump(mode="json")) & forbidden_runtime_writes)


def test_compilation_ids_and_digests_are_deterministic_and_order_normalized() -> None:
    compiler = ScenarioCompiler()
    first = compiler.compile_code_audit(_request(Scenario.CODE_AUDIT))
    second = compiler.compile_code_audit(
        _request(Scenario.CODE_AUDIT).model_copy(
            update={
                "immutable_scope": ("artifact://source/a", "artifact://source/z"),
                "asset_refs": ("asset-a", "asset-z"),
                "constraints": ("do not modify inputs", "offline only"),
                "expected_outputs": ("markdown", "json"),
            }
        )
    )

    assert first.compilation_id == second.compilation_id
    assert first.content_digest == second.content_digest
    assert first.plan_proposal.proposal_id == second.plan_proposal.proposal_id
    assert first.plan_proposal.content_digest == second.plan_proposal.content_digest
    assert first.adapter_digest == second.adapter_digest
    assert first.plan_proposal.proposed_steps[0].inputs["asset_refs"] == ["asset-a", "asset-z"]


def test_compiled_dag_references_only_declared_steps_and_quick_is_single_attempt() -> None:
    result = ScenarioCompiler().compile_log_static(_request(Scenario.LOG_ANALYSIS, strategy=StrategyLevel.QUICK))
    step_ids = {step.step_id for step in result.plan_proposal.proposed_steps}
    assert all(set(step.dependencies) <= step_ids for step in result.plan_proposal.proposed_steps)
    assert all(step.max_attempts == 1 for step in result.plan_proposal.proposed_steps)
    verify = next(step for step in result.plan_proposal.proposed_steps if step.capability == "evidence_verification")
    assert verify.dependencies == ["log_analysis:correlate"]


def test_api_helper_requires_api_scenario_and_static_adapters_reject_dry_run() -> None:
    compiler = ScenarioCompiler()
    with pytest.raises(ScenarioCompilationError, match="must be api_assessment"):
        compiler.compile_api_static(_request(Scenario.CODE_AUDIT))
    with pytest.raises(ScenarioCompilationError, match="dry_run is reserved"):
        compiler.compile(_request(Scenario.API_ASSESSMENT, dry_run=True))


def test_incident_response_is_release_disabled_and_explicit_dry_run_only() -> None:
    compiler = ScenarioCompiler()
    with pytest.raises(ReleaseDisabledError, match="explicitly requested dry-run"):
        compiler.compile(_request(Scenario.INCIDENT_RESPONSE))

    result = compiler.compile(_request(Scenario.INCIDENT_RESPONSE, dry_run=True))
    assert result.execution_mode == ExecutionMode.DRY_RUN
    assert result.release_enabled is False
    assert all(int(step.risk_hint) <= int(RiskLevel.R1) for step in result.plan_proposal.proposed_steps)
    assert "incident.no_action_attestation" in {
        evidence_type for obligation in result.obligations for evidence_type in obligation.required_evidence_types
    }
    assert any("release-disabled" in assumption for assumption in result.plan_proposal.assumptions)


def test_penetration_is_always_rejected_and_unknown_scenario_is_unsupported() -> None:
    compiler = ScenarioCompiler()
    with pytest.raises(PenetrationScenarioRejected, match="rejected"):
        compiler.compile(_request(Scenario.PENETRATION_TEST))
    with pytest.raises(PenetrationScenarioRejected, match="rejected"):
        compiler.adapter_for(Scenario.PENETRATION_TEST)
    reverse = compiler.compile(_request(Scenario.REVERSE_TRIAGE))
    assert reverse.release_enabled is True
    assert reverse.execution_mode == ExecutionMode.STATIC
    with pytest.raises(UnsupportedScenarioError, match="no static scenario"):
        compiler.compile(_request(Scenario.UNKNOWN))


def test_every_adapter_has_mandatory_governance_and_verified_digest() -> None:
    adapters = default_scenario_adapters()
    compiler = ScenarioCompiler(adapters)

    assert compiler.supported_scenarios == (
        Scenario.API_ASSESSMENT,
        Scenario.CODE_AUDIT,
        Scenario.INCIDENT_RESPONSE,
        Scenario.LOG_ANALYSIS,
        Scenario.REVERSE_TRIAGE,
    )
    assert len(compiler.catalog_digest) == 64
    for adapter in adapters:
        assert adapter.requires_plan_contract is True
        assert adapter.requires_verifier is True
        assert adapter.requires_completion_receipt is True
        assert compiler.adapter_for(adapter.scenario) == adapter

    with pytest.raises(ScenarioCompilationError, match="duplicate scenario adapter"):
        ScenarioCompiler([adapters[0], adapters[0]])
    with pytest.raises(ScenarioCompilationError, match="digest mismatch"):
        ScenarioCompiler([adapters[0].model_copy(update={"content_digest": "0" * 64})])
    with pytest.raises(ScenarioCompilationError, match="cannot disable governance"):
        ScenarioCompiler([adapters[0].model_copy(update={"requires_plan_contract": False})])
