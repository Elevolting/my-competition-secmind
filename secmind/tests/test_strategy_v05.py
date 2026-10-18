from __future__ import annotations

from secmind.schemas import (
    BudgetState,
    PlanStep,
    ReplanTrigger,
    RiskLevel,
    Scenario,
    StrategyMode,
    ToolHealth,
    ToolManifest,
)
from secmind.strategy import (
    decide_replan,
    default_strategy_profiles,
    scenario_manifests,
    select_strategy,
)


def manifest(name: str, capability: str, *, health: ToolHealth = ToolHealth.HEALTHY) -> ToolManifest:
    return ToolManifest(
        name=name,
        version="1",
        description=name,
        scenarios=[Scenario.CODE_AUDIT],
        input_schema={"type": "object"},
        output_schema={"type": "object"},
        risk_level=RiskLevel.R1,
        capability_tags=[capability],
        health_status=health,
    )


def tools() -> list[ToolManifest]:
    return [
        manifest("inventory", "inventory"),
        manifest("bandit", "sast"),
        manifest("semgrep", "sast"),
        manifest("secret", "secret_scan"),
        manifest("syft", "sbom"),
        manifest("osv", "dependency_audit"),
    ]


def base_plan() -> list[PlanStep]:
    return [
        PlanStep(
            step_id="inventory-project",
            objective="inventory",
            agent_role="scout",
            capability="inventory",
            tool_candidates=["inventory"],
        ),
        PlanStep(
            step_id="scan-sast",
            objective="sast",
            agent_role="sast_specialist",
            capability="sast",
            dependencies=["inventory-project"],
            tool_candidates=["bandit"],
        ),
        PlanStep(
            step_id="scan-redacted-secrets",
            objective="secrets",
            agent_role="secret_specialist",
            capability="secret_scan",
            dependencies=["inventory-project"],
            tool_candidates=["secret"],
        ),
        PlanStep(
            step_id="generate-sbom",
            objective="sbom",
            agent_role="dependency_specialist",
            capability="sbom",
            dependencies=["inventory-project"],
            tool_candidates=["syft"],
            max_attempts=3,
        ),
        PlanStep(
            step_id="audit-dependencies",
            objective="dependencies",
            agent_role="dependency_specialist",
            capability="dependency_audit",
            dependencies=["generate-sbom"],
            tool_candidates=["osv"],
            max_attempts=3,
        ),
    ]


def test_profiles_are_offline_bounded_and_deterministic() -> None:
    first = default_strategy_profiles()
    second = default_strategy_profiles()

    assert [item.strategy_id for item in first] == list(StrategyMode)
    assert [item.profile_digest for item in first] == [item.profile_digest for item in second]
    assert all(item.max_model_calls == 0 for item in first)
    assert first[0].max_parallel_steps == 2
    assert first[1].max_parallel_steps == 3


def test_cached_strategy_declarations_return_isolated_copies() -> None:
    profiles = default_strategy_profiles()
    manifests = scenario_manifests()
    profiles[0].required_capabilities.append("caller-mutation")
    manifests[0].required_capabilities.append("caller-mutation")

    assert "caller-mutation" not in default_strategy_profiles()[0].required_capabilities
    assert "caller-mutation" not in scenario_manifests()[0].required_capabilities


def test_verified_static_scenarios_are_enabled() -> None:
    manifests = scenario_manifests()
    enabled = [item for item in manifests if item.enabled]

    assert [item.scenario_id for item in enabled] == [
        Scenario.CODE_AUDIT,
        Scenario.LOG_ANALYSIS,
        Scenario.API_ASSESSMENT,
        Scenario.REVERSE_TRIAGE,
    ]
    assert all(item.maturity in {"planned", "scaffolded"} for item in manifests if not item.enabled)
    assert len({item.package_digest for item in manifests}) == len(manifests)


def test_route_selection_is_stable_and_prefers_balanced_coverage() -> None:
    first = select_strategy(
        run_id="00000000-0000-0000-0000-000000000001",
        task_spec_digest="a" * 64,
        scenario=Scenario.CODE_AUDIT,
        tool_manifests=tools(),
        budget=BudgetState(max_tool_calls=12, max_runtime_seconds=1200),
    )
    second = select_strategy(
        run_id="00000000-0000-0000-0000-000000000001",
        task_spec_digest="a" * 64,
        scenario=Scenario.CODE_AUDIT,
        tool_manifests=tools(),
        budget=BudgetState(max_tool_calls=12, max_runtime_seconds=1200),
    )

    assert first.route.selected_strategy == StrategyMode.BALANCED
    assert first.route.route_digest == second.route.route_digest
    assert first.route.route_id == second.route.route_id
    assert [item.candidate_digest for item in first.candidates] == [item.candidate_digest for item in second.candidates]
    assert all(step.estimated_model_calls == 0 for item in first.candidates for step in item.steps)


def test_disabled_scenario_has_no_executable_candidate() -> None:
    selection = select_strategy(
        run_id="run",
        task_spec_digest="b" * 64,
        scenario=Scenario.INCIDENT_RESPONSE,
        tool_manifests=tools(),
        budget=BudgetState(),
    )

    assert selection.candidates == ()
    assert selection.route.selected_candidate_id is None
    assert selection.route.selected_strategy is None
    assert "disabled" in selection.route.rationale_summary


def test_tool_unavailable_replan_uses_a_different_tool() -> None:
    original = base_plan()
    decision = decide_replan(
        run_id="run",
        trigger=ReplanTrigger.TOOL_UNAVAILABLE,
        current_plan=original,
        revision_count=0,
        tool_manifests=tools(),
        unavailable_tools={"bandit"},
    )

    revised = next(item for item in decision.revised_plan if item.step_id == "scan-sast")
    assert decision.action == "revise"
    assert revised.tool_candidates == ["semgrep"]
    assert original[1].tool_candidates == ["bandit"]
    assert decision.revision is not None
    assert decision.revision.parent_plan_digest != decision.revision.plan_digest


def test_insufficient_evidence_adds_independent_validation_step() -> None:
    original = base_plan()
    decision = decide_replan(
        run_id="run",
        trigger=ReplanTrigger.EVIDENCE_INSUFFICIENT,
        current_plan=original,
        revision_count=1,
        tool_manifests=tools(),
    )

    assert decision.action == "revise"
    assert len(decision.revised_plan) == len(original) + 1
    added = decision.revised_plan[-1]
    assert added.tool_candidates == ["semgrep"]
    assert added.dependencies == ["scan-sast"]
    assert decision.revision is not None and decision.revision.revision == 2


def test_budget_pressure_reduces_plan_to_safe_quick_core() -> None:
    decision = decide_replan(
        run_id="run",
        trigger=ReplanTrigger.BUDGET_PRESSURE,
        current_plan=base_plan(),
        revision_count=0,
        tool_manifests=tools(),
    )

    assert decision.action == "revise"
    assert [item.capability for item in decision.revised_plan] == ["inventory", "sast"]
    assert all(item.max_attempts <= 2 for item in decision.revised_plan)


def test_replan_limit_and_missing_alternative_recommend_partial_report() -> None:
    exhausted = decide_replan(
        run_id="run",
        trigger=ReplanTrigger.BUDGET_PRESSURE,
        current_plan=base_plan(),
        revision_count=2,
        tool_manifests=tools(),
    )
    no_alternative = decide_replan(
        run_id="run",
        trigger=ReplanTrigger.EVIDENCE_INSUFFICIENT,
        current_plan=base_plan(),
        revision_count=0,
        tool_manifests=[item for item in tools() if item.name != "semgrep"],
    )

    assert exhausted.action == "partial" and exhausted.partial_report_recommended
    assert no_alternative.action == "partial" and no_alternative.partial_report_recommended
    assert exhausted.revision is None and no_alternative.revision is None
