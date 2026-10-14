import pytest
from conftest import seal_execution_contract

from secmind.dag import DagScheduler, DeterministicReducer, PlanValidator
from secmind.schemas import (
    AgentState,
    BudgetState,
    Evidence,
    EvidenceGapTicket,
    FailurePolicy,
    Finding,
    ModelUsage,
    PlanStep,
    RiskLevel,
    Scenario,
    StepPatch,
    StepStatus,
    TaskRequest,
    ToolManifest,
    ToolResult,
    ToolStatus,
)


def manifest() -> ToolManifest:
    return ToolManifest(
        name="safe_scan",
        version="1",
        description="safe test scanner",
        scenarios=[Scenario.CODE_AUDIT],
        input_schema={"type": "object"},
        output_schema={"type": "object"},
        risk_level=RiskLevel.R1,
        capability_tags=["sast"],
    )


def step(step_id: str, dependencies: list[str] | None = None) -> PlanStep:
    return PlanStep(
        step_id=step_id,
        objective=f"run {step_id}",
        agent_role="sast_specialist",
        capability="sast",
        dependencies=dependencies or [],
        tool_candidates=["safe_scan"],
        inputs={},
        success_criteria=["schema-valid result"],
        risk_hint=RiskLevel.R1,
    )


def state(plan: list[PlanStep]) -> AgentState:
    return seal_execution_contract(
        AgentState(
            run_id="run-dag",
            task=TaskRequest(objective="audit code"),
            scenario=Scenario.CODE_AUDIT,
            plan=plan,
        )
    )


def test_plan_validator_rejects_cycle_self_dependency_and_risk_understatement() -> None:
    cyclic = [step("a", ["b"]), step("b", ["a"])]
    errors = PlanValidator([manifest()]).validate(cyclic, Scenario.CODE_AUDIT, state(cyclic))
    assert "Plan dependencies contain a cycle" in errors

    self_dependent = step("self", ["self"])
    self_dependent.risk_hint = RiskLevel.R0
    errors = PlanValidator([manifest()]).validate([self_dependent], Scenario.CODE_AUDIT, state([self_dependent]))
    assert any("cannot depend on itself" in error for error in errors)
    assert any("understates risk" in error for error in errors)


def test_scheduler_uses_dependencies_not_array_order() -> None:
    plan = [step("second", ["first"]), step("first")]
    agent_state = state(plan)
    scheduler = DagScheduler()
    assert [item.step_id for item in scheduler.ready_steps(agent_state)] == ["first"]
    agent_state.step_runtime["first"].status = StepStatus.SUCCEEDED
    assert [item.step_id for item in scheduler.ready_steps(agent_state)] == ["second"]


def test_reducer_is_order_independent_and_idempotent() -> None:
    plan = [step("a"), step("b")]
    agent_state = state(plan)
    scheduler = DagScheduler()
    scheduler.initialize(agent_state)
    work_a = scheduler.build_work_item(agent_state, plan[0])
    work_b = scheduler.build_work_item(agent_state, plan[1])
    evidence = Evidence(evidence_id="ev", source="scanner", summary="proof")
    finding = Finding(
        rule_id="RULE",
        severity="HIGH",
        confidence="HIGH",
        path="app.py",
        line=1,
        title="issue",
        description="problem",
        evidence_ids=["ev"],
    )
    patches = [
        StepPatch(
            step_id="b",
            transition_id=work_b.transition_id,
            status=StepStatus.SUCCEEDED,
            evidence=[evidence],
            findings=[finding],
        ),
        StepPatch(
            step_id="a",
            transition_id=work_a.transition_id,
            status=StepStatus.SUCCEEDED,
            evidence=[evidence],
            findings=[finding],
        ),
    ]
    DeterministicReducer.apply(agent_state, patches)
    DeterministicReducer.apply(agent_state, reversed(patches))
    assert len(agent_state.evidence) == 1
    assert len(agent_state.findings) == 1
    assert agent_state.step_runtime["a"].status == StepStatus.SUCCEEDED
    assert agent_state.step_runtime["b"].status == StepStatus.SUCCEEDED


def test_validator_reports_all_contract_and_budget_errors() -> None:
    bad = step(" ")
    bad.agent_role = "rogue"
    bad.dependencies = ["missing"]
    bad.success_criteria = []
    bad.tool_candidates = ["missing-tool"]
    bad.estimated_tool_calls = 2
    bad.estimated_model_calls = 2
    bad.estimated_tokens = 5
    bad.estimated_cost_units = 2
    agent_state = state([bad, bad.model_copy()])
    agent_state.budget = BudgetState(
        max_steps=1,
        max_tool_calls=1,
        max_model_calls=1,
        max_input_tokens=1,
        max_output_tokens=1,
        max_cost_units=1,
    )
    errors = PlanValidator([manifest()]).validate(agent_state.plan, Scenario.CODE_AUDIT, agent_state)
    assert any("unique" in item for item in errors)
    assert any("step budget" in item for item in errors)
    assert any("must not be empty" in item for item in errors)
    assert any("Unknown dependencies" in item for item in errors)
    assert any("Unsupported agent role" in item for item in errors)
    assert any("success criteria" in item for item in errors)
    assert any("Unknown tool" in item for item in errors)
    assert any("tool-call budget" in item for item in errors)
    assert any("model-call budget" in item for item in errors)
    assert any("token budget" in item for item in errors)
    assert any("cost budget" in item for item in errors)


def test_validator_rejects_unavailable_wrong_scenario_and_capability() -> None:
    tool = manifest()
    tool.health_status = "unavailable"
    tool.platform_risk = RiskLevel.R2
    bad = step("bad")
    bad.capability = "secret_scan"
    errors = PlanValidator([tool]).validate([bad], Scenario.LOG_ANALYSIS, state([bad]))
    assert any("unavailable" in item for item in errors)
    assert any("does not support scenario" in item for item in errors)
    assert any("understates risk" in item for item in errors)
    assert any("does not provide capability" in item for item in errors)


@pytest.mark.parametrize("policy", [FailurePolicy.FAIL_FAST, FailurePolicy.SKIP_DEPENDENTS])
def test_scheduler_skips_failed_dependencies(policy: FailurePolicy) -> None:
    root = step("root")
    child = step("child", ["root"])
    child.failure_policy = policy
    agent_state = state([root, child])
    scheduler = DagScheduler()
    scheduler.initialize(agent_state)
    agent_state.step_runtime["root"].status = StepStatus.FAILED
    assert scheduler.ready_steps(agent_state) == []
    assert agent_state.step_runtime["child"].status == StepStatus.SKIPPED
    assert scheduler.complete(agent_state)


def test_scheduler_continue_policy_runs_after_terminal_failed_dependency() -> None:
    root = step("root")
    child = step("child", ["root"])
    child.failure_policy = FailurePolicy.CONTINUE
    agent_state = state([root, child])
    scheduler = DagScheduler()
    scheduler.initialize(agent_state)
    agent_state.step_runtime["root"].status = StepStatus.FAILED
    assert [item.step_id for item in scheduler.ready_steps(agent_state)] == ["child"]


def test_build_work_item_is_stable_and_carries_dependency_artifacts() -> None:
    root = step("root")
    child = step("child", ["root"])
    agent_state = state([root, child])
    agent_state.lease.owner_id = "worker-1"
    agent_state.lease.fence = 9
    scheduler = DagScheduler()
    scheduler.initialize(agent_state)
    agent_state.step_runtime["root"].status = StepStatus.SUCCEEDED
    agent_state.step_runtime["root"].artifact_ids = ["z", "a"]
    item = scheduler.build_work_item(agent_state, child)
    assert item.dependency_refs == ["a", "z"]
    assert item.lease_fence == 9
    assert item.lease_owner_id == "worker-1"
    assert agent_state.step_runtime["child"].status == StepStatus.RUNNING


def test_build_work_item_carries_evidence_ticket_tool_limit() -> None:
    only = step("only")
    agent_state = state([only])
    agent_state.evidence_gap_tickets = [
        EvidenceGapTicket(
            ticket_id="gap-ticket-" + "a" * 64,
            run_id=agent_state.run_id,
            snapshot_digest="b" * 64,
            primary_semantic_digest="c" * 64,
            gap_code="empty_or_inconclusive_primary",
            allowed_patch_class="add_finding",
            capability="sast",
            tool_name="safe_scan",
            step_id=only.step_id,
            release_policy="authoritative",
            max_tool_calls=1,
        )
    ]
    scheduler = DagScheduler()
    scheduler.initialize(agent_state)

    item = scheduler.build_work_item(agent_state, only)

    assert item.max_tool_calls == 1


def test_reducer_ignores_stale_patch_and_accumulates_usage_and_observation() -> None:
    only = step("only")
    agent_state = state([only])
    scheduler = DagScheduler()
    scheduler.initialize(agent_state)
    work = scheduler.build_work_item(agent_state, only)
    stale = StepPatch(step_id="only", transition_id="stale", status=StepStatus.FAILED)
    DeterministicReducer.apply(agent_state, [stale])
    assert agent_state.step_runtime["only"].status == StepStatus.RUNNING

    observation = ToolResult(status=ToolStatus.SUCCESS, summary="done")
    patch = StepPatch(
        step_id="only",
        transition_id=work.transition_id,
        status=StepStatus.SUCCEEDED,
        artifact_ids=["b", "a", "a"],
        tool_invocation_ids=["invocation-1"],
        actual_tool_name="safe_scan",
        actual_tool_version="1",
        actual_tool_calls=1,
        observation=observation,
        usage=ModelUsage(provider_requests=2, input_tokens=3, output_tokens=4, cost_units=0.5),
    )
    DeterministicReducer.apply(agent_state, [patch])
    assert agent_state.step_runtime["only"].artifact_ids == ["a", "b"]
    assert agent_state.step_runtime["only"].observation_indexes == [0]
    assert agent_state.step_runtime["only"].actual_tool_calls == 1
    assert agent_state.step_runtime["only"].tool_invocation_ids == ["invocation-1"]
    assert agent_state.budget.usage.provider_requests == 2
