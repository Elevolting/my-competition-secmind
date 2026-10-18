from __future__ import annotations

from types import SimpleNamespace

import pytest
from conftest import seal_execution_contract

from secmind.agents import AnalystAgent, PlannerAgent, ReporterAgent, TaskInterpreterAgent, VerifierAgent
from secmind.llm import QwenGateway
from secmind.schemas import (
    AgentState,
    DecisionRecord,
    Evidence,
    Finding,
    InputArtifact,
    RunStatus,
    Scenario,
    TaskRequest,
    ToolResult,
    ToolStatus,
)


def make_state(objective: str = "audit code", scenario: Scenario = Scenario.CODE_AUDIT) -> AgentState:
    return seal_execution_contract(
        AgentState(run_id="agents-run", task=TaskRequest(objective=objective), scenario=scenario)
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("objective", "expected"),
    [
        ("audit code", Scenario.CODE_AUDIT),
        ("analyze logs", Scenario.LOG_ANALYSIS),
        ("incident response", Scenario.INCIDENT_RESPONSE),
        ("penetration test", Scenario.PENETRATION_TEST),
        ("summarize material", Scenario.UNKNOWN),
    ],
)
async def test_interpreter_routes_every_supported_scenario(settings, objective: str, expected: Scenario) -> None:
    state = await TaskInterpreterAgent(QwenGateway(settings)).run(make_state(objective, expected))
    assert state.scenario == expected
    assert state.decisions[-1].model_id == "deterministic-contract-router"


@pytest.mark.asyncio
async def test_interpreter_uses_sealed_scenario_not_mutable_request_or_inventory(settings) -> None:
    state = make_state("review supplied material", Scenario.LOG_ANALYSIS)
    state.input_artifacts = [
        InputArtifact(original_name="x.py", relative_path="src/x.py", sha256="a" * 64, size_bytes=1)
    ]
    state.task.objective = "audit this Python code instead"
    assert (await TaskInterpreterAgent(QwenGateway(settings)).run(state)).scenario == Scenario.LOG_ANALYSIS


@pytest.mark.asyncio
async def test_planner_offline_budget_and_unsupported_paths(settings) -> None:
    planner = PlannerAgent(QwenGateway(settings))
    unsupported = make_state("logs", Scenario.LOG_ANALYSIS)
    assert not (await planner.run(unsupported)).plan
    assert unsupported.decisions[-1].decision == "no_supported_plan"

    code = make_state()
    code.budget.max_model_calls = 0
    planned = await planner.run(code)
    assert planned.plan[0].tool_candidates == ["bandit_python_audit"]
    assert planned.decisions[-1].model_id == "deterministic-planner-budget-fallback"
    assert planned.budget.usage.provider_requests == 0


class FailingGateway:
    policy = SimpleNamespace(network_enabled=True)

    async def structured(self, **_kwargs):
        raise RuntimeError("provider unavailable")


@pytest.mark.asyncio
async def test_planner_live_failure_degrades_deterministically() -> None:
    state = make_state()
    planned = await PlannerAgent(FailingGateway()).run(state)  # type: ignore[arg-type]
    assert planned.plan
    assert planned.last_error == "Planner model degraded safely: RuntimeError"
    assert planned.decisions[-1].model_id == "deterministic-planner-fallback"


@pytest.mark.asyncio
async def test_analyst_correlates_once_and_handles_empty(settings) -> None:
    analyst = AnalystAgent(QwenGateway(settings))
    empty = make_state()
    assert await analyst.run(empty) is empty

    state = make_state()
    state.observations = [
        ToolResult(
            status=ToolStatus.SUCCESS,
            evidence=[Evidence(evidence_id="ev", source="scanner:1", summary="proof")],
        ),
        ToolResult(status=ToolStatus.ERROR),
    ]
    await analyst.run(state)
    await analyst.run(state)
    assert [item.decision for item in state.decisions].count("cross_tool_correlation") == 1
    assert state.decisions[-1].evidence_ids == ["ev"]


def finding(evidence_ids: list[str]) -> Finding:
    return Finding(
        rule_id="R1",
        severity="HIGH",
        confidence="HIGH",
        path="app.py",
        line=1,
        title="issue",
        description="problem",
        evidence_ids=evidence_ids,
    )


@pytest.mark.asyncio
async def test_verifier_passes_and_rejects_orphaned_or_broken_evidence(settings) -> None:
    verifier = VerifierAgent(QwenGateway(settings))
    passing = make_state()
    passing.evidence = [Evidence(evidence_id="ev", source="scanner", summary="proof")]
    passing.findings = [finding(["ev"])]
    await verifier.run(passing)
    assert passing.decisions[-1].decision == "verification_passed"

    broken = make_state()
    broken.findings = [finding([]), finding(["missing"])]
    await verifier.run(broken)
    assert broken.decisions[-1].decision == "verification_failed"
    assert "broken evidence" in (broken.last_error or "")


@pytest.mark.asyncio
async def test_reporter_requires_authoritative_obligations_before_completed(settings) -> None:
    reporter = ReporterAgent(QwenGateway(settings))
    denied = make_state("logs")
    denied.status = RunStatus.DENIED
    denied.scenario = Scenario.LOG_ANALYSIS
    denied.last_error = "policy denied"
    await reporter.run(denied)
    assert denied.report is not None
    assert denied.report.status == RunStatus.DENIED
    assert len(denied.report.limitations) == 3

    completed = make_state()
    completed.scenario = Scenario.CODE_AUDIT
    completed.observations = [ToolResult(status=ToolStatus.SUCCESS)]
    completed.decisions = [DecisionRecord(decision="ok", rationale_summary="ok")]
    await reporter.run(completed)
    # A successful tool observation alone is not an answer contract.  Without
    # the durable ObligationSet the reporter must fail closed to PARTIAL.
    assert completed.status == RunStatus.PARTIAL
    assert completed.report is not None
    assert completed.report.status == RunStatus.PARTIAL
    assert any("obligation set" in item for item in completed.report.limitations)
    assert "0 finding" in completed.report.executive_summary
