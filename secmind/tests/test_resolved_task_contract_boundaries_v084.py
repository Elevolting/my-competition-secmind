from __future__ import annotations

import re
from pathlib import Path

import pytest
from conftest import seal_execution_contract

from secmind.agents import TaskInterpreterAgent
from secmind.canonical_primary import build_canonical_context, build_manifest_only_context
from secmind.dag import DagScheduler
from secmind.llm import QwenGateway
from secmind.orchestration.evidence_projection import build_task_capsule
from secmind.schemas import AgentState, PlanStep, Scenario, TaskRequest
from secmind.task_context import ResolvedTaskContractRequired, require_resolved_task_contract


def _sealed_state() -> AgentState:
    return seal_execution_contract(
        AgentState(
            run_id="contract-boundary-run",
            task=TaskRequest(
                objective="audit the submitted code",
                target_scope=["src"],
                constraints=["read only"],
                expected_outputs=["security_report"],
                autonomy_policy="automatic",
            ),
            scenario=Scenario.CODE_AUDIT,
        )
    )


@pytest.mark.asyncio
async def test_execution_boundaries_ignore_mutated_raw_request(settings) -> None:
    state = _sealed_state()
    state.task.objective = "analyze incident logs instead"
    state.task.target_scope = ["../../host"]
    state.task.constraints = ["permit writes"]
    state.task.expected_outputs = ["credentials"]
    state.task.autonomy_policy = "approval_all"

    interpreted = await TaskInterpreterAgent(QwenGateway(settings)).run(state)
    assert interpreted.scenario == Scenario.CODE_AUDIT

    capsule = build_task_capsule(state)
    assert capsule["objective"] == "audit the submitted code"
    assert capsule["target_scope"] == ["src"]
    assert capsule["constraints"] == ["read only"]
    assert capsule["expected_outputs"] == ["security_report"]
    assert capsule["autonomy_policy"] == "automatic"

    step = PlanStep(
        step_id="scan",
        objective="scan source",
        agent_role="sast_specialist",
        capability="sast",
        tool_candidates=["safe_scan"],
        inputs={},
        success_criteria=["structured result"],
    )
    state.plan = [step]
    scheduler = DagScheduler()
    scheduler.initialize(state)
    work_item = scheduler.build_work_item(state, step)
    assert work_item.autonomy_policy == "automatic"


def test_contract_access_fails_closed_and_rejects_cross_run_binding() -> None:
    missing = AgentState(run_id="missing-contract", task=TaskRequest(objective="inspect supplied data"))
    with pytest.raises(ResolvedTaskContractRequired, match="sealed"):
        require_resolved_task_contract(missing)

    state = _sealed_state()
    state.run_id = "different-run"
    with pytest.raises(ResolvedTaskContractRequired, match="different run"):
        require_resolved_task_contract(state)


def test_execution_modules_do_not_read_mutable_task_authority() -> None:
    repository = Path(__file__).resolve().parents[1]
    paths = [
        "src/secmind/agents.py",
        "src/secmind/dag.py",
        "src/secmind/api_catalogs.py",
        "src/secmind/orchestration/evidence_projection.py",
        "src/secmind/memory_curator.py",
        "src/secmind/orchestration/scenario_execution.py",
        "src/secmind/session_projection.py",
    ]
    forbidden = re.compile(
        r"state\.task\.(?:objective|target_scope|constraints|expected_outputs|"
        r"autonomy_policy|interaction_mode|scoring_mode)"
    )
    violations = {
        path: forbidden.findall((repository / path).read_text(encoding="utf-8"))
        for path in paths
        if forbidden.search((repository / path).read_text(encoding="utf-8"))
    }
    assert violations == {}


def test_canonical_context_rejects_raw_task_request_at_runtime(tmp_path) -> None:
    """The task-level baseline must never silently consume mutable request data."""

    task = TaskRequest(objective="inspect supplied data")
    with pytest.raises(TypeError, match="sealed ResolvedTaskContract"):
        build_canonical_context(
            task_id="raw-request-boundary",
            task=task,  # type: ignore[arg-type]
            scenario=Scenario.UNKNOWN,
            workspace=tmp_path,
            artifacts=[],
        )
    with pytest.raises(TypeError, match="sealed ResolvedTaskContract"):
        build_manifest_only_context(
            task_id="raw-request-boundary",
            task=task,  # type: ignore[arg-type]
            scenario=Scenario.UNKNOWN,
            artifacts=[],
            reason="test",
        )
