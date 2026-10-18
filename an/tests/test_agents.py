from __future__ import annotations

from types import SimpleNamespace

import pytest

from security_agent.agents import (
    AnalysisOutput,
    AnalystAgent,
    PlannerAgent,
    PlanOutput,
    ReporterAgent,
    ReportOutput,
    RouteOutput,
    TaskInterpreterAgent,
    _record_model_call,
)
from security_agent.llm import ModelCallMeta
from security_agent.schemas import (
    AgentState,
    Evidence,
    InputArtifact,
    PlanStep,
    RiskLevel,
    RunStatus,
    Scenario,
    TaskRequest,
    ToolResult,
    ToolStatus,
)


def test_model_usage_availability_survives_later_missing_receipt():
    state = AgentState(run_id='usage-summary', task=TaskRequest(objective='Check model usage'))
    def meta(usage):
        return ModelCallMeta(model_id='model', prompt_version='v1', response_sha256='digest',
                             duration_ms=1, used_fallback=False, usage=usage)

    _record_model_call(state, meta({'prompt_tokens': 11, 'completion_tokens': 3}))
    _record_model_call(state, meta({}))
    assert state.budget.model_calls_used == 2
    assert state.budget.prompt_tokens_used == 11
    assert state.budget.completion_tokens_used == 3
    assert state.budget.model_usage_recorded is True


class StubPlannerGateway:
    def __init__(self, output: PlanOutput) -> None:
        self.settings = SimpleNamespace(demo_mode=False)
        self.output = output

    async def structured(self, **_kwargs):
        return self.output, ModelCallMeta(
            model_id="test-planner",
            prompt_version="v1",
            response_sha256="response",
            duration_ms=1,
            used_fallback=False,
            usage={},
        )


class RecordingGateway:
    def __init__(self) -> None:
        self.settings = SimpleNamespace(demo_mode=False)
        self.calls: list[dict] = []

    async def structured(self, **kwargs):
        self.calls.append(kwargs)
        output_model = kwargs["output_model"]
        if output_model is RouteOutput:
            output = RouteOutput(
                primary_type="penetration",
                confidence=0.96,
                evidence=["模型识别到授权靶场"],
                rationale_summary="题目包含授权靶场地址，应交由渗透模块处理。",
            )
        elif output_model is PlanOutput:
            output = PlanOutput(
                steps=[plan_step("model-step", ["penetration_module"], {"target": "https://target.local"})],
                rationale_summary="模型规划了一个受授权边界约束的渗透步骤。",
            )
        elif output_model is AnalysisOutput:
            output = AnalysisOutput(summary="模型确认工具观测支持一个高风险问题。", findings=[])
        elif output_model is ReportOutput:
            output = ReportOutput(
                executive_summary="模型生成的最终安全总结。", limitations=[], next_steps=["人工复核证据"]
            )
        else:  # pragma: no cover - protects the test double from silent misuse
            raise AssertionError(output_model)
        return output, ModelCallMeta(
            model_id="test-model",
            prompt_version=kwargs["prompt_version"],
            response_sha256="response",
            duration_ms=1,
            used_fallback=False,
            usage={"prompt_tokens": 10, "completion_tokens": 5},
        )


def code_audit_state() -> AgentState:
    return AgentState(
        run_id="planner-test",
        task=TaskRequest(objective="audit the supplied Python file"),
        scenario=Scenario.CODE_AUDIT,
        input_artifacts=[
            InputArtifact(
                original_name="vulnerable_app.py",
                relative_path="vulnerable_app.py",
                sha256="0" * 64,
                size_bytes=1,
            )
        ],
    )


def multi_artifact_state() -> AgentState:
    state = code_audit_state()
    state.input_artifacts = [
        InputArtifact(
            original_name=f"artifact_{index:02d}.og",
            relative_path=f"T3S-CASE/artifact_{index:02d}.og",
            sha256=str(index) * 64,
            size_bytes=index,
        )
        for index in (1, 2)
    ]
    return state


def plan_step(
    step_id: str,
    tools: list[str],
    inputs: dict | None = None,
) -> PlanStep:
    return PlanStep(
        step_id=step_id,
        objective=step_id,
        agent_role="executor",
        tool_candidates=tools,
        inputs=inputs or {},
    )


@pytest.mark.asyncio
async def test_planner_removes_non_tool_post_processing_steps() -> None:
    output = PlanOutput(
        steps=[
            plan_step("scan", ["bandit_python_audit"], {"target": "."}),
            plan_step("analyze", []),
            plan_step("report", []),
        ],
        rationale_summary="scan, analyze, then report",
    )
    state = await PlannerAgent(StubPlannerGateway(output)).run(code_audit_state())

    assert len(state.plan) == 1
    assert state.plan[0].step_id == "scan"
    assert state.plan[0].tool_candidates == ["workspace_security_audit"]


@pytest.mark.asyncio
async def test_planner_falls_back_when_model_returns_no_known_tool() -> None:
    output = PlanOutput(
        steps=[plan_step("invented", ["unknown_tool"])],
        rationale_summary="use an unavailable tool",
    )
    state = await PlannerAgent(StubPlannerGateway(output)).run(code_audit_state())

    assert len(state.plan) == 1
    assert state.plan[0].step_id == "audit-python-bandit"
    assert state.plan[0].inputs == {"target": "."}
    assert state.plan[0].tool_candidates == ["workspace_security_audit"]


@pytest.mark.asyncio
async def test_planner_normalizes_target_file_to_bandit_target() -> None:
    output = PlanOutput(
        steps=[
            plan_step(
                "scan",
                ["bandit_python_audit"],
                {"target_file": "vulnerable_app.py", "output_format": "json"},
            )
        ],
        rationale_summary="scan the uploaded file",
    )
    state = await PlannerAgent(StubPlannerGateway(output)).run(code_audit_state())

    assert state.plan[0].inputs == {"target": "vulnerable_app.py"}
    assert state.plan[0].risk_hint == RiskLevel.R1


@pytest.mark.asyncio
async def test_planner_keeps_multi_file_case_as_one_audit_target() -> None:
    output = PlanOutput(
        steps=[plan_step("scan", ["workspace_security_audit"], {"target": "T3S-CASE/artifact_01.og"})],
        rationale_summary="scan all registered case inputs",
    )
    state = await PlannerAgent(StubPlannerGateway(output)).run(multi_artifact_state())

    assert state.plan[0].inputs == {"target": "T3S-CASE"}


@pytest.mark.asyncio
async def test_uploaded_module_material_uses_its_audit_or_reverse_adapter() -> None:
    proposed = PlanOutput(
        steps=[plan_step("hash", ["mcp:secmind-local:hash_file"], {"path": "missing-file.py"})],
        rationale_summary="hash uploaded material",
    )
    audit = await PlannerAgent(StubPlannerGateway(proposed)).run(code_audit_state())
    assert audit.plan[0].tool_candidates == ["workspace_security_audit"]
    assert audit.plan[0].inputs == {"target": "."}

    reverse = code_audit_state()
    reverse.scenario = Scenario.REVERSE_TRIAGE
    reverse.input_artifacts[0].relative_path = "sample.exe"
    reverse = await PlannerAgent(StubPlannerGateway(proposed)).run(reverse)
    assert reverse.plan[0].tool_candidates == ["reverse_module"]
    assert reverse.plan[0].inputs == {"target": "."}

    logs = code_audit_state()
    logs.scenario = Scenario.LOG_ANALYSIS
    logs.input_artifacts[0].relative_path = "events.log"
    logs = await PlannerAgent(StubPlannerGateway(proposed)).run(logs)
    assert logs.plan[0].tool_candidates == ["log_analysis_module"]


@pytest.mark.asyncio
async def test_interpreter_uses_model_and_passes_scope_and_material(tmp_path) -> None:
    gateway = RecordingGateway()
    material = tmp_path / "question.txt"
    material.write_text("请对授权靶场执行端口枚举和 Web 漏洞验证。", encoding="utf-8")
    state = AgentState(
        run_id="route-model-test",
        task=TaskRequest(
            objective="分析上传题目",
            attachments=[],
            target_scope=["https://target.local"],
        ),
        workspace=str(tmp_path),
        input_artifacts=[
            InputArtifact(
                original_name="question.txt",
                relative_path="question.txt",
                sha256="0" * 64,
                size_bytes=30,
                media_type="text/plain",
            )
        ],
    )
    result = await TaskInterpreterAgent(gateway).run(state)

    assert result.module_route == "penetration"
    assert result.scenario == Scenario.PENETRATION_TEST
    assert result.budget.model_calls_used == 1
    assert result.decisions[-1].model_id == "test-model"
    prompt = gateway.calls[0]["user_prompt"]
    assert "https://target.local" in prompt
    assert "端口枚举" in prompt


@pytest.mark.asyncio
async def test_planner_uses_model_for_penetration() -> None:
    gateway = RecordingGateway()
    state = AgentState(
        run_id="penetration-plan-model-test",
        task=TaskRequest(objective="授权渗透测试", target_scope=["https://target.local"]),
        scenario=Scenario.PENETRATION_TEST,
        module_route="penetration",
    )
    result = await PlannerAgent(gateway).run(state)

    assert result.plan[0].tool_candidates == ["penetration_module"]
    assert result.plan[0].inputs == {"target": "https://target.local"}
    assert result.budget.model_calls_used == 1
    assert result.decisions[-1].model_id == "test-model"


@pytest.mark.asyncio
async def test_analyst_and_reporter_use_model_summaries() -> None:
    gateway = RecordingGateway()
    evidence = Evidence(
        evidence_id="ev-1", source="test", summary="受控观测", artifact_ref="input.txt", sha256="1" * 64
    )
    state = AgentState(
        run_id="summary-model-test",
        task=TaskRequest(objective="代码审计"),
        scenario=Scenario.CODE_AUDIT,
        module_route="code_audit",
        observations=[
            ToolResult(status=ToolStatus.SUCCESS, summary="工具完成", evidence=[evidence], data={"findings": []})
        ],
    )

    state = await AnalystAgent(gateway).run(state)
    state = await ReporterAgent(gateway).run(state)

    assert state.budget.model_calls_used == 2
    assert state.report is not None
    assert state.report.executive_summary == "模型生成的最终安全总结。"
    assert any(item.model_id == "test-model" for item in state.decisions)


@pytest.mark.asyncio
async def test_penetration_submission_is_not_reported_as_completed() -> None:
    state = AgentState(
        run_id="penetration-submitted-only",
        task=TaskRequest(objective="获取授权靶场 flag"),
        scenario=Scenario.PENETRATION_TEST,
        module_route="penetration",
        observations=[
            ToolResult(
                status=ToolStatus.SUCCESS,
                summary="Security Runtime 项目已创建",
                data={"adapter": "penetration_engine", "project_id": "proj-1", "external_status": "submitted"},
            )
        ],
    )
    result = await ReporterAgent(RecordingGateway()).run(state)
    assert result.status == RunStatus.PARTIAL
    assert result.report is not None
    assert result.report.status == RunStatus.PARTIAL


@pytest.mark.asyncio
async def test_penetration_submission_waits_for_external_evidence_before_model_analysis() -> None:
    gateway = RecordingGateway()
    state = AgentState(
        run_id="penetration-analysis-pending",
        task=TaskRequest(objective="获取授权靶场 flag"),
        scenario=Scenario.PENETRATION_TEST,
        module_route="penetration",
        observations=[ToolResult(
            status=ToolStatus.SUCCESS,
            summary="Security Runtime 项目已创建",
            data={"project_id": "proj-1", "external_status": "submitted"},
        )],
    )

    result = await AnalystAgent(gateway).run(state)

    assert gateway.calls == []
    assert result.budget.model_calls_used == 0
    assert result.decisions[-1].decision == "external_analysis_pending"
    assert result.findings == []


@pytest.mark.asyncio
@pytest.mark.parametrize("allow_model", [False, True])
@pytest.mark.parametrize("workbench", [False, True])
async def test_reporter_outputs_require_independent_goal_review(allow_model, workbench) -> None:
    state = AgentState(
        run_id="penetration-flag-reporter",
        task=TaskRequest(objective="获取授权靶场 flag"),
        scenario=Scenario.PENETRATION_TEST,
        module_route="penetration",
        external_execution=({"blackboard": {"planning_mode": "workbench"},
                             "validated_goal_outputs": ["ctfshow{fixture-123}"]} if workbench else {}),
        observations=[ToolResult(status=ToolStatus.SUCCESS, summary="完成", data={
            "external_status": "completed",
            "objective_reached": True,
            "external_facts": [{"description": "找到 ctfshow{fixture-123}"}],
        })],
    )
    result = await ReporterAgent(RecordingGateway()).run(state, allow_model=allow_model)
    assert result.report is not None
    assert result.status == (RunStatus.COMPLETED if workbench else RunStatus.PARTIAL)
    assert result.report.verified_outputs == (["ctfshow{fixture-123}"] if workbench else [])
    assert ("ctfshow{fixture-123}" in result.report.executive_summary) is workbench
