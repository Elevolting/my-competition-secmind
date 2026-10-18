from __future__ import annotations

from pathlib import Path

import pytest

from security_agent.guardrail import Guardrail
from security_agent.ledger import LedgerStore
from security_agent.llm import ModelGateway
from security_agent.orchestrator import SecurityOrchestrator
from security_agent.schemas import (
    AgentState,
    ApprovalDecision,
    ApprovalResponse,
    AttachmentRef,
    PlanStep,
    RiskLevel,
    RunStatus,
    Scenario,
    TaskRequest,
    ToolContext,
    ToolManifest,
    ToolResult,
    ToolStatus,
)
from security_agent.tools import BaseTool, ToolBroker, ToolRegistry, default_registry


class ControlledAuditTool(BaseTool):
    def __init__(self, risk: RiskLevel, fail_once: bool = False) -> None:
        self.manifest = ToolManifest(
            name="workspace_security_audit",
            version="test",
            description="controlled test tool",
            scenarios=[Scenario.CODE_AUDIT],
            input_schema={},
            output_schema={},
            risk_level=risk,
        )
        self.fail_once = fail_once
        self.calls = 0

    async def invoke(self, args: dict, context: ToolContext) -> ToolResult:
        self.calls += 1
        if self.fail_once and self.calls == 1:
            return ToolResult(
                status=ToolStatus.ERROR,
                error_code="TRANSIENT",
                error_message="temporary failure",
            )
        return ToolResult(status=ToolStatus.SUCCESS, data={"findings": []}, summary="ok")


def controlled_orchestrator(settings, risk: RiskLevel, fail_once: bool = False):
    settings.prepare_directories()
    (settings.input_root / "app.py").write_text("print('ok')", encoding="utf-8")
    ledger = LedgerStore(settings.database_url)
    registry = ToolRegistry()
    tool = ControlledAuditTool(risk, fail_once)
    registry.register(tool)
    orchestrator = SecurityOrchestrator(
        settings,
        ledger,
        ModelGateway(settings),
        ToolBroker(registry, Guardrail()),
    )
    return orchestrator, ledger, tool


@pytest.mark.asyncio
async def test_code_audit_end_to_end(settings, tmp_path: Path) -> None:
    settings.prepare_directories()
    (settings.input_root / "bad.py").write_text(
        "import subprocess\nsubprocess.Popen('echo unsafe', shell=True)\n", encoding="utf-8"
    )
    ledger = LedgerStore(settings.database_url)
    orchestrator = SecurityOrchestrator(
        settings,
        ledger,
        ModelGateway(settings),
        ToolBroker(default_registry(), Guardrail()),
    )
    state = await orchestrator.start(
        TaskRequest(
            objective="审计 Python 代码并给出漏洞报告",
            attachments=[AttachmentRef(ref="bad.py")],
        ),
        "e2e-run",
    )
    assert state.status == RunStatus.COMPLETED
    assert state.report is not None
    assert state.report.findings
    assert state.report.evidence
    assert ledger.verify("e2e-run")
    event_types = [event.event_type for event in ledger.events("e2e-run")]
    assert "guardrail.evaluated" in event_types
    assert "report.generated" in event_types


@pytest.mark.asyncio
async def test_r2_tool_interrupts_and_resumes(settings) -> None:
    orchestrator, ledger, tool = controlled_orchestrator(settings, RiskLevel.R2)
    waiting = await orchestrator.start(
        TaskRequest(
            objective="audit code",
            attachments=[AttachmentRef(ref="app.py")],
            autonomy_policy="graded",
        ),
        "approval-run",
    )
    assert waiting.status == RunStatus.WAITING_APPROVAL
    assert waiting.pending_approval is not None
    completed = await orchestrator.resume(
        "approval-run", ApprovalResponse(decision=ApprovalDecision.APPROVE, reason="authorized")
    )
    assert completed.status == RunStatus.COMPLETED
    assert tool.calls == 1
    assert ledger.verify("approval-run")


@pytest.mark.asyncio
async def test_r3_tool_requires_approval_without_early_execution(settings) -> None:
    orchestrator, _, tool = controlled_orchestrator(settings, RiskLevel.R3)
    state = await orchestrator.start(
        TaskRequest(objective="audit code", attachments=[AttachmentRef(ref="app.py")]),
        "denied-run",
    )
    assert state.status == RunStatus.WAITING_APPROVAL
    assert state.pending_approval is not None and state.pending_approval.risk_level == RiskLevel.R3
    assert tool.calls == 0
    completed = await orchestrator.resume('denied-run', ApprovalResponse(decision=ApprovalDecision.APPROVE))
    assert completed.status == RunStatus.COMPLETED
    assert tool.calls == 1


@pytest.mark.asyncio
async def test_idempotent_tool_failure_is_retried(settings) -> None:
    orchestrator, _, tool = controlled_orchestrator(settings, RiskLevel.R1, fail_once=True)
    state = await orchestrator.start(
        TaskRequest(objective="audit code", attachments=[AttachmentRef(ref="app.py")]),
        "retry-run",
    )
    assert state.status == RunStatus.COMPLETED
    assert state.retry_counts["audit-python-bandit"] == 1
    assert tool.calls == 2


@pytest.mark.asyncio
async def test_unsupported_scenario_produces_partial_report(settings) -> None:
    orchestrator, _, _ = controlled_orchestrator(settings, RiskLevel.R1)
    state = await orchestrator.start(TaskRequest(objective="自动执行应急隔离"), "incident-run")
    assert state.status == RunStatus.PARTIAL
    assert state.report is not None
    assert state.report.limitations


@pytest.mark.asyncio
async def test_penetration_verification_waits_for_external_terminal(monkeypatch, settings) -> None:
    settings.prepare_directories()
    ledger = LedgerStore(settings.database_url)
    registry = ToolRegistry()
    registry.register(ControlledAuditTool(RiskLevel.R1))
    orchestrator = SecurityOrchestrator(settings, ledger, ModelGateway(settings), ToolBroker(registry, Guardrail()))
    state = AgentState(
        run_id="penetration-wait-gate",
        task=TaskRequest(objective="获取授权靶场 flag"),
        scenario=Scenario.PENETRATION_TEST,
        module_route="penetration",
        status=RunStatus.RUNNING,
        plan=[PlanStep(step_id="penetrate", objective="执行", agent_role="analyst", tool_candidates=["workspace_security_audit"], inputs={})],
        observations=[ToolResult(status=ToolStatus.SUCCESS, data={"project_id": "proj-1", "adapter": "penetration_engine"})],
        external_execution={"blackboard": {"backend": "remote", "project_id": "proj-1", "status": "entered"}},
    )
    calls = []

    async def fake_wait(*_args, on_update=None, **_kwargs):
        calls.append(True)
        if on_update:
            await on_update({"project_id": "proj-1", "status": "running", "terminal": False, "objective_reached": False})
        return {
            "status": "completed",
            "terminal": True,
            "objective_reached": True,
            "failed": False,
            "project_id": "proj-1",
            "fact_count": 2,
            "intent_count": 1,
            "detail": {
                "project": {"id": "proj-1", "title": "sec-task-penetration-wait-gate", "status": "completed"},
                "facts": [{"id": "flag", "description": "flag{verified}"}],
                "intents": [{"id": "goal-intent", "to": "goal", "concluded_at": "now"}],
            },
        }

    monkeypatch.setattr("security_agent.orchestrator.wait_for_project_terminal", fake_wait)
    result = await orchestrator._verify({"agent": state.model_dump(mode="json")})
    updated = result["agent"]
    assert calls == [True]
    assert updated["status"] == RunStatus.RUNNING.value
    assert updated["external_execution"]["status"] == "completed"
    assert updated["external_execution"]["objective_reached"] is True
    assert updated["external_execution"]["exploration_complete"] is True
    assert updated["observations"][-1]["data"]["external_facts"][0]["description"] == "flag{verified}"


async def test_penetration_verification_rejects_project_outside_blackboard(monkeypatch, settings) -> None:
    settings.prepare_directories()
    ledger = LedgerStore(settings.database_url)
    orchestrator = SecurityOrchestrator(
        settings, ledger, ModelGateway(settings), ToolBroker(default_registry(), Guardrail()),
    )
    state = AgentState(
        run_id='wrong-penetration-project', task=TaskRequest(objective='授权渗透测试'),
        scenario=Scenario.PENETRATION_TEST, module_route='penetration', status=RunStatus.RUNNING,
        plan=[PlanStep(step_id='penetrate', objective='执行', agent_role='analyst',
                       tool_candidates=['penetration_module'], inputs={'target': 'https://target.test'})],
        observations=[ToolResult(status=ToolStatus.SUCCESS, data={'project_id': 'other-project'})],
        external_execution={'blackboard': {'backend': 'remote', 'project_id': 'bound-project', 'status': 'entered'}},
    )

    async def unexpected_wait(*_args, **_kwargs):
        pytest.fail('mismatched project was polled')

    monkeypatch.setattr('security_agent.orchestrator.wait_for_project_terminal', unexpected_wait)
    result = await orchestrator._verify({'agent': state.model_dump(mode='json')})
    assert result['route'] == 'report'
    assert result['agent']['status'] == RunStatus.FAILED.value
    assert result['agent']['observations'][-1]['status'] == ToolStatus.ERROR.value


async def test_penetration_verification_rejects_changed_remote_project_identity(monkeypatch, settings) -> None:
    settings.prepare_directories()
    ledger = LedgerStore(settings.database_url)
    orchestrator = SecurityOrchestrator(
        settings, ledger, ModelGateway(settings), ToolBroker(default_registry(), Guardrail()),
    )
    state = AgentState(
        run_id='changed-remote-project', task=TaskRequest(objective='授权渗透测试'),
        scenario=Scenario.PENETRATION_TEST, module_route='penetration', status=RunStatus.RUNNING,
        plan=[PlanStep(step_id='penetrate', objective='执行', agent_role='analyst',
                       tool_candidates=['penetration_module'], inputs={'target': 'https://target.test'})],
        observations=[ToolResult(status=ToolStatus.SUCCESS, data={'project_id': 'bound-project'})],
        external_execution={'blackboard': {'backend': 'remote', 'project_id': 'bound-project', 'status': 'entered'}},
    )

    async def wrong_detail(*_args, on_update=None, **_kwargs):
        if on_update:
            await on_update({'project_id': 'bound-project', 'status': 'completed', 'terminal': True})
        return {'project_id': 'bound-project', 'status': 'completed', 'terminal': True,
                'objective_reached': True, 'failed': False,
                'detail': {'project': {'id': 'bound-project', 'title': 'another-task', 'status': 'completed'},
                           'facts': [], 'intents': [{'to': 'goal', 'concluded_at': 'now'}]}}

    monkeypatch.setattr('security_agent.orchestrator.wait_for_project_terminal', wrong_detail)
    result = await orchestrator._verify({'agent': state.model_dump(mode='json')})
    assert result['route'] == 'report'
    assert result['agent']['status'] == RunStatus.FAILED.value
    assert result['agent']['external_execution']['status'] == 'identity_mismatch'
    assert 'external_facts' not in result['agent']['observations'][-1]['data']
