import asyncio
from datetime import UTC, datetime

import httpx
import pytest
from tenacity import wait_none
from test_orchestrator import controlled_orchestrator

from security_agent.agents import ReporterAgent
from security_agent.llm import ModelGateway
from security_agent.schemas import (
    AgentState,
    ApprovalDecision,
    ApprovalResponse,
    AttachmentRef,
    BudgetState,
    PlanStep,
    RiskLevel,
    RunStatus,
    Scenario,
    TaskRequest,
    ToolResult,
    ToolStatus,
)
from security_agent.service import EventHub, RunService


def task():
    return TaskRequest(objective='audit code', attachments=[AttachmentRef(ref='app.py')])


@pytest.mark.asyncio
async def test_queued_run_is_recovered(settings):
    orchestrator, ledger, tool = controlled_orchestrator(settings, RiskLevel.R1)
    pending = AgentState(run_id='queued-restart', task=task())
    ledger.save_state(pending)
    service = RunService(orchestrator, ledger, EventHub())
    await service.recover_incomplete()
    await asyncio.gather(*tuple(service._tasks))
    assert ledger.load_state(pending.run_id).status == RunStatus.COMPLETED
    assert tool.calls == 1
    assert ledger.verify(pending.run_id)


@pytest.mark.asyncio
async def test_cancel_api_service_persists_partial_terminal_report(settings):
    orchestrator, ledger, _ = controlled_orchestrator(settings, RiskLevel.R1)
    state = AgentState(run_id='cancel-before-start', task=task(), status=RunStatus.PENDING)
    ledger.save_state(state)
    service = RunService(orchestrator, ledger, EventHub())

    cancelled = await service.cancel(state.run_id)

    assert cancelled.status == RunStatus.PARTIAL
    assert cancelled.report is not None
    assert cancelled.last_error == "用户请求取消任务"
    assert cancelled.external_execution["status"] == "cancelled"
    assert any(event.event_type == "run.cancel.requested" for event in ledger.events(state.run_id))
    assert ledger.verify(state.run_id)


@pytest.mark.asyncio
async def test_cancel_waiting_approval_removes_stale_request(settings):
    orchestrator, ledger, _ = controlled_orchestrator(settings, RiskLevel.R2)
    waiting = await orchestrator.start(task(), "cancel-awaiting-approval")
    assert waiting.status == RunStatus.WAITING_APPROVAL
    assert waiting.pending_approval is not None
    service = RunService(orchestrator, ledger, EventHub())

    cancelled = await service.cancel(waiting.run_id)

    assert cancelled.status == RunStatus.PARTIAL
    assert cancelled.pending_approval is None
    assert service.summary(waiting.run_id).pending_approval is None
    assert ledger.verify(waiting.run_id)


@pytest.mark.asyncio
async def test_cancel_running_tool_stops_local_coroutine(settings):
    orchestrator, ledger, tool = controlled_orchestrator(settings, RiskLevel.R1)
    service = RunService(orchestrator, ledger, EventHub())
    started = asyncio.Event()
    stopped = asyncio.Event()

    async def slow(*_args):
        started.set()
        try:
            await asyncio.sleep(60)
        finally:
            stopped.set()

    tool.invoke = slow
    run_id = service.submit(task(), run_id="cancel-running")
    await asyncio.wait_for(started.wait(), timeout=10)

    cancelled = await service.cancel(run_id)
    await asyncio.wait_for(stopped.wait(), timeout=10)
    await asyncio.gather(*tuple(service._tasks), return_exceptions=True)

    assert cancelled.status == RunStatus.PARTIAL
    assert ledger.load_state(run_id).status == RunStatus.PARTIAL
    assert ledger.load_state(run_id).report is not None
    assert ledger.verify(run_id)


@pytest.mark.asyncio
async def test_cancel_requests_remote_stop_without_claiming_remote_terminal(settings, monkeypatch):
    orchestrator, ledger, _ = controlled_orchestrator(settings, RiskLevel.R1)
    service = RunService(orchestrator, ledger, EventHub())
    state = AgentState(run_id="cancel-remote-request", task=task(), status=RunStatus.RUNNING,
                       external_execution={"module": "secmind", "remote_run_id": "remote-1", "status": "running"})
    ledger.save_state(state)
    requests = []
    real_client = httpx.AsyncClient

    def handler(request):
        requests.append((request.method, request.url.path))
        return httpx.Response(202, json={"run_id": "remote-1", "status": "cancelled"})

    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: real_client(
        transport=httpx.MockTransport(handler), **kwargs))
    cancelled = await service.cancel(state.run_id)

    assert requests == [("POST", "/api/v1/runs/remote-1/cancel")]
    assert cancelled.external_execution["cancellation_requested"] is True
    assert cancelled.external_execution["status"] == "cancellation_requested"
    assert service.summary(state.run_id).can_retry is False
    assert cancelled.status == RunStatus.PARTIAL
    assert ledger.verify(state.run_id)


@pytest.mark.asyncio
async def test_cancelled_penetration_blackboard_can_retry_after_confirmed_stop(settings, monkeypatch):
    orchestrator, ledger, _ = controlled_orchestrator(settings, RiskLevel.R1)
    service = RunService(orchestrator, ledger, EventHub())
    state = AgentState(run_id="cancel-penetration-board", task=TaskRequest(objective="test"),
                       status=RunStatus.RUNNING, module_route="penetration",
                       external_execution={"project_id": "proj-test", "status": "running",
                           "cancellation_requested": True,
                           "blackboard": {"project_id": "proj-test", "status": "entered"}})
    ledger.save_state(state)

    async def stop_board(current, _reason):
        current.external_execution["blackboard"]["status"] = "stopped"

    monkeypatch.setattr(orchestrator.blackboard, "stop", stop_board)
    cancelled = await service.cancel(state.run_id)

    assert cancelled.external_execution["status"] == "stopped"
    assert service.summary(state.run_id).can_retry is True


@pytest.mark.asyncio
async def test_cancel_rejects_remote_receipt_for_another_run(settings, monkeypatch):
    orchestrator, ledger, _ = controlled_orchestrator(settings, RiskLevel.R1)
    service = RunService(orchestrator, ledger, EventHub())
    state = AgentState(run_id="cancel-invalid-receipt", task=task(), status=RunStatus.RUNNING,
                       external_execution={"remote_run_id": "remote-1", "status": "running"})
    ledger.save_state(state)
    real_client = httpx.AsyncClient
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: real_client(
        transport=httpx.MockTransport(lambda request: httpx.Response(202, json={
            "run_id": "another-run", "status": "cancelled",
        })), **kwargs))

    cancelled = await service.cancel(state.run_id)

    assert cancelled.external_execution["status"] == "cancellation_unconfirmed"
    assert cancelled.external_execution["cancellation_error"] == "ValueError"
    assert cancelled.external_execution.get("cancellation_requested") is not True
    assert service.summary(state.run_id).can_retry is False


@pytest.mark.asyncio
async def test_recovery_continues_after_tool_without_reexecuting(settings):
    orchestrator, ledger, tool = controlled_orchestrator(settings, RiskLevel.R1)
    state = AgentState(run_id='after-tool', task=task(), status=RunStatus.RUNNING,
        scenario=Scenario.CODE_AUDIT, workspace=str(settings.input_root), resume_node='observe',
        plan=[PlanStep(step_id='audit', objective='audit', agent_role='analyst', tool_candidates=['workspace_security_audit'])],
        observations=[ToolResult(status=ToolStatus.SUCCESS, data={'findings': []}, summary='checked')])
    ledger.save_state(state)
    recovered = await orchestrator.recover(state.run_id)
    assert recovered.status == RunStatus.COMPLETED
    assert recovered.resume_node == 'end'
    assert tool.calls == 0
    assert ledger.verify(state.run_id)


@pytest.mark.asyncio
async def test_uncertain_non_idempotent_tool_is_not_replayed(settings):
    orchestrator, ledger, tool = controlled_orchestrator(settings, RiskLevel.R1)
    tool.manifest.idempotent = False
    state = AgentState(run_id='uncertain', task=task(), status=RunStatus.RUNNING,
        active_node='execute', resume_node='execute', active_node_started_at=datetime.now(UTC),
        plan=[PlanStep(step_id='audit', objective='audit', agent_role='analyst', tool_candidates=['workspace_security_audit'])])
    ledger.save_state(state)
    recovered = await orchestrator.recover(state.run_id)
    assert recovered.status == RunStatus.PARTIAL
    assert recovered.report.limitations
    assert tool.calls == 0


@pytest.mark.asyncio
async def test_approval_survives_restart_and_edit_is_reassessed(settings):
    first, ledger, tool = controlled_orchestrator(settings, RiskLevel.R2)
    waiting = await first.start(task(), 'approval-edit')
    assert waiting.status == RunStatus.WAITING_APPROVAL
    restarted, _, restarted_tool = controlled_orchestrator(settings, RiskLevel.R2)
    result = await restarted.resume(waiting.run_id, ApprovalResponse(decision=ApprovalDecision.EDIT,
        edited_parameters={'target': 'destructive'}))
    assert result.status == RunStatus.WAITING_APPROVAL
    assert result.pending_approval is not None and result.pending_approval.risk_level == RiskLevel.R3
    assert restarted_tool.calls == tool.calls == 0
    approved = await restarted.resume(waiting.run_id, ApprovalResponse(decision=ApprovalDecision.APPROVE))
    assert approved.status == RunStatus.COMPLETED
    assert restarted_tool.calls == 1
    assert ledger.verify(waiting.run_id)


@pytest.mark.asyncio
async def test_duplicate_approval_executes_once(settings):
    orchestrator, ledger, tool = controlled_orchestrator(settings, RiskLevel.R2)
    waiting = await orchestrator.start(task(), 'approval-once')
    service = RunService(orchestrator, ledger, EventHub())
    response = ApprovalResponse(decision=ApprovalDecision.APPROVE)
    service.submit_approval(waiting.run_id, response)
    with pytest.raises(ValueError):
        service.submit_approval(waiting.run_id, response)
    await asyncio.gather(*tuple(service._tasks))
    assert ledger.load_state(waiting.run_id).status == RunStatus.COMPLETED
    assert tool.calls == 1


@pytest.mark.asyncio
async def test_runtime_deadline_stops_tool_and_preserves_partial_report(settings):
    orchestrator, ledger, tool = controlled_orchestrator(settings, RiskLevel.R1)
    settings.max_runtime_seconds = 1
    cancelled = []
    async def slow(*_args):
        try:
            await asyncio.sleep(10)
        finally:
            cancelled.append(True)
    tool.invoke = slow
    pending = AgentState(run_id='deadline', task=task(), status=RunStatus.RUNNING,
        workspace=str(settings.input_root), resume_node='execute', budget=BudgetState(max_runtime_seconds=1),
        plan=[PlanStep(step_id='audit', objective='audit', agent_role='analyst', tool_candidates=['workspace_security_audit'])])
    ledger.save_state(pending)
    state = await orchestrator.recover(pending.run_id)
    assert cancelled == [True]
    assert state.status == state.report.status == RunStatus.PARTIAL
    assert state.budget.runtime_seconds_used >= 1
    assert ledger.verify(state.run_id)


@pytest.mark.asyncio
async def test_exhausted_tool_budget_does_not_index_missing_observation(settings):
    orchestrator, ledger, tool = controlled_orchestrator(settings, RiskLevel.R1)
    settings.max_tool_calls = 0
    state = await orchestrator.start(task(), 'tool-budget')
    assert state.status == RunStatus.PARTIAL
    assert tool.calls == 0
    assert state.report is not None


@pytest.mark.asyncio
async def test_failed_provider_requests_consume_budget(monkeypatch, settings):
    orchestrator, ledger, _ = controlled_orchestrator(settings, RiskLevel.R1)
    settings.demo_mode = False
    settings.model_api_key = 'test-only'
    monkeypatch.setattr('security_agent.llm.wait_exponential_jitter', lambda **_: wait_none())
    calls = []
    def provider(request):
        calls.append(request)
        return httpx.Response(503)
    async with httpx.AsyncClient(transport=httpx.MockTransport(provider)) as client:
        orchestrator.interpreter.gateway = ModelGateway(settings, client)
        state = AgentState(run_id='model-budget', task=task(), budget=BudgetState(max_model_calls=2))
        ledger.save_state(state)
        result = await orchestrator._classify({'agent': state.model_dump(mode='json')})
    assert len(calls) == 2
    assert result['agent']['budget']['provider_requests_used'] == 2
    events = ledger.events(state.run_id)
    assert len([e for e in events if e.event_type == 'llm.stream.started']) == 2
    assert len([e for e in events if e.event_type == 'llm.stream.failed']) == 2


@pytest.mark.asyncio
async def test_new_penetration_run_starts_with_longer_timeout(settings, monkeypatch):
    orchestrator, ledger, _ = controlled_orchestrator(settings, RiskLevel.R1)
    task = TaskRequest(objective='渗透测试', target_scope=['https://target.test/'])
    observed = []
    original_timeout = asyncio.timeout

    def capture_timeout(seconds):
        observed.append(seconds)
        return original_timeout(seconds)

    class Graph:
        async def ainvoke(self, value, _config):
            return value

    monkeypatch.setattr(orchestrator, 'graph', Graph())
    monkeypatch.setattr('security_agent.orchestrator.asyncio.timeout', capture_timeout)
    result = await orchestrator.start(task, 'new-penetration-budget')
    assert result.budget.max_runtime_seconds == 2400
    assert observed == [2400]

    service = RunService(orchestrator, ledger, EventHub())
    monkeypatch.setattr(service, '_spawn', lambda coroutine: coroutine.close())
    run_id = service.submit(task, run_id='queued-penetration-budget')
    assert ledger.load_state(run_id).budget.max_runtime_seconds == 2400


@pytest.mark.asyncio
async def test_penetration_classification_preserves_explicit_retry_budget(settings, monkeypatch):
    orchestrator, ledger, _ = controlled_orchestrator(settings, RiskLevel.R1)

    async def classify(state, **_kwargs):
        state.scenario = Scenario.PENETRATION_TEST
        state.module_route = 'penetration'
        return state

    async def enter(_state):
        return 'project-test'

    monkeypatch.setattr(orchestrator.interpreter, 'run', classify)
    monkeypatch.setattr(orchestrator.blackboard, 'enter', enter)
    state = AgentState(run_id='retry-penetration-budget', task=TaskRequest(objective='get the flag'),
                       retry_of='original', status=RunStatus.RUNNING,
                       budget=BudgetState(max_runtime_seconds=1200))
    ledger.save_state(state)
    result = await orchestrator._classify({'agent': state.model_dump(mode='json')})
    assert result['agent']['budget']['max_runtime_seconds'] == 1200


@pytest.mark.asyncio
async def test_report_does_not_promote_partial_or_broken_evidence(settings):
    reporter = ReporterAgent(ModelGateway(settings))
    state = AgentState(run_id='partial-report', task=task(), status=RunStatus.PARTIAL,
        last_error='Evidence validation failed', observations=[ToolResult(status=ToolStatus.SUCCESS)])
    result = await reporter.run(state)
    assert result.status == result.report.status == RunStatus.PARTIAL
