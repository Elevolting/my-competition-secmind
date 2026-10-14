import pytest
from fastapi.testclient import TestClient
from test_orchestrator import controlled_orchestrator

from security_agent.agents import PlannerAgent, PlanOutput
from security_agent.api import create_app
from security_agent.run_recovery import stop_reason
from security_agent.schemas import (
    AgentState,
    BudgetState,
    Finding,
    InputArtifact,
    PlanStep,
    RiskLevel,
    RunRetryRequest,
    RunStatus,
    Scenario,
    TaskRequest,
    ToolResult,
    ToolStatus,
)
from security_agent.scoped_file_post import CONSTRAINT as SCOPED_POST_CONSTRAINT
from security_agent.scoped_file_post import POLICY as SCOPED_POST_POLICY
from security_agent.scoped_file_post import REQUEST_ID as SCOPED_POST_REQUEST_ID
from security_agent.scoped_file_post import SOURCE_RUN_ID as SCOPED_POST_SOURCE_RUN_ID
from security_agent.scoped_file_post import grant_path
from security_agent.service import EventHub, RunService


def failed_run(run_id="original", **kwargs):
    return AgentState(run_id=run_id, task=TaskRequest(objective="audit original input", target_scope=["local"]),
                      status=RunStatus.PARTIAL, **kwargs)


@pytest.mark.asyncio
async def test_retry_is_new_run_preserving_source_and_deduplicating_after_restart(settings):
    orchestrator, ledger, _ = controlled_orchestrator(settings, RiskLevel.R1)
    service = RunService(orchestrator, ledger, EventHub())
    original = failed_run(observations=[ToolResult(status=ToolStatus.TIMEOUT, error_message="request timed out")])
    ledger.save_state(original)
    before = ledger.load_state(original.run_id).model_dump()
    request = RunRetryRequest(request_id="retry-request-0001", max_runtime_seconds=1200)
    child_id = service.retry(original.run_id, request)
    assert child_id != original.run_id
    child = ledger.load_state(child_id)
    assert child.task == original.task
    assert child.retry_of == original.run_id
    assert child.budget.max_runtime_seconds == 1200
    assert child.budget.tool_calls_used == 0
    assert child.approvals == [] and child.observations == []
    assert "timed out" in child.retry_context["stop_reason"]
    assert service.retry(original.run_id, RunRetryRequest(
        request_id="different-click-0002", max_runtime_seconds=1200)) == child_id
    with pytest.raises(ValueError, match="运行时限或网络策略不同"):
        service.retry(original.run_id, RunRetryRequest(request_id="changed-click-0003"))
    restarted = RunService(orchestrator, ledger, EventHub())
    assert restarted.retry(original.run_id, request) == child_id
    with pytest.raises(ValueError, match="已绑定不同"):
        restarted.retry(original.run_id, RunRetryRequest(
            request_id=request.request_id, max_runtime_seconds=1800))
    assert ledger.load_state(original.run_id).model_dump() == before
    assert ledger.verify(child_id)
    await service.shutdown()


def test_legacy_stop_reason_and_runtime_budget(settings):
    assert "deadline exceeded" in stop_reason(failed_run(observations=[
        ToolResult(status=ToolStatus.ERROR, error_message="context deadline exceeded")]))
    state = failed_run(last_error="refreshed external status", budget=BudgetState(runtime_seconds_used=600))
    assert "600" in stop_reason(state)


def test_run_summaries_report_artifact_count_independently_of_tool_calls(settings):
    orchestrator, ledger, _ = controlled_orchestrator(settings, RiskLevel.R1)
    service = RunService(orchestrator, ledger, EventHub())
    state = failed_run(run_id='artifact-summary', budget=BudgetState(tool_calls_used=3),
        input_artifacts=[InputArtifact(original_name='sample.txt', relative_path='sample.txt',
                                       sha256='a' * 64, size_bytes=4)])
    ledger.save_state(state)
    assert service.summary(state.run_id).input_artifact_count == 1
    assert service.summaries()[0].input_artifact_count == 1
    assert service.summary(state.run_id).budget.tool_calls_used == 3


def test_submit_with_existing_run_id_is_idempotent_and_never_overwrites(settings, monkeypatch):
    orchestrator, ledger, _ = controlled_orchestrator(settings, RiskLevel.R1)
    service = RunService(orchestrator, ledger, EventHub())
    existing = failed_run(run_id="stable-run", last_error="keep this", retry_context={"marker": "original"})
    ledger.save_state(existing)
    original_events = len(ledger.events(existing.run_id))
    spawned = []
    monkeypatch.setattr(service, "_spawn", lambda coroutine: (spawned.append(coroutine), coroutine.close()))

    same = service.submit(existing.task.model_copy(deep=True), run_id=existing.run_id)

    assert same == existing.run_id
    assert ledger.load_state(existing.run_id).model_dump() == existing.model_dump()
    assert len(ledger.events(existing.run_id)) == original_events
    assert spawned == []
    with pytest.raises(ValueError, match="已绑定另一项任务"):
        service.submit(TaskRequest(objective="different task"), run_id=existing.run_id)


def test_penetration_retry_updates_only_child_policy_and_runtime(settings, monkeypatch):
    orchestrator, ledger, _ = controlled_orchestrator(settings, RiskLevel.R1)
    service = RunService(orchestrator, ledger, EventHub())
    source = AgentState(run_id='penetration-source',
        task=TaskRequest(objective='get the flag', target_scope=['https://target.test/'],
                         constraints=['仅允许只读静态分析']),
        scenario=Scenario.PENETRATION_TEST, module_route='penetration', status=RunStatus.PARTIAL,
        external_execution={'project_id': 'proj-old', 'status': 'stopped'})
    ledger.save_state(source)
    spawned = []
    monkeypatch.setattr(service, '_spawn', lambda coroutine: (spawned.append(coroutine), coroutine.close()))

    child_id = service.retry(source.run_id, RunRetryRequest(
        request_id='penetration-retry-001', network_policy='read_only_http'))
    child = ledger.load_state(child_id)
    assert child.retry_of == source.run_id
    assert child.task.network_policy == 'read_only_http'
    assert child.task.constraints == ['仅允许对授权 URL 发起 GET/HEAD 只读请求，不发送请求体或跟随跳转']
    assert child.task.target_scope == source.task.target_scope
    assert child.budget.max_runtime_seconds == 2400
    assert ledger.load_state(source.run_id).task.network_policy == 'none'
    assert ledger.load_state(source.run_id).task.constraints == ['仅允许只读静态分析']
    assert len(spawned) == 1

    source.run_id = 'penetration-source-static'
    source.task.network_policy = 'read_only_http'
    source.task.constraints = ['仅允许对授权 URL 发起 GET/HEAD 只读请求，不发送请求体或跟随跳转']
    ledger.save_state(source)
    static_id = service.retry(source.run_id, RunRetryRequest(
        request_id='penetration-retry-002', network_policy='none'))
    static_child = ledger.load_state(static_id)
    assert static_child.task.network_policy == 'none'
    assert static_child.task.constraints == ['仅允许只读静态分析']
    assert static_child.task.target_scope == source.task.target_scope


def test_scoped_post_grant_is_one_retry_only(settings, monkeypatch):
    import json
    orchestrator, ledger, _ = controlled_orchestrator(settings, RiskLevel.R1)
    service = RunService(orchestrator, ledger, EventHub())
    target = 'https://target.test/'
    grant_path(settings).parent.mkdir(parents=True, exist_ok=True)
    grant_path(settings).write_text(json.dumps({
        'source_run_id': SCOPED_POST_SOURCE_RUN_ID,
        'target_url': target,
        'request_id': SCOPED_POST_REQUEST_ID,
    }), encoding='utf-8')
    source = AgentState(run_id=SCOPED_POST_SOURCE_RUN_ID,
        task=TaskRequest(objective='get flag', target_scope=['uploaded-source', target],
                         network_policy='read_only_http',
                         constraints=['仅允许对授权 URL 发起 GET/HEAD 只读请求，不发送请求体或跟随跳转']),
        scenario=Scenario.PENETRATION_TEST, module_route='penetration', status=RunStatus.PARTIAL,
        external_execution={'project_id': 'proj-old', 'status': 'stopped'},
        findings=[Finding(rule_id='PENETRATION-CONFIRMED-RESULT', path=target,
                          title='prior fact', description='POST file form observed',
                          evidence_ids=['prior-evidence'])])
    ledger.save_state(source)
    monkeypatch.setattr(service, '_spawn', lambda coroutine: coroutine.close())
    request = RunRetryRequest(request_id=SCOPED_POST_REQUEST_ID, network_policy=SCOPED_POST_POLICY)
    child_id = service.retry(source.run_id, request)
    child = ledger.load_state(child_id)
    assert child.task.network_policy == SCOPED_POST_POLICY
    assert child.task.constraints == [SCOPED_POST_CONSTRAINT]
    assert child.task.target_scope == ['uploaded-source', target]
    assert child.retry_context['prior_blackboard_fact']['description'] == 'POST file form observed'
    assert child.budget.max_runtime_seconds == 2400
    assert service.retry(source.run_id, request) == child_id
    assert ledger.load_state(source.run_id).task.network_policy == 'read_only_http'
    with pytest.raises(ValueError, match='受限 POST'):
        service.submit(child.task, run_id='forged-run')
    other = source.model_copy(deep=True)
    other.run_id = 'other-source'
    ledger.save_state(other)
    with pytest.raises(ValueError, match='受限 POST'):
        service.retry(other.run_id, request)


def test_direct_api_create_cannot_use_scoped_post(settings):
    app = create_app(settings)
    with TestClient(app) as client:
        response = client.post('/api/v1/tasks', json={
            'objective': 'authorized penetration test',
            'target_scope': ['https://target.test/'],
            'network_policy': SCOPED_POST_POLICY,
        })
    assert response.status_code == 409


def test_retry_api_rejects_invalid_active_and_uncertain_external_runs(settings, monkeypatch):
    app = create_app(settings)
    service = app.state.service
    # API contract only; do not run real tools or background monitors.
    spawned = []
    def capture(coroutine):
        spawned.append(coroutine)
        coroutine.close()
    monkeypatch.setattr(service, "_spawn", capture)
    with TestClient(app) as client:
        source = failed_run()
        service.ledger.save_state(source)
        body = {"request_id": "api-retry-00000001", "max_runtime_seconds": 1200}
        assert client.post('/api/v1/runs/missing/retry', json=body).status_code == 404
        assert client.post('/api/v1/runs/original/retry', json={**body, "max_runtime_seconds": 0}).status_code == 422
        for status in [RunStatus.RUNNING, RunStatus.WAITING_APPROVAL, RunStatus.DENIED, RunStatus.COMPLETED]:
            source.status = status
            service.ledger.save_state(source)
            assert client.post('/api/v1/runs/original/retry', json=body).status_code == 409
        source.status = RunStatus.PARTIAL
        source.external_execution = {"project_id": "remote", "status": "timeout", "cancellation_requested": True}
        service.ledger.save_state(source)
        assert client.get('/api/v1/runs').json()['runs'][0]['can_retry'] is False
        assert client.post('/api/v1/runs/original/retry', json=body).status_code == 409
        source.external_execution['status'] = 'stopped'
        service.ledger.save_state(source)
        first = client.post('/api/v1/runs/original/retry', json=body)
        second = client.post('/api/v1/runs/original/retry', json=body)
        assert first.status_code == second.status_code == 202
        assert first.json()['run_id'] == second.json()['run_id']
        assert len(spawned) == 1


def mcp_step(step_id, dependencies=None, method="GET"):
    return PlanStep(step_id=step_id, objective="probe endpoint", agent_role="analyst",
                    dependencies=dependencies or [], tool_candidates=["mcp:local-tscanplus:http_request"],
                    tool_version="test", inputs={"method": method}, max_attempts=1)


@pytest.mark.asyncio
async def test_http_timeout_retries_once_then_continues_only_independent_branch(settings):
    orchestrator, ledger, tool = controlled_orchestrator(settings, RiskLevel.R1)
    tool.manifest.name = "mcp:local-tscanplus:http_request"
    tool.manifest.idempotent = False
    orchestrator.broker.registry.register(tool)
    calls = []
    async def invoke(args, context):
        calls.append(context.step_id)
        if context.step_id == 'probe':
            return ToolResult(status=ToolStatus.ERROR, error_code="MCP_CALL_FAILED", error_message="context deadline exceeded")
        return ToolResult(status=ToolStatus.SUCCESS, data={"adapter": "mcp"}, summary="independent branch completed")
    tool.invoke = invoke
    state = AgentState(run_id="branches", task=TaskRequest(objective="probe test endpoints"),
        scenario=Scenario.CODE_AUDIT, workspace=str(settings.input_root), resume_node="validate_plan")
    output = PlanOutput(steps=[mcp_step('probe'), mcp_step('dependent', ['probe']),
                              mcp_step('transitive', ['dependent']), mcp_step('independent')], rationale_summary="branches")
    state.plan = PlannerAgent._mcp_plan(output, {tool.manifest.name: tool.manifest}, state).steps
    assert state.plan[0].max_attempts == 2
    ledger.save_state(state)
    result = await orchestrator.recover(state.run_id)
    assert calls == ['probe', 'probe', 'independent']
    assert result.status == RunStatus.PARTIAL
    assert set(result.step_failures) == {'probe', 'dependent', 'transitive'}
    assert result.retry_counts == {'probe': 1}
    assert any('deadline exceeded' in reason for reason in result.report.limitations)
    assert RunService(orchestrator, ledger, EventHub()).summary(state.run_id).current_step == 1
    assert ledger.verify(state.run_id)


@pytest.mark.asyncio
@pytest.mark.parametrize('method,error', [('POST', 'context deadline exceeded'), ('GET', 'malformed HTTP status code')])
async def test_writes_and_protocol_errors_are_not_automatically_replayed(settings, method, error):
    orchestrator, ledger, tool = controlled_orchestrator(settings, RiskLevel.R1)
    tool.manifest.name = 'mcp:local-tscanplus:http_request'
    tool.manifest.idempotent = False
    orchestrator.broker.registry.register(tool)
    step = mcp_step('probe', method=method)
    step.max_attempts = 2  # Execution must enforce the rule even for legacy plans.
    state = AgentState(run_id='no-replay', task=TaskRequest(objective='probe endpoints'),
        plan=[step], observations=[ToolResult(status=ToolStatus.ERROR, error_message=error)])
    result = await orchestrator._verify({'agent': state.model_dump(mode='json')})
    assert result['route'] != 'reflect'
    assert result['agent']['step_failures']['probe'] == error


@pytest.mark.asyncio
async def test_replanning_receives_previous_failure_without_changing_task(settings):
    from test_mcp_agent import SelectingModel
    orchestrator, _, tool = controlled_orchestrator(settings, RiskLevel.R1)
    tool.manifest.name = 'mcp:local-tscanplus:http_request'
    orchestrator.broker.registry.register(tool)
    model = SelectingModel(tool.manifest.name, {'method': 'GET'})
    planner = PlannerAgent(model, orchestrator.broker.registry)
    state = failed_run(retry_context={'stop_reason': 'malformed HTTP status code'})
    state.scenario = Scenario.CODE_AUDIT
    await planner.run(state)
    prompt = next(p['user_prompt'] for p in model.prompts if p['output_model'] is PlanOutput)
    assert '<previous_failure>' in prompt and 'malformed HTTP status code' in prompt
    assert state.task.objective == 'audit original input'
