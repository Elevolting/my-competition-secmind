import asyncio
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from test_orchestrator import controlled_orchestrator

from security_agent.agents import PlannerAgent, PlanOutput
from security_agent.api import build_runtime
from security_agent.blackboard_coordinator import BlackboardBinding, BlackboardCoordinator, BlackboardError
from security_agent.llm import ModelCallMeta
from security_agent.schemas import (
    AgentState,
    ApprovalDecision,
    ApprovalResponse,
    InputArtifact,
    PlanStep,
    RiskLevel,
    RunStatus,
    Scenario,
    TaskRequest,
    ToolResult,
    ToolStatus,
)


def step(name):
    return PlanStep(step_id=name, objective='test', agent_role='executor',
                    tool_candidates=[name], inputs={'target': 'https://target.test'})


def state_for(plan):
    return AgentState(run_id='entry-test', task=TaskRequest(objective='Authorized test',
        target_scope=['https://target.test'], autonomy_policy='automatic'),
        scenario=Scenario.PENETRATION_TEST, module_route='penetration',
        status=RunStatus.RUNNING, plan=plan)


def test_scoped_post_blackboard_hints_preserve_prior_fact_source():
    state = state_for([])
    state.task.network_policy = 'scoped_file_post'
    state.retry_context['prior_blackboard_fact'] = {
        'source_project_id': 'proj-old', 'description': 'POST file form observed',
        'evidence_ids': ['prior-evidence'],
    }
    hints = BlackboardCoordinator._hints(state)
    assert any('POST file form observed' in item['content']
               and 'proj-old' in item['content'] for item in hints)


@pytest.mark.parametrize('value', [
    {'backend': 'other', 'project_id': 'p', 'intent_id': 'i', 'worker': 'w', 'step_id': 's'},
    {'backend': 'remote', 'project_id': 'p', 'intent_id': 'i', 'worker': 'w', 'step_id': 's', 'fact_id': 1},
])
def test_malformed_blackboard_binding_is_rejected(value):
    assert BlackboardBinding.from_state(value) is None


async def test_concluded_blackboard_step_cannot_replay_tool(settings):
    service, _, gateway, _ = build_runtime(settings)
    state = AgentState(
        run_id='concluded-step',
        task=TaskRequest(objective='审计授权源码'),
        status=RunStatus.RUNNING,
        external_execution={
            'blackboard': {
                'backend': 'local', 'project_id': 'local:concluded-step',
                'intent_id': 'i001', 'worker': 'unified-workbench:concluded-step',
                'step_id': 'step-1', 'fact_id': 'f001', 'status': 'concluded',
            },
        },
    )
    try:
        with pytest.raises(BlackboardError, match='拒绝重复执行'):
            await service.orchestrator.blackboard.begin(state, PlanStep(
                step_id='step-1', objective='审计', agent_role='executor',
                tool_candidates=['code_audit_module'], inputs={'target': '.'},
            ))
    finally:
        await gateway.close()


async def test_ordinary_task_enters_blackboard_before_planning(settings, monkeypatch):
    service, _, gateway, _ = build_runtime(settings)
    state = AgentState(run_id='early-entry', task=TaskRequest(objective='审计授权源码'),
                       status=RunStatus.RUNNING)
    service.ledger.save_state(state)
    orchestrator = service.orchestrator
    try:
        classified = await orchestrator._classify({'agent': state.model_dump(mode='json')})
        entered = AgentState.model_validate(classified['agent'])
        board = entered.external_execution['blackboard']
        assert board['status'] == 'entered'
        assert board['project_id'] == 'local:early-entry'
        assert board['graph']['intents'] == []
        assert any(event.event_type == 'blackboard.entered' for event in service.ledger.events(state.run_id))

        async def checked_plan(planning_state, **_kwargs):
            assert planning_state.external_execution['blackboard']['status'] == 'entered'
            planning_state.plan = [PlanStep(step_id='audit', objective='审计', agent_role='executor',
                                            tool_candidates=['code_audit_module'], inputs={'target': '.'})]
            return planning_state

        monkeypatch.setattr(orchestrator.planner, 'run', checked_plan)
        planned = await orchestrator._plan({'agent': entered.model_dump(mode='json')})
        assert planned['agent']['plan'][0]['step_id'] == 'audit'
        entered = AgentState.model_validate(planned['agent'])
        binding = await orchestrator.blackboard.begin(entered, entered.plan[0])
        assert binding.project_id == board['project_id']
        assert len(entered.external_execution['blackboard']['graph']['intents']) == 1
    finally:
        await gateway.close()


async def test_blackboard_selects_and_pins_one_tool_from_candidates(settings):
    service, _, gateway, _ = build_runtime(settings)
    state = AgentState(
        run_id="candidate-selection",
        task=TaskRequest(objective="审计授权源码"),
        scenario=Scenario.CODE_AUDIT,
        module_route="code_audit",
        status=RunStatus.RUNNING,
    )
    step = PlanStep(
        step_id="audit",
        objective="执行代码审计",
        agent_role="executor",
        tool_candidates=["workspace_security_audit", "code_audit_module"],
        inputs={"target": "."},
    )
    try:
        await service.orchestrator.blackboard.enter(state)
        intent_id = await service.orchestrator.blackboard.schedule(state, step)
        assert intent_id == "i001"
        assert state.external_execution["blackboard"]["scheduled_tool"] == "code_audit_module"
        assert await service.orchestrator.blackboard.authorize_tool(state, step) == "code_audit_module"
        state.external_execution["blackboard"]["scheduled_tool"] = "workspace_security_audit"
        with pytest.raises(BlackboardError, match="工具授权"):
            await service.orchestrator.blackboard.authorize_tool(state, step)
    finally:
        await gateway.close()


async def test_penetration_intent_describes_worker_execution_not_project_creation(settings, monkeypatch):
    settings.demo_mode = False
    service, _, gateway, _ = build_runtime(settings)
    state = AgentState(run_id='penetration-intent',
        task=TaskRequest(objective='get the flag', target_scope=['https://target.test/'],
                         network_policy='read_only_http'),
        scenario=Scenario.PENETRATION_TEST, module_route='penetration', status=RunStatus.RUNNING,
        external_execution={'blackboard': {'backend': 'remote', 'project_id': 'p1', 'status': 'entered'}})
    step = PlanStep(step_id='s1', objective='create a blackboard project',
                    agent_role='penetration', tool_candidates=['penetration_module'])
    captured = {}
    project = {'id': 'p1', 'title': 'sec-task-penetration-intent',
               'status': 'active', 'dispatcher_enabled': False}

    async def request(method, path, **kwargs):
        if method == 'GET' and '/events?' in path:
            return {'events': [], 'next_cursor': 0}
        if method == 'GET' and path == '/projects/p1':
            return {'project': project, 'facts': [{'id': 'origin'}], 'intents': []}
        if method == 'POST' and path == '/projects/p1/intents':
            captured.update(kwargs['json'])
            return {'id': 'i001'}
        pytest.fail(f'unexpected request: {method} {path}')

    monkeypatch.setattr(service.orchestrator.blackboard, '_request', request)
    try:
        assert await service.orchestrator.blackboard.schedule(state, step) == 'i001'
        assert '黑板项目已创建并激活' in captured['description']
        assert 'GET/HEAD' in captured['description']
        assert 'get the flag' in captured['description']
        assert 'create a blackboard project' not in captured['description']
        assert captured['tool_name'] == 'penetration_module'
    finally:
        await gateway.close()


@pytest.mark.parametrize('assigned_tool', ['workspace_security_audit', None])
async def test_remote_multi_candidate_recovery_uses_durable_assignment(settings, monkeypatch, assigned_tool):
    settings.demo_mode = False
    service, _, gateway, _ = build_runtime(settings)
    state = AgentState(run_id='remote-assignment', task=TaskRequest(objective='审计授权源码'),
                       status=RunStatus.RUNNING)
    service.ledger.save_state(state)
    worker = 'unified-workbench:remote-assignment'
    project = {'id': 'p1', 'title': 'sec-task-remote-assignment',
               'status': 'active', 'dispatcher_enabled': False}
    intent = {'id': 'i1', 'from': ['origin'], 'to': None,
              'description': '[audit] 审计', 'tool_name': assigned_tool,
              'creator': worker, 'worker': None, 'concluded_at': None}

    async def request(method, path, **_kwargs):
        if method == 'GET' and '/events?' in path:
            return {'events': [], 'next_cursor': 0}
        if method == 'GET' and path == '/projects':
            return [project]
        if method == 'GET' and path == '/projects/p1':
            return {'project': project, 'facts': [{'id': 'origin'}], 'intents': [intent]}
        if method == 'POST' and path == '/projects/p1/intents/i1/heartbeat':
            intent['worker'] = worker
            return intent
        pytest.fail(f'unexpected mutation: {method} {path}')

    monkeypatch.setattr(service.orchestrator.blackboard, '_request', request)
    step = PlanStep(step_id='audit', objective='审计', agent_role='executor',
                    tool_candidates=['code_audit_module', 'workspace_security_audit'],
                    inputs={'target': '.'})
    try:
        if assigned_tool is None:
            with pytest.raises(BlackboardError, match='缺少工具分配'):
                await service.orchestrator.blackboard.schedule(state, step)
            assert intent['worker'] is None
        else:
            await service.orchestrator.blackboard.schedule(state, step)
            assert state.external_execution['blackboard']['scheduled_tool'] == assigned_tool
            binding = await service.orchestrator.blackboard.begin(state, step)
            assert binding.intent_id == 'i1'
            assert await service.orchestrator.blackboard.authorize_tool(state, step) == assigned_tool
    finally:
        await gateway.close()


async def test_remote_multi_candidate_intent_without_tool_cannot_authorize(settings, monkeypatch):
    settings.demo_mode = False
    service, _, gateway, _ = build_runtime(settings)
    state = AgentState(run_id='missing-tool', task=TaskRequest(objective='审计授权源码'),
                       status=RunStatus.RUNNING, external_execution={'blackboard': {
                           'backend': 'remote', 'project_id': 'p1',
                           'scheduled_tool': 'code_audit_module', 'status': 'entered',
                       }})
    project = {'id': 'p1', 'title': 'sec-task-missing-tool',
               'status': 'active', 'dispatcher_enabled': False}
    intent = {'id': 'i1', 'from': ['origin'], 'to': None,
              'description': '[audit] 审计', 'tool_name': None,
              'worker': None, 'concluded_at': None}

    async def request(method, path, **_kwargs):
        if method == 'GET' and '/events?' in path:
            return {'events': [], 'next_cursor': 0}
        assert method == 'GET' and path == '/projects/p1'
        return {'project': project, 'facts': [{'id': 'origin'}], 'intents': [intent]}

    monkeypatch.setattr(service.orchestrator.blackboard, '_request', request)
    step = PlanStep(step_id='audit', objective='审计', agent_role='executor',
                    tool_candidates=['code_audit_module', 'workspace_security_audit'],
                    inputs={'target': '.'})
    try:
        with pytest.raises(BlackboardError, match='工具授权'):
            await service.orchestrator.blackboard.authorize_tool(state, step)
        with pytest.raises(BlackboardError, match='工具授权'):
            await service.orchestrator.blackboard.begin(state, step)
    finally:
        await gateway.close()


async def test_penetration_enters_remote_blackboard_with_material_before_planning(settings, monkeypatch, tmp_path):
    service, _, gateway, _ = build_runtime(settings)
    material = tmp_path / 'question.txt'
    material.write_text('find the authorized flag', encoding='utf-8')
    state = state_for([])
    state.run_id = 'penetration-prepared'
    state.workspace = str(tmp_path)
    state.input_artifacts = [InputArtifact(
        original_name='question.txt', relative_path='question.txt', sha256='a' * 64,
        size_bytes=24, media_type='text/plain',
    )]
    calls = []

    async def interpret(value, **_kwargs):
        return value

    async def request(method, path, **kwargs):
        if method == 'GET' and '/events?' in path:
            return {'events': [], 'next_cursor': 0}
        calls.append((method, path, kwargs))
        if path == '/projects' and method == 'GET':
            return []
        if path == '/projects' and method == 'POST':
            return {'project': {'id': 'proj-prepared'}}
        if path == '/projects/proj-prepared' and method == 'GET':
            return {'project': {'id': 'proj-prepared', 'title': 'sec-task-penetration-prepared',
                                'status': 'active', 'dispatcher_enabled': False},
                    'facts': [{'id': 'origin'}], 'intents': []}
        raise AssertionError((method, path))

    monkeypatch.setattr(service.orchestrator.interpreter, 'run', interpret)
    monkeypatch.setattr(service.orchestrator.blackboard, '_request', request)
    try:
        result = await service.orchestrator._classify({'agent': state.model_dump(mode='json')})
        board = result['agent']['external_execution']['blackboard']
        assert board['project_id'] == 'proj-prepared'
        assert board['status'] == 'entered'
        payload = next(kwargs['json'] for method, path, kwargs in calls if method == 'POST')
        assert payload['dispatcher_enabled'] is False
        assert payload['bootstrap_enabled'] is False
        assert any('authorized flag' in hint['content'] for hint in payload['hints'])
    finally:
        await gateway.close()


async def test_penetration_activation_token_is_not_exposed_in_run_summary(settings):
    service, _, gateway, _ = build_runtime(settings)
    state = AgentState(
        run_id='token-redaction', task=TaskRequest(objective='授权渗透测试'),
        status=RunStatus.WAITING_APPROVAL,
        external_execution={'blackboard': {
            'backend': 'remote', 'project_id': 'p1', 'status': 'entered',
            'activation_token': 'secret-token-value' * 2,
        }},
    )
    service.ledger.save_state(state)
    try:
        summary = service.summary(state.run_id)
        assert 'activation_token' not in summary.blackboard
        assert 'secret-token-value' not in summary.model_dump_json()
    finally:
        await gateway.close()


async def test_blackboard_entry_failure_prevents_planning(settings, monkeypatch):
    settings.demo_mode = False
    service, _, gateway, _ = build_runtime(settings)
    state = AgentState(run_id='entry-failure', task=TaskRequest(objective='审计授权源码'),
                       status=RunStatus.RUNNING)
    service.ledger.save_state(state)

    async def unavailable(*_args, **_kwargs):
        raise BlackboardError('黑板服务不可用')

    async def unexpected_plan(*_args, **_kwargs):
        pytest.fail('planner ran without a blackboard project')

    monkeypatch.setattr(service.orchestrator.blackboard, '_request', unavailable)
    monkeypatch.setattr(service.orchestrator.planner, 'run', unexpected_plan)
    try:
        classified = await service.orchestrator._classify({'agent': state.model_dump(mode='json')})
        failed = AgentState.model_validate(classified['agent'])
        assert failed.status == RunStatus.FAILED
        assert failed.plan == []
        assert classified['route'] == 'report'
    finally:
        await gateway.close()


async def test_entered_project_stops_when_no_tool_step_was_created(settings):
    service, _, gateway, _ = build_runtime(settings)
    state = AgentState(run_id='stop-early-project', task=TaskRequest(objective='审计授权源码'),
                       status=RunStatus.RUNNING)
    service.ledger.save_state(state)
    try:
        await service.orchestrator.blackboard.enter(state)
        await service.orchestrator.blackboard.stop(state, '规划没有可执行步骤')
        board = service.ledger.load_state(state.run_id).external_execution['blackboard']
        assert board['status'] == 'stopped'
        assert board['graph']['status'] == 'stopped'
        assert board['graph']['intents'] == []
    finally:
        await gateway.close()


async def test_selected_step_is_queued_on_blackboard_before_approval(settings):
    orchestrator, ledger, tool = controlled_orchestrator(settings, RiskLevel.R2)
    waiting = await orchestrator.start(TaskRequest(objective='审计授权源码'), 'queued-board-step')
    board = waiting.external_execution['blackboard']
    assert waiting.status == RunStatus.WAITING_APPROVAL
    assert tool.calls == 0
    assert len(board['graph']['intents']) == 1
    assert board['graph']['intents'][0]['worker'] is None
    assert board['graph']['intents'][0]['to'] is None
    assert any(event.event_type == 'blackboard.intent.scheduled' for event in ledger.events(waiting.run_id))

    completed = await orchestrator.resume(waiting.run_id, ApprovalResponse(decision=ApprovalDecision.APPROVE))
    intent = completed.external_execution['blackboard']['graph']['intents'][0]
    assert tool.calls == 1
    assert intent['worker'] == 'unified-workbench:queued-board-step'
    assert intent['to'] is not None
    assert ledger.verify(waiting.run_id)


async def test_remote_workbench_project_disables_dispatcher(settings, monkeypatch):
    settings.demo_mode = False
    service, _, gateway, _ = build_runtime(settings)
    state = AgentState(
        run_id='external-dispatch', task=TaskRequest(objective='审计授权源码'),
        status=RunStatus.RUNNING,
    )
    service.ledger.save_state(state)
    calls = []
    project = {
        'id': 'p1', 'title': 'sec-task-external-dispatch',
        'status': 'active', 'dispatcher_enabled': False,
    }

    async def request(method, path, **kwargs):
        if method == 'GET' and '/events?' in path:
            return {'events': [], 'next_cursor': 0}
        calls.append((method, path, kwargs.get('json')))
        if method == 'GET' and path == '/projects':
            return []
        if method == 'POST' and path == '/projects':
            assert kwargs['json']['dispatcher_enabled'] is False
            assert kwargs['json']['bootstrap_enabled'] is False
            return {'project': project}
        if method == 'GET' and path == '/projects/p1':
            return {'project': project, 'facts': [{'id': 'origin'}], 'intents': [
                {'id': 'i1', 'worker': 'unified-workbench:external-dispatch', 'to': None},
            ]}
        if method == 'POST' and path == '/projects/p1/intents':
            return {'id': 'i1'}
        raise AssertionError((method, path))

    monkeypatch.setattr(service.orchestrator.blackboard, '_request', request)
    try:
        binding = await service.orchestrator.blackboard.begin(state, PlanStep(
            step_id='step-1', objective='审计', agent_role='executor',
            tool_candidates=['code_audit_module'], inputs={'target': '.'},
        ))
        await service.orchestrator.blackboard.validate(state, binding)
        assert binding.project_id == 'p1'
        assert any(method == 'POST' and path == '/projects' for method, path, _ in calls)
        project['dispatcher_enabled'] = True
        with pytest.raises(BlackboardError, match='失效'):
            await service.orchestrator.blackboard.validate(state, binding)
    finally:
        await gateway.close()


@pytest.mark.parametrize('response_lost', [False, True])
async def test_remote_schedule_creates_unclaimed_intent_then_claims_it(settings, monkeypatch, response_lost):
    settings.demo_mode = False
    service, _, gateway, _ = build_runtime(settings)
    state = AgentState(run_id='scheduled-remote', task=TaskRequest(objective='审计授权源码'),
                       status=RunStatus.RUNNING)
    service.ledger.save_state(state)
    project = {'id': 'p1', 'title': 'sec-task-scheduled-remote',
               'status': 'active', 'dispatcher_enabled': False}
    intents = []
    creations = []
    claims = []

    async def request(method, path, **kwargs):
        if method == 'GET' and '/events?' in path:
            return {'events': [], 'next_cursor': 0}
        if method == 'GET' and path == '/projects':
            return []
        if method == 'POST' and path == '/projects':
            return {'project': project}
        if method == 'GET' and path == '/projects/p1':
            return {'project': project, 'facts': [{'id': 'origin'}], 'intents': intents}
        if method == 'POST' and path == '/projects/p1/intents':
            creations.append(kwargs['json'])
            intents.append({'id': 'i1', **kwargs['json'], 'to': None, 'concluded_at': None})
            if response_lost:
                raise BlackboardError('调度响应丢失')
            return {'id': 'i1'}
        if method == 'POST' and path == '/projects/p1/intents/i1/heartbeat':
            claims.append(kwargs['json'])
            intents[0]['worker'] = kwargs['json']['worker']
            return intents[0]
        raise AssertionError((method, path))

    monkeypatch.setattr(service.orchestrator.blackboard, '_request', request)
    step = PlanStep(step_id='audit', objective='审计', agent_role='executor',
                    tool_candidates=['code_audit_module'], inputs={'target': '.'})
    try:
        scheduled = await service.orchestrator.blackboard.schedule(state, step)
        binding = await service.orchestrator.blackboard.begin(state, step)
        assert scheduled == binding.intent_id == 'i1'
        assert len(creations) == 1
        assert creations[0]['worker'] is None
        assert claims == [{'worker': 'unified-workbench:scheduled-remote', 'attempt_id': None, 'claim': True}]
    finally:
        await gateway.close()


@pytest.mark.parametrize('response_lost', [False, True])
async def test_remote_step_intent_recovers_without_duplicate_dispatch(settings, monkeypatch, response_lost):
    settings.demo_mode = False
    service, _, gateway, _ = build_runtime(settings)
    state = AgentState(run_id='recover-intent', task=TaskRequest(objective='审计授权源码'),
                       status=RunStatus.RUNNING)
    service.ledger.save_state(state)
    worker = 'unified-workbench:recover-intent'
    description = '[audit] 审计'
    intents = [] if response_lost else [{
        'id': 'i1', 'from': ['origin'], 'to': None, 'description': description,
        'creator': worker, 'worker': worker, 'concluded_at': None,
    }]
    posts = []
    project = {'id': 'p1', 'title': 'sec-task-recover-intent',
               'status': 'active', 'dispatcher_enabled': False}

    async def request(method, path, **kwargs):
        if method == 'GET' and '/events?' in path:
            return {'events': [], 'next_cursor': 0}
        if method == 'GET' and path == '/projects':
            return [project]
        if method == 'GET' and path == '/projects/p1':
            return {'project': project, 'facts': [{'id': 'origin'}], 'intents': intents}
        if method == 'POST' and path == '/projects/p1/intents':
            posts.append(kwargs['json'])
            intents.append({'id': 'i1', 'from': ['origin'], 'to': None,
                            **kwargs['json'], 'concluded_at': None})
            raise BlackboardError('响应丢失')
        raise AssertionError((method, path))

    monkeypatch.setattr(service.orchestrator.blackboard, '_request', request)
    try:
        binding = await service.orchestrator.blackboard.begin(state, PlanStep(
            step_id='audit', objective='审计', agent_role='executor',
            tool_candidates=['code_audit_module'], inputs={'target': '.'},
        ))
        assert binding.intent_id == 'i1'
        assert len(intents) == 1
        assert len(posts) == int(response_lost)
        assert service.ledger.load_state(state.run_id).external_execution['blackboard']['intent_id'] == 'i1'
    finally:
        await gateway.close()


async def test_remote_project_creation_recovers_after_lost_receipt(settings, monkeypatch):
    settings.demo_mode = False
    service, _, gateway, _ = build_runtime(settings)
    state = AgentState(run_id='recover-project', task=TaskRequest(objective='审计授权源码'),
                       status=RunStatus.RUNNING)
    service.ledger.save_state(state)
    projects = []
    project = {'id': 'p1', 'title': 'sec-task-recover-project',
               'status': 'active', 'dispatcher_enabled': False}
    creations = []

    async def request(method, path, **kwargs):
        if method == 'GET' and '/events?' in path:
            return {'events': [], 'next_cursor': 0}
        if method == 'GET' and path == '/projects':
            return projects
        if method == 'POST' and path == '/projects':
            creations.append(kwargs['json'])
            projects.append(project)
            raise BlackboardError('创建已提交，回执丢失')
        if method == 'GET' and path == '/projects/p1':
            return {'project': project, 'facts': [{'id': 'origin'}], 'intents': []}
        if method == 'POST' and path == '/projects/p1/intents':
            return {'id': 'i1'}
        raise AssertionError((method, path))

    monkeypatch.setattr(service.orchestrator.blackboard, '_request', request)
    try:
        binding = await service.orchestrator.blackboard.begin(state, PlanStep(
            step_id='audit', objective='审计', agent_role='executor',
            tool_candidates=['code_audit_module'], inputs={'target': '.'},
        ))
        assert binding.project_id == 'p1'
        assert binding.intent_id == 'i1'
        assert len(creations) == 1
    finally:
        await gateway.close()


async def test_duplicate_open_step_intents_block_tool_dispatch(settings, monkeypatch):
    settings.demo_mode = False
    service, _, gateway, _ = build_runtime(settings)
    state = AgentState(run_id='duplicate-intents', task=TaskRequest(objective='审计授权源码'),
                       status=RunStatus.RUNNING)
    service.ledger.save_state(state)
    worker = 'unified-workbench:duplicate-intents'
    project = {'id': 'p1', 'title': 'sec-task-duplicate-intents',
               'status': 'active', 'dispatcher_enabled': False}
    intent = {'from': ['origin'], 'to': None, 'description': '[audit] 审计',
              'creator': worker, 'worker': worker, 'concluded_at': None}

    async def request(method, path, **_kwargs):
        if method == 'GET' and '/events?' in path:
            return {'events': [], 'next_cursor': 0}
        if method == 'GET' and path == '/projects':
            return [project]
        if method == 'GET' and path == '/projects/p1':
            return {'project': project, 'facts': [{'id': 'origin'}],
                    'intents': [{'id': 'i1', **intent}, {'id': 'i2', **intent}]}
        pytest.fail(f'unexpected mutation: {method} {path}')

    monkeypatch.setattr(service.orchestrator.blackboard, '_request', request)
    try:
        with pytest.raises(BlackboardError, match='多个未完成黑板意图'):
            await service.orchestrator.blackboard.begin(state, PlanStep(
                step_id='audit', objective='审计', agent_role='executor',
                tool_candidates=['code_audit_module'], inputs={'target': '.'},
            ))
    finally:
        await gateway.close()


@pytest.mark.parametrize('stored_source, stored_worker, expected_error', [
    (['origin'], None, None),
    (['other-fact'], 'unified-workbench:reclaim-intent', '来源事实不一致'),
])
async def test_remote_intent_reclaim_checks_source(settings, monkeypatch,
                                                    stored_source, stored_worker, expected_error):
    settings.demo_mode = False
    service, _, gateway, _ = build_runtime(settings)
    state = AgentState(run_id='reclaim-intent', task=TaskRequest(objective='审计授权源码'),
                       status=RunStatus.RUNNING)
    service.ledger.save_state(state)
    worker = 'unified-workbench:reclaim-intent'
    project = {'id': 'p1', 'title': 'sec-task-reclaim-intent',
               'status': 'active', 'dispatcher_enabled': False}
    intent = {'id': 'i1', 'from': stored_source, 'to': None,
              'description': '[audit] 审计', 'creator': worker,
              'worker': stored_worker, 'concluded_at': None}
    heartbeats = []

    async def request(method, path, **kwargs):
        if method == 'GET' and '/events?' in path:
            return {'events': [], 'next_cursor': 0}
        if method == 'GET' and path == '/projects':
            return [project]
        if method == 'GET' and path == '/projects/p1':
            return {'project': project, 'facts': [{'id': 'origin'}], 'intents': [intent]}
        if method == 'POST' and path == '/projects/p1/intents/i1/heartbeat':
            heartbeats.append(kwargs['json'])
            intent['worker'] = worker
            return intent
        if method == 'GET' and path.startswith('/projects/p1/events?'):
            return {'events': [], 'next_cursor': 0}
        pytest.fail(f'unexpected mutation: {method} {path}')

    monkeypatch.setattr(service.orchestrator.blackboard, '_request', request)
    try:
        operation = service.orchestrator.blackboard.begin(state, PlanStep(
            step_id='audit', objective='审计', agent_role='executor',
            tool_candidates=['code_audit_module'], inputs={'target': '.'},
        ))
        if expected_error:
            with pytest.raises(BlackboardError, match=expected_error):
                await operation
            assert not heartbeats
        else:
            binding = await operation
            assert binding.intent_id == 'i1'
            assert heartbeats == [{'worker': worker, 'attempt_id': None, 'claim': True}]
    finally:
        await gateway.close()


async def test_persisted_active_intent_reclaims_expired_worker(settings, monkeypatch):
    settings.demo_mode = False
    service, _, gateway, _ = build_runtime(settings)
    worker = 'unified-workbench:persisted-intent'
    state = AgentState(run_id='persisted-intent', task=TaskRequest(objective='审计授权源码'),
                       status=RunStatus.RUNNING, external_execution={'blackboard': {
                           'backend': 'remote', 'project_id': 'p1', 'intent_id': 'i1',
                           'worker': worker, 'step_id': 'audit', 'fact_id': 'origin',
                           'status': 'active',
                       }})
    project = {'id': 'p1', 'title': 'sec-task-persisted-intent',
               'status': 'active', 'dispatcher_enabled': False}
    intent = {'id': 'i1', 'from': ['origin'], 'to': None,
              'description': '[audit] 审计', 'creator': worker,
              'worker': None, 'concluded_at': None}
    heartbeats = []

    async def request(method, path, **kwargs):
        if method == 'GET' and '/events?' in path:
            return {'events': [], 'next_cursor': 0}
        if method == 'GET' and path == '/projects/p1':
            return {'project': project, 'facts': [{'id': 'origin'}], 'intents': [intent]}
        if method == 'POST' and path == '/projects/p1/intents/i1/heartbeat':
            heartbeats.append(kwargs['json'])
            intent['worker'] = worker
            return intent
        if method == 'GET' and path.startswith('/projects/p1/events?'):
            return {'events': [], 'next_cursor': 0}
        pytest.fail(f'unexpected mutation: {method} {path}')

    monkeypatch.setattr(service.orchestrator.blackboard, '_request', request)
    try:
        binding = await service.orchestrator.blackboard.begin(state, PlanStep(
            step_id='audit', objective='审计', agent_role='executor',
            tool_candidates=['code_audit_module'], inputs={'target': '.'},
        ))
        assert binding.intent_id == 'i1'
        assert heartbeats == [{'worker': worker, 'attempt_id': None, 'claim': True}]
    finally:
        await gateway.close()


async def test_remote_completion_requires_goal_receipt(settings, monkeypatch):
    settings.demo_mode = False
    service, _, gateway, _ = build_runtime(settings)
    state = AgentState(
        run_id='invalid-goal-receipt', task=TaskRequest(objective='审计授权源码'),
        status=RunStatus.COMPLETED,
        external_execution={'blackboard': {
            'backend': 'remote', 'project_id': 'p1', 'intent_id': 'i1',
            'worker': 'worker-1', 'step_id': 'step-1', 'fact_id': 'f001',
            'status': 'concluded',
        }},
    )
    service.ledger.save_state(state)

    async def invalid_receipt(*_args, **_kwargs):
        return {'id': 'i2', 'to': None, 'worker': 'worker-1', 'from': ['f001']}

    monkeypatch.setattr(service.orchestrator.blackboard, '_request', invalid_receipt)
    try:
        with pytest.raises(BlackboardError, match='完成回执'):
            await service.orchestrator.blackboard.complete(state)
        assert service.ledger.load_state(state.run_id).external_execution['blackboard']['status'] == 'concluded'
    finally:
        await gateway.close()


@pytest.mark.parametrize('matching_fact', [True, False])
async def test_remote_conclusion_recovers_only_matching_committed_fact(settings, monkeypatch, matching_fact):
    service, _, gateway, _ = build_runtime(settings)
    coordinator = service.orchestrator.blackboard
    state = AgentState(run_id='lost-conclusion', task=TaskRequest(objective='审计授权源码'),
                       status=RunStatus.RUNNING, external_execution={'blackboard': {
                           'backend': 'remote', 'project_id': 'p1', 'status': 'active',
                       }})
    service.ledger.save_state(state)
    binding = BlackboardBinding('remote', 'p1', 'i1', 'worker-1', 'audit', 'origin')
    result = ToolResult(status=ToolStatus.SUCCESS, summary='已审计')
    description = coordinator._summary(result)

    async def request(method, path, **_kwargs):
        if method == 'GET' and '/events?' in path:
            return {'events': [], 'next_cursor': 0}
        if method == 'POST':
            raise BlackboardError('response lost after commit')
        assert (method, path) == ('GET', '/projects/p1')
        return {'project': {'id': 'p1', 'title': 'sec-task-lost-conclusion', 'status': 'active'},
                'intents': [{'id': 'i1', 'from': ['origin'], 'to': 'f001',
                             'worker': 'worker-1', 'concluded_at': 'now'}],
                'facts': [{'id': 'f001', 'description': description if matching_fact else 'other result'}]}

    monkeypatch.setattr(coordinator, '_request', request)
    try:
        if matching_fact:
            await coordinator.conclude(state, binding, result)
            assert state.external_execution['blackboard']['fact_id'] == 'f001'
            assert state.external_execution['blackboard']['status'] == 'concluded'
        else:
            with pytest.raises(BlackboardError, match='结果事实不匹配'):
                await coordinator.conclude(state, binding, result)
            assert state.external_execution['blackboard']['status'] == 'active'
    finally:
        await gateway.close()


@pytest.mark.parametrize('matching_goal', [True, False])
async def test_remote_completion_recovers_only_matching_goal_intent(settings, monkeypatch, matching_goal):
    service, _, gateway, _ = build_runtime(settings)
    coordinator = service.orchestrator.blackboard
    state = AgentState(run_id='lost-completion', task=TaskRequest(objective='审计授权源码'),
                       status=RunStatus.COMPLETED, external_execution={'blackboard': {
                           'backend': 'remote', 'project_id': 'p1', 'intent_id': 'i1',
                           'worker': 'worker-1', 'step_id': 'audit', 'fact_id': 'f001',
                           'status': 'concluded',
                       }})
    service.ledger.save_state(state)

    async def request(method, path, **_kwargs):
        if method == 'GET' and '/events?' in path:
            return {'events': [], 'next_cursor': 0}
        if method == 'POST':
            raise BlackboardError('response lost after commit')
        assert (method, path) == ('GET', '/projects/p1')
        return {'project': {'id': 'p1', 'title': 'sec-task-lost-completion', 'status': 'completed'},
                'intents': [{'id': 'i2', 'from': ['f001'], 'to': 'goal', 'worker': 'worker-1',
                             'description': state.task.objective if matching_goal else 'other task',
                             'concluded_at': 'now'}]}

    monkeypatch.setattr(coordinator, '_request', request)
    try:
        if matching_goal:
            await coordinator.complete(state)
            assert state.external_execution['blackboard']['status'] == 'completed'
        else:
            with pytest.raises(BlackboardError, match='目标意图不匹配'):
                await coordinator.complete(state)
            assert state.external_execution['blackboard']['status'] == 'concluded'
    finally:
        await gateway.close()


async def test_real_runtime_recovers_lost_conclusion_and_completion_receipts(settings, monkeypatch, tmp_path):
    runtime_src = Path(__file__).parents[2] / 'security-runtime' / 'security-runtime' / 'src'
    monkeypatch.syspath_prepend(str(runtime_src))
    from security_runtime.server import db
    from security_runtime.server.app import app as runtime_app

    monkeypatch.setattr(db, '_db_path', None)
    db.configure(tmp_path / 'security-runtime.db')
    settings.demo_mode = False
    service, _, gateway, _ = build_runtime(settings)
    state = AgentState(run_id='real-runtime-lost-receipts', task=TaskRequest(objective='审计授权源码'),
                       module_route='code_audit', status=RunStatus.RUNNING, workspace=str(tmp_path))
    service.ledger.save_state(state)
    coordinator = service.orchestrator.blackboard
    step = PlanStep(step_id='audit', objective='审计', agent_role='executor',
                    tool_candidates=['code_audit_module'], inputs={'target': '.'})
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=runtime_app),
                                     base_url='http://localhost') as client:
            async def request(method, path, **kwargs):
                response = await client.request(method, path, **kwargs)
                if response.status_code >= 400:
                    raise BlackboardError(f'Runtime HTTP {response.status_code}: {response.text}')
                if method == 'POST' and (path.endswith('/conclude') or path.endswith('/complete')):
                    raise BlackboardError('response lost after commit')
                return response.json()

            monkeypatch.setattr(coordinator, '_request', request)
            project_id = await coordinator.enter(state)
            await coordinator.schedule(state, step)
            binding = await coordinator.begin(state, step)
            await coordinator.conclude(state, binding, ToolResult(status=ToolStatus.SUCCESS, summary='已审计'))
            state.status = RunStatus.COMPLETED
            await coordinator.complete(state)
            detail = (await client.get(f'/projects/{project_id}')).json()
            assert detail['project']['status'] == 'completed'
            assert state.external_execution['blackboard']['status'] == 'completed'
            assert len([item for item in detail['intents'] if item['to'] == 'goal']) == 1
            journal = service.ledger.events(state.run_id)
            assert any(e.event_type == 'runtime.claimed' and e.payload['attempt_id'] == binding.attempt_id for e in journal)
            assert any(e.event_type == 'runtime.completed' and e.payload.get('fact_id') != 'goal' for e in journal)
            await coordinator.sync_events(state)
            count = len(service.ledger.events(state.run_id))
            await coordinator.sync_events(state)
            assert len(service.ledger.events(state.run_id)) == count
            assert service.ledger.verify(state.run_id)
    finally:
        await gateway.close()


@pytest.mark.parametrize('already_concluded', [False, True])
async def test_recovery_uses_observed_blackboard_result_without_reinvoking_tool(
    settings, monkeypatch, already_concluded,
):
    service, _, gateway, _ = build_runtime(settings)
    coordinator = service.orchestrator.blackboard
    run_id = f'recover-tool-result-{already_concluded}'
    result = ToolResult(status=ToolStatus.SUCCESS, summary='已完成分析')
    description = coordinator._summary(result)
    board = {'backend': 'remote', 'project_id': 'p1', 'intent_id': 'i1',
             'worker': 'worker-1', 'step_id': 'reverse',
             'fact_id': 'f001' if already_concluded else 'origin',
             'status': 'concluded' if already_concluded else 'active'}
    if already_concluded:
        board['fact_description'] = description
    else:
        board['pending_conclusion'] = {'step_id': 'reverse', 'intent_id': 'i1',
                                       'description': description}
    state = AgentState(
        run_id=run_id, task=TaskRequest(objective='分析授权样本'),
        scenario=Scenario.REVERSE_TRIAGE, module_route='reverse', status=RunStatus.RUNNING,
        plan=[PlanStep(step_id='reverse', objective='分析', agent_role='executor',
                       tool_candidates=['reverse_module'], inputs={'target': '.'})],
        observations=[result], external_execution={'blackboard': board},
        active_node='execute', resume_node='execute',
    )
    service.ledger.save_state(state)
    tool = service.orchestrator.broker.registry.get('reverse_module')

    async def never_invoke(*_args, **_kwargs):
        pytest.fail('observed tool was invoked again')

    async def capture_invoke(value, _run_id):
        return AgentState.model_validate(value['agent'])

    async def request(method, path, **_kwargs):
        if method == 'GET' and '/events?' in path:
            return {'events': [], 'next_cursor': 0}
        if method == 'POST':
            raise BlackboardError('response lost after commit')
        assert (method, path) == ('GET', '/projects/p1')
        return {'project': {'id': 'p1', 'title': f'sec-task-{run_id}', 'status': 'active'},
                'intents': [{'id': 'i1', 'from': ['origin'], 'to': 'f001',
                             'worker': 'worker-1', 'concluded_at': 'now'}],
                'facts': [{'id': 'f001', 'description': description}]}

    monkeypatch.setattr(tool, 'invoke', never_invoke)
    monkeypatch.setattr(coordinator, '_request', request)
    monkeypatch.setattr(service.orchestrator, '_invoke', capture_invoke)
    try:
        recovered = await service.orchestrator.recover(run_id)
        assert recovered.resume_node == 'observe'
        assert recovered.external_execution['blackboard']['status'] == 'concluded'
        assert recovered.external_execution['blackboard']['fact_id'] == 'f001'
        assert len(recovered.observations) == 1
    finally:
        await gateway.close()


async def test_penetration_completion_uses_dispatcher_goal_intent(settings, monkeypatch):
    service, _, gateway, _ = build_runtime(settings)
    state = state_for([])
    state.run_id = 'dispatcher-goal'
    state.external_execution = {'blackboard': {
        'backend': 'remote', 'project_id': 'p1', 'status': 'entered',
    }}
    service.ledger.save_state(state)
    detail = {'project': {'id': 'p1', 'title': 'sec-task-dispatcher-goal', 'status': 'completed'},
              'intents': []}

    async def request(method, path, **_kwargs):
        if method == 'GET' and '/events?' in path:
            return {'events': [], 'next_cursor': 0}
        assert (method, path) == ('GET', '/projects/p1')
        return detail

    monkeypatch.setattr(service.orchestrator.blackboard, '_request', request)
    try:
        with pytest.raises(BlackboardError, match='目标意图'):
            await service.orchestrator.blackboard.complete(state)
        assert state.external_execution['blackboard']['status'] == 'entered'
        detail['intents'].append({'id': 'i-goal', 'to': 'goal', 'concluded_at': 'now'})
        await service.orchestrator.blackboard.complete(state)
        assert state.external_execution['blackboard']['status'] == 'completed'
    finally:
        await gateway.close()


@pytest.mark.parametrize('dispatcher_enabled,expected_node', [
    (False, 'execute'), (True, 'verify'),
])
async def test_penetration_recovery_reconciles_lost_activation_receipt(
    settings, monkeypatch, dispatcher_enabled, expected_node,
):
    service, _, gateway, _ = build_runtime(settings)
    run_id = f'recover-activation-{dispatcher_enabled}'
    state = state_for([PlanStep(
        step_id='penetrate', objective='执行授权渗透', agent_role='executor',
        tool_candidates=['penetration_module'], inputs={'target': 'https://target.test'},
    )])
    state.run_id = run_id
    state.active_node = 'execute'
    state.resume_node = 'execute'
    state.external_execution = {
        'status': 'submitting',
        'blackboard': {'backend': 'remote', 'project_id': 'p1', 'status': 'entered'},
    }
    state.budget.tool_calls_used = 1
    service.ledger.save_state(state)

    async def request(method, path, **_kwargs):
        if method == 'GET' and '/events?' in path:
            return {'events': [], 'next_cursor': 0}
        assert (method, path) == ('GET', '/projects/p1')
        return {'project': {'id': 'p1', 'title': f'sec-task-{run_id}',
                            'status': 'active', 'dispatcher_enabled': dispatcher_enabled}}

    async def capture_invoke(value, _run_id):
        return AgentState.model_validate(value['agent'])

    monkeypatch.setattr(service.orchestrator.blackboard, '_request', request)
    monkeypatch.setattr(service.orchestrator, '_invoke', capture_invoke)
    try:
        recovered = await service.orchestrator.recover(run_id)
        assert recovered.resume_node == expected_node
        assert recovered.budget.tool_calls_used == 1
        if dispatcher_enabled:
            assert recovered.external_execution['project_id'] == 'p1'
            assert recovered.observations[-1].data['project_id'] == 'p1'
        else:
            assert recovered.external_execution['activation_retry'] is True
            assert recovered.observations == []
    finally:
        await gateway.close()


async def test_penetration_recovery_rejects_mismatched_saved_project(settings, monkeypatch):
    service, _, gateway, _ = build_runtime(settings)
    state = state_for([PlanStep(
        step_id='penetrate', objective='执行授权渗透', agent_role='executor',
        tool_candidates=['penetration_module'], inputs={'target': 'https://target.test'},
    )])
    state.run_id = 'recover-wrong-project'
    state.active_node = 'execute'
    state.external_execution = {
        'project_id': 'other-project',
        'blackboard': {'backend': 'remote', 'project_id': 'bound-project', 'status': 'entered'},
    }
    service.ledger.save_state(state)

    async def unexpected_invoke(*_args, **_kwargs):
        pytest.fail('mismatched project was resumed')

    async def stopped(method, path, **_kwargs):
        if method == 'GET' and path.startswith('/projects/bound-project/events?'):
            return {'events': [], 'next_cursor': 0}
        if (method, path) == ('GET', '/projects/bound-project'):
            return {'project': {'id': 'bound-project', 'title': 'sec-task-recover-wrong-project',
                                'status': 'active'}}
        if (method, path) == ('PUT', '/projects/bound-project/status'):
            return {'id': 'bound-project', 'title': 'sec-task-recover-wrong-project', 'status': 'stopped'}
        pytest.fail(f'unexpected blackboard request: {method} {path}')

    monkeypatch.setattr(service.orchestrator, '_invoke', unexpected_invoke)
    monkeypatch.setattr(service.orchestrator.blackboard, '_request', stopped)
    try:
        recovered = await service.orchestrator.recover(state.run_id)
        assert recovered.status == RunStatus.PARTIAL
        assert recovered.external_execution['blackboard']['status'] == 'stopped'
        assert '绑定不一致' in recovered.last_error
    finally:
        await gateway.close()


async def test_penetration_activation_retry_does_not_double_charge_tool_budget(settings, monkeypatch):
    service, _, gateway, _ = build_runtime(settings)
    state = state_for([PlanStep(
        step_id='penetrate', objective='执行授权渗透', agent_role='executor',
        tool_candidates=['penetration_module'], inputs={'target': 'https://target.test'},
    )])
    state.run_id = 'activation-budget-retry'
    state.external_execution = {
        'status': 'submitting', 'activation_retry': True,
        'blackboard': {'backend': 'remote', 'project_id': 'p1', 'status': 'entered'},
    }
    state.budget.tool_calls_used = 1
    service.ledger.save_state(state)

    async def accepted(_args, _context):
        return ToolResult(status=ToolStatus.SUCCESS, data={'project_id': 'p1'})

    monkeypatch.setattr(service.orchestrator.broker.registry.get('penetration_module'), 'invoke', accepted)
    try:
        result = await service.orchestrator._execute({'agent': state.model_dump(mode='json')})
        updated = AgentState.model_validate(result['agent'])
        assert updated.budget.tool_calls_used == 1
        assert 'activation_retry' not in updated.external_execution
        assert updated.external_execution['project_id'] == 'p1'
        assert updated.external_execution['blackboard']['project_id'] == 'p1'
    finally:
        await gateway.close()


async def test_remote_stop_requires_stopped_project_receipt(settings, monkeypatch):
    settings.demo_mode = False
    service, _, gateway, _ = build_runtime(settings)
    state = AgentState(
        run_id='invalid-stop-receipt', task=TaskRequest(objective='审计授权源码'),
        status=RunStatus.FAILED,
        external_execution={'blackboard': {
            'backend': 'remote', 'project_id': 'p1', 'intent_id': 'i1',
            'worker': 'worker-1', 'step_id': 'step-1', 'status': 'active',
        }},
    )
    service.ledger.save_state(state)

    async def invalid_receipt(*_args, **_kwargs):
        return {'id': 'p1', 'status': 'active'}

    monkeypatch.setattr(service.orchestrator.blackboard, '_request', invalid_receipt)
    try:
        await service.orchestrator.blackboard.stop(state, '任务失败')
        assert service.ledger.load_state(state.run_id).external_execution['blackboard']['status'] == 'stop_failed'
    finally:
        await gateway.close()


async def test_remote_stop_recovers_lost_stopped_receipt(settings, monkeypatch):
    service, _, gateway, _ = build_runtime(settings)
    state = AgentState(run_id='lost-stop', task=TaskRequest(objective='审计授权源码'),
                       status=RunStatus.FAILED, external_execution={'blackboard': {
                           'backend': 'remote', 'project_id': 'p1', 'status': 'entered',
                       }})
    service.ledger.save_state(state)

    async def request(method, path, **_kwargs):
        if method == 'GET' and '/events?' in path:
            return {'events': [], 'next_cursor': 0}
        if method == 'PUT':
            raise BlackboardError('response lost after commit')
        assert (method, path) == ('GET', '/projects/p1')
        return {'project': {'id': 'p1', 'title': 'sec-task-lost-stop', 'status': 'stopped'}}

    monkeypatch.setattr(service.orchestrator.blackboard, '_request', request)
    try:
        await service.orchestrator.blackboard.stop(state, '任务失败')
        assert state.external_execution['blackboard']['status'] == 'stopped'
        assert service.ledger.load_state(state.run_id).external_execution['blackboard']['status'] == 'stopped'
    finally:
        await gateway.close()


async def test_heartbeat_failure_cancels_running_tool(settings, monkeypatch):
    service, _, gateway, _ = build_runtime(settings)
    coordinator = service.orchestrator.blackboard
    coordinator.heartbeat_interval_seconds = 0.01
    state = AgentState(run_id='lease-loss', task=TaskRequest(objective='审计授权源码'), status=RunStatus.RUNNING)
    binding = BlackboardBinding('remote', 'p1', 'i1', 'worker-1', 'step-1')
    interrupted = False

    async def valid(_state, _binding):
        return None

    async def revoked(_state, _binding):
        raise BlackboardError('租约已被撤销')

    monkeypatch.setattr(coordinator, 'validate', valid)
    monkeypatch.setattr(coordinator, 'heartbeat', revoked)
    try:
        with pytest.raises(BlackboardError, match='租约在工具执行期间失效'):
            async with coordinator.lease(state, binding):
                try:
                    await asyncio.sleep(10)
                except asyncio.CancelledError:
                    interrupted = True
                    raise
        assert interrupted
    finally:
        await gateway.close()


@pytest.mark.parametrize('tools', [[], ['mcp:test:request'],
    ['mcp:test:request', 'penetration_module'], ['penetration_module', 'mcp:test:request']])
async def test_planner_always_submits_blackboard_even_when_model_tries_mcp(tools):
    class Gateway:
        settings = SimpleNamespace(demo_mode=False)

        async def structured(self, **kwargs):
            assert kwargs['output_model'] is PlanOutput
            assert '不得直接调用 MCP' in kwargs['user_prompt']
            return (PlanOutput(steps=[step(name) for name in tools], rationale_summary='test'),
                    ModelCallMeta('model', 'test', 'digest', 1, False, {}))

    planner = PlannerAgent(Gateway())

    async def unexpected_selection(*args):
        pytest.fail('Main penetration planner must not select MCP tools')

    planner._select_mcp = unexpected_selection
    state = await planner.run(state_for([]))
    assert len(state.plan) == 1
    assert state.plan[0].tool_candidates == ['penetration_module']
    assert state.plan[0].inputs == {'target': 'https://target.test'}


@pytest.mark.parametrize('node', ['_validate_plan', '_guardrail', '_execute'])
@pytest.mark.parametrize('tools', [['mcp:test:request'], ['penetration_module', 'mcp:test:request']])
async def test_old_or_mixed_plans_cannot_bypass_blackboard(settings, node, tools):
    service, _, gateway, _ = build_runtime(settings)
    state = state_for([step(name) for name in tools])
    service.ledger.save_state(state)
    try:
        result = await getattr(service.orchestrator, node)({'agent': state.model_dump(mode='json')})
        failed = AgentState.model_validate(result['agent'])
        assert failed.status == RunStatus.FAILED
        assert '黑板' in failed.last_error
        assert failed.budget.tool_calls_used == 0
        assert service.orchestrator.mcp_runtime.store.recent('mcp') == []
    finally:
        await gateway.close()


async def test_unavailable_blackboard_never_falls_back_to_direct_mcp(settings):
    service, _, gateway, _ = build_runtime(settings)
    try:
        state = await service.orchestrator.start(TaskRequest(
            objective='授权渗透测试 https://target.test', target_scope=['https://target.test'],
            autonomy_policy='automatic'), 'unavailable-blackboard')
        assert state.plan == []
        assert state.status == RunStatus.FAILED
        assert state.observations == []
        assert '黑板' in state.last_error
        assert service.orchestrator.mcp_runtime.store.recent('mcp') == []
    finally:
        await gateway.close()


async def test_unavailable_blackboard_blocks_non_penetration_tool(settings):
    settings.demo_mode = False
    service, _, gateway, _ = build_runtime(settings)
    try:
        state = await service.orchestrator.start(
            TaskRequest(objective='审计授权源码', autonomy_policy='automatic'),
            'unavailable-code-blackboard',
        )
        assert state.status == RunStatus.FAILED
        assert '黑板' in (state.last_error or '')
        assert state.observations == []
        assert service.orchestrator.mcp_runtime.store.recent('mcp') == []
    finally:
        await gateway.close()


async def test_blackboard_stop_failure_is_persisted_for_cleanup(settings, monkeypatch):
    settings.demo_mode = False
    service, _, gateway, _ = build_runtime(settings)
    state = AgentState(
        run_id='blackboard-stop-failed',
        task=TaskRequest(objective='审计授权源码'),
        status=RunStatus.FAILED,
        external_execution={
            'blackboard': {
                'backend': 'remote', 'project_id': 'p1', 'intent_id': 'i1',
                'worker': 'worker-1', 'step_id': 'step-1', 'status': 'active',
            },
        },
    )
    service.ledger.save_state(state)

    async def fail_request(*_args, **_kwargs):
        raise BlackboardError('黑板暂不可用')

    monkeypatch.setattr(service.orchestrator.blackboard, '_request', fail_request)
    try:
        await service.orchestrator.blackboard.stop(state, '任务失败')
        persisted = service.ledger.load_state(state.run_id)
        assert persisted is not None
        assert persisted.external_execution['blackboard']['status'] == 'stop_failed'
        assert persisted.external_execution['blackboard']['stop_reason'] == '任务失败'
        assert any(event.event_type == 'blackboard.stop_failed'
                   for event in service.ledger.events(state.run_id))
    finally:
        await gateway.close()
