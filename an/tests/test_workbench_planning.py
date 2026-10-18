"""Exercise the workbench side of authenticated, incremental Runtime planning."""
import hashlib
import json

import httpx
import pytest

from security_agent.agents import CompletionReviewOutput
from security_agent.api import build_runtime, create_app
from security_agent.llm import ModelCallMeta
from security_agent.report_sections import report_sections
from security_agent.report_sync import synchronize_report
from security_agent.schemas import (
    AgentReport,
    AgentState,
    DecisionRecord,
    Evidence,
    PlanningCallbackRequest,
    RunStatus,
    TaskRequest,
    ToolResult,
    ToolStatus,
)
from security_agent.workbench_results import (
    has_live_planning_work,
    merge_workbench_results,
    receipt_for_ref,
    validated_step_outputs,
)


def bound_state(settings, route='penetration'):
    workspace = settings.run_root / 'planning-test' / 'workspace'
    workspace.mkdir(parents=True, exist_ok=True)
    return AgentState(run_id='planning-test', status=RunStatus.RUNNING, module_route=route,
        task=TaskRequest(objective='验证授权目标', target_scope=['https://authorized.test']),
        workspace=str(workspace), external_execution={'blackboard': {
            'backend': 'remote', 'planning_mode': 'workbench', 'project_id': 'proj-test',
            'title': 'sec-task-planning-test'}})


def request(state, key='decision-initial', facts=None, intents=None, hints=None, **extra):
    snapshot = {'facts': facts if facts is not None else [{'id': 'origin', 'description': '已知授权入口'}],
                'intents': intents or [], 'hints': hints or []}
    digest = hashlib.sha256(json.dumps(snapshot, ensure_ascii=False, sort_keys=True,
                                       separators=(',', ':')).encode()).hexdigest()
    return PlanningCallbackRequest(run_id=state.run_id, project_id='proj-test', trigger='test',
        goal=state.task.objective, target_scope=state.task.target_scope, module_route=state.module_route,
        decision_id=key, snapshot_hash=digest, **snapshot, **extra)


def direction(title, sources=None, **extra):
    return {'from': sources or ['origin'], 'title': title, 'description': title,
            'verification_target': title, 'success_criteria': ['返回可复核的工具证据'], **extra}


def test_step_outputs_need_observed_item_and_successful_current_receipt():
    intents = [{'step_id': 'A', 'to': 'f001', 'execution_status': 'completed'}]
    fact = {'id': 'f001', 'items': [
        {'type': 'artifact', 'output_key': 'session', 'outcome': 'observed', 'evidence_ids': ['ok']},
        {'type': 'artifact', 'output_key': 'failed', 'outcome': 'observed', 'evidence_ids': ['bad']},
        {'type': 'fact', 'output_key': 'negative', 'outcome': 'negative', 'evidence_ids': ['ok']},
    ]}
    receipts = {'ok': {'fact_id': 'f001', 'status': 'completed',
                       'result': {'structuredContent': {'status': 'success'}}},
                'bad': {'fact_id': 'f001', 'status': 'failed', 'result': {}},
                'other': {'fact_id': 'f002', 'status': 'completed', 'result': {}}}
    assert validated_step_outputs(intents, [fact], receipts) == {'A': ['session']}
    assert validated_step_outputs(intents, [{'id': 'f001', 'items': None}], receipts) == {}
    assert validated_step_outputs(intents, [{'id': 'f001', 'items': [
        {'type': 'artifact', 'output_key': 'session', 'outcome': 'observed', 'evidence_ids': ['other']},
    ]}], receipts) == {}


def test_step_outputs_resolve_the_receipt_file_the_worker_cites():
    """Workers cite `.mcp-results/<call_id>.json`; the ledger keys by call id.

    Regression for 渗透33: the bare lookup never matched, so a dependent step's
    required_outputs gate could never be satisfied and the chain stalled.
    """
    intents = [{'step_id': 'recon-target', 'to': 'f001', 'execution_status': 'completed'}]
    fact = {'id': 'f001', 'items': [{
        'type': 'observation', 'output_key': 'recon', 'outcome': 'observed',
        'evidence_ids': [r'C:\ws\.mcp-results\00af57ef-cda5-4158-84f8-fd9d22f26a9f.json'],
    }]}
    receipts = {'00af57ef-cda5-4158-84f8-fd9d22f26a9f': {
        'fact_id': 'f001', 'status': 'completed', 'result': {'isError': False}}}
    assert validated_step_outputs(intents, [fact], receipts) == {'recon-target': ['recon']}


def test_merge_links_the_receipt_file_the_worker_cites(settings):
    """The goal review walks fact items through the same file reference.

    Regression for the observed-flag case: a fact item citing
    ``.mcp-results/<call_id>.json`` must yield an Evidence whose metadata
    receipt the verifier can cite, otherwise a captured flag can never be
    independently confirmed and the run ends as partial.
    """
    state = bound_state(settings)
    call_id = '2b0281af-3133-463a-bf23-8fc10b926a7f'
    facts = [{'id': 'f002', 'items': [{
        'id': 'f002:i007:flag', 'type': 'finding', 'output_key': 'flag',
        'outcome': 'observed', 'title': 'Flag via /read',
        'evidence_ids': [rf'C:\ws\.mcp-results\{call_id}.json'],
    }]}]
    receipts = {call_id: {'fact_id': 'f002', 'status': 'completed',
                          'blackboard': {'intent_id': 'i007'},
                          'result': {'isError': False, 'structuredContent': {'data': {}}}}}
    merge_workbench_results(state, facts, receipts)
    cited = rf'C:\ws\.mcp-results\{call_id}.json'
    assert [item.evidence_id for item in state.evidence] == [cited]
    assert state.evidence[0].metadata['receipt'] == receipts[call_id]
    assert [item.evidence_ids for item in state.findings] == [[cited]]
    # The verifier cites this same reference; the orchestrator maps it back to
    # the ledger's call id, which is what a completion decision must contain.
    assert receipt_for_ref(cited, receipts, 'f002') is receipts[call_id]


def waiting_chain(status='completed', outputs=None):
    return [
        {'id': 'i001', 'step_id': 'A', 'description': '执行A', 'execution_status': status,
         'to': 'f001' if status == 'completed' else None, 'worker': 'worker' if status == 'completed' else None,
         'attempt_id': 'attempt-current', 'validated_outputs': outputs or [], 'from': ['origin']},
        {'id': 'i002', 'step_id': 'B', 'description': '执行B', 'execution_status': 'waiting',
         'depends_on': ['A'], 'required_outputs': {'A': ['session']}, 'from': ['origin']},
    ]


@pytest.mark.parametrize('status', ['failed', 'timeout', 'cancelled', 'completed'])
def test_blocked_chain_is_not_live_but_independent_branch_remains_live(status):
    chain = waiting_chain(status)
    assert not has_live_planning_work(chain, {})
    assert has_live_planning_work(chain + [{'id': 'x', 'execution_status': 'waiting'}], {})


def test_waiting_chain_stays_live_until_upstream_finishes_or_output_is_confirmed():
    assert has_live_planning_work(waiting_chain('running'), {})
    assert has_live_planning_work(waiting_chain(), {'A': ['session']})
    assert has_live_planning_work(waiting_chain(outputs=['session']), {})


async def test_all_blocked_steps_stop_on_budget_exhaustion(planning):
    orchestrator, state, _, calls = planning
    state.budget.model_calls_used = state.budget.max_model_calls
    orchestrator.ledger.save_state(state)
    result = await orchestrator.planning_callback(request(state, intents=waiting_chain()))
    assert result.stop_reason and not result.intents and not calls


@pytest.mark.parametrize('receipt_case,confirmed', [
    ('success', True), ('failed', False), ('old-attempt', False), ('other-project', False),
    ('other-worker', False), ('native-failure', False), ('mcp-error', False),
])
async def test_callback_confirms_only_bound_current_successful_outputs(planning, receipt_case, confirmed):
    orchestrator, state, _, calls = planning
    state.budget.model_calls_used = state.budget.max_model_calls
    orchestrator.ledger.save_state(state)
    binding = {'project_id': 'proj-test', 'intent_id': 'i001',
               'worker': 'worker', 'attempt_id': 'attempt-current'}
    if receipt_case == 'old-attempt':
        binding['attempt_id'] = 'attempt-old'
    if receipt_case == 'other-project':
        binding['project_id'] = 'other'
    if receipt_case == 'other-worker':
        binding['worker'] = 'other'
    result = {'structuredContent': {'status': 'failed' if receipt_case == 'native-failure' else 'success'}}
    if receipt_case == 'mcp-error':
        result['isError'] = True
    orchestrator.ledger.append(state.run_id, 'mcp.call.completed', {
        'blackboard': binding, 'call_id': 'receipt',
        'status': 'failed' if receipt_case == 'failed' else 'completed', 'result': result})
    facts = [{'id': 'origin'}, {'id': 'f001', 'items': [{
        'type': 'artifact', 'output_key': 'session', 'outcome': 'observed', 'evidence_ids': ['receipt']}]}]
    req = request(state, facts=facts, intents=waiting_chain())
    response = await orchestrator.planning_callback(req)
    assert response.validated_outputs == ({'A': ['session']} if confirmed else {})
    assert bool(response.stop_reason) is not confirmed
    assert not calls
    replay = await orchestrator.planning_callback(req)
    assert replay.replayed and replay.validated_outputs == response.validated_outputs


async def test_independent_branch_prevents_whole_task_stop_on_failed_dependency(planning):
    orchestrator, state, queue, _ = planning
    queue.append({'stop_reason': 'A失败'})
    result = await orchestrator.planning_callback(request(state, intents=waiting_chain('failed') + [
        {'id': 'x', 'description': '独立方向', 'execution_status': 'waiting'}]))
    assert result.stop_reason is None


async def test_serial_todos_survive_one_independent_direction_limit(planning):
    orchestrator, state, queue, _ = planning
    queue.append({'intents': [direction('执行A', step_id='A'),
        direction('执行B', step_id='B', depends_on=['A'], required_outputs={'A': ['session']}),
        direction('执行C', step_id='C', depends_on=['B']), direction('独立X', step_id='X'),
        direction('执行Y', step_id='Y', depends_on=['X'])]})
    response = await orchestrator.planning_callback(request(state, budget={'max_new_intents': 1}))
    assert [item.step_id for item in response.intents] == ['A', 'B', 'C']
    assert not response.stop_reason


async def test_invalid_branch_does_not_consume_independent_direction_limit(planning):
    orchestrator, state, queue, _ = planning
    queue.append({'intents': [direction('重复1', step_id='A'), direction('重复2', step_id='A'),
        direction('执行B', step_id='B', depends_on=['A']), direction('可行X', step_id='X')]})
    response = await orchestrator.planning_callback(request(state, budget={'max_new_intents': 1}))
    assert [item.step_id for item in response.intents] == ['X']


@pytest.mark.parametrize('proposals', [
    [direction('执行A', step_id='A', depends_on=['B']), direction('执行B', step_id='B', depends_on=['A'])],
    [direction('执行A', step_id='A', depends_on=['unknown'])],
    [direction('执行A', step_id='A', required_outputs={'unknown': ['session']})],
    [direction('执行A', depends_on=['A'])],
])
async def test_invalid_dependency_contract_triggers_bounded_repair(planning, proposals):
    orchestrator, state, queue, calls = planning
    queue.extend([{'intents': proposals}, {'intents': [direction('修复后方向', step_id='X')]}])
    response = await orchestrator.planning_callback(request(state))
    assert [item.step_id for item in response.intents] == ['X'] and len(calls) == 2
    assert '上一轮方向未通过应用层校验' in calls[1]['user_prompt']


async def test_step_retry_preserves_dependency_contract_when_model_omits_fields(planning):
    orchestrator, state, queue, _ = planning
    chain = waiting_chain(outputs=['session'])
    chain[1]['execution_status'] = 'failed'
    queue.append({'intents': [direction('执行B', retry_intent_id='i002')]})
    response = await orchestrator.planning_callback(request(state, intents=chain))
    item = response.intents[0]
    assert item.step_id == 'B' and item.depends_on == ['A'] and item.required_outputs == {'A': ['session']}


async def test_self_keyed_required_outputs_does_not_discard_the_direction(planning):
    """A Planner reading required_outputs as "my own products" must not stop the task.

    Regression for 渗透33 (run a98a1c48): every round keyed the field by the
    direction's own step_id, so the strict gate check rejected the whole round,
    no directions were created, and the project stopped on a partial run.
    """
    orchestrator, state, queue, _ = planning
    queue.append({'intents': [
        direction('验证读取端点', step_id='s011', required_outputs={'s011': ['read_endpoint']}),
        direction('伪造会话', step_id='s012', depends_on=['s011'],
                  required_outputs={'s012': ['forged_session']}),
    ]})
    response = await orchestrator.planning_callback(request(state))
    assert [(item.step_id, item.depends_on, item.required_outputs) for item in response.intents] == [
        ('s011', [], {}), ('s012', ['s011'], {}),
    ]
    assert not response.stop_reason
    assert '指向自身的产物要求' in response.summary


async def test_output_gate_on_unlisted_declared_step_declares_the_dependency(planning):
    orchestrator, state, queue, _ = planning
    queue.append({'intents': [
        direction('执行A', step_id='A'),
        direction('执行B', step_id='B', required_outputs={'A': ['session']}),
    ]})
    response = await orchestrator.planning_callback(request(state, budget={'max_new_intents': 1}))
    b = next(item for item in response.intents if item.step_id == 'B')
    assert b.depends_on == ['A'] and b.required_outputs == {'A': ['session']}


async def test_planner_accepts_twelve_serial_todos(planning):
    orchestrator, state, queue, _ = planning
    queue.append({'intents': [direction(f'步骤{index}', step_id=str(index),
        depends_on=[str(index-1)] if index else []) for index in range(12)]})
    response = await orchestrator.planning_callback(request(state, budget={'max_new_intents': 1}))
    assert len(response.intents) == 12


@pytest.fixture
async def planning(settings, monkeypatch):
    service, _, gateway, _ = build_runtime(settings)
    settings.demo_mode = False
    state = bound_state(settings)
    service.ledger.save_state(state)
    queue, calls = [], []

    async def structured(**kwargs):
        calls.append(kwargs)
        return kwargs['output_model'].model_validate(queue.pop(0)), ModelCallMeta(
            model_id='mock', prompt_version='test', response_sha256='test',
            duration_ms=1, used_fallback=False, usage={'prompt_tokens': 2, 'completion_tokens': 1})

    monkeypatch.setattr(gateway, 'structured', structured)
    yield service.orchestrator, state, queue, calls
    await gateway.close()


async def test_initial_parallel_fact_continuation_merge_and_restart_replay(planning):
    orchestrator, state, queue, calls = planning
    queue.append({'intents': [direction('验证输入'), direction('验证限速')], 'rationale_summary': '并行验证两个方向'})
    first_request = request(state)
    first = await orchestrator.planning_callback(first_request)
    assert len(first.intents) == 2 and first.intents[0].success_criteria
    assert (await orchestrator.planning_callback(first_request)).replayed and len(calls) == 1
    orchestrator._planning_locks.clear()  # Only the durable decision survives a restart.
    assert (await orchestrator.planning_callback(first_request)).replayed and len(calls) == 1
    queue.append({'intents': [direction('交叉核验', ['f001', 'f002'])]})
    next_request = request(state, 'decision-next', facts=[{'id': 'f001'}, {'id': 'f002'}],
        intents=[{'id': 'i001', 'description': '验证输入', 'to': 'f001'},
                 {'id': 'i002', 'description': '验证限速', 'to': 'f002'}])
    second = await orchestrator.planning_callback(next_request)
    assert second.intents[0].from_ == ['f001', 'f002']
    assert len([e for e in orchestrator.ledger.events(state.run_id) if e.event_type == 'planning.decision']) == 2
    with pytest.raises(ValueError, match='另一份'):
        await orchestrator.planning_callback(next_request.model_copy(update={'decision_id': first_request.decision_id}))


async def test_goal_and_hint_sources_are_normalized_to_existing_fact(planning):
    orchestrator, state, queue, calls = planning
    queue.append({'intents': [direction('入口指纹与目标可达性确认',
        ['origin', 'goal', 'h003', 'h007'])], 'rationale_summary': '入口基线验证'})
    result = await orchestrator.planning_callback(request(state,
        facts=[{'id': 'origin'}, {'id': 'goal'}],
        hints=[{'id': 'h003', 'description': '目标 URL'}, {'id': 'h007', 'description': '会话线索'}]))
    assert len(result.intents) == 1 and result.intents[0].from_ == ['origin']
    assert result.stop_reason is None and len(calls) == 1
    assert '来源规范化' in result.summary and 'h003' in result.summary
    assert 'from 字段只能填写' in calls[0]['user_prompt']


async def test_goal_only_sources_are_reanchored_to_origin(planning):
    """A fresh project has only origin and goal, and goal is not a legal source.

    Regression for 渗透37: the Planner anchored every first-round direction on
    goal, Runtime rejects goal in ``from``, so the whole round was filtered out
    and the task stopped before it could start.
    """
    orchestrator, state, queue, calls = planning
    queue.append({'intents': [direction('入口基线与会话形态确认', ['goal'])], 'rationale_summary': '首轮基线'})
    result = await orchestrator.planning_callback(request(state,
        facts=[{'id': 'origin'}, {'id': 'goal'}]))
    assert len(result.intents) == 1 and result.intents[0].from_ == ['origin']
    assert result.stop_reason is None and len(calls) == 1
    assert 'goal' in result.summary


async def test_invalid_source_triggers_one_repair_with_feedback(planning):
    orchestrator, state, queue, calls = planning
    queue.extend([
        # A hint is a legal graph node but not a usable source. A proposal that
        # also names goal is re-anchored to origin instead (see the goal-only
        # regression below), so a hint-only source is what still needs repair.
        {'intents': [direction('首轮验证', ['h003'])]},
        {'intents': [direction('首轮验证', ['origin'])]},
    ])
    result = await orchestrator.planning_callback(request(state,
        facts=[{'id': 'origin'}, {'id': 'goal'}], hints=[{'id': 'h003', 'description': '线索'}]))
    assert len(result.intents) == 1 and result.intents[0].from_ == ['origin']
    assert not result.stop_reason and len(calls) == 2
    assert '上一轮方向未通过应用层校验' in calls[1]['user_prompt']
    assert '没有有效事实来源' in calls[1]['user_prompt']


async def test_unrepairable_source_error_is_explained_after_one_retry(planning):
    orchestrator, state, queue, calls = planning
    queue.extend([
        {'intents': [direction('首轮验证', ['origin', 'invented'])]},
        {'intents': [direction('首轮验证', ['origin', 'invented'])]},
    ])
    result = await orchestrator.planning_callback(request(state))
    assert not result.intents and len(calls) == 2
    assert result.stop_reason and '图一致性校验' in result.stop_reason
    assert 'invented' in result.summary


async def test_continuation_can_pass_the_previous_twelve_tool_and_twenty_model_limits(planning, monkeypatch):
    orchestrator, state, queue, calls = planning
    state.budget = orchestrator.initial_budget(state.task)
    state.budget.model_calls_used = 21
    orchestrator.ledger.save_state(state)
    monkeypatch.setattr(orchestrator.mcp_runtime.store, 'blackboard_calls_used', lambda run_id: 13)
    queue.append({'intents': [direction('根据新增证据继续验证')]})
    result = await orchestrator.planning_callback(request(state))
    assert result.intents and not result.stop_reason
    assert len(calls) == 1


@pytest.mark.parametrize('field,value', [('project_id', 'other'), ('goal', 'other'),
    ('target_scope', ['https://other.test']), ('snapshot_hash', 'incorrect-hash')])
async def test_callback_rejects_binding_scope_and_snapshot_changes(planning, field, value):
    orchestrator, state, _, calls = planning
    with pytest.raises(ValueError):
        await orchestrator.planning_callback(request(state).model_copy(update={field: value}))
    assert not calls


async def test_waiting_attempt_is_preserved_and_failure_requires_explicit_retry(planning):
    orchestrator, state, queue, _ = planning
    queue.append({'stop_reason': '没有新方向'})
    waiting = await orchestrator.planning_callback(request(state,
        intents=[{'id': 'i001', 'description': '验证输入', 'execution_status': 'running', 'worker': 'worker'}]))
    assert not waiting.stop_reason
    queue.append({'intents': [direction('验证输入', retry_intent_id='i001')]})
    retry = await orchestrator.planning_callback(request(state, 'decision-retry',
        intents=[{'id': 'i001', 'description': '验证输入', 'execution_status': 'failed', 'worker': None}]))
    assert retry.intents[0].retry_intent_id == 'i001'


async def test_retry_sources_are_pinned_to_original_intent(planning):
    orchestrator, state, queue, _ = planning
    queue.append({'intents': [direction('重试验证', ['origin', 'goal'], retry_intent_id='i001')]})
    result = await orchestrator.planning_callback(request(state, 'decision-retry-pinned',
        facts=[{'id': 'origin'}, {'id': 'goal'}],
        intents=[{'id': 'i001', 'description': '原始验证', 'from': ['origin'],
                  'execution_status': 'failed', 'worker': None}]))
    assert result.intents[0].from_ == ['origin']


@pytest.mark.parametrize('budget', ['model', 'tool', 'runtime', 'unsupported'])
async def test_budget_exhaustion_preserves_negative_results_and_stops(planning, budget):
    orchestrator, state, _, calls = planning
    if budget == 'model':
        state.budget.model_calls_used = state.budget.max_model_calls
    if budget == 'tool':
        state.budget.max_tool_calls = 0
    if budget == 'runtime':
        state.budget.runtime_seconds_used = state.budget.max_runtime_seconds
    orchestrator.ledger.save_state(state)
    facts = [{'id': 'f001', 'items': [{'id': 'negative', 'type': 'fact', 'title': '未复现', 'outcome': 'negative'}]}]
    result = await orchestrator.planning_callback(request(state, facts=facts,
        budget={'execution_supported': budget != 'unsupported'}))
    assert result.stop_reason and not result.completion_validated and not calls
    saved = orchestrator.ledger.load_state(state.run_id)
    assert saved.external_execution['external_facts'] == facts
    assert report_sections(saved)['ruled_out_directions'] and not saved.findings


@pytest.mark.parametrize('achieved', [True, False])
async def test_completion_requires_independent_review_of_actual_receipts(planning, achieved):
    orchestrator, state, queue, calls = planning
    binding = {'project_id': 'proj-test', 'intent_id': 'i001', 'attempt_id': 'attempt-one', 'worker': 'worker'}
    orchestrator.ledger.append(state.run_id, 'mcp.call.completed', {
        'blackboard': binding, 'call_id': 'call-one', 'result': {'body': '真实目标响应'}})
    facts = [{'id': 'f001', 'items': [{'id': 'one', 'type': 'fact', 'title': '观察响应', 'evidence_ids': ['call-one']}]}]
    queue.append({'achieved': achieved, 'evidence_ids': ['call-one'],
                  'rationale_summary': '独立核验依据'})
    if not achieved:
        queue.append({'intents': [direction('验证未满足的目标', ['f001'])]})
    result = await orchestrator.planning_callback(request(state, facts=facts,
        intents=[{'id': 'i001', 'to': 'f001', 'worker': 'worker', 'attempt_id': 'attempt-one'}]))
    assert result.completion_validated is achieved
    assert calls[0]['output_model'] == CompletionReviewOutput
    if achieved:
        assert result.completion_fact_ids == ['f001'] and not result.stop_reason
    else:
        assert result.intents and not result.stop_reason and not result.completion_fact_ids
        assert '独立目标核验未通过' in calls[-1]['user_prompt']


@pytest.mark.parametrize('arguments,declared,expected', [
    ({}, ['flag{server_response}'], ['flag{server_response}']),
    ({}, [], []),
    ({'body': 'flag{server_response}'}, ['flag{server_response}'], []),
    ({}, ['flag{not_in_receipt}'], []),
    ({}, ['response contains flag{server_response}'], []),
])
async def test_verified_outputs_require_verifier_and_non_reflected_receipt(
        planning, arguments, declared, expected):
    orchestrator, state, queue, _ = planning
    queue.append({'achieved': True, 'evidence_ids': ['call-one'],
                  'verified_outputs': declared, 'rationale_summary': '目标已核验'})
    facts = {'f001': {'id': 'f001', 'items': [{'evidence_ids': ['call-one']}]}}
    receipts = {'call-one': {'fact_id': 'f001', 'arguments': arguments,
                             'result': {'body': 'flag{server_response}'}}}
    valid, _, cited = await orchestrator.planner._validate_incremental_completion(
        state, request(state), facts, ['call-one'], '目标完成', None, receipts)
    assert valid
    assert cited == {'call-one'}
    assert state.external_execution['validated_goal_outputs'] == expected


async def test_environment_dump_flag_is_not_the_target_output(planning):
    """渗透39: ``/proc/self/environ`` leaked the platform's per-instance FLAG.

    The verifier accepted it, so the run reported ``ctfshow{971f3e2b-...}``
    while the challenge's own ``/flag`` route returned
    ``CTF{flask_session_is_secure}``.  A value that only appears in a process
    metadata dump must not be promoted to the target output.
    """
    orchestrator, state, queue, _ = planning
    queue.append({'achieved': True, 'evidence_ids': ['call-one'],
                  'verified_outputs': ['ctfshow{971f3e2b-a734-4744-90f3-5a4fd930a200}'],
                  'rationale_summary': '环境变量中包含 FLAG'})
    facts = {'f001': {'id': 'f001', 'items': [{'evidence_ids': ['call-one']}]}}
    receipts = {'call-one': {'fact_id': 'f001', 'arguments': {'url': 'https://target.test/read?url=file:///proc/self/environ'},
                             'result': {'body': 'HOSTNAME=abc\x00HOME=/root\x00PATH=/usr/bin\x00'
                                                'FLAG=ctfshow{971f3e2b-a734-4744-90f3-5a4fd930a200}\x00'}}}
    goal = request(state).model_copy(update={'goal': 'get the flag'})
    valid, reason, cited = await orchestrator.planner._validate_incremental_completion(
        state, goal, facts, ['call-one'], '目标完成', None, receipts)
    assert not valid and cited == set()
    assert 'flag' in reason
    assert 'validated_goal_outputs' not in state.external_execution


async def test_application_flag_still_wins_over_an_environment_dump(planning):
    """The challenge's own flag path must keep working after the metadata guard."""
    orchestrator, state, queue, _ = planning
    queue.append({'achieved': True, 'evidence_ids': ['call-one', 'call-two'],
                  'verified_outputs': ['CTF{flask_session_is_secure}'],
                  'rationale_summary': '伪造 admin 会话后 /flag 返回题目 flag'})
    facts = {'f001': {'id': 'f001', 'items': [{'evidence_ids': ['call-one', 'call-two']}]}}
    receipts = {
        'call-one': {'fact_id': 'f001', 'arguments': {'url': 'https://target.test/read?url=file:///proc/self/environ'},
                     'result': {'body': 'HOSTNAME=abc\x00HOME=/root\x00PATH=/usr/bin\x00FLAG=ctfshow{per-instance}\x00'}},
        'call-two': {'fact_id': 'f001', 'arguments': {'url': 'https://target.test/flag',
                                                      'cookie': 'session=forged'},
                     'result': {'body': 'CTF{flask_session_is_secure}'}},
    }
    goal = request(state).model_copy(update={'goal': 'get the flag'})
    valid, _, cited = await orchestrator.planner._validate_incremental_completion(
        state, goal, facts, ['call-one', 'call-two'], '目标完成', None, receipts)
    assert valid and cited == {'call-one', 'call-two'}
    assert state.external_execution['validated_goal_outputs'] == ['CTF{flask_session_is_secure}']


@pytest.mark.parametrize('arguments,declared,achieved', [
    ({}, [], False),
    ({'body': 'flag{server_response}'}, ['flag{server_response}'], False),
    ({}, ['flag{server_response}'], True),
])
async def test_flag_goal_requires_verified_output(planning, arguments, declared, achieved):
    orchestrator, state, queue, _ = planning
    queue.append({'achieved': True, 'evidence_ids': ['call-one'],
                  'verified_outputs': declared, 'rationale_summary': '目标已核验'})
    facts = {'f001': {'id': 'f001', 'items': [{'evidence_ids': ['call-one']}]}}
    receipts = {'call-one': {'fact_id': 'f001', 'arguments': arguments,
                             'result': {'body': 'flag{server_response}'}}}
    goal = request(state).model_copy(update={'goal': '取得目标 flag'})
    valid, reason, cited = await orchestrator.planner._validate_incremental_completion(
        state, goal, facts, ['call-one'], '目标完成', None, receipts)
    assert valid is achieved
    assert cited == ({'call-one'} if achieved else set())
    assert len(state.decisions) == int(achieved)
    if not achieved:
        assert 'flag' in reason and 'validated_goal_outputs' not in state.external_execution


async def test_verified_completion_can_preempt_waiting_directions(planning):
    orchestrator, state, queue, calls = planning
    queue.append({'achieved': True, 'evidence_ids': ['call-one'], 'rationale_summary': '回执证明目标'})
    binding = {'project_id': 'proj-test', 'intent_id': 'i001', 'attempt_id': 'attempt-one', 'worker': 'worker'}
    orchestrator.ledger.append(state.run_id, 'mcp.call.completed', {
        'blackboard': binding, 'call_id': 'call-one', 'result': {'body': '目标响应'}})
    facts = [{'id': 'f001', 'items': [{'id': 'one', 'type': 'fact',
                                     'evidence_ids': ['call-one']}]}]
    intents = [{'id': 'i001', 'to': 'f001', 'worker': 'worker', 'attempt_id': 'attempt-one'},
               {'id': 'i002', 'execution_status': 'waiting', 'worker': None}]
    result = await orchestrator.planning_callback(request(state, facts=facts, intents=intents))
    assert result.completion_validated and result.completion_fact_ids == ['f001']
    assert len(calls) == 1


async def test_flag_fact_completes_before_running_directions_and_reaches_report(planning, monkeypatch):
    orchestrator, state, queue, calls = planning
    flag = 'CTF{ctfshow_session_fixation_is_a_common_web_security_vulnerability}'
    state.task.objective = '取得 flag'
    state.budget.max_tool_calls = 0
    orchestrator.ledger.save_state(state)
    binding = {'project_id': 'proj-test', 'intent_id': 'i010',
               'attempt_id': 'attempt-one', 'worker': 'worker'}
    orchestrator.ledger.append(state.run_id, 'mcp.call.completed', {
        'blackboard': binding, 'call_id': 'flag-response',
        'arguments': {'url': 'https://authorized.test/'},
        'result': {'body': f'<h3>FLAG: {flag}</h3>'}})
    facts = [{'id': 'f006', 'items': [{'evidence_ids': ['flag-response']}]}]
    intents = [{'id': 'i010', 'to': 'f006', 'worker': 'worker', 'attempt_id': 'attempt-one'},
               {'id': 'i011', 'execution_status': 'running', 'worker': 'other'},
               {'id': 'i012', 'execution_status': 'waiting', 'worker': None}]
    queue.append({'achieved': True, 'evidence_ids': ['flag-response'],
                  'verified_outputs': [flag], 'rationale_summary': '响应包含目标 flag'})
    decision = await orchestrator.planning_callback(request(state, facts=facts, intents=intents))
    assert decision.completion_validated and decision.completion_fact_ids == ['f006']
    assert not decision.intents and len(calls) == 1
    saved = orchestrator.ledger.load_state(state.run_id)
    assert saved.external_execution['validated_goal_outputs'] == [flag]

    async def terminal_project(*args, **kwargs):
        return {'status': 'completed', 'objective_reached': True,
            'detail': {'project': {'id': 'proj-test', 'title': 'sec-task-planning-test',
                                   'status': 'completed'}, 'facts': facts, 'intents': intents}}

    monkeypatch.setattr('security_agent.orchestrator.wait_for_project_terminal', terminal_project)
    result = await orchestrator._runtime_wait({'agent': saved.model_dump(mode='json')})
    final = await orchestrator.reporter.run(AgentState.model_validate(result['agent']), allow_model=False)
    assert final.status == RunStatus.COMPLETED
    assert final.report.verified_outputs == [flag]


async def test_goal_review_reuses_failed_evidence_set_until_new_receipt(planning):
    orchestrator, state, queue, calls = planning
    binding = {'project_id': 'proj-test', 'intent_id': 'i001',
               'attempt_id': 'attempt-one', 'worker': 'worker'}
    orchestrator.ledger.append(state.run_id, 'mcp.call.completed', {
        'blackboard': binding, 'call_id': 'call-one', 'result': {'body': 'partial'}})
    facts = [{'id': 'f001', 'items': [{'evidence_ids': ['call-one']}]}]
    intents = [{'id': 'i001', 'to': 'f001', 'worker': 'worker', 'attempt_id': 'attempt-one'},
               {'id': 'i002', 'execution_status': 'running', 'worker': 'other'}]
    queue.extend([{'achieved': False, 'rationale_summary': '证据不足'},
                  {'stop_reason': '等待已有方向'}, {'stop_reason': '等待已有方向'}])
    first = await orchestrator.planning_callback(request(state, facts=facts, intents=intents))
    second = await orchestrator.planning_callback(request(state, 'decision-next', facts=facts, intents=intents))
    assert not first.stop_reason and not second.stop_reason
    assert [call['output_model'] for call in calls].count(CompletionReviewOutput) == 1
    assert orchestrator.ledger.load_state(state.run_id).external_execution['goal_review']['reason'] == '证据不足'

    orchestrator.ledger.append(state.run_id, 'mcp.call.completed', {
        'blackboard': {'project_id': 'proj-test', 'intent_id': 'i003',
                       'attempt_id': 'attempt-two', 'worker': 'worker'},
        'call_id': 'call-two', 'result': {'body': 'target response'}})
    queue.extend([{'achieved': True, 'evidence_ids': ['call-two'],
                   'rationale_summary': '新增回执满足目标'}])
    facts.append({'id': 'f002', 'items': [{'evidence_ids': ['call-two']}]})
    intents.append({'id': 'i003', 'to': 'f002', 'worker': 'worker', 'attempt_id': 'attempt-two'})
    third = await orchestrator.planning_callback(request(state, 'decision-third', facts=facts, intents=intents))
    assert third.completion_validated and third.completion_fact_ids == ['f002']
    assert [call['output_model'] for call in calls].count(CompletionReviewOutput) == 2


async def test_last_model_call_used_for_review_waits_for_running_direction(planning):
    orchestrator, state, queue, calls = planning
    state.budget.max_model_calls = 1
    orchestrator.ledger.save_state(state)
    orchestrator.ledger.append(state.run_id, 'mcp.call.completed', {
        'blackboard': {'project_id': 'proj-test', 'intent_id': 'i001',
                       'attempt_id': 'attempt-one', 'worker': 'worker'},
        'call_id': 'call-one', 'result': {'body': 'partial'}})
    facts = [{'id': 'f001', 'items': [{'evidence_ids': ['call-one']}]}]
    intents = [{'id': 'i001', 'to': 'f001', 'worker': 'worker', 'attempt_id': 'attempt-one'},
               {'id': 'i002', 'execution_status': 'running', 'worker': 'other'}]
    queue.append({'achieved': False, 'rationale_summary': '仍缺少目标输出'})
    result = await orchestrator.planning_callback(request(state, facts=facts, intents=intents))
    assert not result.completion_validated and not result.stop_reason
    assert len(calls) == 1


async def test_failed_goal_review_stops_when_no_direction_remains(planning):
    orchestrator, state, queue, calls = planning
    orchestrator.ledger.append(state.run_id, 'mcp.call.completed', {
        'blackboard': {'project_id': 'proj-test', 'intent_id': 'i001',
                       'attempt_id': 'attempt-one', 'worker': 'worker'},
        'call_id': 'call-one', 'result': {'body': 'partial'}})
    facts = [{'id': 'f001', 'items': [{'evidence_ids': ['call-one']}]}]
    intents = [{'id': 'i001', 'to': 'f001', 'worker': 'worker', 'attempt_id': 'attempt-one'}]
    queue.extend([{'achieved': False, 'rationale_summary': '证据不足'},
                  {'stop_reason': '没有可执行的新方向'}])
    result = await orchestrator.planning_callback(request(state, facts=facts, intents=intents))
    assert result.stop_reason and not result.completion_validated
    assert [call['output_model'] for call in calls].count(CompletionReviewOutput) == 1


async def test_completion_sources_include_only_verifier_cited_facts(planning):
    orchestrator, state, queue, _ = planning
    queue.append({'achieved': True, 'evidence_ids': ['call-one'],
                  'rationale_summary': '第一份回执足够证明目标'})
    for intent_id, call_id in [('i001', 'call-one'), ('i002', 'call-two')]:
        orchestrator.ledger.append(state.run_id, 'mcp.call.completed', {
            'blackboard': {'project_id': 'proj-test', 'intent_id': intent_id,
                           'attempt_id': 'attempt-one', 'worker': 'worker'},
            'call_id': call_id, 'result': {'body': 'target response'}})
    facts = [{'id': fact_id, 'items': [{'evidence_ids': [call_id]}]}
             for fact_id, call_id in [('f001', 'call-one'), ('f002', 'call-two')]]
    intents = [{'id': intent_id, 'to': fact_id, 'worker': 'worker',
                'attempt_id': 'attempt-one'}
               for intent_id, fact_id in [('i001', 'f001'), ('i002', 'f002')]]
    result = await orchestrator.planning_callback(request(state, facts=facts, intents=intents))
    assert result.completion_validated and result.completion_fact_ids == ['f001']


async def test_verifier_cannot_cite_unlinked_receipt(planning):
    orchestrator, state, queue, _ = planning
    queue.append({'achieved': True, 'evidence_ids': ['call-two']})
    facts = {'f001': {'id': 'f001', 'items': [{'evidence_ids': ['call-one']}]}}
    receipts = {'call-one': {'fact_id': 'f001', 'result': {'body': 'target response'}},
                'call-two': {'fact_id': 'f002', 'result': {'body': 'unlinked response'}}}
    valid, _, cited = await orchestrator.planner._validate_incremental_completion(
        state, request(state), facts, ['call-one', 'call-two'], '目标完成', None, receipts)
    assert not valid and not cited


async def test_running_direction_does_not_block_completion_review(planning):
    orchestrator, state, queue, calls = planning
    queue.append({'achieved': True, 'evidence_ids': ['call-one']})
    facts = {'f001': {'id': 'f001', 'items': [{'evidence_ids': ['call-one']}]}}
    receipts = {'call-one': {'fact_id': 'f001', 'result': {'body': 'target response'}}}
    intents = [{'id': 'i002', 'execution_status': 'running', 'worker': 'worker'}]
    valid, reason, cited = await orchestrator.planner._validate_incremental_completion(
        state, request(state, intents=intents), facts, ['call-one'], '目标完成', None, receipts)
    assert valid and cited == {'call-one'} and len(calls) == 1


async def test_wrong_attempt_receipt_cannot_verify_goal(planning):
    orchestrator, state, queue, calls = planning
    orchestrator.ledger.append(state.run_id, 'mcp.call.completed', {
        'blackboard': {'project_id': 'proj-test', 'intent_id': 'i001', 'worker': 'worker', 'attempt_id': 'old'},
        'call_id': 'call-one', 'result': {'body': 'response'}})
    queue.append({'completion_requested': True, 'completion_evidence_ids': ['call-one'], 'completion_summary': '完成'})
    queue.append({'stop_reason': '没有可行的新验证方向'})
    result = await orchestrator.planning_callback(request(state, facts=[{'id': 'f001'}],
        intents=[{'id': 'i001', 'to': 'f001', 'worker': 'worker', 'attempt_id': 'new'}]))
    assert not result.completion_validated and len(calls) == 2 and result.stop_reason


@pytest.mark.parametrize('verdict', ['confirmed', 'excluded', 'insufficient'])
async def test_facts_candidates_and_vulnerability_review_remain_separate(planning, verdict):
    orchestrator, state, queue, _ = planning
    facts = [{'id': 'f001', 'items': [
        {'id': 'fact', 'type': 'fact', 'title': '普通事实', 'evidence_ids': ['call-one']},
        {'id': 'candidate', 'type': 'finding', 'title': '候选', 'evidence_ids': ['call-one', 'foreign']},
        {'id': 'missing', 'type': 'finding', 'title': 'Worker 报告', 'evidence_ids': ['foreign']}]}]
    receipts = {'call-one': {'fact_id': 'f001', 'result': {'body': '工具输出'}},
                'foreign': {'fact_id': 'different-fact', 'result': {'body': '不属于此结果'}}}
    merge_workbench_results(state, facts, receipts)
    assert len(state.findings) == 2 and len(state.evidence) == 1
    assert not report_sections(state)['confirmed_findings']
    queue.append({'verdict': verdict, 'evidence_ids': ['call-one'], 'rationale_summary': '证据核验'})
    await orchestrator.planner.verify_incremental_findings(state)
    sections = report_sections(state)
    assert len(sections['confirmed_findings']) == (1 if verdict == 'confirmed' else 0)
    assert bool(sections['ruled_out_directions']) is (verdict == 'excluded')
    assert sections['insufficient_evidence']


async def test_native_candidates_are_projected_once_and_new_evidence_reopens_review(planning):
    _, state, _, _ = planning
    facts = [{'id': 'f001', 'items': []}]
    receipt = {'fact_id': 'f001', 'result': {'structuredContent': {'data': {'findings': [
        {'finding_id': 'native-one', 'title': '静态候选', 'evidence_ids': ['evidence-one']}]}}}}
    merge_workbench_results(state, facts, {'evidence-one': receipt})
    assert state.external_execution['external_facts'][0]['items'][0]['id'] == 'native:native-one'
    state.findings[0].raw['verification_status'] = 'insufficient'
    merge_workbench_results(state, facts, {'evidence-one': receipt})
    assert state.findings[0].raw['verification_status'] == 'insufficient' and len(state.findings) == 1
    receipt['result']['structuredContent']['data']['findings'][0]['evidence_ids'].append('evidence-two')
    merge_workbench_results(state, facts, {'evidence-one': receipt, 'evidence-two': receipt})
    assert state.findings[0].raw['verification_status'] == 'pending'


async def test_internal_callback_requires_token_and_url_binding(settings, monkeypatch):
    settings.security_runtime_callback_token = 'unit-test-planning-credential'
    app = create_app(settings)
    service = app.state.service
    state = bound_state(settings)
    service.ledger.save_state(state)
    body = request(state).model_dump(mode='json')
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://testserver') as client:
            url = '/api/v1/internal/runs/planning-test/planning'
            assert (await client.post(url, json=body)).status_code == 401
            headers = {'X-Security-Runtime-Token': settings.security_runtime_callback_token}
            assert (await client.post(url, json={**body, 'run_id': 'other'}, headers=headers)).status_code == 409
            response = await client.post(url, json=body, headers=headers)
            assert response.status_code == 200 and response.json()['stop_reason']
            assert response.json()['cold_digest']['status'] == 'compacted'
            replay = await client.post(url, json=body, headers=headers)
            assert replay.status_code == 200
            assert replay.json()['cold_digest']['status'] == 'replayed'
            digest = await client.get('/api/v1/runs/planning-test/cold-digest')
            assert digest.status_code == 200
            assert len(digest.json()['rounds']) == 1
            compacted = [event for event in service.ledger.events('planning-test', limit=1000)
                         if event.event_type == 'blackboard.cold_digest.compacted']
            assert len(compacted) == 1
    finally:
        await service.orchestrator.gateway.close()


async def test_runtime_planning_keeps_response_when_cold_digest_fails(settings, monkeypatch):
    settings.security_runtime_callback_token = 'unit-test-planning-credential'
    app = create_app(settings)
    service = app.state.service
    state = bound_state(settings)
    service.ledger.save_state(state)

    def fail_compact(*args, **kwargs):
        raise RuntimeError('digest fixture failure')

    monkeypatch.setattr(app.state.cold_digests, 'compact', fail_compact)
    body = request(state).model_dump(mode='json')
    headers = {'X-Security-Runtime-Token': settings.security_runtime_callback_token}
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://testserver') as client:
            response = await client.post('/api/v1/internal/runs/planning-test/planning', json=body, headers=headers)
            assert response.status_code == 200
            assert response.json()['stop_reason']
            assert response.json()['cold_digest']['status'] == 'failed'
            failed = [event for event in service.ledger.events('planning-test', limit=1000)
                      if event.event_type == 'blackboard.cold_digest.failed']
            assert len(failed) == 1
    finally:
        await service.orchestrator.gateway.close()


@pytest.mark.parametrize('terminal,verification,expected', [
    ('stopped', 'none', RunStatus.PARTIAL),
    ('timeout', 'none', RunStatus.PARTIAL),
    ('completed', 'none', RunStatus.PARTIAL),
    ('completed', 'missing_evidence', RunStatus.PARTIAL),
    ('completed', 'verified', RunStatus.COMPLETED),
])
async def test_runtime_terminal_requires_verified_goal_and_preserves_stop_reason(
        planning, monkeypatch, terminal, verification, expected):
    orchestrator, state, _, _ = planning
    state.external_execution['planning_decisions'] = {
        'decision-stop': {'stop_reason': '没有授权范围内可行的验证方向'}}
    if verification != 'none':
        state.decisions.append(DecisionRecord(decision='goal_verification_passed',
            rationale_summary='目标证据已核验', evidence_ids=['actual-evidence']))
    if verification == 'verified':
        state.evidence.append(Evidence(evidence_id='actual-evidence', source='security_runtime_tool',
            summary='真实证据', metadata={'receipt': {'fact_id': 'f001', 'result': {'body': '目标响应'}}}))
    orchestrator.ledger.save_state(state)

    async def terminal_project(*args, **kwargs):
        return {'status': terminal, 'objective_reached': terminal == 'completed',
            'detail': {'project': {'id': 'proj-test', 'title': 'sec-task-planning-test', 'status': terminal},
                       'facts': [{'id': 'f001', 'items': []}], 'intents': []}}

    monkeypatch.setattr('security_agent.orchestrator.wait_for_project_terminal', terminal_project)
    result = await orchestrator._runtime_wait({'agent': state.model_dump(mode='json')})
    saved = AgentState.model_validate(result['agent'])
    assert result['route'] == 'report' and saved.status == expected
    if terminal == 'stopped':
        assert saved.last_error == '没有授权范围内可行的验证方向'
    elif terminal == 'completed' and verification != 'verified':
        assert '目标核验记录' in saved.last_error
    elif expected == RunStatus.COMPLETED:
        assert saved.last_error is None


async def test_runtime_terminal_keeps_native_candidates_in_canvas(planning, monkeypatch):
    from security_agent.penetration_integration import normalize_penetration_graph
    orchestrator, state, _, _ = planning
    facts = [{'id': 'f001', 'description': '静态分析产出', 'items': []}]
    receipt = {'fact_id': 'f001', 'result': {'structuredContent': {'data': {'findings': [
        {'finding_id': 'native-candidate', 'title': '待验证静态候选', 'evidence_ids': ['native-evidence']}]}}}}
    merge_workbench_results(state, facts, {'native-evidence': receipt})
    orchestrator.ledger.save_state(state)
    detail = {'project': {'id': 'proj-test', 'title': 'sec-task-planning-test', 'status': 'stopped'},
              'facts': facts, 'intents': []}

    async def terminal_project(*args, **kwargs):
        return {'status': 'stopped', 'objective_reached': False, 'detail': detail}

    monkeypatch.setattr('security_agent.orchestrator.wait_for_project_terminal', terminal_project)
    result = await orchestrator._runtime_wait({'agent': state.model_dump(mode='json')})
    saved = AgentState.model_validate(result['agent'])
    graph = normalize_penetration_graph(detail, state=saved)
    assert len(saved.findings) == 1 and len(graph['result_items']) == 1
    assert graph['result_items'][0]['title'] == '待验证静态候选'
    assert graph['result_items'][0]['verification_status'] == 'pending'


async def test_runtime_wait_success_exposes_external_status_to_reporter(planning, monkeypatch):
    """A verified Runtime-owned goal must not be downgraded to PARTIAL.

    Regression for 渗透31_retry (run 3aa7844b): the blackboard goal had been
    verified and the flag captured, yet the run ended as ``partial`` because
    ``_runtime_wait`` recorded the terminal state under ``status`` while
    ``ReporterAgent.is_successful`` only looks at ``external_status``.
    """
    orchestrator, state, _, _ = planning
    state.task = TaskRequest(objective='get the flag', target_scope=['https://authorized.test'])
    state.external_execution['validated_goal_outputs'] = ['CTF{fixture-flag}']
    state.decisions.append(DecisionRecord(decision='goal_verification_passed',
        rationale_summary='目标证据已核验', evidence_ids=['flag-evidence']))
    state.evidence.append(Evidence(evidence_id='flag-evidence', source='security_runtime_tool',
        summary='目标响应', metadata={'receipt': {'fact_id': 'f001', 'result': {'body': 'CTF{fixture-flag}'}}}))
    orchestrator.ledger.save_state(state)

    async def terminal_project(*args, **kwargs):
        return {'status': 'completed', 'objective_reached': True, 'terminal': True,
            'fact_count': 2, 'intent_count': 1,
            'detail': {'project': {'id': 'proj-test', 'title': 'sec-task-planning-test',
                                   'status': 'completed'},
                       'facts': [{'id': 'f001', 'items': []}], 'intents': []}}

    monkeypatch.setattr('security_agent.orchestrator.wait_for_project_terminal', terminal_project)
    result = await orchestrator._runtime_wait({'agent': state.model_dump(mode='json')})
    saved = AgentState.model_validate(result['agent'])

    assert saved.status == RunStatus.COMPLETED
    latest = saved.observations[-1]
    # Reporter contract: an asynchronous Runtime project counts as a success
    # only when both external_status and objective_reached agree.
    assert latest.data['external_status'] == 'completed'
    assert latest.data['external_terminal'] is True
    assert latest.data['external_fact_count'] == 2

    reported = await orchestrator.reporter.run(saved)
    assert reported.status == reported.report.status == RunStatus.COMPLETED
    assert not any('未返回成功结果' in item for item in reported.report.limitations)


async def test_report_refresh_promotes_verified_runtime_goal_from_partial(settings):
    """A verified flag must not stay sealed as partial after a mis-projection.

    Regression for 渗透31_retry (run 3aa7844b): the run was persisted as
    ``partial`` before the external_status fix, so the history entry kept
    showing "部分完成" even though the goal was independently verified.  The
    refresh entry point must re-derive the terminal status from the persisted
    blackboard evidence instead of projecting the stale snapshot.
    """
    flag = 'CTF{ctfshow_session_fixation_is_a_common_web_security_vulnerability}'
    state = AgentState(
        run_id='planning-refresh-promote', status=RunStatus.PARTIAL,
        module_route='penetration', scenario='penetration_test',
        task=TaskRequest(objective='get the flag', target_scope=['https://authorized.test']),
        last_error='外部模块未返回成功结果；请检查对应服务地址和授权配置。',
        external_execution={'blackboard': {'backend': 'remote', 'planning_mode': 'workbench',
                                           'project_id': 'proj-test', 'status': 'completed'},
                            'validated_goal_outputs': [flag], 'objective_reached': True},
        observations=[ToolResult(status=ToolStatus.SUCCESS, summary='Runtime 项目完成：completed',
            data={'external_status': 'completed', 'objective_reached': True, 'adapter': 'penetration'})],
        report=AgentReport(run_id='planning-refresh-promote', status=RunStatus.PARTIAL,
            executive_summary='任务部分完成，已保留结果。',
            limitations=['外部模块未返回成功结果；请检查对应服务地址和授权配置。']))
    refreshed = await synchronize_report(state, settings)
    assert refreshed.status == RunStatus.COMPLETED
    assert refreshed.report.status == RunStatus.COMPLETED
    assert refreshed.last_error is None
    assert not any('未返回成功结果' in item for item in refreshed.report.limitations)


async def test_report_refresh_keeps_partial_without_verified_goal(settings):
    """The refresh must never promote a run that still lacks verified evidence."""
    state = AgentState(
        run_id='planning-refresh-keep', status=RunStatus.PARTIAL,
        module_route='penetration', scenario='penetration_test',
        task=TaskRequest(objective='get the flag', target_scope=['https://authorized.test']),
        external_execution={'blackboard': {'backend': 'remote', 'planning_mode': 'workbench',
                                           'project_id': 'proj-test', 'status': 'stopped'}},
        observations=[ToolResult(status=ToolStatus.SUCCESS, summary='Runtime 项目完成：stopped',
            data={'external_status': 'stopped', 'objective_reached': False, 'adapter': 'penetration'})],
        report=AgentReport(run_id='planning-refresh-keep', status=RunStatus.PARTIAL,
            executive_summary='探索已停止，目标未验证完成。'))
    refreshed = await synchronize_report(state, settings)
    assert refreshed.status == RunStatus.PARTIAL
    assert refreshed.report.status == RunStatus.PARTIAL
