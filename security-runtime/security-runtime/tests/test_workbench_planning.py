from concurrent.futures import ThreadPoolExecutor
import hashlib
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from tests.test_server_api import client
from security_runtime.server import db
from security_runtime.server.models import ProjectDetail
from security_runtime.server.services import planning_snapshot_hash


def project(client):
    body = {'title': 'sec-task-test', 'origin': 'start', 'goal': 'finish',
            'bootstrap_enabled': False, 'idempotency_key': 'run-test',
            'hints': [{'creator': 'unified-workbench', 'content': 'workbench_planner:run_id=test;schema=1.1'}]}
    return client.post('/projects', json=body).json()['project']['id'], body


def decision(client, pid, key, **extra):
    detail = ProjectDetail.model_validate(client.get(f'/projects/{pid}').json())
    if detail.project.reason is None and detail.project.status == 'active':
        claim = client.post(f'/projects/{pid}/reason/claim', json={
            'worker': 'pi_planner', 'trigger': 'test', 'attempt_id': detail.project.reason_attempt_id,
        })
        assert claim.status_code == 200, claim.text
        detail = ProjectDetail.model_validate(client.get(f'/projects/{pid}').json())
    return {'decision_id': key, 'snapshot_hash': planning_snapshot_hash(detail),
            'reason_attempt_id': detail.project.reason_attempt_id,
            'trigger': 'test', 'summary': 'public summary', **extra}


def test_project_creation_is_atomic_and_replays_after_lost_response(client):
    pid, body = project(client)
    with ThreadPoolExecutor(max_workers=4) as pool:
        responses = list(pool.map(lambda _: client.post('/projects', json=body), range(8)))
    assert all(r.status_code == 201 and r.json()['project']['id'] == pid for r in responses)
    assert len(client.get('/projects').json()) == 1
    assert client.post('/projects', json={**body, 'goal': 'different'}).status_code == 409


def test_authenticated_round_retry_restart_and_stop(client, monkeypatch):
    monkeypatch.setenv('SECURITY_RUNTIME_CALLBACK_TOKEN', 'test-planning-token')
    headers = {'X-Security-Runtime-Token': 'test-planning-token'}
    pid, _ = project(client)
    route = f'/projects/{pid}/planning/decisions'
    proposal = {'from': ['origin'], 'description': 'check login', 'title': 'check',
                'verification_target': 'login', 'success_criteria': ['response observed']}
    first = decision(client, pid, 'decision-first', intents=[proposal, {**proposal, 'description': 'check limits'}])
    assert client.post(route, json=first).status_code == 403
    created = client.post(route, json=first, headers=headers).json()
    assert len(created['intent_ids']) == 2
    assert client.post(route, json=first, headers=headers).json()['status'] == 'replayed'
    assert len(client.get(f'/projects/{pid}').json()['intents']) == 2
    intent = created['intent_ids'][0]
    path = f'/projects/{pid}/intents/{intent}'
    attempt = client.post(path + '/heartbeat', json={'worker': 'worker', 'claim': True}).json()['attempt_id']
    # Heartbeat traffic must not invalidate an otherwise unchanged planning snapshot.
    snapshot = decision(client, pid, 'decision-heartbeat')
    client.post(path + '/heartbeat', json={'worker': 'worker', 'attempt_id': attempt})
    assert client.post(route, json=snapshot, headers=headers).status_code == 200
    client.post(path + '/release', json={'worker': 'worker', 'outcome': 'timeout', 'attempt_id': attempt})
    assert client.post(path + '/heartbeat', json={'worker': 'worker', 'attempt_id': attempt, 'claim': True}).status_code == 409
    retry = decision(client, pid, 'decision-retry', intents=[{**proposal, 'retry_intent_id': intent}])
    assert client.post(route, json=retry, headers=headers).json()['intent_ids'] == [intent]
    second = client.post(path + '/heartbeat', json={'worker': 'worker', 'attempt_id': attempt, 'claim': True}).json()['attempt_id']
    assert second != attempt
    result = {'worker': 'worker', 'attempt_id': second, 'description': 'negative result', 'title': 'no injection',
              'items': [{'type': 'fact', 'title': 'not reproduced', 'summary': 'response unchanged', 'outcome': 'negative'}]}
    fact = client.post(path + '/conclude', json=result).json()['fact']
    assert client.post(path + '/conclude', json=result).json()['fact']['id'] == fact['id']
    assert client.post(route, json=snapshot, headers=headers).json()['status'] == 'replayed'
    stale = {**snapshot, 'decision_id': 'decision-stale'}
    assert client.post(route, json=stale, headers=headers).status_code == 409
    stop = decision(client, pid, 'decision-stop', stop_reason='model budget exhausted')
    assert client.post(route, json=stop, headers=headers).json()['status'] == 'stopped'
    # A restarted client can replay a terminal decision without creating more results.
    assert client.post(route, json=stop, headers=headers).json()['status'] == 'replayed'
    detail = client.get(f'/projects/{pid}').json()
    assert len(detail['facts']) == 3
    assert detail['intents'][1]['execution_status'] == 'cancelled'
    events = client.get(f'/projects/{pid}/events').json()['events']
    assert len([e for e in events if e['event_type'] == 'completed']) == 1
    assert any(e['event_type'] == 'retry' and e['payload']['previous_attempt_id'] == attempt for e in events)


def test_stale_worker_attempt_cannot_change_retried_intent(client, monkeypatch):
    monkeypatch.setenv('SECURITY_RUNTIME_CALLBACK_TOKEN', 'test-planning-token')
    headers = {'X-Security-Runtime-Token': 'test-planning-token'}
    pid, _ = project(client)
    proposal = {'from': ['origin'], 'description': 'check login', 'title': 'check',
                'verification_target': 'login', 'success_criteria': ['response observed']}
    route = f'/projects/{pid}/planning/decisions'
    response = client.post(route, json=decision(client, pid, 'decision-create', intents=[proposal]), headers=headers)
    assert response.status_code == 200, response.text
    created = response.json()
    path = f"/projects/{pid}/intents/{created['intent_ids'][0]}"
    first = client.post(path + '/heartbeat', json={'worker': 'worker', 'claim': True}).json()['attempt_id']
    assert client.post(path + '/release', json={'worker': 'worker', 'attempt_id': first, 'outcome': 'failed'}).status_code == 200
    retry = decision(client, pid, 'decision-retry', intents=[{**proposal, 'retry_intent_id': created['intent_ids'][0]}])
    assert client.post(route, json=retry, headers=headers).status_code == 200
    second = client.post(path + '/heartbeat', json={'worker': 'worker', 'attempt_id': first, 'claim': True}).json()['attempt_id']
    assert second != first

    before = client.get(f'/projects/{pid}').json()
    events_before = client.get(f'/projects/{pid}/events').json()['events']
    stale_requests = [
        ('/heartbeat', {'worker': 'worker', 'attempt_id': first}),
        ('/release', {'worker': 'worker', 'attempt_id': first, 'outcome': 'failed'}),
        ('/stage', {'worker': 'worker', 'attempt_id': first, 'phase': 'explore_execute', 'status': 'failed'}),
        ('/conclude', {'worker': 'worker', 'attempt_id': first, 'description': 'stale result'}),
        ('/conclude', {'worker': 'worker', 'description': 'missing attempt'}),
    ]
    for route_suffix, body in stale_requests:
        assert client.post(path + route_suffix, json=body).status_code == 409
    assert client.get(f'/projects/{pid}').json() == before
    assert client.get(f'/projects/{pid}/events').json()['events'] == events_before

    result = {'worker': 'worker', 'attempt_id': second, 'description': 'current result'}
    assert client.post(path + '/conclude', json=result).status_code == 200
    assert client.post(path + '/conclude', json={'worker': 'worker', 'attempt_id': first,
                                               'description': 'current result'}).status_code == 409


def test_stale_reason_attempt_cannot_renew_release_or_apply_decision(client, monkeypatch):
    monkeypatch.setenv('SECURITY_RUNTIME_CALLBACK_TOKEN', 'test-planning-token')
    headers = {'X-Security-Runtime-Token': 'test-planning-token'}
    pid, _ = project(client)
    path = f'/projects/{pid}/reason'
    first = client.post(path + '/claim', json={'worker': 'pi_planner', 'trigger': 'initial'}).json()['reason_attempt_id']
    assert client.get(f'/projects/{pid}').json()['project']['reason_decision_pending'] is True
    assert client.post(path + '/release', json={'worker': 'pi_planner', 'attempt_id': first}).status_code == 200
    second_response = client.post(path + '/claim', json={
        'worker': 'pi_planner', 'trigger': 'retry', 'attempt_id': first,
    })
    assert second_response.status_code == 200
    second = second_response.json()['reason_attempt_id']
    assert second != first

    before = client.get(f'/projects/{pid}').json()
    stale_decision = {'decision_id': 'decision-stale', 'reason_attempt_id': first,
                      'snapshot_hash': planning_snapshot_hash(ProjectDetail.model_validate(before)),
                      'trigger': 'initial', 'summary': 'stale',
                      'intents': [{'from': ['origin'], 'description': 'wrong direction'}]}
    assert client.post(path + '/heartbeat', json={'worker': 'pi_planner', 'attempt_id': first}).status_code == 409
    assert client.post(path + '/release', json={'worker': 'pi_planner', 'attempt_id': first}).status_code == 409
    assert client.post(path + '/claim', json={'worker': 'pi_planner', 'trigger': 'initial',
                                               'attempt_id': first}).status_code == 409
    assert client.post(f'/projects/{pid}/planning/decisions', json=stale_decision, headers=headers).status_code == 409
    assert client.post(f'/projects/{pid}/planning/decisions', json={**stale_decision,
                       'reason_attempt_id': None}, headers=headers).status_code == 409
    assert client.get(f'/projects/{pid}').json() == before

    assert client.post(path + '/heartbeat', json={'worker': 'pi_planner', 'attempt_id': second}).status_code == 200
    current_decision = {**stale_decision, 'reason_attempt_id': second}
    assert client.post(f'/projects/{pid}/planning/decisions', json=current_decision, headers=headers).status_code == 200
    assert client.get(f'/projects/{pid}').json()['project']['reason_decision_pending'] is False


def test_expired_reason_attempt_cannot_apply_decision_before_reclaim(client, monkeypatch):
    monkeypatch.setenv('SECURITY_RUNTIME_CALLBACK_TOKEN', 'test-planning-token')
    pid, _ = project(client)
    body = decision(client, pid, 'decision-expired', intents=[
        {'from': ['origin'], 'description': 'late direction'},
    ])
    with db.get_conn() as conn:
        conn.execute("UPDATE projects SET reason_last_heartbeat_at='2000-01-01T00:00:00Z' WHERE id=?", (pid,))

    response = client.post(f'/projects/{pid}/planning/decisions', json=body,
                           headers={'X-Security-Runtime-Token': 'test-planning-token'})
    assert response.status_code == 409
    detail = client.get(f'/projects/{pid}').json()
    assert detail['project']['reason'] is None
    assert detail['project']['reason_decision_pending'] is True
    assert detail['intents'] == []


def test_replayed_decision_clears_new_reason_attempt_pending_state(client, monkeypatch):
    monkeypatch.setenv('SECURITY_RUNTIME_CALLBACK_TOKEN', 'test-planning-token')
    headers = {'X-Security-Runtime-Token': 'test-planning-token'}
    pid, _ = project(client)
    path = f'/projects/{pid}/reason'
    body = decision(client, pid, 'decision-noop')
    first = body['reason_attempt_id']
    route = f'/projects/{pid}/planning/decisions'
    assert client.post(route, json=body, headers=headers).status_code == 200
    assert client.post(path + '/release', json={'worker': 'pi_planner', 'attempt_id': first}).status_code == 200
    claim = client.post(path + '/claim', json={'worker': 'pi_planner', 'trigger': 'retry',
                                              'attempt_id': first})
    assert claim.status_code == 200
    second = claim.json()['reason_attempt_id']
    assert claim.json()['reason_decision_pending'] is True
    assert client.post(route, json=body, headers=headers).status_code == 409
    replay = client.post(route, json={**body, 'reason_attempt_id': second}, headers=headers)
    assert replay.status_code == 200
    assert replay.json()['status'] == 'replayed'
    assert client.get(f'/projects/{pid}').json()['project']['reason_decision_pending'] is False


def test_failed_attempt_triggers_planner_once_and_is_not_open():
    from conftest import make_project, make_intent
    from tests.test_scheduler_logic import _loop
    from security_runtime.dispatcher.models import ReasonCheckpoint
    from security_runtime.server.models import Hint
    loop = _loop()
    p = make_project(intents=[make_intent().model_copy(update={'worker': None, 'attempt_id': 'attempt-one', 'execution_status': 'failed'})])
    p.hints.append(Hint(id='h002', creator='unified-workbench', content='workbench_planner:run_id=test;schema=1.1', created_at='now'))
    loop.reason_checkpoints[p.project.id] = ReasonCheckpoint(len(p.facts), len(p.hints), 1)
    assert 'attempt_finished' in loop._reason_trigger(p)
    assert loop._project_open_intent_count(p) == 0
    loop.reason_checkpoints[p.project.id] = ReasonCheckpoint(len(p.facts), len(p.hints), 0, loop._terminal_attempts(p))
    assert loop._reason_trigger(p) is None


def test_invalid_workbench_decision_stops_same_snapshot_retry(monkeypatch):
    from conftest import make_project
    from security_runtime.dispatcher.tasks import reason

    project_detail = make_project()
    snapshot = planning_snapshot_hash(project_detail)
    decision_id = 'decision-' + hashlib.sha256(
        f'{project_detail.project.id}:{snapshot}'.encode()).hexdigest()[:48]
    client = Mock()
    client.workbench_plan.return_value = SimpleNamespace(ok=True, data={
        'decision_id': decision_id, 'snapshot_hash': snapshot,
        'completion_validated': True, 'completion_fact_ids': [],
        'completion_reason': 'invalid source', 'intents': [],
    })
    client.planning_decision.side_effect = [
        SimpleNamespace(ok=False, status_code=422, text='source facts required'),
        SimpleNamespace(ok=True, status_code=200, text='stopped'),
    ]
    monkeypatch.setattr(reason, '_workbench_tool_event_ids', lambda *args: [])
    config = SimpleNamespace(tasks=SimpleNamespace(reason=SimpleNamespace(max_intents=2, timeout=30)),
                             runtime=SimpleNamespace(execution='local'), workers=[],
                             workbench_callback_token='test-token')
    result = reason._run_workbench_reason_task(config, client, project_detail,
        SimpleNamespace(workbench_url='http://workbench.test'),
        SimpleNamespace(is_cancelled=False), SimpleNamespace(failure=None))
    assert result == 'success'
    assert client.planning_decision.call_count == 2
    fallback = client.planning_decision.call_args.args[1]
    assert fallback['stop_reason'].startswith('规划决策未通过 Runtime 校验')
    assert fallback['snapshot_hash'] == snapshot and not fallback['intents']


def test_invalid_decision_can_be_replaced_by_stopping_decision(client, monkeypatch):
    monkeypatch.setenv('SECURITY_RUNTIME_CALLBACK_TOKEN', 'test-planning-token')
    headers = {'X-Security-Runtime-Token': 'test-planning-token'}
    pid, _ = project(client)
    route = f'/projects/{pid}/planning/decisions'
    invalid = decision(client, pid, 'decision-invalid', completion_validated=True,
                       completion_reason='missing source facts')
    assert client.post(route, json=invalid, headers=headers).status_code == 422
    stopped = {**invalid, 'completion_validated': False,
               'completion_reason': None, 'stop_reason': 'Runtime rejected invalid decision'}
    assert client.post(route, json=stopped, headers=headers).json()['status'] == 'stopped'
    assert client.post(route, json=stopped, headers=headers).json()['status'] == 'replayed'


def test_retry_scheduling_does_not_trigger_duplicate_reason_round():
    from conftest import make_project, make_intent
    from tests.test_scheduler_logic import _loop
    from security_runtime.dispatcher.models import ReasonCheckpoint
    from security_runtime.server.models import Hint

    loop = _loop()
    failed = make_intent().model_copy(update={
        'worker': None, 'attempt_id': 'attempt-one', 'execution_status': 'failed',
    })
    p = make_project(intents=[failed])
    p.hints.append(Hint(id='h002', creator='unified-workbench',
                        content='workbench_planner:run_id=test;schema=1.1', created_at='now'))
    loop.reason_checkpoints[p.project.id] = ReasonCheckpoint(
        len(p.facts), len(p.hints), 0, loop._terminal_attempts(p))

    p.intents[0] = failed.model_copy(update={'execution_status': 'waiting'})
    assert loop._reason_trigger(p) is None

    p.intents[0] = failed.model_copy(update={'attempt_id': 'attempt-two'})
    assert loop._reason_trigger(p) == 'attempt_finished'


def test_completion_is_distinct_from_failure_and_requires_planner(client, monkeypatch):
    monkeypatch.setenv('SECURITY_RUNTIME_CALLBACK_TOKEN', 'test-planning-token')
    headers = {'X-Security-Runtime-Token': 'test-planning-token'}
    pid, _ = project(client)
    route = f'/projects/{pid}/planning/decisions'
    proposal = {'from': ['origin'], 'description': 'check'}
    created = client.post(route, headers=headers, json=decision(client, pid, 'decision-start', intents=[proposal])).json()
    path = f"/projects/{pid}/intents/{created['intent_ids'][0]}"
    claimed = client.post(path + '/heartbeat', json={'worker': 'worker', 'claim': True}).json()
    client.post(path + '/release', json={'worker': 'worker', 'attempt_id': claimed['attempt_id'], 'outcome': 'failed'})
    body = decision(client, pid, 'decision-complete', completion_validated=True,
                    completion_fact_ids=['origin'], completion_reason='trusted validator accepted')
    assert client.post(route, json=body).status_code == 403
    assert client.post(route, json=body, headers=headers).json()['status'] == 'completed'
    assert client.post(route, json=body, headers=headers).json()['status'] == 'replayed'


def test_verified_completion_cancels_waiting_and_running_directions(client, monkeypatch):
    monkeypatch.setenv('SECURITY_RUNTIME_CALLBACK_TOKEN', 'test-planning-token')
    headers = {'X-Security-Runtime-Token': 'test-planning-token'}
    pid, _ = project(client)
    route = f'/projects/{pid}/planning/decisions'
    proposals = [{'from': ['origin'], 'description': f'check {number}'} for number in (1, 2)]
    created = client.post(route, json=decision(client, pid, 'decision-start', intents=proposals),
                          headers=headers).json()
    path = f"/projects/{pid}/intents/{created['intent_ids'][0]}"
    claimed = client.post(path + '/heartbeat', json={'worker': 'worker', 'claim': True}).json()
    completed = decision(client, pid, 'decision-completed', completion_validated=True,
                       completion_fact_ids=['origin'], completion_reason='evidence verified')
    assert client.post(route, json=completed, headers=headers).json()['status'] == 'completed'
    detail = client.get(f'/projects/{pid}').json()
    assert detail['intents'][1]['execution_status'] == 'cancelled'
    assert detail['intents'][0]['execution_status'] == 'cancelled'
    assert detail['intents'][0]['worker'] is None
    assert client.post(path + '/heartbeat', json={'worker': 'worker',
        'attempt_id': claimed['attempt_id']}).status_code == 403
    assert client.post(path + '/conclude', json={'worker': 'worker',
        'attempt_id': claimed['attempt_id'], 'description': 'late result',
        'items': []}).status_code == 409
    assert len(client.get(f'/projects/{pid}').json()['facts']) == len(detail['facts'])
    assert client.post(route, json=completed, headers=headers).json()['status'] == 'replayed'


def test_workbench_directions_cannot_bypass_authenticated_planner(client):
    pid, _ = project(client)
    response = client.post(f'/projects/{pid}/intents', json={
        'from': ['origin'], 'description': 'worker tries to plan', 'creator': 'worker'})
    assert response.status_code == 403
    assert client.get(f'/projects/{pid}').json()['intents'] == []
    # Existing standalone projects retain their original planning interface.
    standalone = client.post('/projects', json={'title': 'legacy', 'origin': 'start', 'goal': 'finish'}).json()['project']['id']
    assert client.post(f'/projects/{standalone}/intents', json={
        'from': ['origin'], 'description': 'legacy direction', 'creator': 'worker'}).status_code == 201


@pytest.mark.parametrize('failure', ['callback_lost', 'apply_lost', 'apply_forbidden', 'apply_stale'])
def test_dispatcher_reuses_decision_identity_after_lost_or_rejected_response(failure):
    from conftest import FakeLease, make_config, make_project
    from security_runtime.dispatcher.protocol.client import ApiResult
    from security_runtime.dispatcher.runtime.cancellation import TaskCancellation
    from security_runtime.dispatcher.tasks.reason import _run_workbench_reason_task
    from security_runtime.server.models import ProjectReason
    config = make_config()
    current = make_project()
    api = Mock()
    requests, committed = [], {}
    api.project_events.return_value = ApiResult(200, {'events': [], 'next_cursor': 0})

    def callback(url, project, trigger, decision_id, **kwargs):
        requests.append(decision_id)
        if failure == 'callback_lost' and len(requests) == 1:
            return ApiResult(0, text='lost response')
        return ApiResult(200, {'decision_id': decision_id,
            'snapshot_hash': planning_snapshot_hash(project), 'summary': '公开规划摘要',
            'intents': [{'from': ['f001'], 'description': '下一轮探索'}]})

    def apply(pid, payload, **kwargs):
        key = payload['decision_id']
        if key in committed:
            return ApiResult(200, {'status': 'replayed'})
        if failure == 'apply_lost':
            committed[key] = payload  # Commit succeeded but the response disappeared.
            return ApiResult(0, text='lost response')
        if len(requests) == 1 and failure.startswith('apply_'):
            return ApiResult(403 if failure == 'apply_forbidden' else 409, {'detail': 'rejected'})
        committed[key] = payload
        return ApiResult(200, {'status': 'created'})

    api.workbench_plan.side_effect = callback
    api.planning_decision.side_effect = apply
    cancellation, lease = TaskCancellation(), FakeLease()
    assert _run_workbench_reason_task(config, api, current, config.workers[0], cancellation, lease) == 'failed'
    # A restart may change the scheduler trigger; the unchanged graph must keep its key.
    current.project.reason = ProjectReason(worker='worker', trigger='restart', started_at='now', last_heartbeat_at='now')
    assert _run_workbench_reason_task(config, api, current, config.workers[0], cancellation, lease) == 'success'
    assert len(set(requests)) == 1 and len(committed) == 1
