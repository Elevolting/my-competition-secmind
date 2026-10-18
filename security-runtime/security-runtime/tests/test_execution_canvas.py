from tests.test_server_api import client, _create_project


def test_result_bundle_retry_and_event_cursor(client):
    pid = _create_project(client)
    route = f'/projects/{pid}/intents'
    created = client.post(route, json={'from': ['origin'], 'description': 'check login', 'creator': 'reasoner'}).json()
    path = route + '/' + created['id']
    first = client.post(path + '/heartbeat', json={'worker': 'explorer'}).json()
    assert first['attempt_id']
    assert client.post(path + '/stage', json={'worker': 'explorer', 'phase': 'explore_execute', 'status': 'timeout'}).status_code == 200
    released = client.post(path + '/release', json={'worker': 'explorer', 'outcome': 'failed'}).json()
    assert released['execution_status'] == 'timeout'
    retry = client.post(path + '/heartbeat', json={'worker': 'explorer'}).json()
    assert retry['attempt_id'] != first['attempt_id']
    body = {'worker': 'explorer', 'description': 'raw output', 'title': '登录测试结果', 'items': [
        {'id': 'same', 'type': 'fact', 'title': '观察', 'summary': 'response'},
        {'id': 'same', 'type': 'finding', 'title': '注入候选', 'summary': 'needs validation', 'verification_status': 'confirmed', 'evidence_ids': []}]}
    response = client.post(path + '/conclude', json=body)
    assert response.status_code == 200
    bundle = response.json()['fact']
    assert len({item['id'] for item in bundle['items']}) == 2
    assert bundle['items'][1]['verification_status'] == 'insufficient'
    persisted = next(f for f in client.get(f'/projects/{pid}').json()['facts'] if f['id'] == bundle['id'])
    from security_runtime.server.models import Fact
    assert Fact.model_validate(persisted) == Fact.model_validate(bundle)
    page = client.get(f'/projects/{pid}/events?limit=2').json()
    rest = client.get(f"/projects/{pid}/events?after={page['next_cursor']}").json()['events']
    events = page['events'] + rest
    assert len({e['event_id'] for e in events}) == len(events)
    assert next(e for e in events if e['event_type'] == 'retry')['payload']['previous_attempt_id'] == first['attempt_id']
    assert next(e for e in events if e['event_type'] == 'completed')['attempt_id'] == retry['attempt_id']
    assert client.get(f"/projects/{pid}/events?after={events[-1]['sequence']}").json()['events'] == []
    assert '登录测试结果' in client.get(f'/projects/{pid}/export?format=yaml').text


def test_dispatcher_structured_outputs_and_legacy_descriptions():
    import pytest
    from security_runtime.dispatcher.contracts import (
        validate_bootstrap_execute_payload, validate_bootstrap_conclude_payload, validate_explore_payload,
    )
    bundle = {'description': 'raw output', 'title': '响应观察', 'items': [
        {'id': 'response', 'type': 'observation', 'title': '返回异常响应', 'summary': 'response', 'evidence_ids': ['call-1']}]}
    assert validate_explore_payload({'accepted': True, 'data': bundle}) == ('fact', bundle)
    assert validate_bootstrap_conclude_payload({'fact': bundle}) == ('fact', bundle)
    status, data = validate_bootstrap_execute_payload({'fact': bundle, 'complete': {'description': 'done'}})
    assert status == 'complete' and data['fact_description'] == bundle
    assert validate_explore_payload({'description': 'legacy'}) == ('fact', 'legacy')
    with pytest.raises(ValueError):
        validate_explore_payload({'description': 'bad', 'items': [{'title': 'unsupported', 'type': 'worker'}]})


def test_completion_and_cancellation_have_distinct_durable_states(client):
    pid = _create_project(client)
    created = client.post(f'/projects/{pid}/intents', json={'from': ['origin'], 'description': 'check', 'creator': 'reasoner'})
    assert created.status_code == 201
    claimed = client.post(f"/projects/{pid}/intents/{created.json()['id']}/heartbeat", json={'worker': 'explorer'})
    assert claimed.status_code == 200
    intent = claimed.json()
    completion = client.post(f'/projects/{pid}/complete', json={'from': ['origin'], 'description': 'done', 'worker': 'reasoner'}).json()
    assert completion['execution_status'] == 'completed'
    remaining = next(i for i in client.get(f'/projects/{pid}').json()['intents'] if i['id'] == intent['id'])
    assert remaining['execution_status'] == 'cancelled'
    events = client.get(f'/projects/{pid}/events').json()['events']
    assert any(e['event_type'] == 'cancelled' and e['attempt_id'] == intent['attempt_id'] for e in events)
