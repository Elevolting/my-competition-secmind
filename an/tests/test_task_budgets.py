"""Task-selected budgets survive creation, replay, retry and legacy recovery."""
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from test_orchestrator import controlled_orchestrator

from security_agent.api import create_app
from security_agent.schemas import AgentState, BudgetState, RiskLevel, RunRetryRequest, RunStatus, TaskRequest
from security_agent.service import EventHub, RunService


def test_defaults_and_selected_budget_are_persisted_and_replayed(settings, monkeypatch):
    app = create_app(settings)
    service = app.state.service
    monkeypatch.setattr(service, "_spawn", lambda coroutine: coroutine.close())
    with TestClient(app) as client:
        config = client.get('/api/v1/task-budget-defaults').json()
        assert config['defaults']['max_tool_calls'] == 600
        assert config['defaults']['max_model_calls'] == 200
        assert config['defaults']['penetration_max_model_calls'] == 600
        headers = {'X-Request-Id': 'budget-create-request-0001'}
        payload = {'objective': 'audit an authorized source', 'max_runtime_seconds': 1800,
                   'max_tool_calls': 800, 'max_model_calls': 250}
        first = client.post('/api/v1/tasks', json=payload, headers=headers)
        assert first.status_code == 202
        run_id = first.json()['run_id']
        state = service.state(run_id)
        assert state.budget.max_runtime_seconds == 1800
        assert state.budget.max_tool_calls == 800
        assert state.budget.max_model_calls == 250
        assert state.task.max_tool_calls == 800
        settings.max_tool_calls = 900
        replay = client.post('/api/v1/tasks', json=payload, headers=headers)
        assert replay.status_code == 202 and replay.json()['run_id'] == run_id
        assert service.state(run_id).budget.max_tool_calls == 800
        assert client.post('/api/v1/tasks', json={**payload, 'max_tool_calls': 801},
                           headers=headers).status_code == 409
        queued = next(e for e in service.ledger.events(run_id) if e.event_type == 'run.queued')
        assert queued.payload['budget']['max_tool_calls'] == 800


def test_omitted_budget_uses_server_defaults_and_explicit_small_budget_is_respected(settings, monkeypatch):
    app = create_app(settings)
    service = app.state.service
    monkeypatch.setattr(service, '_spawn', lambda coroutine: coroutine.close())
    settings.max_tool_calls, settings.max_model_calls = 700, 240
    default_id = service.submit(TaskRequest(objective='audit authorized local input'))
    small_id = service.submit(TaskRequest(objective='audit with a small budget', max_tool_calls=2, max_model_calls=3))
    assert service.state(default_id).budget.max_tool_calls == 700
    assert service.state(default_id).budget.max_model_calls == 240
    assert service.state(small_id).budget.max_tool_calls == 2
    assert service.state(small_id).budget.max_model_calls == 3


def test_penetration_budget_uses_its_own_default_but_respects_selected_limit(settings, monkeypatch):
    app = create_app(settings)
    service = app.state.service
    monkeypatch.setattr(service, '_spawn', lambda coroutine: coroutine.close())
    task = {'objective': 'Authorized penetration test of https://example.invalid/',
            'target_scope': ['https://example.invalid/']}
    default_id = service.submit(TaskRequest(**task))
    selected_id = service.submit(TaskRequest(**task, max_model_calls=25))
    assert service.state(default_id).budget.max_model_calls == settings.penetration_max_model_calls
    assert service.state(selected_id).budget.max_model_calls == 25


@pytest.mark.parametrize('model', [TaskRequest, RunRetryRequest])
@pytest.mark.parametrize('key,value', [('max_tool_calls', 0), ('max_tool_calls', 100001),
    ('max_model_calls', -1), ('max_model_calls', 10001), ('max_runtime_seconds', 7201),
    ('max_tool_calls', 1.5)])
def test_invalid_budgets_are_rejected(model, key, value):
    payload = {'objective': 'audit local input'} if model is TaskRequest else {'request_id': 'retry-budget-0001'}
    with pytest.raises(ValidationError):
        model(**payload, **{key: value})


def test_retry_budget_survives_restart_and_does_not_mutate_original(settings, monkeypatch):
    orchestrator, ledger, _ = controlled_orchestrator(settings, RiskLevel.R1)
    service = RunService(orchestrator, ledger, EventHub())
    monkeypatch.setattr(service, '_spawn', lambda coroutine: coroutine.close())
    original = AgentState(run_id='legacy-budget', task=TaskRequest(objective='audit old input'),
                          status=RunStatus.PARTIAL, budget=BudgetState())
    ledger.save_state(original)
    before = original.model_dump()
    request = RunRetryRequest(request_id='retry-selected-budget-0001', max_runtime_seconds=1800,
                              max_tool_calls=600, max_model_calls=200)
    child_id = service.retry(original.run_id, request)
    assert service.state(child_id).budget.max_tool_calls == 600
    assert service.state(child_id).budget.max_model_calls == 200
    restarted = RunService(orchestrator, ledger, EventHub())
    assert restarted.retry(original.run_id, request) == child_id
    with pytest.raises(ValueError, match='已绑定不同'):
        restarted.retry(original.run_id, request.model_copy(update={'max_model_calls': 201}))
    assert ledger.load_state(original.run_id).model_dump() == before
    assert service.state(original.run_id).budget.max_tool_calls == 12


def test_old_retry_snapshot_without_optional_budgets_still_replays(settings, monkeypatch):
    orchestrator, ledger, _ = controlled_orchestrator(settings, RiskLevel.R1)
    service = RunService(orchestrator, ledger, EventHub())
    monkeypatch.setattr(service, '_spawn', lambda coroutine: coroutine.close())
    source = AgentState(run_id='old-retry-source', task=TaskRequest(objective='audit old input'),
                        status=RunStatus.PARTIAL)
    ledger.save_state(source)
    request = RunRetryRequest(request_id='old-retry-request-0001')
    child_id = service.retry(source.run_id, request)
    child = service.state(child_id)
    for key in ('max_tool_calls', 'max_model_calls'):
        child.retry_context['retry_parameters'].pop(key)
    ledger.save_state(child)
    assert service.retry(source.run_id, request) == child_id
    assert child.budget.max_tool_calls == source.budget.max_tool_calls
