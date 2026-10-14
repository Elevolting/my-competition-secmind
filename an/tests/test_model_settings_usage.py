import json

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import BaseModel

from security_agent.api import _usage_totals, create_app
from security_agent.config import Settings
from security_agent.ledger import LedgerStore
from security_agent.llm import ModelGateway, ModelGatewayError
from security_agent.model_usage import normalize_usage


def test_config_validation_and_disk_failure_are_atomic(settings, monkeypatch):
    settings.model_api_key = 'existing-secret'
    app = create_app(settings)
    with TestClient(app) as client:
        before = client.get('/api/v1/model-config').json()
        invalid = client.put('/api/v1/model-config', json={'base_url': before['base_url'],
            'api_key': 'replacement-secret', 'planner_model': '   '})
        assert invalid.status_code == 422
        assert settings.model_api_key == 'existing-secret'
        assert client.get('/api/v1/model-config').json() == before
        for suffix in ('/test', '/models', ''):
            method = client.put if not suffix else client.post
            response = method('/api/v1/model-config' + suffix, json={'base_url': 'https://different.test/v1'})
            assert response.status_code == 422
        def failure(self):
            raise OSError('disk full')
        monkeypatch.setattr(Settings, 'save_runtime_model_config', failure)
        response = client.put('/api/v1/model-config', json={'base_url': before['base_url'], 'api_key': 'new-secret-value'})
        assert response.status_code == 500 and settings.model_api_key == 'existing-secret'
        response = client.put('/api/v1/model-usage/quota', json={'daily_tokens': 100})
        assert response.status_code == 500 and settings.model_daily_token_quota == 0


def test_config_preserve_replace_clear_reload_and_origin(settings):
    app = create_app(settings)
    with TestClient(app) as client:
        content = {'base_url': 'https://example.test/v1', 'api_key': 'new-secret-value', 'worker_model': ' real-worker '}
        assert client.put('/api/v1/model-config', json=content, headers={'Origin': 'https://evil.test'}).status_code == 403
        assert client.put('/api/v1/model-config', json=content).status_code == 200
        assert client.put('/api/v1/model-config', json={'base_url': content['base_url'], 'api_key': None}).status_code == 200
        assert settings.model_api_key == content['api_key']
        reloaded = settings.model_copy(deep=True)
        reloaded.model_api_key = ''
        reloaded.load_runtime_model_config()
        assert reloaded.model_api_key == content['api_key'] and reloaded.worker_model == 'real-worker'
        assert content['api_key'] not in client.get('/api/v1/model-config').text
        assert client.put('/api/v1/model-config', json={'base_url': content['base_url'], 'clear_api_key': True}).status_code == 200
        reloaded.load_runtime_model_config()
        assert reloaded.model_api_key == '' and reloaded.demo_mode


def test_connection_is_real_inference_with_persistent_usage(settings, monkeypatch):
    original = ModelGateway.__init__
    requests = []
    def provider(request):
        requests.append(request)
        if request.url.path.endswith('/models'):
            return httpx.Response(200, json={'data': [{'id': 'ok-model'}]})
        model = json.loads(request.content)['model']
        if model == 'blocked-model':
            return httpx.Response(403, json={'error': 'inference denied'})
        return httpx.Response(200, json={'choices': [{'message': {'content': 'OK'}}],
            'usage': {'prompt_tokens': 10, 'completion_tokens': 2, 'prompt_cache_hit_tokens': 7}})
    def gateway_init(self, settings, client=None):
        original(self, settings, httpx.AsyncClient(transport=httpx.MockTransport(provider)))
        self._owns_client = True
    monkeypatch.setattr(ModelGateway, '__init__', gateway_init)
    app = create_app(settings)
    with TestClient(app) as client:
        content = {'base_url': settings.model_base_url, 'api_key': 'test-key-123',
                   'planner_model': 'ok-model', 'worker_model': 'ok-model', 'fallback_model': 'ok-model'}
        result = client.post('/api/v1/model-config/test', json=content)
        assert result.status_code == 200 and result.json()['model_count'] == 1
        assert len(requests) == 1 and requests[0].url.path.endswith('/chat/completions')
        assert settings.model_api_key == ''  # Testing does not save the draft.
        usage = client.get('/api/v1/model-usage').json()
        assert usage['total_tokens'] == 12 and usage['cache_read_tokens'] == 7
        assert usage['model_call_count'] == 1 and usage['models'][0]['call_count'] == 1
        assert usage['series']['daily'][-1]['usage_receipt_count'] == 1
        assert usage['quota_mode'] == 'warning_only'
        content.update(planner_model='blocked-model', worker_model='blocked-model', fallback_model='blocked-model')
        assert client.post('/api/v1/model-config/test', json=content).status_code == 400
        usage = client.get('/api/v1/model-usage').json()
        assert usage['failed_call_count'] == 1 and usage['missing_usage_count'] == 1
        assert usage['total_tokens'] == 12 and usage['model_call_count'] == 2


@pytest.mark.parametrize('raw,expected', [({}, {}), (None, {}), ({'unknown': 7}, {}),
    ({'prompt_tokens': 0, 'completion_tokens': 0}, {'prompt_tokens': 0, 'completion_tokens': 0, 'total_tokens': 0, 'cache_read_tokens': 0}),
    ({'prompt_cache_hit_tokens': 10, 'prompt_cache_miss_tokens': 5, 'completion_tokens': 3},
     {'prompt_tokens': 15, 'completion_tokens': 3, 'total_tokens': 18, 'cache_read_tokens': 10})])
def test_usage_missing_zero_and_cache_are_distinct(raw, expected):
    assert normalize_usage(raw) == expected


async def test_http_retries_are_counted_separately(settings):
    settings.demo_mode = False
    settings.model_api_key = 'test-key'
    settings.worker_model = settings.fallback_model = 'worker'
    ledger = LedgerStore(settings.database_url)
    count = 0
    def provider(request):
        nonlocal count
        count += 1
        if count == 1:
            return httpx.Response(429)
        body = {'choices': [{'delta': {'content': '{"ok":true}'}, 'finish_reason': 'stop'}],
                'usage': {'prompt_tokens': 4, 'completion_tokens': 3}}
        return httpx.Response(200, text='data: '+json.dumps(body)+'\n\ndata: [DONE]\n\n')
    class Output(BaseModel):
        ok: bool
    async def observer(kind, data):
        ledger.append('retry', kind, data)
    async with httpx.AsyncClient(transport=httpx.MockTransport(provider)) as client:
        gateway = ModelGateway(settings, client)
        result, _ = await gateway.structured(role='worker', system_prompt='test', user_prompt='test',
            output_model=Output, prompt_version='test', stream_observer=observer)
    assert result.ok and count == 2
    usage = _usage_totals(ledger, [])
    assert usage['model_call_count'] == 2 and usage['failed_call_count'] == 1
    assert usage['incomplete_call_count'] == 0 and usage['missing_usage_count'] == 1
    assert usage['total_tokens'] == 7


async def test_malformed_model_list_does_not_pass(settings):
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(200, text='<html>OK</html>'))) as client:
        with pytest.raises(ModelGatewayError):
            await ModelGateway(settings, client).test_connection('https://example.test/v1', 'test-key')


def test_model_chart_series_conserve_receipts_and_include_missing_usage(settings):
    app = create_app(settings)
    ledger = app.state.service.ledger
    receipts = [('one', 'model-a', {'prompt_tokens': 100, 'completion_tokens': 20, 'cache_read_tokens': 30}),
                ('two', 'model-b', {'total_tokens': 50}), ('three', 'model-a', {})]
    for trace, model, usage in receipts:
        payload = {'trace_id': trace, 'model': model}
        ledger.append('chart-run', 'llm.stream.started', payload)
        ledger.append('chart-run', 'llm.stream.completed', {**payload, 'usage': usage})
    # Duplicate terminal receipt must not inflate charts.
    ledger.append('chart-run', 'llm.stream.failed', {'trace_id': 'one', 'model': 'model-a'})
    with TestClient(app) as client:
        body = client.get('/api/v1/model-usage').json()
        assert body['total_tokens'] == 170
        for period in ('hourly', 'daily', 'monthly'):
            overall = body['series'][period][-1]
            a = body['model_series']['model-a'][period][-1]
            b = body['model_series']['model-b'][period][-1]
            assert overall['tokens'] == a['tokens'] + b['tokens'] == 170
            assert overall['calls'] == a['calls'] + b['calls'] == 3
            assert a['usage_receipt_count'] == 1 and a['calls'] == 2
            assert (a['cache_read_tokens'], a['other_input_tokens'], a['completion_tokens']) == (30, 70, 20)
            assert b['unclassified_tokens'] == 50
            for point in (overall, a, b):
                assert point['tokens'] == sum(point[key] for key in (
                    'cache_read_tokens', 'other_input_tokens', 'completion_tokens', 'unclassified_tokens'))
        assert body['series']['daily'][0]['tokens'] == 0
