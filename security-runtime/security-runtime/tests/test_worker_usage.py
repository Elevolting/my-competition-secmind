import json
import sqlite3
from types import SimpleNamespace

import pytest

from security_runtime.dispatcher.config import WorkerConfig
from security_runtime.dispatcher.runtime.process import ProcessResult
from security_runtime.dispatcher.tasks.common import run_worker_process
from security_runtime.dispatcher.usage import claude_usage, pi_usage
from security_runtime.dispatcher.workers.adapters.claudecode import ClaudeCodeDriver


def envelope(usage):
    return json.dumps({'type': 'result', 'result': '{"accepted":true}', 'usage': usage})


@pytest.mark.parametrize('raw', [None, {}, {'input_tokens': True, 'output_tokens': 1},
                                    {'input_tokens': -1, 'output_tokens': 2}])
def test_missing_or_invalid_usage_is_not_zero(raw):
    assert claude_usage(envelope(raw)) == {}


def test_claude_cache_tokens_and_result_unwrapping():
    driver = ClaudeCodeDriver()
    output = envelope({'input_tokens': 10, 'output_tokens': 4, 'cache_read_input_tokens': 20, 'cache_creation_input_tokens': 30})
    assert claude_usage(output) == {'prompt_tokens': 60, 'completion_tokens': 4, 'total_tokens': 64, 'cache_read_tokens': 20}
    assert driver.extract_response_text(output, '') == '{"accepted":true}'
    assert claude_usage('{"usage":{"input_tokens":999,"output_tokens":999}}') == {}
    assert claude_usage(envelope({'input_tokens': 0, 'output_tokens': 0}))['total_tokens'] == 0


def test_pi_usage_counts_each_assistant_response_with_cache_once():
    first = {'role': 'assistant', 'content': [{'type': 'text', 'text': 'private response'}],
             'usage': {'input': 10, 'output': 4, 'cacheRead': 20, 'cacheWrite': 30,
                       'totalTokens': 64}}
    second = {'role': 'assistant', 'usage': {'input': 5, 'output': 3,
              'cacheRead': 7, 'cacheWrite': 0, 'totalTokens': 15}}
    stdout = '\n'.join(json.dumps(event) for event in [
        {'type': 'message_end', 'message': first},
        {'type': 'turn_end', 'message': first},
        {'type': 'message_end', 'message': {'role': 'toolResult', 'usage': first['usage']}},
        {'type': 'message_end', 'message': second},
        {'type': 'agent_end', 'messages': [first, second]},
    ])
    assert pi_usage(stdout) == {'prompt_tokens': 72, 'completion_tokens': 7,
                                'total_tokens': 79, 'cache_read_tokens': 27}
    assert pi_usage('{"type":"message_end","message":{"role":"assistant","usage":'
                    '{"input":true,"output":1,"cacheRead":0,"cacheWrite":0}}}') == {}
    assert pi_usage('{"type":"message_end","message":{"role":"assistant","usage":'
                    '{"input":-1,"output":1,"cacheRead":0,"cacheWrite":0}}}') == {}


def test_pi_process_persists_numeric_receipt_without_model_text(tmp_path):
    path = tmp_path / 'usage.db'
    worker = WorkerConfig(name='pi_default', type='pi', task_types=['explore'], priority=0,
        max_running=1, usage_journal=path, env={'PI_MODEL': 'test-model', 'PI_API_KEY': 'secret'})
    stdout = json.dumps({'type': 'message_end', 'message': {'role': 'assistant',
        'content': [{'type': 'text', 'text': 'private response'}],
        'usage': {'input': 2, 'output': 3, 'cacheRead': 4, 'cacheWrite': 5}}})
    process = SimpleNamespace(start=lambda: None,
                              communicate=lambda **kw: ProcessResult(0, stdout, 'secret error'))
    manager = SimpleNamespace(build_exec_process=lambda *a, **kw: process)
    run_worker_process(manager, 'workspace', worker, ['pi', 'private prompt'], phase='explore_execute',
                       timeout_seconds=10, project_id='proj_1', intent_id='intent_1')
    with sqlite3.connect(path) as conn:
        rows = [json.loads(row[0]) for row in conn.execute('SELECT payload_json FROM usage_events')]
    assert rows[-1]['usage'] == {'prompt_tokens': 11, 'completion_tokens': 3,
                                 'total_tokens': 14, 'cache_read_tokens': 4}
    assert 'secret' not in json.dumps(rows) and 'private' not in json.dumps(rows)


def test_process_records_execute_conclude_and_failure_without_secrets(tmp_path):
    path = tmp_path / 'usage.db'
    worker = WorkerConfig(name='w', type='claudecode', task_types=['explore'], priority=0, max_running=1,
        usage_journal=path, env={'ANTHROPIC_MODEL': 'model', 'ANTHROPIC_AUTH_TOKEN': 'secret'})
    driver = ClaudeCodeDriver()
    for argv in (driver.build_execute(worker, 'private prompt', 'session').argv, driver.build_conclude(worker, 'private prompt', 'session')):
        assert argv[argv.index('--output-format') + 1] == 'json'
    for phase, rc, stdout in [('explore_execute', 0, envelope({'input_tokens': 10, 'output_tokens': 2})),
                              ('explore_conclude', 0, envelope({'input_tokens': 5, 'output_tokens': 1})),
                              ('reason_execute', 1, 'timeout')]:
        process = SimpleNamespace(start=lambda: None, communicate=lambda **kw: ProcessResult(rc, stdout, 'secret error'))
        manager = SimpleNamespace(build_exec_process=lambda *a, **kw: process)
        run_worker_process(manager, 'workspace', worker, ['claude', 'private prompt'], phase=phase,
                           timeout_seconds=10, project_id='proj_1', intent_id='intent_1')
    with sqlite3.connect(path) as conn:
        rows = [json.loads(row[0]) for row in conn.execute('SELECT payload_json FROM usage_events')]
    assert len(rows) == 6 and len({row['trace_id'] for row in rows}) == 3
    assert sum(row['usage'].get('total_tokens', 0) for row in rows) == 18
    assert rows[-1]['status'] == 'failed' and rows[-1]['usage'] == {}
    assert 'secret' not in json.dumps(rows) and 'private prompt' not in json.dumps(rows)
