from __future__ import annotations

import json
from concurrent.futures import Future

import pytest
from conftest import make_config

from security_runtime.dispatcher.config import DispatchConfig
from security_runtime.dispatcher.runtime.local_backend import LocalBackend
from security_runtime.dispatcher.scheduler.loop import DispatcherLoop
from security_runtime.dispatcher.shared_model import shared_anthropic_env
from security_runtime.dispatcher.workers.adapters.claudecode import ClaudeCodeDriver
from security_runtime.dispatcher.workers.adapters.pi import PiDriver


def save_model(path, model="glm-5.3", key="test-key", base="https://example.test/v1",
               planner="planner-one"):
    path.write_text(json.dumps({"base_url": base, "planner_model": planner,
                                "worker_model": model, "api_key": key}), encoding="utf-8")


def load_shared(tmp_path):
    source = tmp_path / "model-runtime.json"
    save_model(source)
    payload = make_config().model_dump(mode="json")
    payload["shared_model_config"] = source.name
    payload["runtime"]["execution"] = "local"
    payload["workers"] = [{"name": "claudecode_shared_model", "type": "claudecode", "task_types": ["bootstrap", "reason", "explore"], "max_running": 1, "priority": 0}]
    path = tmp_path / "dispatch.yaml"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return DispatchConfig.load(path), source


def test_pi_reads_platform_worker_model_and_refreshes_without_restart(tmp_path, monkeypatch):
    monkeypatch.setattr(type(tmp_path), 'home', lambda: tmp_path)
    source = tmp_path / 'model-runtime.json'
    save_model(source, model='worker-one')
    payload = make_config().model_dump(mode='json')
    payload['shared_model_config'] = source.name
    payload['runtime']['execution'] = 'local'
    payload['workers'] = [{'name': 'pi_default', 'type': 'pi',
        'task_types': ['bootstrap', 'explore'], 'max_running': 1, 'priority': 0},
        {'name': 'pi_planner', 'type': 'pi', 'shared_model_role': 'planner',
         'task_types': ['reason'], 'max_running': 1, 'priority': 0}]
    path = tmp_path / 'dispatch.yaml'
    path.write_text(json.dumps(payload), encoding='utf-8')
    config = DispatchConfig.load(path)
    loop = DispatcherLoop(path)
    loop.close()
    old = config.workers[0]
    assert old.env['PI_MODEL'] == 'worker-one'
    assert old.env['PI_BASE_URL'] == 'https://example.test/v1'
    assert old.env['PI_PROVIDER_API'] == 'openai-completions'
    assert old.usage_journal == tmp_path / 'worker-usage.db'
    assert config.workers[1].env['PI_MODEL'] == 'planner-one'

    save_model(source, model='worker-two', planner='planner-two', key='new-key',
               base='https://new.example.test/v1')
    assert config.refresh_shared_models()
    current = config.workers[0]
    assert current.env['PI_MODEL'] == 'worker-two'
    assert current.env['PI_API_KEY'] == 'new-key'
    assert old.env['PI_MODEL'] == 'worker-one'
    assert config.workers[1].env['PI_MODEL'] == 'planner-two'
    argv = PiDriver(local=True).build_execute(current, 'prompt', None).argv
    assert argv[argv.index('--model') + 1] == 'worker-two'
    assert 'new-key' not in ' '.join(argv)

    source.write_text('{}', encoding='utf-8')
    with pytest.raises(ValueError):
        config.refresh_shared_models()


def test_saved_model_changes_replace_workers_without_mutating_inflight_snapshot(tmp_path):
    config, source = load_shared(tmp_path)
    inflight = config.workers[0]
    assert inflight.env["ANTHROPIC_MODEL"] == "glm-5.3"
    assert not config.refresh_shared_models()
    save_model(source, model="new-model", key="new-key", base="https://new.example.test/v1")
    assert config.refresh_shared_models()
    current = config.workers[0]
    assert current.env["ANTHROPIC_MODEL"] == "new-model"
    assert current.env["ANTHROPIC_AUTH_TOKEN"] == "new-key"
    assert current.env["ANTHROPIC_BASE_URL"] == "https://new.example.test"
    assert inflight.env["ANTHROPIC_MODEL"] == "glm-5.3"
    for argv in (ClaudeCodeDriver().build_execute(current, "prompt", "session").argv,
                 ClaudeCodeDriver().build_conclude(current, "prompt", "session")):
        assert argv[0] == "claude"
        assert "new-key" not in " ".join(argv)
        backend = LocalBackend(config.local)
        process = backend.build_exec_process(backend.ensure_running("proj_001"), current.env, argv)
        assert process.env["ANTHROPIC_MODEL"] == "new-model"
        assert process.env["ANTHROPIC_BASE_URL"] == "https://new.example.test"
        assert process.env["ANTHROPIC_AUTH_TOKEN"] == "new-key"


@pytest.mark.parametrize("contents", ["not json", "[]", '{"api_key":"secret"}',
    '{"base_url":"https://example.test/v1","worker_model":"glm-5.3","api_key":""}'])
def test_invalid_or_cleared_settings_block_dispatch(tmp_path, contents):
    config, source = load_shared(tmp_path)
    source.write_text(contents, encoding="utf-8")
    with pytest.raises(ValueError):
        config.refresh_shared_models()
    loop = DispatcherLoop.__new__(DispatcherLoop)
    loop.config = config
    loop._log_state = {}
    # No scheduling dependencies exist: invalid settings must return before dispatch.
    loop._dispatch_available([])
    assert "dispatch/model-config" in loop._log_state


def test_missing_shared_file_does_not_fall_back_to_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_AUTH_TOKEN", "old-provider-key")
    with pytest.raises(ValueError, match="Cannot read shared"):
        shared_anthropic_env(tmp_path / "missing.json")


@pytest.mark.parametrize("base,expected", [
    ("https://gateway.test/v1/", "https://gateway.test"),
    ("https://gateway.test/prefix/v1", "https://gateway.test/prefix"),
    ("https://gateway.test/anthropic", "https://gateway.test/anthropic"),
])
def test_claude_base_preserves_gateway_prefix_without_duplicate_v1(tmp_path, base, expected):
    source = tmp_path / "model-runtime.json"
    save_model(source, base=base)
    assert shared_anthropic_env(source)["ANTHROPIC_BASE_URL"] == expected


def test_scheduler_refreshes_settings_and_recovers_after_invalid_save(tmp_path):
    config, source = load_shared(tmp_path)
    loop = DispatcherLoop.__new__(DispatcherLoop)
    loop.config = config
    loop._log_state = {}
    loop.worker_unhealthy_until = {"claudecode_shared_model": 99999}
    loop.worker_rejected_until = {("project", "intent", "claudecode_shared_model"): 99999}
    # At capacity to avoid launching work while exercising the real refresh path.
    loop.futures = {Future(): None for _ in range(config.runtime.max_workers)}
    source.write_text("{}", encoding="utf-8")
    loop._dispatch_available([])
    save_model(source, model="updated-glm")
    loop._dispatch_available([])
    assert loop.config.workers[0].env["ANTHROPIC_MODEL"] == "updated-glm"
    assert not loop.worker_unhealthy_until and not loop.worker_rejected_until
    assert "dispatch/model-config" not in loop._log_state
