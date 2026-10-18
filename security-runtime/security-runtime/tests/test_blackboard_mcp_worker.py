import json
import os
import shutil
import sys
from types import SimpleNamespace

import pytest

from security_runtime.dispatcher.config import WorkerConfig
from security_runtime.dispatcher.runtime.local_process import LocalProcess
from security_runtime.dispatcher.runtime.process import ProcessResult
from security_runtime.dispatcher.tasks.common import run_worker_process
from security_runtime.dispatcher.workers.adapters.claudecode import ClaudeCodeDriver
from security_runtime.dispatcher.workers.adapters.pi import PiDriver


@pytest.mark.parametrize('phase', ['bootstrap', 'explore_execute', 'reason', 'bootstrap_conclude', 'explore_conclude'])
def test_worker_connects_tools_only_for_assigned_execution(tmp_path, phase):
    worker = WorkerConfig(name='assigned-worker', type='claudecode', task_types=['explore'],
        priority=0, max_running=1, mcp_bridge_python=sys.executable)
    saved = {}

    def capture(directory, env, argv, **kwargs):
        saved['argv'] = argv
        return SimpleNamespace(start=lambda: None,
            communicate=lambda **kwargs: ProcessResult(0, '{}', ''))

    def write(directory, path, content):
        saved['path'] = path
        saved['config'] = json.loads(content)

    manager = SimpleNamespace(is_local=True, build_exec_process=capture, write_text_file=write)
    argv = ClaudeCodeDriver().build_execute(worker, 'original prompt', 'session-id').argv
    run_worker_process(manager, str(tmp_path), worker, argv, phase=phase, timeout_seconds=5,
        project_id='proj-test', intent_id='i001')
    assert saved['argv'][-2:] == ['--', 'original prompt']
    assert '--strict-mcp-config' in saved['argv']
    assert saved['argv'][saved['argv'].index('--mcp-config') + 1] == saved['path']
    assert '--dangerously-skip-permissions' not in saved['argv']
    assert '--restricted' in saved['argv']
    assert saved['argv'][saved['argv'].index('--tools') + 1] == 'Read'
    assert saved['argv'][saved['argv'].index('--permission-mode') + 1] == 'dontAsk'
    servers = saved['config']['mcpServers']
    if phase in {'bootstrap', 'explore_execute'}:
        assert saved['argv'][saved['argv'].index('--allowedTools') + 1] == 'Read,mcp__secmind-blackboard__*'
        server = servers['secmind-blackboard']
        assert server['command'] == sys.executable
        assert server['env']['SECMIND_PROJECT_ID'] == 'proj-test'
        assert server['env']['SECMIND_INTENT_ID'] == 'i001'
        assert server['env']['SECMIND_WORKER_NAME'] == worker.name
    else:
        assert saved['argv'][saved['argv'].index('--allowedTools') + 1] == 'Read'
        assert servers == {}


@pytest.mark.parametrize('phase', ['bootstrap', 'explore_execute', 'reason', 'bootstrap_conclude', 'explore_conclude'])
@pytest.mark.parametrize('launcher', ['pi', 'node'])
def test_pi_worker_exposes_blackboard_only_during_assigned_execution(tmp_path, monkeypatch, phase, launcher):
    monkeypatch.setattr(type(tmp_path), 'home', lambda: tmp_path)
    extension = tmp_path / 'pi_blackboard.ts'
    extension.write_text('export default function () {}', encoding='utf-8')
    cli = tmp_path / 'pi-cli.js'
    cli.write_text('console.log(JSON.stringify(process.argv.slice(2)))', encoding='utf-8')
    if launcher == 'node':
        monkeypatch.setenv('PI_CLI_JS', str(cli))
    else:
        monkeypatch.delenv('PI_CLI_JS', raising=False)
    worker = WorkerConfig(name='pi-assigned', type='pi', task_types=['explore'],
        priority=0, max_running=1, pi_blackboard_extension=extension)
    saved = {}

    def capture(_directory, env, argv, **_kwargs):
        saved.update(env=env, argv=argv)
        return SimpleNamespace(start=lambda: None,
            communicate=lambda **_kwargs: ProcessResult(0, '{}', ''))

    manager = SimpleNamespace(is_local=True, build_exec_process=capture)
    argv = PiDriver(local=True).build_execute(worker, 'prompt', None).argv
    run_worker_process(manager, str(tmp_path), worker, argv, phase=phase,
        timeout_seconds=5, project_id='proj-test', intent_id='i001')

    if phase in {'bootstrap', 'explore_execute'}:
        assert saved['argv'][saved['argv'].index('--tools') + 1] == 'read,blackboard_tools,blackboard_invoke'
        extension_index = saved['argv'].index('--extension')
        if launcher == 'node':
            assert saved['argv'][0] == 'node'
            assert saved['argv'][1] == str(cli)
            assert saved['argv'][extension_index:extension_index + 2] == ['--extension', str(extension)]
            assert extension_index == 2
        else:
            assert saved['argv'][0] == 'pi'
            assert saved['argv'][1:3] == ['--extension', str(extension)]
        assert saved['env']['SECMIND_PROJECT_ID'] == 'proj-test'
        assert saved['env']['SECMIND_INTENT_ID'] == 'i001'
        assert saved['env']['SECMIND_WORKER_NAME'] == 'pi-assigned'
    elif phase == 'explore_conclude':
        assert saved['argv'][saved['argv'].index('--tools') + 1] == 'read'
        assert '--extension' in saved['argv']
        assert saved['env']['SECMIND_INTENT_ID'] == 'i001'
    else:
        assert saved['argv'][saved['argv'].index('--tools') + 1] == 'read'
        assert '--extension' not in saved['argv']
        assert 'SECMIND_PROJECT_ID' not in saved['env']


@pytest.mark.skipif(shutil.which('node') is None, reason='Node is unavailable')
def test_pi_blackboard_extension_runs_after_node_entrypoint(tmp_path, monkeypatch):
    monkeypatch.setattr(type(tmp_path), 'home', lambda: tmp_path)
    extension = tmp_path / 'pi_blackboard.ts'
    extension.write_text('export default function () {}', encoding='utf-8')
    cli = tmp_path / 'pi-cli.js'
    cli.write_text('console.log(JSON.stringify(process.argv.slice(2)))', encoding='utf-8')
    monkeypatch.setenv('PI_CLI_JS', str(cli))
    worker = WorkerConfig(name='pi-node-smoke', type='pi', task_types=['explore'],
        priority=0, max_running=1, pi_blackboard_extension=extension)

    def build_process(directory, env, argv, **kwargs):
        return LocalProcess(argv, cwd=directory, env={**os.environ, **env}, timeout_seconds=10)

    manager = SimpleNamespace(is_local=True, build_exec_process=build_process)
    argv = PiDriver(local=True).build_execute(worker, 'prompt', None).argv
    result = run_worker_process(manager, str(tmp_path), worker, argv, phase='explore_execute',
        timeout_seconds=10, project_id='proj-test', intent_id='i001')

    assert result.returncode == 0
    assert 'bad option: --extension' not in result.stderr
    node_args = json.loads(result.stdout)
    assert node_args[:2] == ['--extension', str(extension)]
