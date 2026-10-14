from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest
from conftest import FakeClient, make_config, make_intent, make_project
from pydantic import ValidationError

from security_runtime.dispatcher.config import DispatchConfig, LocalConfig, WorkerConfig
from security_runtime.dispatcher.runtime.cancellation import TaskCancellation
from security_runtime.dispatcher.runtime.local_backend import LocalBackend
from security_runtime.dispatcher.runtime.local_process import (
    LocalProcess,
    command_for_popen,
)
from security_runtime.dispatcher.scheduler import loop as loop_module
from security_runtime.dispatcher.tasks import common, explore
from security_runtime.dispatcher.workers.adapters.codex import CodexDriver
from security_runtime.dispatcher.workers.adapters.pi import PiDriver
from security_runtime.dispatcher.workers.registry import get_driver

REPO_ROOT = Path(__file__).resolve().parents[2]


# --------------------------------------------------------------------------- LocalProcess


def test_local_process_captures_stdout_and_exit_code() -> None:
    process = LocalProcess(
        [sys.executable, "-c", "import sys; print('hello'); sys.exit(3)"],
        cwd=os.getcwd(),
        env=dict(os.environ),
        timeout_seconds=10,
    )
    process.start()
    result = process.communicate(timeout=20)

    assert result.stdout.strip() == "hello"
    assert result.returncode == 3
    assert not result.timed_out


def test_local_process_drains_short_json_events_without_waiting_for_large_read() -> None:
    class EventPipe:
        def __init__(self):
            self.closed = False

        def __iter__(self):
            yield '{"type":"session"}\n'
            yield '{"type":"message_end","message":{"role":"assistant"}}\n'

        def read(self, _size):
            raise AssertionError("a sized read can block after the CLI exits")

        def close(self):
            self.closed = True

    pipe = EventPipe()
    events: list[str] = []
    LocalProcess._drain(pipe, events)

    assert len(events) == 2
    assert json.loads(events[-1])["type"] == "message_end"
    assert pipe.closed


def test_local_process_inherits_cwd(tmp_path: Path) -> None:
    process = LocalProcess(
        [sys.executable, "-c", "import os; print(os.getcwd())"],
        cwd=str(tmp_path),
        env=dict(os.environ),
        timeout_seconds=10,
    )
    process.start()
    result = process.communicate(timeout=20)

    assert Path(result.stdout.strip()).resolve() == tmp_path.resolve()


def test_local_process_times_out_and_kills_within_grace() -> None:
    process = LocalProcess(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        cwd=os.getcwd(),
        env=dict(os.environ),
        timeout_seconds=1,
        term_grace_seconds=2,
    )
    process.start()
    started = time.monotonic()
    result = process.communicate(timeout=30)
    elapsed = time.monotonic() - started

    assert result.timed_out
    assert elapsed < 10  # killed on its own timeout, not the 30s outer backstop


def test_local_process_kill_terminates_child_process_group(tmp_path: Path) -> None:
    pid_file = tmp_path / "child.pid"
    script = (
        "import subprocess,sys,pathlib; "
        "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); "
        f"pid_path=pathlib.Path({str(pid_file)!r}); "
        "staging=pid_path.with_suffix('.tmp'); staging.write_text(str(child.pid)); "
        "staging.replace(pid_path); child.wait()"
    )
    process = LocalProcess(
        [sys.executable, "-c", script],
        cwd=str(tmp_path),
        env=dict(os.environ),
        timeout_seconds=1,
        term_grace_seconds=2,
    )
    process.start()
    try:
        # Measure tree termination only after the child actually exists. Python
        # startup (especially a Windows venv launcher) can exceed the one-second
        # execution timeout; killing it before PID publication tests no tree.
        ready_deadline = time.monotonic() + 15
        while not pid_file.exists() and time.monotonic() < ready_deadline:
            time.sleep(0.05)
        if not pid_file.exists():
            process.cancel('test child failed to start')
            failed = process.communicate(timeout=5)
            pytest.fail(f'Child did not publish its PID: {failed.stderr}')
        child_pid = int(pid_file.read_text().strip())
        result = process.communicate(timeout=30)
    finally:
        process.kill()

    assert result.timed_out
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if os.name == "nt":
            import ctypes
            from ctypes import wintypes
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            kernel.OpenProcess.restype = wintypes.HANDLE
            kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
            kernel.CloseHandle.argtypes = [wintypes.HANDLE]
            handle = kernel.OpenProcess(0x00100000, False, child_pid)
            if not handle:
                break
            try:
                if kernel.WaitForSingleObject(handle, 0) == 0:
                    break
            finally:
                kernel.CloseHandle(handle)
        else:
            try:
                os.kill(child_pid, 0)
            except ProcessLookupError:
                break
        time.sleep(0.1)
    else:
        raise AssertionError(f"child process {child_pid} survived the group kill")


def test_local_process_cancel_records_reason() -> None:
    process = LocalProcess(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        cwd=os.getcwd(),
        env=dict(os.environ),
        timeout_seconds=30,
        term_grace_seconds=2,
    )
    process.start()
    process.cancel("project stopped")
    result = process.communicate(timeout=30)

    assert result.cancelled
    assert result.cancel_reason == "project stopped"


# --------------------------------------------------------------------------- LocalBackend


def test_local_backend_creates_isolated_project_dir(tmp_path: Path) -> None:
    backend = LocalBackend(LocalConfig(workspace_root=str(tmp_path)))
    handle = backend.ensure_running("proj_001")

    assert Path(handle) == tmp_path / "proj_001"
    assert Path(handle).is_dir()
    assert backend.container_name("proj_001") == str(tmp_path / "proj_001")


def test_local_backend_merges_host_env_with_worker_env(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SECURITY_RUNTIME_HOST_VAR", "host")
    backend = LocalBackend(LocalConfig(workspace_root=str(tmp_path)))
    handle = backend.ensure_running("proj_001")

    process = backend.build_exec_process(
        handle,
        {"SECURITY_RUNTIME_WORKER_VAR": "worker"},
        [sys.executable, "-c", "import os; print(os.environ['SECURITY_RUNTIME_HOST_VAR']+'-'+os.environ['SECURITY_RUNTIME_WORKER_VAR'],end='')"],
        timeout_seconds=10,
    )
    process.start()
    result = process.communicate(timeout=20)

    assert result.stdout == "host-worker"


def test_local_common_env_reaches_worker_subprocess(tmp_path: Path, monkeypatch) -> None:
    # common_env (e.g. an outbound proxy) merges into every worker's env and must survive
    # all the way to the host subprocess in local mode.
    payload = _local_payload()
    payload["local"] = {"workspace_root": str(tmp_path)}
    payload["common_env"] = {
        "https_proxy": "http://127.0.0.1:7897",
        "http_proxy": "http://127.0.0.1:7897",
        "all_proxy": "http://127.0.0.1:7897",
    }
    config = DispatchConfig.model_validate(payload)
    worker = next(w for w in config.workers if w.type == "claudecode")
    assert worker.env["https_proxy"] == "http://127.0.0.1:7897"

    assert config.local is not None
    backend = LocalBackend(config.local)
    handle = backend.ensure_running("proj_001")
    process = backend.build_exec_process(
        handle,
        dict(worker.env),
        [sys.executable, "-c", "import os; print('|'.join(os.environ[k] for k in ('https_proxy','http_proxy','all_proxy')),end='')"],
        timeout_seconds=10,
    )
    process.start()
    result = process.communicate(timeout=20)

    proxy = "http://127.0.0.1:7897"
    assert result.stdout == f"{proxy}|{proxy}|{proxy}"


def test_local_backend_write_text_file_writes_to_host(tmp_path: Path) -> None:
    backend = LocalBackend(LocalConfig(workspace_root=str(tmp_path)))
    handle = backend.ensure_running("proj_001")
    target = Path(handle) / "snapshots" / "graph.yaml"

    backend.write_text_file(handle, str(target), "facts: []\n")

    assert target.read_text() == "facts: []\n"


@pytest.mark.parametrize("project_id", ["../escape", "..\\escape", "proj_001/other", "CON", "proj_001."])
def test_local_backend_rejects_unsafe_project_ids(tmp_path: Path, project_id: str) -> None:
    backend = LocalBackend(LocalConfig(workspace_root=str(tmp_path)))
    with pytest.raises(ValueError, match="identifier"):
        backend.ensure_running(project_id)


def test_local_backend_rejects_workspace_escape_and_links(tmp_path: Path) -> None:
    backend = LocalBackend(LocalConfig(workspace_root=str(tmp_path / "work")))
    handle = backend.ensure_running("proj_001")
    outside = tmp_path / "outside"
    outside.mkdir()
    with pytest.raises(ValueError, match="escapes"):
        backend.write_text_file(handle, str(outside / "graph.yaml"), "facts: []\n")
    assert not (outside / "graph.yaml").exists()
    link = Path(handle) / "redirect"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        if getattr(exc, "winerror", None) == 1314:
            pytest.skip("Windows account cannot create symlinks")
        raise
    with pytest.raises(ValueError, match="escapes"):
        backend.write_text_file(handle, str(link / "graph.yaml"), "facts: []\n")
    assert not (outside / "graph.yaml").exists()
    link.unlink()
    Path(handle).rmdir()
    Path(handle).symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="link"):
        backend.ensure_running("proj_001")
    with pytest.raises(ValueError, match="link"):
        backend.build_exec_process(handle, {}, [sys.executable, "-c", "pass"])


def test_local_backend_keep_leaves_dir_and_reports_no_cleanup(tmp_path: Path) -> None:
    backend = LocalBackend(LocalConfig(workspace_root=str(tmp_path), completed_action="keep"))
    handle = backend.ensure_running("proj_001")

    assert backend.needs_completed_cleanup("proj_001") is False
    assert backend.cleanup_completed("proj_001") is True
    assert Path(handle).is_dir()


def test_local_backend_remove_deletes_dir_on_completion(tmp_path: Path) -> None:
    backend = LocalBackend(LocalConfig(workspace_root=str(tmp_path), completed_action="remove"))
    handle = backend.ensure_running("proj_001")

    assert backend.needs_completed_cleanup("proj_001") is True
    assert backend.cleanup_completed("proj_001") is True
    assert not Path(handle).exists()


def test_local_backend_stopped_cleanup_is_noop(tmp_path: Path) -> None:
    backend = LocalBackend(LocalConfig(workspace_root=str(tmp_path)))
    backend.ensure_running("proj_001")

    assert backend.needs_stopped_cleanup("proj_001") is False
    assert backend.cleanup_stopped("proj_001") is True


# --------------------------------------------------------------------------- config


def _local_payload() -> dict:
    return {
        "server": "http://127.0.0.1:8000",
        "runtime": {
            "execution": "local",
            "worker_healthcheck": "disabled",
            "interval": 3,
            "max_workers": 2,
            "max_running_projects": 1,
            "max_project_workers": 2,
            "healthcheck_timeout": 5,
            "prompt_group": "default",
        },
        "tasks": {
            "bootstrap": {"timeout": 10, "conclude_timeout": 5},
            "reason": {"timeout": 10, "max_intents": 3},
            "explore": {"timeout": 10, "conclude_timeout": 5},
        },
        "workers": [
            {"name": "local-claude", "type": "claudecode", "task_types": ["explore"], "max_running": 1, "priority": 0},
            {"name": "local-codex", "type": "codex", "task_types": ["explore"], "max_running": 1, "priority": 1},
            {"name": "local-pi", "type": "pi", "task_types": ["reason"], "max_running": 1, "priority": 2},
        ],
    }


def test_local_execution_needs_no_container_or_worker_env() -> None:
    config = DispatchConfig.model_validate(_local_payload())

    assert config.container is None
    assert config.local is not None
    assert config.local.completed_action == "keep"
    assert all(worker.env == {} for worker in config.workers)


def test_local_workspace_root_is_optional_and_defaults_null() -> None:
    payload = _local_payload()
    payload["local"] = {"completed_action": "remove"}
    config = DispatchConfig.model_validate(payload)

    assert config.local is not None
    assert config.local.workspace_root is None
    assert config.local.completed_action == "remove"


def test_container_execution_requires_container_block() -> None:
    payload = make_config().model_dump()
    payload["container"] = None

    with pytest.raises(ValidationError, match="container config is required"):
        DispatchConfig.model_validate(payload)


def test_container_execution_still_requires_worker_env() -> None:
    payload = _local_payload()
    payload["runtime"]["execution"] = "container"
    payload["runtime"]["worker_healthcheck"] = "startup_only"
    payload["container"] = {"image": "img", "network_mode": "host", "completed_action": "stop"}

    with pytest.raises(ValidationError, match="missing env keys"):
        DispatchConfig.model_validate(payload)


def test_shipped_local_example_config_is_valid() -> None:
    config = DispatchConfig.load(REPO_ROOT / "dispatch.local.example.yaml")

    assert config.runtime.execution == "local"
    assert config.container is None
    assert config.local is not None
    assert config.local.completed_action == "keep"


# --------------------------------------------------------------------------- startup CLI check


def _bare_loop(config: DispatchConfig) -> loop_module.DispatcherLoop:
    loop = loop_module.DispatcherLoop.__new__(loop_module.DispatcherLoop)
    loop.config = config
    return loop


def test_local_cli_check_passes_when_cli_present() -> None:
    payload = _local_payload()
    payload["workers"] = [{"name": "m", "type": "mock", "task_types": ["reason"], "max_running": 1, "priority": 0}]
    config = DispatchConfig.model_validate(payload)

    _bare_loop(config)._run_local_binary_check()  # mock -> python3 --help runs; must not raise


def test_local_cli_check_exits_when_no_cli_installed(monkeypatch) -> None:
    monkeypatch.setattr(loop_module.shutil, "which", lambda _binary: None)
    config = DispatchConfig.model_validate(_local_payload())

    with pytest.raises(RuntimeError, match="none of the configured worker CLIs"):
        _bare_loop(config)._run_local_binary_check()


def test_local_cli_check_exits_when_cli_is_not_runnable(monkeypatch) -> None:
    config = DispatchConfig.model_validate(_local_payload())
    monkeypatch.setattr(loop_module.shutil, "which", lambda _binary: r"C:\Program Files\Claude\claude.CMD")
    monkeypatch.setattr(
        loop_module.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 1),
    )

    with pytest.raises(RuntimeError, match="none of the configured worker CLIs"):
        _bare_loop(config)._run_local_binary_check()


def test_windows_cmd_shim_is_invoked_through_comspec(tmp_path: Path, monkeypatch) -> None:
    cli_dir = tmp_path / "path with spaces"
    cli_dir.mkdir()
    cli = cli_dir / "claude.CMD"
    cli.write_text("@echo off\necho READY:%*\n", encoding="utf-8")
    monkeypatch.setenv("PATH", f"{cli_dir}{os.pathsep}{os.environ['PATH']}")

    command = command_for_popen(["claude", "--help"], windows=True)
    assert isinstance(command, str)
    assert "cmd.exe" in command.lower()
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    assert result.returncode == 0
    assert result.stdout.strip() == "READY:--help"


# --------------------------------------------------------------------------- drivers


def _bare_worker(worker_type: str) -> WorkerConfig:
    return WorkerConfig.model_validate(
        {"name": worker_type, "type": worker_type, "task_types": ["explore"], "max_running": 1, "priority": 0}
    )


def test_codex_local_driver_omits_provider_injection() -> None:
    worker = _bare_worker("codex")
    argv = CodexDriver(local=True).build_execute(worker, "PROMPT", None).argv

    assert argv == ["codex", "exec", "--dangerously-bypass-approvals-and-sandbox", "--", "PROMPT"]
    assert not any("model_providers" in part for part in argv)
    assert "--model" not in argv

    conclude = CodexDriver(local=True).build_conclude(worker, "PROMPT", "sess-1")
    assert conclude[:4] == ["codex", "exec", "resume", "sess-1"]
    assert conclude[-2:] == ["--", "PROMPT"]
    assert not any("model_providers" in part for part in conclude)


def test_pi_local_driver_omits_models_json_and_provider() -> None:
    worker = _bare_worker("pi")
    argv = PiDriver(local=True).build_execute(worker, "PROMPT", None).argv

    assert argv[0] == "pi"
    assert argv[argv.index('--tools') + 1] == 'read'
    assert "--provider" not in argv
    assert "--model" not in argv
    assert argv[-2:] == ["-p", "PROMPT"]


def test_pi_local_driver_uses_isolated_model_without_leaking_key(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(Path, 'home', lambda: tmp_path)
    worker = _bare_worker('pi')
    worker.env.update({
        'PI_MODEL': 'custom-model', 'PI_BASE_URL': 'https://models.example/v1',
        'PI_API_KEY': 'private-key', 'PI_PROVIDER_API': 'openai-completions',
    })
    argv = PiDriver(local=True).build_execute(worker, 'PROMPT', None).argv
    model_path = Path(worker.env['PI_CODING_AGENT_DIR']) / 'models.json'
    model_data = json.loads(model_path.read_text(encoding='utf-8'))

    assert argv[argv.index('--provider') + 1] == 'security_runtime'
    assert argv[argv.index('--model') + 1] == 'custom-model'
    assert 'private-key' not in ' '.join(argv)
    assert model_data['providers']['security_runtime']['apiKey'] == 'PI_API_KEY'
    assert 'private-key' not in model_path.read_text(encoding='utf-8')


@pytest.mark.skipif(shutil.which('node') is None, reason='Node is unavailable')
def test_pi_local_driver_preserves_multiline_prompt_on_windows(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(Path, 'home', lambda: tmp_path)
    entry = tmp_path / 'pi-stub.js'
    entry.write_text('console.log(JSON.stringify(process.argv.slice(2)))', encoding='utf-8')
    monkeypatch.setenv('PI_CLI_JS', str(entry))
    worker = _bare_worker('pi')
    prompt = '# Task\nRead the entire graph.\nReturn JSON.'
    argv = PiDriver(local=True).build_execute(worker, prompt, None).argv
    process = LocalProcess(argv, cwd=str(tmp_path), env={**os.environ, **worker.env}, timeout_seconds=10)
    process.start()
    result = process.communicate(timeout=15)
    assert result.returncode == 0
    assert json.loads(result.stdout)[-1] == prompt


def test_get_driver_selects_local_or_container_variant() -> None:
    assert get_driver("codex", "local").local is True
    assert get_driver("codex").local is False
    assert get_driver("pi", "local").local is True
    # Container commands must not receive a host-only interpreter path.
    assert get_driver("claudecode", "local") is get_driver("claudecode")
    assert get_driver("mock", "local").local_binary() == sys.executable
    assert get_driver("mock").local_binary() == "python3"


# --------------------------------------------------------------------------- end to end


def _local_config_for_worker(name: str, worker_type: str) -> DispatchConfig:
    return DispatchConfig.model_validate(
        {
            "server": "in-process",
            "runtime": {
                "execution": "local",
                "worker_healthcheck": "disabled",
                "interval": 60,
                "max_workers": 1,
                "max_running_projects": 1,
                "max_project_workers": 1,
                "healthcheck_timeout": 5,
                "prompt_group": "default",
            },
            "tasks": {
                "bootstrap": {"timeout": 30, "conclude_timeout": 10},
                "reason": {"timeout": 30, "max_intents": 3},
                "explore": {"timeout": 30, "conclude_timeout": 10},
            },
            "workers": [
                {"name": name, "type": worker_type, "task_types": ["explore"], "max_running": 1, "priority": 0}
            ],
        }
    )


def _install_fake_cli(tmp_path: Path, monkeypatch, name: str, body: str) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    script = bin_dir / name
    if script.suffix.lower() in {".cmd", ".bat"}:
        script.write_text(f"@echo off\n{body}\n")
    else:
        script.write_text(f"#!/bin/sh\n{body}\n")
        script.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")


def test_explore_runs_real_local_cli_end_to_end(tmp_path: Path, monkeypatch) -> None:
    # A fake `claude` on PATH stands in for the real CLI: the whole local path is exercised
    # for real — driver argv -> LocalBackend -> LocalProcess subprocess -> stdout parsing.
    _install_fake_cli(
        tmp_path,
        monkeypatch,
        "claude.CMD" if os.name == "nt" else "claude",
        "echo '{\"accepted\":true,\"data\":{\"description\":\"local fake fact\"}}'",
    )
    monkeypatch.setattr(common, "GRAPH_SNAPSHOT_ROOT", str(tmp_path / "prompts"))

    config = _local_config_for_worker("test-worker", "claudecode")
    backend = LocalBackend(LocalConfig(workspace_root=str(tmp_path / "work")))
    intent = make_intent()
    project = make_project(intents=[intent])
    client = FakeClient(project)

    outcome = explore.run_explore_task(
        config,
        client,
        backend,
        project,
        "facts:\n- id: f001\n",
        intent,
        config.workers[0],
        TaskCancellation(),
    )

    assert outcome == "success"
    assert client.concluded == [("proj_001", "i001", "test-worker", "local fake fact")]
    # Local snapshots are materialised inside the isolated project workspace.
    snapshot_root = tmp_path / "work" / "proj_001" / ".security-runtime-prompts"
    assert any(p.name == "graph.yaml" for p in snapshot_root.rglob("*"))


def test_explore_local_cli_rejection_releases_intent(tmp_path: Path, monkeypatch) -> None:
    _install_fake_cli(
        tmp_path,
        monkeypatch,
        "claude.CMD" if os.name == "nt" else "claude",
        "echo '{\"accepted\":false,\"reason\":\"policy_refusal\"}'",
    )
    monkeypatch.setattr(common, "GRAPH_SNAPSHOT_ROOT", str(tmp_path / "prompts"))

    config = _local_config_for_worker("test-worker", "claudecode")
    backend = LocalBackend(LocalConfig(workspace_root=str(tmp_path / "work")))
    intent = make_intent()
    project = make_project(intents=[intent])
    client = FakeClient(project)

    outcome = explore.run_explore_task(
        config,
        client,
        backend,
        project,
        "facts:\n- id: f001\n",
        intent,
        config.workers[0],
        TaskCancellation(),
    )

    assert outcome == "rejected"
    assert client.concluded == []
    assert client.released == [("proj_001", "i001", "test-worker")]
