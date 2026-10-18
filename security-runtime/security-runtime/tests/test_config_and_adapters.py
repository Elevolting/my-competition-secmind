from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from security_runtime.dispatcher.config import DispatchConfig, WorkerConfig, validate_prompt_resources
from security_runtime.dispatcher.workers.adapters.codex import CodexDriver
from security_runtime.dispatcher.workers.adapters.pi import PiDriver
from security_runtime.dispatcher.shared_model import shared_anthropic_env

from conftest import make_config


def test_shared_anthropic_env_reads_platform_model_runtime(tmp_path: Path) -> None:
    path = tmp_path / "model-runtime.json"
    path.write_text(json.dumps({"base_url": "https://model.example/v1", "worker_model": "glm-5.3", "api_key": "secret"}), encoding="utf-8")
    assert shared_anthropic_env(path) == {
        "ANTHROPIC_BASE_URL": "https://model.example",
        "ANTHROPIC_MODEL": "glm-5.3",
        "ANTHROPIC_AUTH_TOKEN": "secret",
    }


def test_dispatch_config_merges_common_env_with_worker_override() -> None:
    payload = make_config().model_dump()
    payload["common_env"] = {"SHARED": "common", "OVERRIDE": "common"}
    payload["workers"][0]["env"] = {"OVERRIDE": "worker"}

    config = DispatchConfig.model_validate(payload)

    assert config.workers[0].env["SHARED"] == "common"
    assert config.workers[0].env["OVERRIDE"] == "worker"


def test_dispatch_config_defaults_worker_healthcheck_and_rejects_unknown_mode() -> None:
    payload = make_config().model_dump()
    payload["runtime"].pop("worker_healthcheck")

    assert DispatchConfig.model_validate(payload).runtime.worker_healthcheck == "startup_only"

    payload["runtime"]["worker_healthcheck"] = "sometimes"
    with pytest.raises(ValidationError):
        DispatchConfig.model_validate(payload)


def test_dispatch_config_rejects_duplicate_workers_and_excess_project_parallelism() -> None:
    payload = make_config().model_dump()
    payload["workers"].append(dict(payload["workers"][0]))
    with pytest.raises(ValidationError, match="worker names must be unique"):
        DispatchConfig.model_validate(payload)

    payload = make_config().model_dump()
    payload["runtime"]["max_project_workers"] = 3
    with pytest.raises(ValidationError, match="max_project_workers cannot exceed max_workers"):
        DispatchConfig.model_validate(payload)


def test_pi_worker_rejects_invalid_context_window() -> None:
    with pytest.raises(ValidationError, match="PI_MODEL_CONTEXT_WINDOW must be greater than 0"):
        WorkerConfig.model_validate(
            {
                "name": "pi",
                "type": "pi",
                "task_types": ["explore"],
                "max_running": 1,
                "priority": 0,
                "env": {
                    "PI_MODEL": "model",
                    "PI_BASE_URL": "http://api",
                    "PI_API_KEY": "secret",
                    "PI_PROVIDER_API": "openai-completions",
                    "PI_MODEL_CONTEXT_WINDOW": "0",
                },
            }
        )


def test_pi_worker_rejects_unknown_provider_api() -> None:
    with pytest.raises(ValidationError, match="PI_PROVIDER_API must be one of"):
        WorkerConfig.model_validate(
            {
                "name": "deepseek",
                "type": "pi",
                "task_types": ["reason", "explore"],
                "max_running": 1,
                "priority": 0,
                "env": {
                    "PI_MODEL": "deepseek-v4-flash",
                    "PI_BASE_URL": "http://model.internal/v1",
                    "PI_API_KEY": "secret",
                    "PI_PROVIDER_API": "openai-compatible",
                },
            }
        )


def test_dispatch_config_load_resolves_environment_references(tmp_path: Path, monkeypatch) -> None:
    payload = make_config().model_dump()
    payload["common_env"] = {"MODEL_API_KEY": "${SECURITY_RUNTIME_TEST_MODEL_API_KEY}"}
    config_path = tmp_path / "dispatch.yaml"
    config_path.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setenv("SECURITY_RUNTIME_TEST_MODEL_API_KEY", "secret-from-environment")

    config = DispatchConfig.load(config_path)

    assert config.workers[0].env["MODEL_API_KEY"] == "secret-from-environment"


def test_dispatch_config_load_rejects_missing_environment_reference(tmp_path: Path, monkeypatch) -> None:
    payload = make_config().model_dump()
    payload["common_env"] = {"MODEL_API_KEY": "${SECURITY_RUNTIME_TEST_MISSING_API_KEY}"}
    config_path = tmp_path / "dispatch.yaml"
    config_path.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.delenv("SECURITY_RUNTIME_TEST_MISSING_API_KEY", raising=False)

    with pytest.raises(ValueError, match="SECURITY_RUNTIME_TEST_MISSING_API_KEY.*not set"):
        DispatchConfig.load(config_path)


def test_deepseek_example_loads_as_pi_openai_completions(monkeypatch) -> None:
    monkeypatch.setenv("DEEPSEEK_BASE_URL", "http://model.internal/v1")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "internal-secret")
    example = Path(__file__).parents[2] / "dispatch.deepseek.example.yaml"

    config = DispatchConfig.load(example)

    worker = config.workers[0]
    assert worker.type == "pi"
    assert worker.env["PI_MODEL"] == "deepseek-v4-flash"
    assert worker.env["PI_BASE_URL"] == "http://model.internal/v1"
    assert worker.env["PI_API_KEY"] == "internal-secret"
    assert worker.env["PI_PROVIDER_API"] == "openai-completions"


def test_mock_worker_rejects_unknown_phase_configuration() -> None:
    with pytest.raises(ValidationError, match="unsupported mock env keys"):
        WorkerConfig.model_validate(
            {
                "name": "mock",
                "type": "mock",
                "task_types": ["explore"],
                "max_running": 1,
                "priority": 0,
                "env": {"MOCK_UNKNOWN": "{}"},
            }
        )


def test_bundled_prompt_groups_have_required_placeholders() -> None:
    validate_prompt_resources("default")
    validate_prompt_resources("mock")


def test_pi_driver_models_json_and_execute_argv_include_context_window_and_tools() -> None:
    worker = WorkerConfig.model_validate(
        {
            "name": "pi-worker",
            "type": "pi",
            "task_types": ["explore"],
            "max_running": 1,
            "priority": 0,
            "env": {
                "PI_MODEL": "model",
                "PI_BASE_URL": "http://api",
                "PI_API_KEY": "secret",
                "PI_PROVIDER_API": "openai-completions",
                "PI_MODEL_CONTEXT_WINDOW": "131072",
            },
        }
    )

    result = PiDriver().build_execute(worker, "prompt", None)
    models = json.loads(result.argv[5])

    assert models["providers"]["security_runtime"]["models"][0]["contextWindow"] == 131072
    assert "--tools" in result.argv
    assert result.argv[-2:] == ["-p", "prompt"]


def test_codex_driver_execute_argv_passes_model_endpoint_and_prompt() -> None:
    worker = WorkerConfig.model_validate(
        {
            "name": "codex",
            "type": "codex",
            "task_types": ["reason"],
            "max_running": 1,
            "priority": 0,
            "env": {
                "CODEX_MODEL": "gpt-test",
                "CODEX_BASE_URL": "http://api/v1",
                "OPENAI_API_KEY": "secret",
            },
        }
    )

    argv = CodexDriver().build_execute(worker, "prompt", None).argv

    assert "--model" in argv
    assert "gpt-test" in argv
    assert 'model_providers.security_runtime.base_url="http://api/v1"' in argv
    assert argv[-2:] == ["--", "prompt"]
