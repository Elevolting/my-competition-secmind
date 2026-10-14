from __future__ import annotations

import json
from pathlib import Path

import pytest

from secmind.config import Settings
from secmind.runtime_profile import PROFILE_SETTING_FIELDS, SECRET_SETTING_FIELDS, resolve_runtime_profile


def _example_environment() -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in Path(".env.example").read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value
    return values


def _settings(**updates: object) -> Settings:
    values: dict[str, object] = {
        "model_mode": "offline",
        "allow_live_models": False,
        "qwen_api_key": "",
        "deepseek_api_key": "",
        "openai_api_key": "",
        "sandbox_token": "",
        "sandbox_control_token": "",
        "operator_token": "",
    }
    values.update(updates)
    return Settings(_env_file=None, **values)


def test_profile_inventory_is_exhaustive_against_settings_model() -> None:
    settings_fields = set(Settings.model_fields)
    assert settings_fields == PROFILE_SETTING_FIELDS | SECRET_SETTING_FIELDS
    assert PROFILE_SETTING_FIELDS.isdisjoint(SECRET_SETTING_FIELDS)


def test_example_environment_matches_reviewed_model_deadline_defaults() -> None:
    """The deployable example must not silently restore the old timeout storm."""

    example = _example_environment()
    settings = _settings()
    expected = {
        "SECMIND_MODEL_TIMEOUT_SECONDS": settings.model_timeout_seconds,
        "SECMIND_MODEL_PRIMARY_SOFT_TIMEOUT_SECONDS": settings.model_primary_soft_timeout_seconds,
        "SECMIND_MODEL_TASK_HARD_TIMEOUT_SECONDS": settings.model_task_hard_timeout_seconds,
        "SECMIND_MODEL_RECOVERY_RESERVE_SECONDS": settings.model_recovery_reserve_seconds,
        "SECMIND_MODEL_STREAM_MAX_SECONDS": settings.model_stream_max_seconds,
        "SECMIND_MODEL_CONNECT_TIMEOUT_SECONDS": settings.model_connect_timeout_seconds,
        "SECMIND_MODEL_POOL_TIMEOUT_SECONDS": settings.model_pool_timeout_seconds,
        "SECMIND_MODEL_WRITE_TIMEOUT_SECONDS": settings.model_write_timeout_seconds,
        "SECMIND_MODEL_READ_IDLE_TIMEOUT_SECONDS": settings.model_read_idle_timeout_seconds,
        "SECMIND_MODEL_FALLBACK_MAX_OUTPUT_TOKENS": settings.model_fallback_max_output_tokens,
    }
    assert set(expected) <= set(example)
    assert {name: float(example[name]) for name in expected} == {name: float(value) for name, value in expected.items()}


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("model_structured_output_mode", "json_object"),
        ("model_timeout_seconds", 240.0),
        ("model_read_idle_timeout_seconds", 90.0),
        ("max_steps", 7),
        ("max_cost_units", 20.0),
        ("prompt_mode", "catalog"),
        ("prompt_optimizer_enabled", True),
        ("semgrep_candidate_rules_enabled", True),
        ("sandbox_runner_url", "https://runner.example"),
    ],
)
def test_behavior_sensitive_setting_changes_digest(field: str, value: object) -> None:
    baseline = resolve_runtime_profile(_settings())
    changed = resolve_runtime_profile(_settings(**{field: value}))

    assert changed.digest != baseline.digest
    assert changed.effective_settings[field] != baseline.effective_settings[field]


def test_secrets_bind_only_name_and_presence_not_value() -> None:
    baseline = resolve_runtime_profile(_settings())
    first = resolve_runtime_profile(_settings(openai_api_key="first-secret"))
    second = resolve_runtime_profile(_settings(openai_api_key="second-secret"))

    assert first.digest == second.digest
    assert first.digest != baseline.digest
    assert first.secret_bindings["openai_api_key"] is True
    assert baseline.secret_bindings["openai_api_key"] is False

    serialized = json.dumps(first.model_dump(mode="json"), sort_keys=True)
    assert "first-secret" not in serialized
    assert "second-secret" not in serialized
    assert '"openai_api_key": true' in serialized


def test_endpoint_credentials_are_redacted_but_endpoint_identity_is_bound() -> None:
    baseline = resolve_runtime_profile(_settings(database_url="postgresql://db.example/a"))
    changed = resolve_runtime_profile(
        _settings(database_url="postgresql://user:password@db.example/a?sslpassword=secret")
    )

    assert changed.digest != baseline.digest
    rendered = json.dumps(changed.model_dump(mode="json"), sort_keys=True)
    assert "user:password@" not in rendered
    assert "sslpassword=secret" not in rendered
    assert "sslpassword=<configured>" in rendered
    assert "db.example" in rendered


def test_disabled_and_unresolved_reasons_are_deterministic() -> None:
    profile = resolve_runtime_profile(
        _settings(
            enable_log_analysis=False,
            hybrid_knowledge_enabled=True,
            sandbox_runner_url="https://runner.example",
        )
    )

    assert profile.disabled_reasons["log_analysis"] == "disabled_by_setting:enable_log_analysis"
    assert profile.disabled_reasons["model.live"] == "disabled_by_model_mode"
    assert profile.unresolved_reasons["model.provider"] == "provider_resolution_deferred_to_model_policy"
    assert profile.unresolved_reasons["tools.hybrid_knowledge"] == "knowledge_vector_source_unconfigured"
    assert profile.unresolved_reasons["tools.sandbox_runner"] == "sandbox_control_token_unconfigured"
