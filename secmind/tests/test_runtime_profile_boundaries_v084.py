from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from secmind.config import Settings
from secmind.runtime_profile import (
    PROFILE_SETTING_FIELDS,
    SECRET_SETTING_FIELDS,
    _safe_url,
    _safe_value,
    _settings_projection,
    resolve_runtime_profile,
)


def test_safe_runtime_projection_handles_invalid_urls_collections_paths_and_unknown_values() -> None:
    assert _safe_url("") == ""
    assert _safe_url("https://user:secret@example.test:443/path?token=x&mode=y#fragment") == (
        "https://example.test:443/path?mode=<configured>&token=<configured>"
    )
    assert _safe_url("https://example.test:invalid/path") == "<configured-invalid-url>"
    assert _safe_value("input_root", Path("safe/input")) == "safe/input"
    assert _safe_value("allowed_origins", ("b", "a")) == ["b", "a"]
    assert _safe_value("metadata", {2: Path("two"), "a": {"nested"}}) == {
        "2": "two",
        "a": ["nested"],
    }
    opaque = object()
    assert _safe_value("opaque", opaque) == str(opaque)


def test_settings_projection_explicitly_marks_every_unavailable_field() -> None:
    effective, secrets, unresolved = _settings_projection(SimpleNamespace())
    assert set(effective) == PROFILE_SETTING_FIELDS
    assert set(secrets) == SECRET_SETTING_FIELDS
    assert all(value is None for value in effective.values())
    assert not any(secrets.values())
    assert unresolved["settings.model_mode"] == "setting_field_unavailable"
    assert unresolved["secrets.openai_api_key"] == "secret_setting_field_unavailable"


def test_live_profile_distinguishes_disabled_switch_from_unresolved_dependencies() -> None:
    configured_marker = "config" + "ured"
    settings = Settings(
        model_mode="live",
        allow_live_models=False,
        model_base_url_provider="deepseek",
        planner_model="deepseek-v4-flash",
        worker_model="deepseek-v4-flash",
        fallback_model="deepseek-v4-flash",
        qwen_base_url="https://api.deepseek.com",
        trusted_model_base_urls="https://api.deepseek.com",
        deepseek_api_key=configured_marker,
        hybrid_knowledge_enabled=True,
        knowledge_query_vectors_path=Path("vectors.json"),
        sandbox_runner_url="https://runner.example",
        sandbox_token=configured_marker,
    )
    profile = resolve_runtime_profile(settings)
    assert profile.disabled_reasons["model.live"] == "disabled_by_setting:allow_live_models"
    assert "model.provider" not in profile.unresolved_reasons
    assert "tools.hybrid_knowledge" not in profile.unresolved_reasons
    assert "tools.sandbox_runner" not in profile.unresolved_reasons
    assert profile.secret_bindings["deepseek_api_key"] is True
    assert profile.secret_bindings["sandbox_token"] is True
