from pathlib import Path

import pytest

from secmind.config import Settings
from secmind.runtime import build_runtime


def settings_for(tmp_path: Path, **updates) -> Settings:
    values = {
        "demo_mode": True,
        "model_mode": "offline",
        "allow_live_models": False,
        "model_base_url_provider": "auto",
        "qwen_base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
        "trusted_model_base_urls": "https://dashscope.aliyuncs.com/compatible-mode/v1",
        "qwen_api_key": "",
        "deepseek_api_key": "",
        "openai_api_key": "",
        "planner_model": "qwen-plus",
        "worker_model": "qwen-turbo",
        "fallback_model": "qwen-turbo",
        "embedding_model": "text-embedding-v3",
        "model_structured_output_mode": "auto",
        "sandbox_runner_url": "",
        "sandbox_token": "",
        "sandbox_control_token": "",
        "sandbox_ticket_private_key_file": None,
        "unsafe_development_tools": False,
        "enable_api_dynamic_probes": False,
        "database_url": f"sqlite:///{(tmp_path / 'runtime.db').as_posix()}",
        "input_root": tmp_path / "inputs",
        "upload_root": tmp_path / "uploads",
        "run_root": tmp_path / "runs",
        "artifact_root": tmp_path / "artifacts",
    }
    values.update(updates)
    return Settings(_env_file=None, **values)


def test_settings_helper_ignores_hostile_local_dotenv(tmp_path, monkeypatch) -> None:
    """Local operator credentials/configuration cannot alter generic test defaults."""

    (tmp_path / ".env").write_text(
        "\n".join(
            (
                "SECMIND_MODEL_BASE_URL_PROVIDER=deepseek",
                "SECMIND_QWEN_BASE_URL=https://api.deepseek.com",
                "SECMIND_PLANNER_MODEL=deepseek-v4-flash",
                "SECMIND_SANDBOX_RUNNER_URL=https://sandbox.example.invalid",
                "SECMIND_UNSAFE_DEVELOPMENT_TOOLS=true",
            )
        ),
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    settings = settings_for(tmp_path)

    assert settings.model_base_url_provider == "auto"
    assert settings.qwen_base_url == "https://dashscope.aliyuncs.com/compatible-mode/v1"
    assert settings.planner_model == "qwen-plus"
    assert settings.sandbox_runner_url == ""
    assert settings.unsafe_development_tools is False


def test_runtime_requires_explicit_sandbox_or_unsafe_development_flag(tmp_path) -> None:
    with pytest.raises(RuntimeError, match="sandbox runner"):
        build_runtime(settings_for(tmp_path))
    with pytest.raises(RuntimeError, match="dynamic API probes"):
        build_runtime(
            settings_for(
                tmp_path,
                unsafe_development_tools=True,
                enable_api_dynamic_probes=True,
            )
        )


def test_runtime_reuses_one_database_engine(tmp_path) -> None:
    service, gateway = build_runtime(settings_for(tmp_path, unsafe_development_tools=True))
    try:
        engine = service.coordinator.engine
        assert service.ledger.engine is engine
        assert service.unit_of_work is not None
        assert service.unit_of_work.engine is engine
        assert service.orchestrator.knowledge_store is not None
        assert service.orchestrator.knowledge_store.engine is engine
        assert service.orchestrator.broker.execution_store.engine is engine
    finally:
        import asyncio

        asyncio.run(gateway.close())
        asyncio.run(service.orchestrator.broker.aclose())
        service.orchestrator.broker.close()
        service.orchestrator.knowledge_store.close()
        service.ledger.close()
        service.coordinator.close()


def test_production_runtime_fails_closed_before_startup(tmp_path) -> None:
    with pytest.raises(RuntimeError, match="SANDBOX_RUNNER_URL"):
        build_runtime(settings_for(tmp_path, env="production"))
    with pytest.raises(RuntimeError, match="unsafe development"):
        build_runtime(
            settings_for(
                tmp_path,
                env="competition",
                sandbox_runner_url="http://runner:8010",
                unsafe_development_tools=True,
            )
        )
    with pytest.raises(RuntimeError, match="ticket private key"):
        build_runtime(
            settings_for(
                tmp_path,
                env="production",
                sandbox_runner_url="http://runner:8010",
            )
        )
    with pytest.raises(RuntimeError, match="control token"):
        build_runtime(
            settings_for(
                tmp_path,
                env="production",
                sandbox_runner_url="http://runner:8010",
                sandbox_ticket_private_key_file=tmp_path / "unused.pem",
            )
        )


def test_strict_api_runtime_has_no_sandbox_ticket_signing_authority(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr("secmind.runtime.verify_database_at_head", lambda *_args: None)
    service, gateway = build_runtime(
        settings_for(
            tmp_path,
            env="competition",
            runtime_role="api",
            sandbox_runner_url="http://runner:8010",
            sandbox_token=tmp_path.name,
            sandbox_control_token=f"control-{tmp_path.name}",
        )
    )
    try:
        tool = service.orchestrator.broker.registry.get("bandit_python_audit")
        assert tool.service_token == ""  # type: ignore[attr-defined]
        assert tool._client is service.orchestrator.broker._owned_async_clients[0]  # type: ignore[attr-defined]
        with pytest.raises(RuntimeError, match="not authorized"):
            tool.capability_ticket_provider(object())  # type: ignore[attr-defined]
    finally:
        import asyncio

        asyncio.run(gateway.close())
        asyncio.run(service.orchestrator.broker.aclose())
        service.orchestrator.broker.close()
        service.ledger.close()
        service.coordinator.close()
