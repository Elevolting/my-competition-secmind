from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from security_agent.budget_policy import (
    DEFAULT_MODEL_CALLS,
    DEFAULT_PENETRATION_MODEL_CALLS,
    DEFAULT_TOOL_CALLS,
    MAX_MODEL_CALLS,
    MAX_TOOL_CALLS,
)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="SECURITY_AGENT_", case_sensitive=False, extra="ignore")

    env: str = "development"
    demo_mode: bool = True
    database_url: str = "sqlite:///./data/security_agent.db"
    input_root: Path = Path("data/inputs")
    run_root: Path = Path("data/runs")
    upload_root: Path = Path("data/uploads")
    evaluation_root: Path = Path("data/evaluations")
    question_bank_root: Path = Path("data/question-banks")
    mcp_generated_root: Path = Path("data/mcp-generated")

    benchmark_dataset_root: Path | None = None
    benchmark_private_root: Path | None = None
    benchmark_scorer_root: Path | None = None
    benchmark_python_executable: str = "python"
    benchmark_dataset_version: str = "3.0.0-2026.07"
    benchmark_candidate_id: str = "anonymous-candidate"
    benchmark_candidate_version: str = "0.8.3"
    benchmark_dashboard_url: str = "http://127.0.0.1:3001/"
    tsec_base_url: str = Field(default="", validation_alias=AliasChoices("BENCHMARK_BASE_URL", "tsec_base_url"))
    tsec_token: str = Field(default="", exclude=True, repr=False,
                            validation_alias=AliasChoices("BENCHMARK_TOKEN", "tsec_token"))

    model_base_url: str = "https://model-gateway.example/v1"
    model_api_key: str = ""
    planner_model: str = "planner-model"
    worker_model: str = "worker-model"
    fallback_model: str = "fallback-model"
    embedding_model: str = "text-embedding-v3"
    qdrant_url: str = "http://qdrant:6333"
    qdrant_collection: str = "security_agent_knowledge"
    model_timeout_seconds: float = 45.0
    side_question_max_concurrency: int = Field(default=2, ge=1, le=16)
    side_question_input_token_budget: int = Field(default=256_000, ge=1_000, le=2_000_000)
    side_question_output_token_budget: int = Field(default=8_192, ge=128, le=128_000)
    model_hourly_token_quota: int = Field(default=0, ge=0)
    model_daily_token_quota: int = Field(default=0, ge=0)
    model_monthly_token_quota: int = Field(default=0, ge=0)
    api_host: str = "127.0.0.1"
    api_port: int = Field(default=8001, ge=1, le=65535)
    allowed_hosts: str = ""
    allowed_browser_origins: str = ""
    reverse_base_url: str = "http://127.0.0.1:8002"
    secmind_operator_token: str = Field(default="", exclude=True, repr=False)
    # Shared secret for Security Runtime -> workbench incremental planning
    # callbacks.  Empty keeps local/demo deployments backwards compatible;
    # production deployments should set it explicitly.
    security_runtime_callback_token: str = Field(default="", exclude=True, repr=False,
                                                 validation_alias=AliasChoices("SECURITY_RUNTIME_CALLBACK_TOKEN", "security_runtime_callback_token"))
    secmind_usage_database: Path | None = None
    penetration_base_url: str = "http://127.0.0.1:8000"
    module_timeout_seconds: float = Field(default=20.0, ge=1, le=300)
    penetration_poll_interval_seconds: float = Field(default=3.0, ge=0.2, le=60.0)
    penetration_poll_timeout_seconds: float = Field(default=1800.0, ge=1.0, le=7200.0)
    penetration_max_runtime_seconds: int = Field(default=2400, ge=60, le=7200)
    kali_mcp_enabled: bool = False
    kali_container: str = "security-runtime-kali"

    max_steps: int = Field(default=12, ge=1, le=100)
    max_tool_calls: int = Field(default=DEFAULT_TOOL_CALLS, ge=1, le=MAX_TOOL_CALLS)
    # Cairn bounds dispatcher work with runtime/lease timeouts rather than a
    # fixed number of tool calls.  ``None`` keeps the durable counters for
    # observability but does not turn them into a second stop condition.  A
    # finite value can still be supplied by an operator for a controlled
    # deployment or a test.
    blackboard_max_mcp_calls_per_run: int | None = Field(default=None, ge=1, le=100_000)
    blackboard_max_mcp_calls_per_intent: int | None = Field(default=None, ge=1, le=100_000)
    max_model_calls: int = Field(default=DEFAULT_MODEL_CALLS, ge=1, le=MAX_MODEL_CALLS)
    penetration_max_model_calls: int = Field(default=DEFAULT_PENETRATION_MODEL_CALLS, ge=1, le=MAX_MODEL_CALLS)
    max_runtime_seconds: int = Field(default=600, ge=10, le=7200)
    max_upload_bytes: int = Field(default=50 * 1024 * 1024, ge=1024)
    max_extracted_bytes: int = Field(default=200 * 1024 * 1024, ge=1024)
    max_files: int = Field(default=10_000, ge=1)
    max_zip_ratio: int = Field(default=100, ge=1)
    max_question_bank_bytes: int = Field(default=2 * 1024 * 1024 * 1024, ge=1024)
    max_question_bank_files: int = Field(default=50_000, ge=1)
    max_question_bank_questions: int = Field(default=500, ge=1)
    max_question_bank_archive_depth: int = Field(default=5, ge=0, le=8)
    question_bank_scan_batch_size: int = Field(default=80, ge=1, le=200)
    question_bank_classification_batch_size: int = Field(default=8, ge=1, le=50)
    question_bank_boundary_confidence: float = Field(default=0.65, ge=0, le=1)
    question_bank_type_confidence: float = Field(default=0.60, ge=0, le=1)
    question_bank_model_timeout_seconds: float = Field(default=120.0, ge=10, le=600)

    def prepare_directories(self) -> None:
        for path in (
            self.input_root,
            self.run_root,
            self.upload_root,
            self.evaluation_root,
            self.question_bank_root,
            self.mcp_generated_root,
        ):
            path.mkdir(parents=True, exist_ok=True)
        if self.database_url.startswith("sqlite:///"):
            Path(self.database_url.removeprefix("sqlite:///")).parent.mkdir(parents=True, exist_ok=True)

    @property
    def runtime_model_config_path(self) -> Path:
        return self.run_root.parent / "model-runtime.json"

    @staticmethod
    def validate_model_base_url(value: str) -> str:
        normalized = value.strip().rstrip("/")
        parsed = urlparse(normalized)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("Base URL must be a valid HTTP or HTTPS URL")
        if parsed.username or parsed.password:
            raise ValueError("Base URL must not contain embedded credentials")
        if parsed.query or parsed.fragment:
            raise ValueError("Base URL must not contain query parameters or fragments")
        try:
            _ = parsed.port
        except ValueError as exc:
            raise ValueError("Base URL contains an invalid port") from exc
        return normalized

    def load_runtime_model_config(self) -> None:
        path = self.runtime_model_config_path
        if not path.exists():
            return
        data = json.loads(path.read_text(encoding="utf-8"))
        self.model_base_url = self.validate_model_base_url(str(data.get("base_url", self.model_base_url)))
        api_key = data.get("api_key")
        if isinstance(api_key, str):
            self.model_api_key = api_key
        for field_name in ("planner_model", "worker_model", "fallback_model"):
            value = data.get(field_name)
            if isinstance(value, str) and value.strip():
                setattr(self, field_name, value.strip())
        for field_name in ("model_hourly_token_quota", "model_daily_token_quota", "model_monthly_token_quota"):
            value = data.get(field_name)
            if isinstance(value, int) and value >= 0:
                setattr(self, field_name, value)
        self.demo_mode = not bool(self.model_api_key)

    def save_runtime_model_config(self) -> None:
        path = self.runtime_model_config_path
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".tmp")
        temporary.write_text(
            json.dumps(
                {
                    "base_url": self.model_base_url,
                    "api_key": self.model_api_key,
                    "planner_model": self.planner_model,
                    "worker_model": self.worker_model,
                    "fallback_model": self.fallback_model,
                    "model_hourly_token_quota": self.model_hourly_token_quota,
                    "model_daily_token_quota": self.model_daily_token_quota,
                    "model_monthly_token_quota": self.model_monthly_token_quota,
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        try:
            os.chmod(temporary, 0o600)
        except OSError:
            pass
        os.replace(temporary, path)

    def apply_model_changes(self, changes: dict) -> None:
        """Persist a validated candidate before changing the shared live settings."""
        candidate = self.model_copy(deep=True)
        for key, value in changes.items():
            setattr(candidate, key, value)
        candidate.save_runtime_model_config()
        for key, value in changes.items():
            setattr(self, key, value)


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    settings.prepare_directories()
    settings.load_runtime_model_config()
    return settings
