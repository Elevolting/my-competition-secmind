from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="SECMIND_", case_sensitive=False, extra="ignore")

    env: str = "development"
    runtime_role: Literal["api", "worker", "projector", "embedded"] = "embedded"
    runtime_profile: Literal["offline-ci", "local-full", "competition-full"] = "local-full"
    demo_mode: bool = True
    database_url: str = "sqlite:///./data/secmind.db"
    checkpoint_database_url: str = ""
    input_root: Path = Path("data/inputs")
    run_root: Path = Path("data/runs")
    upload_root: Path = Path("data/uploads")
    artifact_root: Path = Path("data/artifacts")
    alembic_config_path: Path = Path("alembic.ini")

    model_mode: Literal["offline", "mock", "live"] = "offline"
    allow_live_models: bool = False
    max_model_tier: float = Field(default=5.4, ge=0, le=5.4)
    trusted_model_base_urls: str = "https://dashscope.aliyuncs.com/compatible-mode/v1"
    qwen_base_url: str = "https://dashscope.aliyuncs.com/compatible-mode/v1"
    model_base_url_provider: Literal["auto", "dashscope", "deepseek", "openai-compatible"] = "auto"
    qwen_api_key: str = Field(default="", repr=False, exclude=True)
    deepseek_api_key: str = Field(default="", repr=False, exclude=True)
    openai_api_key: str = Field(default="", repr=False, exclude=True)
    planner_model: str = "qwen-plus"
    worker_model: str = "qwen-turbo"
    fallback_model: str = "qwen-turbo"
    embedding_model: str = "text-embedding-v3"
    model_reasoning_effort: Literal["high", "max"] = "high"
    model_thinking_enabled: bool = True
    model_structured_output_mode: Literal["auto", "json_schema", "json_object"] = "auto"
    # Match the frozen Direct evaluation envelope.  The task/global output
    # budgets still bound spend; this ceiling prevents structured findings
    # from being truncated solely because they pass through the Agent path.
    model_max_output_tokens: int = Field(default=16_000, ge=256, le=32_768)
    # A fallback is deliberately cheaper and shorter than the strong Primary
    # profile.  It is still a real provider request, not a replay of the same
    # payload under a different label.
    model_fallback_max_output_tokens: int = Field(default=12_000, ge=256, le=32_768)
    model_fallback_thinking_enabled: bool = False
    model_fallback_reasoning_effort: Literal["high", "max"] = "high"
    model_primary_fallback_enabled: bool = True
    model_max_response_bytes: int = Field(default=8 * 1024 * 1024, ge=64 * 1024, le=32 * 1024 * 1024)
    model_max_attempts: int = Field(default=3, ge=1, le=3)
    # Bound provider pressure across independent API processes on the same
    # host.  The evaluation harness starts one SecMind service per task, so an
    # in-process asyncio.Semaphore cannot prevent synchronized request waves.
    # File locks are crash-safe and contain no request or credential data.
    model_provider_host_concurrency: int = Field(default=2, ge=1, le=32)
    model_provider_gate_directory: Path | None = None
    model_provider_recovery_backoff_seconds: float = Field(default=12.0, ge=0, le=120)
    model_structured_repair_attempts: int = Field(default=1, ge=0, le=2)
    model_json_recovery_max_chars: int = Field(default=262_144, ge=1_024, le=1_000_000)
    model_json_recovery_max_depth: int = Field(default=64, ge=1, le=128)
    # v0.8.2 evaluation controls are separate from the product model retry
    # settings above.  They are frozen into the evaluation provenance
    # envelope and cannot be inferred later from a dashboard score.
    evaluation_profile: Literal["v0.8.1-A", "v0.8.1-B", "v0.8.2-default"] = "v0.8.2-default"
    evaluation_workers: int = Field(default=6, ge=1, le=1_000)
    evaluation_primary_timeout_seconds: float = Field(default=180.0, ge=1, le=7_200)
    evaluation_logical_budget_seconds: float = Field(default=180.0, ge=1, le=7_200)
    evaluation_max_attempts: int = Field(default=2, ge=1, le=2)
    evaluation_fallback_model: str = "deepseek-v4-flash"
    evaluation_task_order_seed: int | None = None
    evaluation_provider_seed: int | None = None
    evaluation_randomized_blocks: int = Field(default=5, ge=5, le=1_000)
    qdrant_url: str = "http://qdrant:6333"
    qdrant_collection: str = "secmind_knowledge"
    knowledge_query_vectors_path: Path | None = None
    knowledge_vector_corpus_digest: str = ""
    qdrant_vector_size: int = Field(default=1024, ge=1)
    hybrid_knowledge_timeout_seconds: float = Field(default=0.5, ge=0.05, le=5)
    sandbox_runner_url: str = ""
    sandbox_token: str = ""
    sandbox_control_token: str = ""
    sandbox_ticket_private_key_file: Path | None = None
    operator_token: str = ""
    # A short-lived, process-local capability used only by the sealed Test 3
    # evaluation bridge.  It is deliberately separate from the operator
    # bearer token: ordinary API consumers must never be able to request the
    # value-bearing exact-answer projection.
    evaluation_bridge_token: str = Field(default="", repr=False, exclude=True)
    allowed_websocket_origins: str = "http://127.0.0.1,http://localhost"
    unsafe_development_tools: bool = False
    enable_log_analysis: bool = True
    enable_incident_dry_run: bool = False
    enable_api_static_assessment: bool = True
    enable_api_dynamic_probes: bool = False
    worker_id: str = "secmind-worker-1"
    worker_poll_seconds: float = Field(default=0.25, ge=0.05, le=30)
    worker_lease_seconds: int = Field(default=60, ge=10, le=3600)
    worker_claim_limit: int = Field(default=8, ge=1, le=64)
    worker_max_attempts: int = Field(default=5, ge=1, le=100)
    # ``model_timeout_seconds`` is the logical call deadline.  It must not be
    # reused as the HTTP read timeout: a healthy chunked response may take
    # longer than one read interval while still making progress.
    model_timeout_seconds: float = Field(default=180.0, ge=0.1, le=900)
    # v0.8.4 separates the Primary slot from the task hard deadline.  The
    # former 180 second value was shared by Primary and fallback, so a slow
    # but progressing HTTP 200 response consumed every recovery opportunity.
    # ``model_timeout_seconds`` remains the compatibility default for
    # non-primary calls; task-level Primary calls use the explicit envelope.
    model_primary_soft_timeout_seconds: float = Field(default=300.0, ge=1, le=1_800)
    model_task_hard_timeout_seconds: float = Field(default=540.0, ge=1, le=3_600)
    model_recovery_reserve_seconds: float = Field(default=120.0, ge=1, le=1_800)
    model_stream_max_seconds: float = Field(default=360.0, ge=1, le=1_800)
    primary_advisory_context_bytes: int = Field(default=128_000, ge=8_192, le=1_000_000)
    model_connect_timeout_seconds: float = Field(default=10.0, ge=0.1, le=300)
    model_pool_timeout_seconds: float = Field(default=10.0, ge=0.1, le=300)
    model_write_timeout_seconds: float = Field(default=30.0, ge=0.1, le=300)
    model_read_idle_timeout_seconds: float = Field(default=240.0, ge=0.1, le=300)
    side_question_max_concurrency: int = Field(default=2, ge=1, le=16)
    side_question_input_token_budget: int = Field(default=32_000, ge=1_000, le=2_000_000)
    side_question_output_token_budget: int = Field(default=8_192, ge=128, le=128_000)
    audit_kernel_mode: Literal["baseline", "shadow", "authoritative"] = "shadow"
    # Ablation showed unconditional critic adjudication reduced quality while
    # more than doubling provider work. It is an explicit canary, never a
    # default part of the product path.
    audit_critic_enabled: bool = False
    audit_profile: Literal["core", "extended"] = "extended"
    audit_primary_concurrency: int = Field(default=3, ge=1, le=3)
    audit_critic_concurrency: int = Field(default=2, ge=1, le=3)
    audit_shard_size: int = Field(default=6, ge=1, le=6)
    audit_minimum_dispatch_seconds: float = Field(default=5.0, ge=0.1, le=120)
    prompt_mode: Literal["fixed", "catalog", "adaptive_shadow", "adaptive"] = "fixed"
    prompt_catalog_path: str = ""
    prompt_top_k: int = Field(default=3, ge=1, le=10)
    prompt_optimizer_enabled: bool = False
    prompt_adaptive_policy_approved: bool = False
    # Explicit evaluation-only release valve for the reviewed v0.7 catalog.
    # Production remains approval-only unless an operator opts into this flag.
    prompt_reviewed_authoritative_enabled: bool = False
    prompt_optimizer_max_tier: float = Field(default=5.4, ge=0, le=5.4)
    prompt_optimizer_max_output_tokens: int = Field(default=1024, ge=128, le=4096)
    prompt_optimizer_timeout_seconds: float = Field(default=30, ge=1, le=120)
    prompt_optimizer_max_repairs: int = Field(default=1, ge=0, le=1)
    prompt_optimizer_trigger_rate_limit: float = Field(default=0.20, ge=0, le=1)
    prompt_artifact_cache_enabled: bool = True
    source_triage_mode: Literal["baseline", "rank", "rank_and_signed_skill"] = "rank_and_signed_skill"
    binary_log_parsers_enabled: bool = False
    reverse_dynamic_mode: Literal["off", "speakeasy"] = "off"
    hybrid_knowledge_enabled: bool = False
    hybrid_knowledge_offline_fallback_enabled: bool = True
    semgrep_candidate_rules_enabled: bool = False
    api_host: str = "127.0.0.1"
    api_port: int = Field(default=8000, ge=1, le=65535)
    allowed_hosts: str = ""
    allowed_browser_origins: str = ""

    max_steps: int = Field(default=12, ge=1, le=100)
    max_tool_calls: int = Field(default=12, ge=1, le=100)
    max_model_calls: int = Field(default=32, ge=1, le=200)
    max_provider_requests: int = Field(default=40, ge=1, le=1_000)
    # Match the Direct adapter's bounded 2 MiB input envelope after prompt,
    # manifest and schema overhead.  The gateway's conservative two-byte
    # estimator would otherwise reject the expanded Canonical context before
    # the provider sees it, recreating the information asymmetry v0.8.4 is
    # meant to remove.  Actual provider usage remains settled against this
    # shared run budget and the hard context-byte cap.
    max_input_tokens: int = Field(default=2_000_000, ge=1_000, le=20_000_000)
    # One 16k Primary plus one bounded 12k schema-repair fallback must fit
    # alongside optional critic/optimizer calls.  Fifty thousand was too
    # narrow in real Full60 runs and rejected the fallback before transport.
    max_output_tokens: int = Field(default=250_000, ge=1_000, le=5_000_000)
    # The parent cost envelope must dominate the largest legal 2M-token input
    # at the reviewed 5.4 tier plus one bounded response.  A lower default can
    # reject an otherwise legal request before the provider sees it even while
    # the input/output token budgets still have headroom.
    max_cost_units: float = Field(default=12.0, ge=0.01, le=1_000)
    max_runtime_seconds: int = Field(default=600, ge=10, le=7200)
    max_upload_bytes: int = Field(default=50 * 1024 * 1024, ge=1024)
    max_upload_total_bytes: int = Field(default=500 * 1024 * 1024, ge=1024)
    upload_ttl_seconds: int = Field(default=24 * 60 * 60, ge=60, le=30 * 24 * 60 * 60)
    max_extracted_bytes: int = Field(default=200 * 1024 * 1024, ge=1024)
    max_files: int = Field(default=10_000, ge=1)
    max_zip_ratio: int = Field(default=100, ge=1)

    @field_validator("model_provider_gate_directory", mode="before")
    @classmethod
    def normalize_empty_provider_gate_directory(cls, value: object) -> object:
        """Keep an empty environment value on the safe system-temp default."""

        if isinstance(value, str) and not value.strip():
            return None
        return value

    @model_validator(mode="after")
    def validate_model_deadline_envelope(self) -> Settings:
        """Reject deadline profiles that silently eliminate recovery.

        A strict Primary route always receives a positive slot and a positive
        recovery reserve.  This is intentionally a startup error instead of a
        runtime clamp because the resolved values are part of release identity.
        """

        if self.model_recovery_reserve_seconds >= self.model_task_hard_timeout_seconds:
            raise ValueError("model recovery reserve must be smaller than the task hard timeout")
        primary_cap = self.model_task_hard_timeout_seconds - self.model_recovery_reserve_seconds
        if self.model_primary_soft_timeout_seconds > primary_cap:
            raise ValueError("model primary soft timeout must preserve the configured recovery reserve")
        if self.model_stream_max_seconds > self.model_task_hard_timeout_seconds:
            raise ValueError("model stream maximum must not exceed the task hard timeout")
        return self

    def model_api_key_value(self, provider: str | None = None) -> str:
        """Return the provider credential only at the outbound HTTP boundary."""

        if provider == "deepseek":
            return str(self.deepseek_api_key)
        if provider == "openai-compatible":
            return str(self.openai_api_key)
        return str(self.qwen_api_key)

    def prepare_directories(self) -> None:
        for path in (
            self.input_root,
            self.run_root,
            self.upload_root,
            self.artifact_root,
        ):
            path.mkdir(parents=True, exist_ok=True)
        if self.database_url.startswith("sqlite:///"):
            Path(self.database_url.removeprefix("sqlite:///")).parent.mkdir(parents=True, exist_ok=True)


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    settings.prepare_directories()
    return settings
