"""Named, digest-bound runtime capability projection.

Environment variables remain deployment inputs for compatibility.  They no
longer serve as the only description of what a run could actually do: every
run records a redacted, resolved profile and its content digest.

The profile deliberately has an explicit settings inventory.  This makes a
new ``Settings`` field a review item instead of allowing it to silently alter
runtime behaviour without changing the release identity.  Credential values
are never copied into the profile; only their names and configured state are
published.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Literal
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field

RUNTIME_PROFILE_VERSION = "runtime-profile-1.2"

# Keep this inventory explicit.  The static contract test compares it with
# ``Settings.model_fields`` so adding a setting without deciding how it is
# represented fails before a release can be built.
SECRET_SETTING_FIELDS = frozenset(
    {
        "qwen_api_key",
        "deepseek_api_key",
        "openai_api_key",
        "sandbox_token",
        "sandbox_control_token",
        "operator_token",
        "evaluation_bridge_token",
    }
)

PROFILE_SETTING_FIELDS = frozenset(
    {
        "env",
        "runtime_role",
        "runtime_profile",
        "demo_mode",
        "database_url",
        "checkpoint_database_url",
        "input_root",
        "run_root",
        "upload_root",
        "artifact_root",
        "alembic_config_path",
        "model_mode",
        "allow_live_models",
        "max_model_tier",
        "trusted_model_base_urls",
        "qwen_base_url",
        "model_base_url_provider",
        "planner_model",
        "worker_model",
        "fallback_model",
        "embedding_model",
        "model_reasoning_effort",
        "model_thinking_enabled",
        "model_structured_output_mode",
        "model_max_output_tokens",
        "model_fallback_max_output_tokens",
        "model_fallback_thinking_enabled",
        "model_fallback_reasoning_effort",
        "model_primary_fallback_enabled",
        "model_max_response_bytes",
        "model_max_attempts",
        "model_provider_host_concurrency",
        "model_provider_gate_directory",
        "model_provider_recovery_backoff_seconds",
        "model_structured_repair_attempts",
        "model_json_recovery_max_chars",
        "model_json_recovery_max_depth",
        "evaluation_profile",
        "evaluation_workers",
        "evaluation_primary_timeout_seconds",
        "evaluation_logical_budget_seconds",
        "evaluation_max_attempts",
        "evaluation_fallback_model",
        "evaluation_task_order_seed",
        "evaluation_provider_seed",
        "evaluation_randomized_blocks",
        "qdrant_url",
        "qdrant_collection",
        "knowledge_query_vectors_path",
        "knowledge_vector_corpus_digest",
        "qdrant_vector_size",
        "hybrid_knowledge_timeout_seconds",
        "sandbox_runner_url",
        "sandbox_ticket_private_key_file",
        "allowed_websocket_origins",
        "unsafe_development_tools",
        "enable_log_analysis",
        "enable_incident_dry_run",
        "enable_api_static_assessment",
        "enable_api_dynamic_probes",
        "worker_id",
        "worker_poll_seconds",
        "worker_lease_seconds",
        "worker_claim_limit",
        "worker_max_attempts",
        "model_timeout_seconds",
        "model_primary_soft_timeout_seconds",
        "model_task_hard_timeout_seconds",
        "model_recovery_reserve_seconds",
        "model_stream_max_seconds",
        "primary_advisory_context_bytes",
        "model_connect_timeout_seconds",
        "model_pool_timeout_seconds",
        "model_write_timeout_seconds",
        "model_read_idle_timeout_seconds",
        "audit_kernel_mode",
        "audit_critic_enabled",
        "audit_profile",
        "audit_primary_concurrency",
        "audit_critic_concurrency",
        "audit_shard_size",
        "audit_minimum_dispatch_seconds",
        "prompt_mode",
        "prompt_catalog_path",
        "prompt_top_k",
        "prompt_optimizer_enabled",
        "prompt_adaptive_policy_approved",
        "prompt_reviewed_authoritative_enabled",
        "prompt_optimizer_max_tier",
        "prompt_optimizer_max_output_tokens",
        "prompt_optimizer_timeout_seconds",
        "prompt_optimizer_max_repairs",
        "prompt_optimizer_trigger_rate_limit",
        "prompt_artifact_cache_enabled",
        "source_triage_mode",
        "binary_log_parsers_enabled",
        "reverse_dynamic_mode",
        "hybrid_knowledge_enabled",
        "hybrid_knowledge_offline_fallback_enabled",
        "semgrep_candidate_rules_enabled",
        "api_host",
        "api_port",
        "allowed_hosts",
        "allowed_browser_origins",
        "max_steps",
        "max_tool_calls",
        "max_model_calls",
        "max_provider_requests",
        "max_input_tokens",
        "max_output_tokens",
        "max_cost_units",
        "max_runtime_seconds",
        "max_upload_bytes",
        "max_upload_total_bytes",
        "upload_ttl_seconds",
        "max_extracted_bytes",
        "max_files",
        "max_zip_ratio",
    }
)

_URL_SETTING_FIELDS = frozenset(
    {
        "database_url",
        "checkpoint_database_url",
        "qdrant_url",
        "qwen_base_url",
        "sandbox_runner_url",
        "trusted_model_base_urls",
    }
)


class CapabilityState(BaseModel):
    """One explicit capability decision in the startup report."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal["enabled", "disabled", "degraded", "unavailable"]
    reason: str | None = None
    setting: str | None = None


class ResolvedRuntimeProfile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: str = RUNTIME_PROFILE_VERSION
    name: Literal["offline-ci", "local-full", "competition-full"]
    capability_profile: Literal["offline-ci", "local-full", "competition-full"]
    # These projections are intentionally kept stable for existing health and
    # release consumers.  ``effective_settings`` is the exhaustive contract.
    model: dict[str, Any]
    domains: dict[str, bool]
    tools: dict[str, Any]
    prompting: dict[str, Any]
    security: dict[str, Any]
    budgets: dict[str, int | float | None]
    effective_settings: dict[str, Any]
    secret_bindings: dict[str, bool]
    capabilities: dict[str, CapabilityState]
    disabled_reasons: dict[str, str] = Field(default_factory=dict)
    unresolved_reasons: dict[str, str] = Field(default_factory=dict)
    resolved_config_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    profile_identity: str = Field(min_length=1, max_length=200)
    digest: str = Field(pattern=r"^[a-f0-9]{64}$")

    def startup_report(self) -> dict[str, Any]:
        """Return the stable, secret-free startup capability report."""

        return {
            "version": self.version,
            "capability_profile": self.capability_profile,
            "profile_identity": self.profile_identity,
            "resolved_config_digest": self.resolved_config_digest,
            "capabilities": {name: state.model_dump(mode="json") for name, state in sorted(self.capabilities.items())},
            "disabled_reasons": dict(sorted(self.disabled_reasons.items())),
            "unresolved_reasons": dict(sorted(self.unresolved_reasons.items())),
        }


def _safe_url(value: str) -> str:
    """Preserve endpoint identity while removing URL credentials and values."""

    if not value:
        return value
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname or ""
        if parsed.port is not None:
            hostname = f"{hostname}:{parsed.port}"
        # Query keys can affect behaviour; query values may contain tokens.
        query_keys = sorted({key for key, _ in parse_qsl(parsed.query, keep_blank_values=True)})
        query = "&".join(f"{key}=<configured>" for key in query_keys)
        return urlunsplit((parsed.scheme, hostname, parsed.path, query, ""))
    except ValueError:
        # A malformed endpoint is still represented deterministically without
        # copying an arbitrary credential-bearing string into the profile.
        return "<configured-invalid-url>"


def _safe_value(name: str, value: Any) -> Any:
    if name in _URL_SETTING_FIELDS and isinstance(value, str):
        # The trusted-model field is a comma-separated endpoint list.
        return ",".join(_safe_url(item.strip()) for item in value.split(","))
    if isinstance(value, Path):
        return value.as_posix()
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, (list, tuple, set)):
        return [_safe_value(name, item) for item in value]
    if isinstance(value, dict):
        return {str(key): _safe_value(name, item) for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))}
    return str(value)


def _settings_projection(settings: Any) -> tuple[dict[str, Any], dict[str, bool], dict[str, str]]:
    """Return exhaustive redacted settings plus deterministic unresolved state."""

    effective: dict[str, Any] = {}
    secret_bindings: dict[str, bool] = {}
    unresolved: dict[str, str] = {}
    for name in sorted(PROFILE_SETTING_FIELDS):
        if not hasattr(settings, name):
            effective[name] = None
            unresolved[f"settings.{name}"] = "setting_field_unavailable"
            continue
        effective[name] = _safe_value(name, getattr(settings, name))
    for name in sorted(SECRET_SETTING_FIELDS):
        if not hasattr(settings, name):
            secret_bindings[name] = False
            unresolved[f"secrets.{name}"] = "secret_setting_field_unavailable"
            continue
        secret_bindings[name] = bool(str(getattr(settings, name) or "").strip())
    return effective, secret_bindings, unresolved


def resolve_runtime_profile(settings: Any) -> ResolvedRuntimeProfile:
    effective_settings, secret_bindings, unresolved = _settings_projection(settings)

    def value(name: str, default: Any = None) -> Any:
        return effective_settings.get(name, default)

    name = str(value("runtime_profile", "local-full"))
    domains = {
        "code_audit": True,
        "log_analysis": bool(value("enable_log_analysis")),
        "api_static_assessment": bool(value("enable_api_static_assessment")),
        "incident_dry_run": bool(value("enable_incident_dry_run")),
        "binary_log_parsers": bool(value("binary_log_parsers_enabled")),
    }
    disabled = {
        key: f"disabled_by_setting:{setting}"
        for key, setting in {
            "log_analysis": "enable_log_analysis",
            "api_static_assessment": "enable_api_static_assessment",
            "incident_dry_run": "enable_incident_dry_run",
            "binary_log_parsers": "binary_log_parsers_enabled",
        }.items()
        if not domains[key]
    }
    if value("model_mode") != "live":
        disabled["model.live"] = "disabled_by_model_mode"
    elif not bool(value("allow_live_models")):
        disabled["model.live"] = "disabled_by_setting:allow_live_models"

    if value("model_base_url_provider") == "auto":
        unresolved["model.provider"] = "provider_resolution_deferred_to_model_policy"
    if bool(value("hybrid_knowledge_enabled")) and not value("knowledge_query_vectors_path"):
        unresolved["tools.hybrid_knowledge"] = "knowledge_vector_source_unconfigured"
    if value("sandbox_runner_url") and not secret_bindings.get("sandbox_token", False):
        unresolved["tools.sandbox_runner"] = "sandbox_control_token_unconfigured"

    capabilities: dict[str, CapabilityState] = {}

    def capability(
        name: str,
        *,
        enabled: bool,
        setting: str | None = None,
        disabled_reason: str | None = None,
        unavailable_reason: str | None = None,
        degraded_reason: str | None = None,
    ) -> None:
        if unavailable_reason is not None:
            state = CapabilityState(status="unavailable", reason=unavailable_reason, setting=setting)
        elif degraded_reason is not None:
            state = CapabilityState(status="degraded", reason=degraded_reason, setting=setting)
        elif enabled:
            state = CapabilityState(status="enabled", setting=setting)
        else:
            state = CapabilityState(
                status="disabled",
                reason=disabled_reason or (f"disabled_by_setting:{setting}" if setting else "disabled_by_profile"),
                setting=setting,
            )
        capabilities[name] = state
        if state.status == "disabled" and state.reason is not None:
            disabled.setdefault(name, state.reason)
        elif state.status in {"degraded", "unavailable"} and state.reason is not None:
            unresolved.setdefault(name, state.reason)

    capability("domain.code_audit", enabled=True)
    capability("domain.log_analysis", enabled=domains["log_analysis"], setting="enable_log_analysis")
    capability(
        "domain.api_static_assessment",
        enabled=domains["api_static_assessment"],
        setting="enable_api_static_assessment",
    )
    capability("domain.incident_dry_run", enabled=domains["incident_dry_run"], setting="enable_incident_dry_run")
    capability(
        "domain.api_dynamic_probes",
        enabled=False,
        setting="enable_api_dynamic_probes",
        unavailable_reason=("dynamic_api_probes_not_implemented" if bool(value("enable_api_dynamic_probes")) else None),
        disabled_reason="disabled_by_setting:enable_api_dynamic_probes",
    )

    live_requested = value("model_mode") == "live"
    live_allowed = live_requested and bool(value("allow_live_models"))
    provider = str(value("model_base_url_provider", "auto"))
    provider_secret = {
        "dashscope": secret_bindings.get("qwen_api_key", False),
        "deepseek": secret_bindings.get("deepseek_api_key", False),
        "openai-compatible": secret_bindings.get("openai_api_key", False),
    }.get(provider, False)
    live_unavailable = None
    if live_allowed and provider == "auto":
        live_unavailable = "provider_resolution_deferred_to_model_policy"
    elif live_allowed and not provider_secret:
        live_unavailable = "provider_credential_unconfigured"
    capability(
        "model.live",
        enabled=live_allowed,
        setting="allow_live_models",
        disabled_reason=("disabled_by_model_mode" if not live_requested else "disabled_by_setting:allow_live_models"),
        unavailable_reason=live_unavailable,
    )
    capability("model.offline_or_mock", enabled=not live_requested, setting="model_mode")

    prompt_mode = str(value("prompt_mode", "fixed"))
    optimizer_enabled = bool(value("prompt_optimizer_enabled"))
    capability(
        "prompt.catalog",
        enabled=prompt_mode != "fixed",
        setting="prompt_mode",
        disabled_reason="disabled_by_prompt_mode:fixed",
    )
    capability(
        "prompt.optimizer",
        enabled=optimizer_enabled and prompt_mode in {"adaptive", "adaptive_shadow"},
        setting="prompt_optimizer_enabled",
        disabled_reason=(
            "disabled_by_setting:prompt_optimizer_enabled"
            if not optimizer_enabled
            else f"disabled_by_prompt_mode:{prompt_mode}"
        ),
    )
    # No positive paired-gain release receipt is wired into v0.8.6.  A plain
    # boolean approval must never silently make optimizer output authoritative.
    capability(
        "prompt.optimizer_authoritative",
        enabled=False,
        setting="prompt_adaptive_policy_approved",
        disabled_reason="positive_paired_gain_receipt_unavailable",
    )
    capability(
        "prompt.reviewed_catalog_authoritative",
        enabled=bool(value("prompt_reviewed_authoritative_enabled")) and prompt_mode != "fixed",
        setting="prompt_reviewed_authoritative_enabled",
    )

    capability("audit.critic", enabled=bool(value("audit_critic_enabled")), setting="audit_critic_enabled")
    capability(
        "tools.binary_log_parsers",
        enabled=bool(value("binary_log_parsers_enabled")),
        setting="binary_log_parsers_enabled",
    )
    hybrid_enabled = bool(value("hybrid_knowledge_enabled"))
    hybrid_vectors = bool(value("knowledge_query_vectors_path"))
    hybrid_fallback = bool(value("hybrid_knowledge_offline_fallback_enabled"))
    capability(
        "tools.hybrid_knowledge",
        enabled=hybrid_enabled and hybrid_vectors,
        setting="hybrid_knowledge_enabled",
        degraded_reason=(
            "offline_keyword_fallback_only" if hybrid_enabled and not hybrid_vectors and hybrid_fallback else None
        ),
        unavailable_reason=(
            "knowledge_vector_source_unconfigured"
            if hybrid_enabled and not hybrid_vectors and not hybrid_fallback
            else None
        ),
    )
    runner_configured = bool(value("sandbox_runner_url"))
    capability(
        "tools.sandbox_runner",
        enabled=runner_configured and secret_bindings.get("sandbox_token", False),
        setting="sandbox_runner_url",
        unavailable_reason=(
            "sandbox_control_token_unconfigured"
            if runner_configured and not secret_bindings.get("sandbox_token", False)
            else None
        ),
    )
    capability(
        "tools.local_subprocess",
        enabled=bool(value("unsafe_development_tools")),
        setting="unsafe_development_tools",
    )
    capability(
        "tools.semgrep_candidate_rules",
        enabled=bool(value("semgrep_candidate_rules_enabled")),
        setting="semgrep_candidate_rules_enabled",
    )

    timeout = {
        "logical_seconds": value("model_timeout_seconds"),
        "primary_soft_seconds": value("model_primary_soft_timeout_seconds"),
        "stream_max_seconds": value("model_stream_max_seconds"),
        "task_hard_seconds": value("model_task_hard_timeout_seconds"),
        "recovery_reserve_seconds": value("model_recovery_reserve_seconds"),
        "connect_seconds": value("model_connect_timeout_seconds"),
        "pool_seconds": value("model_pool_timeout_seconds"),
        "write_seconds": value("model_write_timeout_seconds"),
        "read_idle_seconds": value("model_read_idle_timeout_seconds"),
    }
    values: dict[str, Any] = {
        "version": RUNTIME_PROFILE_VERSION,
        "name": name,
        "capability_profile": name,
        "model": {
            "mode": value("model_mode"),
            "provider": value("model_base_url_provider"),
            "planner": value("planner_model"),
            "worker": value("worker_model"),
            "fallback": value("fallback_model"),
            "embedding": value("embedding_model"),
            "max_tier": value("max_model_tier"),
            "thinking": value("model_thinking_enabled"),
            "reasoning_effort": value("model_reasoning_effort"),
            "structured_output_mode": value("model_structured_output_mode"),
            "primary_max_output_tokens": value("model_max_output_tokens"),
            "fallback_max_output_tokens": value("model_fallback_max_output_tokens"),
            "fallback_thinking": value("model_fallback_thinking_enabled"),
            "fallback_reasoning_effort": value("model_fallback_reasoning_effort"),
            "primary_fallback_enabled": value("model_primary_fallback_enabled"),
            "max_response_bytes": value("model_max_response_bytes"),
            "max_attempts": value("model_max_attempts"),
            "provider_host_concurrency": value("model_provider_host_concurrency"),
            "provider_gate_directory": value("model_provider_gate_directory"),
            "provider_recovery_backoff_seconds": value("model_provider_recovery_backoff_seconds"),
            "structured_repair_attempts": value("model_structured_repair_attempts"),
            "json_recovery": {
                "max_chars": value("model_json_recovery_max_chars"),
                "max_depth": value("model_json_recovery_max_depth"),
            },
            "endpoint": {
                "provider": value("model_base_url_provider"),
                "trusted_base_urls": value("trusted_model_base_urls"),
                "qwen_base_url": value("qwen_base_url"),
            },
            "timeouts": timeout,
            # ``deadline`` is retained as a compatibility alias.
            "deadline": timeout,
        },
        "domains": domains,
        "tools": {
            "unsafe_development_tools": bool(value("unsafe_development_tools")),
            "sandbox_runner_configured": bool(value("sandbox_runner_url")),
            "semgrep_candidate_rules": bool(value("semgrep_candidate_rules_enabled")),
            "hybrid_knowledge": bool(value("hybrid_knowledge_enabled")),
            "hybrid_knowledge_offline_fallback": bool(value("hybrid_knowledge_offline_fallback_enabled")),
            "hybrid_knowledge_timeout_seconds": value("hybrid_knowledge_timeout_seconds"),
            "source_triage_mode": value("source_triage_mode"),
            "api_dynamic_probes": bool(value("enable_api_dynamic_probes")),
            "binary_log_parsers": bool(value("binary_log_parsers_enabled")),
        },
        "prompting": {
            "mode": value("prompt_mode"),
            "catalog_path": value("prompt_catalog_path"),
            "top_k": value("prompt_top_k"),
            "optimizer_enabled": bool(value("prompt_optimizer_enabled")),
            "adaptive_policy_approved": bool(value("prompt_adaptive_policy_approved")),
            "reviewed_authoritative": bool(value("prompt_reviewed_authoritative_enabled")),
            "optimizer_max_tier": value("prompt_optimizer_max_tier"),
            "optimizer_max_output_tokens": value("prompt_optimizer_max_output_tokens"),
            "optimizer_timeout_seconds": value("prompt_optimizer_timeout_seconds"),
            "optimizer_max_repairs": value("prompt_optimizer_max_repairs"),
            "optimizer_trigger_rate_limit": value("prompt_optimizer_trigger_rate_limit"),
            "artifact_cache_enabled": bool(value("prompt_artifact_cache_enabled")),
        },
        "security": {
            "operator_auth_configured": secret_bindings.get("operator_token", False),
            "runner_ticket_key_configured": bool(value("sandbox_ticket_private_key_file")),
            "live_models_allowed": bool(value("allow_live_models")),
            "secret_bindings": dict(secret_bindings),
            "allowed_websocket_origins": value("allowed_websocket_origins"),
        },
        "budgets": {
            "max_steps": value("max_steps"),
            "max_tool_calls": value("max_tool_calls"),
            "max_model_calls": value("max_model_calls"),
            "max_provider_requests": value("max_provider_requests"),
            "max_input_tokens": value("max_input_tokens"),
            "max_output_tokens": value("max_output_tokens"),
            "max_cost_units": value("max_cost_units"),
            "max_runtime_seconds": value("max_runtime_seconds"),
            "max_upload_bytes": value("max_upload_bytes"),
            "max_upload_total_bytes": value("max_upload_total_bytes"),
            "upload_ttl_seconds": value("upload_ttl_seconds"),
            "max_extracted_bytes": value("max_extracted_bytes"),
            "max_files": value("max_files"),
            "max_zip_ratio": value("max_zip_ratio"),
        },
        "effective_settings": effective_settings,
        "secret_bindings": secret_bindings,
        "capabilities": {key: item.model_dump(mode="json") for key, item in sorted(capabilities.items())},
        "disabled_reasons": disabled,
        "unresolved_reasons": unresolved,
    }
    resolved_config_digest = hashlib.sha256(
        json.dumps(values, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    values["resolved_config_digest"] = resolved_config_digest
    values["digest"] = resolved_config_digest
    values["profile_identity"] = f"{RUNTIME_PROFILE_VERSION}:{name}:{resolved_config_digest}"
    return ResolvedRuntimeProfile.model_validate(values)


__all__ = [
    "PROFILE_SETTING_FIELDS",
    "RUNTIME_PROFILE_VERSION",
    "SECRET_SETTING_FIELDS",
    "CapabilityState",
    "ResolvedRuntimeProfile",
    "resolve_runtime_profile",
]
