from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from math import isfinite
from typing import Any
from urllib.parse import urlsplit, urlunsplit

HARD_MAX_MODEL_TIER = 5.4

_OFFICIAL_PROVIDER_HOSTS: dict[str, frozenset[str]] = {
    "dashscope": frozenset({"dashscope.aliyuncs.com"}),
    "deepseek": frozenset({"api.deepseek.com"}),
    "openai-compatible": frozenset({"api.openai.com"}),
}


class ModelMode(StrEnum):
    OFFLINE = "offline"
    MOCK = "mock"
    LIVE = "live"


class ModelPolicyError(ValueError):
    """Raised before a provider client can be used with an unsafe configuration."""


@dataclass(frozen=True, slots=True)
class ModelCatalogEntry:
    model_id: str
    provider: str
    tier: float
    capabilities: frozenset[str]


# This allow-list is intentionally closed. Adding a model is a reviewed code/config
# change instead of silently accepting a provider-side alias that may change cost.
MODEL_CATALOG: dict[str, ModelCatalogEntry] = {
    "qwen-turbo": ModelCatalogEntry("qwen-turbo", "dashscope", 2.0, frozenset({"chat"})),
    "qwen-plus": ModelCatalogEntry("qwen-plus", "dashscope", 4.0, frozenset({"chat"})),
    "qwen-max": ModelCatalogEntry("qwen-max", "dashscope", 5.4, frozenset({"chat"})),
    "qwen3-coder-plus": ModelCatalogEntry("qwen3-coder-plus", "dashscope", 4.0, frozenset({"chat"})),
    "qwen3-plus": ModelCatalogEntry("qwen3-plus", "dashscope", 4.0, frozenset({"chat"})),
    "qwen3-max": ModelCatalogEntry("qwen3-max", "dashscope", 5.4, frozenset({"chat"})),
    "text-embedding-v3": ModelCatalogEntry("text-embedding-v3", "dashscope", 2.0, frozenset({"embedding"})),
    "gpt-5.4": ModelCatalogEntry("gpt-5.4", "openai-compatible", 5.4, frozenset({"chat"})),
    "gpt-5.4-mini": ModelCatalogEntry("gpt-5.4-mini", "openai-compatible", 4.0, frozenset({"chat"})),
    "gpt-5.4-nano": ModelCatalogEntry("gpt-5.4-nano", "openai-compatible", 2.0, frozenset({"chat"})),
    # GPT-5.6 Luna is the cost-sensitive GPT-5.6 tier and is documented as
    # roughly corresponding to the earlier nano tier. Keep the internal cost
    # tier aligned with gpt-5.4-nano instead of treating the model's version
    # number as its cost/capability ceiling.
    "gpt-5.6-luna": ModelCatalogEntry("gpt-5.6-luna", "openai-compatible", 2.0, frozenset({"chat"})),
    # Terra is the balanced 5.6 deployment tier. The numeric tier is the
    # reviewed cost class, not the model-family version, so it remains below
    # the hard 5.4 cost ceiling while still requiring an explicit catalog
    # entry and trusted OpenAI-compatible base URL.
    "gpt-5.6-terra": ModelCatalogEntry("gpt-5.6-terra", "openai-compatible", 4.0, frozenset({"chat"})),
    "deepseek-v4-flash": ModelCatalogEntry("deepseek-v4-flash", "deepseek", 4.0, frozenset({"chat"})),
}


def _canonical_base_url(value: str) -> str:
    parsed = urlsplit(value.strip())
    if not parsed.scheme or not parsed.netloc or parsed.query or parsed.fragment:
        raise ModelPolicyError("Model base URL must be an absolute URL without query or fragment")
    path = parsed.path.rstrip("/")
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), path, "", ""))


def _trusted_urls(raw: str) -> frozenset[str]:
    return frozenset(_canonical_base_url(item) for item in raw.split(",") if item.strip())


def _resolve_model(model_id: str, capability: str, max_tier: float) -> ModelCatalogEntry:
    entry = MODEL_CATALOG.get(model_id)
    if entry is None:
        version = re.match(r"^gpt-(\d+(?:\.\d+)?)", model_id)
        if version and float(version.group(1)) > HARD_MAX_MODEL_TIER:
            raise ModelPolicyError(f"Model {model_id!r} exceeds the hard maximum tier {HARD_MAX_MODEL_TIER}")
        raise ModelPolicyError(f"Unknown model {model_id!r}; add it to the reviewed model catalog first")
    if capability not in entry.capabilities:
        raise ModelPolicyError(f"Model {model_id!r} does not support {capability}")
    ceiling = min(max_tier, HARD_MAX_MODEL_TIER)
    if entry.tier > ceiling:
        raise ModelPolicyError(f"Model {model_id!r} tier {entry.tier} exceeds configured maximum {ceiling}")
    return entry


@dataclass(frozen=True, slots=True)
class ModelPolicy:
    mode: ModelMode
    planner: ModelCatalogEntry
    worker: ModelCatalogEntry
    fallback: ModelCatalogEntry
    embedding: ModelCatalogEntry
    base_url: str
    chat_provider: str

    @classmethod
    def from_settings(cls, settings: Any, *, injected_client: bool) -> ModelPolicy:
        try:
            mode = ModelMode(settings.model_mode)
        except ValueError as exc:
            raise ModelPolicyError("model_mode must be one of: offline, mock, live") from exc

        max_tier = float(settings.max_model_tier)
        if not isfinite(max_tier) or max_tier < 0:
            raise ModelPolicyError("max_model_tier must be a finite non-negative number")
        if max_tier > HARD_MAX_MODEL_TIER:
            raise ModelPolicyError(f"max_model_tier cannot exceed {HARD_MAX_MODEL_TIER}")
        planner = _resolve_model(settings.planner_model, "chat", max_tier)
        worker = _resolve_model(settings.worker_model, "chat", max_tier)
        fallback = _resolve_model(settings.fallback_model, "chat", max_tier)
        embedding = _resolve_model(settings.embedding_model, "embedding", max_tier)
        if fallback.tier > min(planner.tier, worker.tier):
            raise ModelPolicyError("fallback_model cannot be more expensive than planner_model or worker_model")

        base_url = _canonical_base_url(settings.qwen_base_url)
        if mode is ModelMode.MOCK and not injected_client:
            raise ModelPolicyError("mock mode requires an injected HTTP client")
        if mode is ModelMode.LIVE:
            if settings.demo_mode:
                raise ModelPolicyError("live mode is incompatible with deterministic demo mode")
            if not settings.allow_live_models:
                raise ModelPolicyError("live model calls require allow_live_models=true")
            if urlsplit(base_url).scheme != "https":
                raise ModelPolicyError("live model base URL must use HTTPS")
            if base_url not in _trusted_urls(settings.trusted_model_base_urls):
                raise ModelPolicyError("model base URL is not in trusted_model_base_urls")

            chat_providers = {planner.provider, worker.provider, fallback.provider}
            if len(chat_providers) != 1:
                raise ModelPolicyError("live planner, worker, and fallback models must use one provider")
            chat_provider = next(iter(chat_providers))
            configured_provider = str(settings.model_base_url_provider)
            host = (urlsplit(base_url).hostname or "").lower()
            inferred_provider = next(
                (provider for provider, hosts in _OFFICIAL_PROVIDER_HOSTS.items() if host in hosts),
                None,
            )
            if configured_provider == "auto":
                if inferred_provider is None:
                    raise ModelPolicyError("custom live model gateways require an explicit model_base_url_provider")
                base_url_provider = inferred_provider
            else:
                base_url_provider = configured_provider
                if inferred_provider is not None and inferred_provider != base_url_provider:
                    raise ModelPolicyError("model_base_url_provider conflicts with the official provider host")
            if chat_provider != base_url_provider:
                raise ModelPolicyError("configured chat models do not match the trusted model base URL provider")
            if not settings.model_api_key_value(chat_provider).strip():
                key_name = {
                    "dashscope": "SECMIND_QWEN_API_KEY",
                    "deepseek": "SECMIND_DEEPSEEK_API_KEY",
                    "openai-compatible": "SECMIND_OPENAI_API_KEY",
                }.get(chat_provider, "a provider API key")
                raise ModelPolicyError(f"live model calls require {key_name}")
        else:
            chat_providers = {planner.provider, worker.provider, fallback.provider}
            chat_provider = next(iter(chat_providers)) if len(chat_providers) == 1 else "mixed"

        return cls(mode, planner, worker, fallback, embedding, base_url, chat_provider)

    @property
    def network_enabled(self) -> bool:
        return self.mode in {ModelMode.MOCK, ModelMode.LIVE}
