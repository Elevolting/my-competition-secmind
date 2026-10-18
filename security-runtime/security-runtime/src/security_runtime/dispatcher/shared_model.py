"""Read the suite's saved provider configuration without retaining a second secret."""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse


def _shared_worker_settings(path: Path, model_field: str = "worker_model") -> tuple[str, str, str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError("Cannot read shared model configuration; save model settings in the platform") from exc
    fields = ("base_url", model_field, "api_key")
    if not isinstance(data, dict) or any(
        not isinstance(data.get(key), str) or not data[key].strip() for key in fields
    ):
        raise ValueError(f"Shared model configuration requires base_url, {model_field} and api_key")
    base = data["base_url"].strip().rstrip("/")
    parsed = urlparse(base)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Shared model configuration has an invalid base_url")
    return base, data[model_field].strip(), data["api_key"].strip()


def shared_pi_env(path: Path, role: str = "worker") -> dict[str, str]:
    if role not in {"planner", "worker"}:
        raise ValueError("Pi shared model role must be planner or worker")
    base, model, key = _shared_worker_settings(path, f"{role}_model")
    return {"PI_BASE_URL": base, "PI_MODEL": model, "PI_API_KEY": key,
            "PI_PROVIDER_API": "openai-completions"}


def shared_anthropic_env(path: Path) -> dict[str, str]:
    base, model, key = _shared_worker_settings(path)
    parsed = urlparse(base)
    # The platform stores an OpenAI base ending in /v1; Claude Code appends
    # /v1/messages itself. Preserve any earlier gateway path prefix.
    anthropic_base = base[:-3] if parsed.path.endswith("/v1") else base
    return {"ANTHROPIC_BASE_URL": anthropic_base, "ANTHROPIC_MODEL": model, "ANTHROPIC_AUTH_TOKEN": key}
