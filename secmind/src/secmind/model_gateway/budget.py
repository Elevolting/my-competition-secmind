"""Provider-independent usage and reservation calculations."""

from __future__ import annotations

import math
from typing import Any

from secmind.schemas import ModelUsage

MAX_PROVIDER_TOKEN_COUNT = 1_000_000_000
PROMPT_TOKEN_SAFETY_MARGIN = 256


def merge_usage(*items: ModelUsage) -> ModelUsage:
    return ModelUsage(
        provider_requests=sum(item.provider_requests for item in items),
        input_tokens=sum(item.input_tokens for item in items),
        output_tokens=sum(item.output_tokens for item in items),
        cache_hit_input_tokens=sum(item.cache_hit_input_tokens for item in items),
        cache_miss_input_tokens=sum(item.cache_miss_input_tokens for item in items),
        cost_units=sum(item.cost_units for item in items),
    )


def bounded_usage_count(value: Any) -> tuple[int, bool]:
    """Parse one provider counter and reject unknown telemetry.

    An explicit numeric zero is a valid provider measurement.  ``None`` and
    the empty string, on the other hand, are missing measurements and must
    force the caller onto its conservative estimate path instead of silently
    releasing a reservation as zero usage.
    """

    if value is None or value == "":
        return 0, True
    if isinstance(value, bool):
        return 0, True
    try:
        if isinstance(value, float):
            if not math.isfinite(value) or not value.is_integer():
                return 0, True
        parsed = int(value)
    except (TypeError, ValueError, OverflowError):
        return 0, True
    if parsed < 0 or parsed > MAX_PROVIDER_TOKEN_COUNT:
        return 0, True
    return parsed, False


def estimate_prompt_tokens(input_bytes: int) -> int:
    """Return the conservative provider-independent prompt reservation."""

    if input_bytes < 0:
        raise ValueError("input_bytes cannot be negative")
    return max(1, math.ceil(input_bytes / 2) + PROMPT_TOKEN_SAFETY_MARGIN)


def cost_units(
    model_id: str,
    input_tokens: int,
    output_tokens: int,
    *,
    model_tiers: tuple[tuple[str, float], ...],
    default_tier: float,
) -> float:
    tier = next((tier for candidate, tier in model_tiers if candidate == model_id), default_tier)
    return round(float(tier) * (input_tokens + output_tokens) / 1_000_000, 9)
