"""Normalize provider receipts without inventing zero usage for missing data."""
from typing import Any


def normalize_usage(value: Any) -> dict[str, int]:
    if not isinstance(value, dict):
        return {}

    def number(raw):
        if isinstance(raw, bool):
            return None
        try:
            result = int(raw)
            return result if result >= 0 else None
        except (TypeError, ValueError, OverflowError):
            return None

    fields = {key: number(value.get(key)) for key in (
        'prompt_tokens', 'completion_tokens', 'total_tokens', 'prompt_cache_hit_tokens',
        'prompt_cache_miss_tokens', 'cache_read_tokens')}
    details = value.get('prompt_tokens_details')
    cached = number(details.get('cached_tokens')) if isinstance(details, dict) else None
    if all(v is None for v in fields.values()) and cached is None:
        return {}
    cache = next((v for v in (fields['prompt_cache_hit_tokens'], fields['cache_read_tokens'], cached) if v is not None), 0)
    prompt = max(fields['prompt_tokens'] or 0, cache + (fields['prompt_cache_miss_tokens'] or 0))
    completion = fields['completion_tokens'] or 0
    return {'prompt_tokens': prompt, 'completion_tokens': completion,
            'total_tokens': max(fields['total_tokens'] or 0, prompt + completion), 'cache_read_tokens': cache}
