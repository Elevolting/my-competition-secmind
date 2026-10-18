"""Durable, content-free CLI usage receipts on the dispatcher host."""
from __future__ import annotations

import json
import logging
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

LOG = logging.getLogger(__name__)


def claude_result(stdout: str) -> dict | None:
    try:
        value = json.loads(stdout)
    except (ValueError, TypeError):
        return None
    # Only the CLI result envelope is authoritative; never parse model text as usage.
    if isinstance(value, dict) and value.get("type") == "result":
        return value
    return None


def claude_usage(stdout: str) -> dict:
    result = claude_result(stdout)
    raw = result.get("usage") if result else None
    if not isinstance(raw, dict):
        return {}
    def count(key):
        value = raw.get(key, 0)
        return value if type(value) is int and value >= 0 else None
    keys = ("input_tokens", "output_tokens", "cache_read_input_tokens", "cache_creation_input_tokens")
    if not all(key in raw for key in keys[:2]) or any(count(key) is None for key in keys):
        return {}
    # Anthropic input_tokens excludes cache reads AND cache creation.
    prompt = count("input_tokens") + count("cache_read_input_tokens") + count("cache_creation_input_tokens")
    output = count("output_tokens")
    return {"prompt_tokens": prompt, "completion_tokens": output, "total_tokens": prompt + output,
            "cache_read_tokens": count("cache_read_input_tokens")}


def pi_usage(stdout: str) -> dict:
    """Sum Pi's final assistant messages, once per model response."""
    prompt = completion = cache_read = 0
    found = False
    for line in stdout.splitlines():
        try:
            event = json.loads(line)
        except (TypeError, ValueError):
            continue
        if not isinstance(event, dict) or event.get("type") != "message_end":
            continue
        message = event.get("message")
        if not isinstance(message, dict) or message.get("role") != "assistant":
            continue
        raw = message.get("usage")
        if not isinstance(raw, dict):
            continue
        keys = ("input", "output", "cacheRead", "cacheWrite")
        if any(type(raw.get(key)) is not int or raw[key] < 0 for key in keys):
            continue
        prompt += raw["input"] + raw["cacheRead"] + raw["cacheWrite"]
        completion += raw["output"]
        cache_read += raw["cacheRead"]
        found = True
    if not found:
        return {}
    return {"prompt_tokens": prompt, "completion_tokens": completion,
            "total_tokens": prompt + completion, "cache_read_tokens": cache_read}


def write_receipt(path: Path | None, payload: dict) -> None:
    if path is None:
        return
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(path, timeout=10)) as conn, conn:
            conn.execute("CREATE TABLE IF NOT EXISTS usage_events (sequence INTEGER PRIMARY KEY AUTOINCREMENT, "
                         "receipt_id TEXT NOT NULL UNIQUE, payload_json TEXT NOT NULL)")
            body = {**payload, "occurred_at": datetime.now(UTC).isoformat()}
            receipt_id = payload["trace_id"] + ":" + payload["status"]
            conn.execute("INSERT OR IGNORE INTO usage_events(receipt_id, payload_json) VALUES (?, ?)",
                         (receipt_id, json.dumps(body)))
    except (OSError, sqlite3.Error):
        # A telemetry outage must not repeat an already paid model request.
        LOG.exception("Worker usage receipt could not be persisted")
