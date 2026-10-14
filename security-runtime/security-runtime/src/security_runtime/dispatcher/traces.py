"""Persist public CLI outputs apart from content-free usage receipts."""
from __future__ import annotations

import json
import logging
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

from security_runtime.dispatcher.trace_redaction import redact_trace
from security_runtime.dispatcher.usage import claude_result

LOG = logging.getLogger(__name__)
MAX_OUTPUT_CHARS = 2 * 1024 * 1024


def public_output(stdout: str, kind: str) -> list[dict]:
    if kind == "claudecode":
        envelope = claude_result(stdout)
        if envelope:
            output = envelope.get("structured_output") or envelope.get("result")
            return [{"type": "result", "output": output}] if output is not None else []
        return []
    if kind == "pi":
        results = []
        for line in stdout.splitlines():
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if not isinstance(event, dict):
                continue
            message = event.get("message")
            if event.get("type") == "message_end" and isinstance(message, dict) and message.get("role") == "assistant":
                for block in message.get("content", []):
                    if not isinstance(block, dict):
                        continue
                    if block.get("type") == "text":
                        results.append({"type": "message", "output": block.get("text", "")})
                    elif block.get("type") == "toolCall":
                        results.append({"type": "tool_call", "tool": block.get("name"),
                                        "call_id": block.get("id"), "arguments": block.get("arguments")})
            elif event.get("type") == "tool_execution_end":
                results.append({"type": "tool_result", "tool": event.get("toolName"),
                                "call_id": event.get("toolCallId"), "result": event.get("result"),
                                "status": "failed" if event.get("isError") else "completed"})
        return results
    return [{"type": "result", "output": stdout}] if stdout else []


def write_trace(path: Path | None, receipt: dict, *, kind: str, stdout: str = "") -> None:
    if path is None or not receipt.get("project_id"):
        return
    try:
        output = redact_trace(public_output(stdout, kind))
        encoded = json.dumps(output, ensure_ascii=False)
        truncated = len(encoded) > MAX_OUTPUT_CHARS
        payload = redact_trace({**receipt, "occurred_at": datetime.now(UTC).isoformat(),
                                "output": encoded[:MAX_OUTPUT_CHARS] if truncated else output,
                                "output_truncated": truncated, "output_available": bool(output)})
        path.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(path, timeout=10)) as conn, conn:
            conn.execute("CREATE TABLE IF NOT EXISTS worker_traces (sequence INTEGER PRIMARY KEY AUTOINCREMENT, "
                         "trace_id TEXT NOT NULL UNIQUE, project_id TEXT NOT NULL, payload_json TEXT NOT NULL)")
            conn.execute("CREATE INDEX IF NOT EXISTS worker_traces_project ON worker_traces(project_id)")
            conn.execute("INSERT OR IGNORE INTO worker_traces(trace_id,project_id,payload_json) VALUES (?,?,?)",
                         (receipt["trace_id"], receipt["project_id"], json.dumps(payload, ensure_ascii=False)))
    except (OSError, sqlite3.Error, ValueError, TypeError):
        LOG.exception("Worker public execution record could not be persisted")
