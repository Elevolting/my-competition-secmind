"""Recover provider-confirmed usage from retained Claude Code session records.

Only assistant usage metadata is read. Session content is discarded and never
written to the Worker journal. A dispatcher project directory and matching
terminal project record are required before a response is eligible.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sqlite3
from collections import defaultdict
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path

WORKER = "claudecode_shared_model"
CALL_UNIT = "claude_session_response_backfill"
PROJECT_TOLERANCE_SECONDS = 60
_PROJECT_PATH = re.compile(r"(?:^|[/\\])dispatcher-workspaces[/\\](proj_[0-9]+)(?:[/\\]|$)", re.IGNORECASE)


def _time(value):
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return timestamp.astimezone(UTC) if timestamp.tzinfo else None
    except (AttributeError, ValueError):
        return None


def _project_id(entry):
    if not isinstance(entry, dict) or not isinstance(entry.get("cwd"), str):
        return None
    match = _PROJECT_PATH.search(entry["cwd"])
    return match.group(1).lower() if match else None


def _provider_usage(value):
    if not isinstance(value, dict) or "input_tokens" not in value or "output_tokens" not in value:
        return None
    input_tokens = value.get("input_tokens")
    output_tokens = value.get("output_tokens")
    cache_read = value.get("cache_read_input_tokens", 0)
    cache_create = value.get("cache_creation_input_tokens", 0)
    values = (input_tokens, output_tokens, cache_read, cache_create)
    if any(type(item) is not int or item < 0 for item in values):
        return None
    prompt = input_tokens + cache_read + cache_create
    total = prompt + output_tokens
    if total <= 0:
        return None
    return {
        "prompt_tokens": prompt,
        "completion_tokens": output_tokens,
        "total_tokens": total,
        "cache_read_tokens": cache_read,
    }


def _project_windows(runtime_database: Path):
    projects = {}
    with closing(sqlite3.connect(runtime_database.resolve().as_uri() + "?mode=ro", uri=True, timeout=2)) as conn:
        conn.row_factory = sqlite3.Row
        for project in conn.execute("SELECT id, status, created_at FROM projects"):
            if project["status"] not in {"completed", "stopped", "failed"}:
                continue
            begun = _time(project["created_at"])
            if begun is None:
                continue
            last_activity = begun
            for intent in conn.execute(
                "SELECT created_at, concluded_at, last_heartbeat_at FROM intents WHERE project_id = ?",
                (project["id"],),
            ):
                for field in ("created_at", "concluded_at", "last_heartbeat_at"):
                    observed = _time(intent[field])
                    if observed is not None:
                        last_activity = max(last_activity, observed)
            projects[str(project["id"]).lower()] = (
                begun - timedelta(seconds=PROJECT_TOLERANCE_SECONDS),
                last_activity + timedelta(seconds=PROJECT_TOLERANCE_SECONDS),
            )
    return projects


def _known_cli_intervals(journal: Path):
    # Each project maps trace IDs to their started and terminal receipts.
    intervals = defaultdict(dict)
    with closing(sqlite3.connect(journal.resolve().as_uri() + "?mode=ro", uri=True, timeout=2)) as conn:
        for (body,) in conn.execute("SELECT payload_json FROM usage_events"):
            try:
                receipt = json.loads(body)
            except (TypeError, ValueError):
                continue
            if not isinstance(receipt, dict):
                continue
            if receipt.get("worker") != WORKER or receipt.get("call_unit") != "cli_execution":
                continue
            project = receipt.get("project_id")
            if project is not None and not isinstance(project, str):
                continue
            key = receipt.get("trace_id")
            if not isinstance(key, str):
                continue
            state = receipt.get("status")
            interval = intervals[project].setdefault(key, {})
            if state in {"started", "completed", "failed"}:
                interval[state] = receipt
        result = defaultdict(list)
        for project, traces in intervals.items():
            for states in traces.values():
                begun = _time((states.get("started") or {}).get("occurred_at"))
                terminal = states.get("completed") or states.get("failed")
                ended = _time((terminal or {}).get("occurred_at"))
                if begun is None or ended is None or ended < begun:
                    continue
                usage = terminal.get("usage") if terminal else None
                has_usage = isinstance(usage, dict) and any(
                    type(usage.get(field)) is int and usage[field] > 0
                    for field in ("prompt_tokens", "completion_tokens", "total_tokens")
                )
                result[project].append((begun, ended, has_usage))
    return result


def backfill_claude_usage(
    journal: Path,
    sessions_root: Path,
    runtime_database: Path,
    *,
    dry_run: bool = False,
) -> dict[str, int]:
    """Import eligible Claude assistant responses with stable, content-free IDs."""
    projects = _project_windows(runtime_database)
    intervals = _known_cli_intervals(journal)
    responses = {}
    conflicts = set()
    scanned = 0

    for path in sorted(sessions_root.rglob("*.jsonl")):
        session_project = None
        try:
            stream = path.open(encoding="utf-8", errors="replace")
        except OSError:
            continue
        with stream:
            for line in stream:
                try:
                    entry = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(entry, dict):
                    continue
                entry_project = _project_id(entry)
                session_project = session_project or entry_project
                if entry_project is not None and entry_project != session_project:
                    continue
                if entry.get("type") != "assistant" or session_project not in projects:
                    continue
                message = entry.get("message")
                if not isinstance(message, dict) or message.get("role") != "assistant":
                    continue
                usage = _provider_usage(message.get("usage"))
                timestamp = _time(entry.get("timestamp"))
                message_id = message.get("id")
                if usage is None or timestamp is None or not isinstance(message_id, str) or not message_id:
                    continue
                scanned += 1
                begun, ended = projects[session_project]
                if not begun <= timestamp <= ended:
                    continue
                covered = [start <= timestamp <= finish for start, finish, _known in intervals[session_project]]
                matching = [item for item, is_covered in zip(intervals[session_project], covered) if is_covered]
                # A provider receipt already covers this response. Otherwise,
                # the terminal project and its bounded session window provide
                # the ownership proof needed to recover the provider number,
                # including projects whose CLI receipt was never retained.
                if any(is_known for _start, _finish, is_known in matching):
                    continue
                identity = hashlib.sha256(f"{session_project}:{message_id}".encode()).hexdigest()
                model = message.get("model")
                if not isinstance(model, str) or len(model) > 200:
                    model = "unknown"
                item = (session_project, timestamp.isoformat(), model, usage)
                prior = responses.get(identity)
                if prior is not None and (prior[0], prior[2], prior[3]) != (item[0], item[2], item[3]):
                    conflicts.add(identity)
                elif prior is None or item[1] < prior[1]:
                    # Claude Code writes one assistant row per content block.
                    # Rows for the same provider message repeat identical usage
                    # with slightly different timestamps. Count the message once.
                    responses[identity] = item

    for identity in conflicts:
        responses.pop(identity, None)

    inserted = inserted_tokens = 0
    if not dry_run and responses:
        with closing(sqlite3.connect(journal, timeout=10)) as conn, conn:
            for identity, (project, occurred_at, model, usage) in responses.items():
                payload = {
                    "trace_id": "claude-session:" + identity,
                    "source": "security_runtime_worker",
                    "project_id": project,
                    "worker": WORKER,
                    "model": model,
                    "status": "completed",
                    "call_unit": CALL_UNIT,
                    "usage": usage,
                    "occurred_at": occurred_at,
                }
                cursor = conn.execute(
                    "INSERT OR IGNORE INTO usage_events(receipt_id, payload_json) VALUES (?, ?)",
                    (CALL_UNIT + ":" + identity, json.dumps(payload)),
                )
                if cursor.rowcount:
                    inserted += 1
                    inserted_tokens += usage["total_tokens"]

    return {
        "scanned_responses": scanned,
        "eligible_responses": len(responses),
        "conflicting_responses": len(conflicts),
        "eligible_tokens": sum(item[3]["total_tokens"] for item in responses.values()),
        "inserted_responses": inserted,
        "inserted_tokens": inserted_tokens,
    }


def main():
    repository = Path(__file__).resolve().parents[3]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--journal", type=Path, default=repository / "an/data/worker-usage.db")
    parser.add_argument("--sessions-root", type=Path, default=Path.home() / ".claude/projects")
    parser.add_argument("--runtime-database", type=Path,
                        default=repository / "security-runtime/datas/security-runtime/security_runtime.db")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    print(json.dumps(backfill_claude_usage(args.journal, args.sessions_root,
                                           args.runtime_database, dry_run=args.dry_run)))


if __name__ == "__main__":
    main()
