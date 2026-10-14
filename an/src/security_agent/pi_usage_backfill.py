"""Recover numeric usage from old Pi sessions whose CLI receipts omitted usage.

Run with ``python -m security_agent.pi_usage_backfill`` on the local dispatcher
host. Session text is read transiently; only numeric usage and safe metadata
are written to the worker usage journal. Re-running is idempotent.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
from collections import defaultdict
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

WORKERS = ('pi_default', 'pi_planner')
SESSION_RECEIPT_TOLERANCE_SECONDS = 60


def _time(value):
    try:
        timestamp = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return timestamp.astimezone(UTC) if timestamp.tzinfo else None
    except (AttributeError, ValueError):
        return None


def _usage(value):
    if not isinstance(value, dict):
        return None
    keys = ('input', 'output', 'cacheRead', 'cacheWrite')
    if any(type(value.get(key)) is not int or value[key] < 0 for key in keys):
        return None
    prompt = value['input'] + value['cacheRead'] + value['cacheWrite']
    output = value['output']
    return {'prompt_tokens': prompt, 'completion_tokens': output,
            'total_tokens': prompt + output, 'cache_read_tokens': value['cacheRead']}


def _session_project(entry):
    """Read the Pi session's dispatcher workspace, never the prompt text."""
    if not isinstance(entry, dict) or entry.get('type') != 'session':
        return None
    cwd = entry.get('cwd')
    if not isinstance(cwd, str):
        return None
    parts = cwd.replace('\\', '/').rstrip('/').split('/')
    if len(parts) < 2 or parts[-2] != 'dispatcher-workspaces':
        return None
    project = parts[-1]
    return project if project.startswith('proj_') and project[5:].isdigit() else None


def _near_project_receipt(timestamp, project, intervals):
    tolerance = SESSION_RECEIPT_TOLERANCE_SECONDS
    return any(known is False and receipt_project == project and
               min(abs((timestamp - begun).total_seconds()),
                   abs((timestamp - ended).total_seconds())) <= tolerance
               for begun, ended, known, receipt_project in intervals)


def backfill_pi_usage(journal: Path, sessions_root: Path) -> dict[str, int]:
    """Count session responses covered by an old empty Pi execution receipt."""
    intervals = defaultdict(list)
    with closing(sqlite3.connect(journal)) as conn, conn:
        rows = conn.execute('SELECT payload_json FROM usage_events').fetchall()
        traces = defaultdict(dict)
        for (body,) in rows:
            receipt = json.loads(body)
            if receipt.get('worker') in WORKERS and receipt.get('call_unit') == 'cli_execution':
                traces[receipt.get('trace_id')][receipt.get('status')] = receipt
        for states in traces.values():
            start = states.get('started')
            terminal = states.get('completed') or states.get('failed')
            if not start or not terminal:
                continue
            begun, ended = _time(start.get('occurred_at')), _time(terminal.get('occurred_at'))
            if begun and ended and begun <= ended:
                intervals[start['worker']].append((begun, ended, bool(terminal.get('usage')),
                                                   start.get('project_id')))

        inserted = total = scanned = 0
        seen = set()
        session_projects = {}
        for worker in WORKERS:
            for path in (sessions_root / worker / 'sessions').rglob('*.jsonl'):
                try:
                    with path.open(encoding='utf-8') as stream:
                        session_project = None
                        session_time = None
                        for line in stream:
                            try:
                                entry = json.loads(line)
                            except ValueError:
                                continue
                            if session_project is None:
                                session_project = _session_project(entry)
                                if session_project:
                                    session_time = _time(entry.get('timestamp'))
                            if not isinstance(entry, dict) or entry.get('type') != 'message':
                                continue
                            message = entry.get('message')
                            if not isinstance(message, dict) or message.get('role') != 'assistant':
                                continue
                            usage = _usage(message.get('usage'))
                            timestamp = _time(entry.get('timestamp'))
                            entry_id = entry.get('id')
                            if not usage or not timestamp or not isinstance(entry_id, str) or not entry_id:
                                continue
                            scanned += 1
                            covered = [known for begun, ended, known, _project in intervals[worker]
                                       if begun <= timestamp <= ended]
                            # A response in any modern execution may already be counted.
                            if any(covered):
                                continue
                            # Old Pi sometimes wrote the session response just
                            # beyond the CLI receipt. Require a dispatcher
                            # workspace and a nearby receipt for that project.
                            adjacent = (not covered and session_project and session_time and
                                        _near_project_receipt(session_time, session_project, intervals[worker]) and
                                        _near_project_receipt(timestamp, session_project, intervals[worker]))
                            if not covered and not adjacent:
                                continue
                            identity = hashlib.sha256(f'{path.resolve()}:{entry_id}'.encode()).hexdigest()
                            if session_project:
                                session_projects[identity] = session_project
                            if identity in seen:
                                continue
                            seen.add(identity)
                            model = message.get('model')
                            if not isinstance(model, str) or len(model) > 200:
                                model = 'unknown'
                            payload = {'trace_id': 'pi-session:' + identity, 'source': 'security_runtime_worker',
                                       'worker': worker, 'model': model, 'status': 'completed',
                                       'call_unit': 'pi_session_response_backfill', 'usage': usage,
                                       'occurred_at': timestamp.isoformat()}
                            if adjacent:
                                payload['project_id'] = session_project
                            cursor = conn.execute(
                                'INSERT OR IGNORE INTO usage_events(receipt_id, payload_json) VALUES (?, ?)',
                                ('pi-session-backfill:' + identity, json.dumps(payload)))
                            if cursor.rowcount:
                                inserted += 1
                                total += usage['total_tokens']
                except OSError:
                    continue
        linked = linked_tokens = 0
        for sequence, body in conn.execute('SELECT sequence, payload_json FROM usage_events'):
            receipt = json.loads(body)
            if receipt.get('call_unit') != 'pi_session_response_backfill' or receipt.get('project_id'):
                continue
            timestamp = _time(receipt.get('occurred_at'))
            if timestamp is None:
                continue
            identity = receipt.get('trace_id', '').removeprefix('pi-session:')
            exact_project = session_projects.get(identity)
            projects = {exact_project} if exact_project else {project for begun, ended, known, project in intervals[receipt.get('worker')]
                        if begun <= timestamp <= ended and not known and project}
            if len(projects) != 1:
                continue
            receipt['project_id'] = projects.pop()
            conn.execute('UPDATE usage_events SET payload_json = ? WHERE sequence = ?',
                         (json.dumps(receipt), sequence))
            linked += 1
            linked_tokens += receipt['usage']['total_tokens']
        return {'scanned_responses': scanned, 'inserted_responses': inserted, 'inserted_tokens': total,
                'linked_responses': linked, 'linked_tokens': linked_tokens}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--journal', type=Path, default=Path(__file__).resolve().parents[2] / 'data/worker-usage.db')
    parser.add_argument('--sessions-root', type=Path, default=Path.home() / '.security-runtime-pi')
    args = parser.parse_args()
    print(json.dumps(backfill_pi_usage(args.journal, args.sessions_root)))


if __name__ == '__main__':
    main()
