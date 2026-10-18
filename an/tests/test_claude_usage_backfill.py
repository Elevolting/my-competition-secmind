import json
import sqlite3
from datetime import UTC, datetime, timedelta

from security_agent.claude_usage_backfill import backfill_claude_usage


def _create_worker_journal(path):
    with sqlite3.connect(path) as conn:
        conn.execute('CREATE TABLE usage_events (sequence INTEGER PRIMARY KEY AUTOINCREMENT, receipt_id TEXT UNIQUE, payload_json TEXT)')


def _receipt(conn, trace_id, status, timestamp, usage):
    payload = {
        'trace_id': trace_id,
        'status': status,
        'worker': 'claudecode_shared_model',
        'call_unit': 'cli_execution',
        'project_id': 'proj_101',
        'occurred_at': timestamp.isoformat(),
        'usage': usage,
    }
    conn.execute('INSERT INTO usage_events(receipt_id, payload_json) VALUES (?, ?)',
                 (trace_id + ':' + status, json.dumps(payload)))


def _create_runtime_db(path, began, ended):
    with sqlite3.connect(path) as conn:
        conn.execute('CREATE TABLE projects (id TEXT PRIMARY KEY, status TEXT, created_at TEXT)')
        conn.execute('CREATE TABLE intents (project_id TEXT, created_at TEXT, concluded_at TEXT, last_heartbeat_at TEXT)')
        conn.execute('INSERT INTO projects VALUES (?, ?, ?)', ('proj_101', 'completed', began.isoformat()))
        conn.execute('INSERT INTO intents VALUES (?, ?, ?, ?)',
                     ('proj_101', began.isoformat(), ended.isoformat(), None))


def _assistant(message_id, timestamp, *, cwd, usage, model='claude-test'):
    return {
        'type': 'assistant',
        'timestamp': timestamp.isoformat(),
        'cwd': cwd,
        'message': {'id': message_id, 'role': 'assistant', 'model': model,
                    'usage': usage, 'content': [{'type': 'text', 'text': 'private transcript text'}]},
    }


def test_claude_backfill_is_project_scoped_idempotent_and_dry_run_safe(tmp_path):
    journal = tmp_path / 'worker-usage.db'
    runtime = tmp_path / 'security-runtime.db'
    sessions = tmp_path / 'claude-projects'
    sessions.mkdir()
    _create_worker_journal(journal)

    began = datetime(2026, 10, 1, 10, 0, tzinfo=UTC)
    ended = began + timedelta(minutes=4)
    _create_runtime_db(runtime, began, ended)
    known_start = began + timedelta(seconds=10)
    known_end = known_start + timedelta(seconds=30)
    unknown_start = began + timedelta(minutes=1)
    unknown_end = unknown_start + timedelta(seconds=30)
    with sqlite3.connect(journal) as conn:
        _receipt(conn, 'known', 'started', known_start, {})
        _receipt(conn, 'known', 'completed', known_end, {'total_tokens': 77})
        _receipt(conn, 'unknown', 'started', unknown_start, {})
        _receipt(conn, 'unknown', 'completed', unknown_end, {})

    cwd = str(tmp_path / 'dispatcher-workspaces' / 'proj_101')
    rows = [
        _assistant('known-response', known_start + timedelta(seconds=15), cwd=cwd,
                   usage={'input_tokens': 50, 'output_tokens': 8}),
        _assistant('recover-response', unknown_start + timedelta(seconds=15), cwd=cwd,
                   usage={'input_tokens': 10, 'output_tokens': 4,
                          'cache_read_input_tokens': 3, 'cache_creation_input_tokens': 2}),
        _assistant('recover-response', unknown_start + timedelta(seconds=16), cwd=cwd,
                   usage={'input_tokens': 10, 'output_tokens': 4,
                          'cache_read_input_tokens': 3, 'cache_creation_input_tokens': 2}),
        _assistant('outside-window', ended + timedelta(minutes=2), cwd=cwd,
                   usage={'input_tokens': 100, 'output_tokens': 10}),
        _assistant('wrong-project', unknown_start + timedelta(seconds=20),
                   cwd=str(tmp_path / 'dispatcher-workspaces' / 'proj_999'),
                   usage={'input_tokens': 100, 'output_tokens': 10}),
    ]
    (sessions / 'session.jsonl').write_text('\n'.join(map(json.dumps, rows)) + '\n', encoding='utf-8')

    with sqlite3.connect(journal) as conn:
        before_count, = conn.execute('SELECT count(*) FROM usage_events').fetchone()
    dry_run = backfill_claude_usage(journal, sessions, runtime, dry_run=True)
    assert dry_run['eligible_responses'] == 1
    assert dry_run['eligible_tokens'] == 19
    assert dry_run['inserted_responses'] == 0
    with sqlite3.connect(journal) as conn:
        assert conn.execute('SELECT count(*) FROM usage_events').fetchone()[0] == before_count

    inserted = backfill_claude_usage(journal, sessions, runtime)
    assert inserted['inserted_responses'] == 1
    assert inserted['inserted_tokens'] == 19
    repeated = backfill_claude_usage(journal, sessions, runtime)
    assert repeated['eligible_responses'] == 1
    assert repeated['inserted_responses'] == repeated['inserted_tokens'] == 0

    with sqlite3.connect(journal) as conn:
        body, = conn.execute("SELECT payload_json FROM usage_events WHERE receipt_id LIKE 'claude_session_response_backfill:%'").fetchone()
        receipt = json.loads(body)
        total_rows = conn.execute('SELECT count(*) FROM usage_events').fetchone()[0]
    assert total_rows == before_count + 1
    assert receipt['project_id'] == 'proj_101'
    assert receipt['call_unit'] == 'claude_session_response_backfill'
    assert receipt['usage'] == {
        'prompt_tokens': 15, 'completion_tokens': 4,
        'total_tokens': 19, 'cache_read_tokens': 3,
    }
    assert 'private transcript text' not in body
