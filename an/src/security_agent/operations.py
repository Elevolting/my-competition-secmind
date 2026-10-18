"""Durable local operations state, independent of model/task execution."""
from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4


class OperationsStore:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(path)) as db, db:
            db.execute('PRAGMA journal_mode=WAL')
            db.execute('CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS receipts (id INTEGER PRIMARY KEY, kind TEXT NOT NULL, value TEXT NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS blackboard_budget ('
                       'run_id TEXT NOT NULL, intent_id TEXT NOT NULL, used INTEGER NOT NULL, '
                       'PRIMARY KEY (run_id, intent_id))')
            db.execute('CREATE TABLE IF NOT EXISTS mcp_idempotency ('
                       'request_key TEXT PRIMARY KEY, call_id TEXT NOT NULL, '
                       'receipt TEXT NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS mcp_approvals ('
                       'id TEXT PRIMARY KEY, request_key TEXT NOT NULL UNIQUE, '
                       'status TEXT NOT NULL, value TEXT NOT NULL)')

    def request_mcp_approval(self, request_key: str, payload: dict) -> dict:
        record = {**payload, 'approval_id': str(uuid4()), 'status': 'pending',
                  'created_at': datetime.now(UTC).isoformat()}
        with closing(sqlite3.connect(self.path, timeout=10)) as db, db:
            inserted = db.execute(
                'INSERT OR IGNORE INTO mcp_approvals(id, request_key, status, value) VALUES (?, ?, ?, ?)',
                (record['approval_id'], request_key, 'pending', json.dumps(record, ensure_ascii=False)),
            ).rowcount
            if not inserted:
                row = db.execute('SELECT value FROM mcp_approvals WHERE request_key=?', (request_key,)).fetchone()
                if row is None:
                    raise ValueError('MCP 审批请求冲突')
                existing = json.loads(row[0])
                if any(existing.get(key) != payload.get(key) for key in payload):
                    raise ValueError('MCP 请求 ID 已用于不同调用')
                return existing
        return record

    def mcp_approval(self, approval_id: str) -> dict | None:
        with closing(sqlite3.connect(self.path)) as db:
            row = db.execute('SELECT value FROM mcp_approvals WHERE id=?', (approval_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def mcp_approval_for_request(self, request_key: str) -> dict | None:
        with closing(sqlite3.connect(self.path)) as db:
            row = db.execute('SELECT value FROM mcp_approvals WHERE request_key=?',
                             (request_key,)).fetchone()
        return json.loads(row[0]) if row else None

    def mcp_request_receipt(self, request_key: str) -> dict | None:
        with closing(sqlite3.connect(self.path)) as db:
            row = db.execute('SELECT receipt FROM mcp_idempotency WHERE request_key=?',
                             (request_key,)).fetchone()
        return json.loads(row[0]) if row else None

    def pending_mcp_approvals(self, run_id: str) -> list[dict]:
        with closing(sqlite3.connect(self.path)) as db:
            rows = db.execute("SELECT value FROM mcp_approvals WHERE status='pending'").fetchall()
        return [value for row in rows if (value := json.loads(row[0])).get('run_id') == run_id]

    def transition_mcp_approval(self, approval_id: str, expected: str, status: str) -> dict | None:
        with closing(sqlite3.connect(self.path, timeout=10)) as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT value FROM mcp_approvals WHERE id=? AND status=?',
                             (approval_id, expected)).fetchone()
            if row is None:
                db.rollback()
                return None
            record = json.loads(row[0])
            record['status'] = status
            record['updated_at'] = datetime.now(UTC).isoformat()
            db.execute('UPDATE mcp_approvals SET status=?, value=? WHERE id=? AND status=?',
                       (status, json.dumps(record, ensure_ascii=False), approval_id, expected))
            db.commit()
            return record

    def claim_mcp_request(self, request_key: str, call_id: str, receipt: dict) -> tuple[bool, dict | None]:
        """Claim one durable MCP request key, returning an existing receipt on replay."""
        if not request_key or not call_id:
            raise ValueError('MCP 幂等请求键无效')
        encoded = json.dumps(receipt, ensure_ascii=False)
        with closing(sqlite3.connect(self.path, timeout=10)) as db, db:
            inserted = db.execute(
                'INSERT OR IGNORE INTO mcp_idempotency(request_key, call_id, receipt) VALUES (?, ?, ?)',
                (request_key, call_id, encoded),
            ).rowcount
            if inserted:
                db.execute('INSERT INTO state(key, value) VALUES (?, ?)', ('call:' + call_id, encoded))
                return True, None
            row = db.execute('SELECT receipt FROM mcp_idempotency WHERE request_key=?', (request_key,)).fetchone()
        return False, json.loads(row[0]) if row else None

    def finish_mcp_call(self, receipt: dict) -> None:
        """Persist the terminal call, replay value and history in one transaction."""
        encoded = json.dumps(receipt, ensure_ascii=False)
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute('INSERT INTO state(key, value) VALUES (?, ?) '
                       'ON CONFLICT(key) DO UPDATE SET value=excluded.value',
                       ('call:' + receipt['call_id'], encoded))
            request_key = receipt.get('idempotency_key')
            if request_key:
                updated = db.execute(
                    'UPDATE mcp_idempotency SET receipt=? WHERE request_key=? AND call_id=?',
                    (encoded, request_key, receipt['call_id']),
                ).rowcount
                if updated != 1:
                    raise ValueError('MCP 幂等请求记录不一致')
            db.execute('INSERT INTO receipts(kind,value) VALUES (?, ?)', ('mcp', encoded))

    def reserve_blackboard_call(
        self, run_id: str, intent_id: str, *, run_limit: int | None, intent_limit: int | None,
    ) -> bool:
        """Reserve both budgets atomically before a blackboard tools/call.

        The empty intent ID stores the run total. A reserved call stays charged
        when its outcome is unknown, preventing a retry from evading the limit.
        """
        if (not run_id or not intent_id
                or (run_limit is not None and run_limit < 1)
                or (intent_limit is not None and intent_limit < 1)):
            raise ValueError('黑板调用预算参数无效')
        with closing(sqlite3.connect(self.path, timeout=10)) as db:
            db.execute('BEGIN IMMEDIATE')
            counts = {}
            for scope in ('', intent_id):
                row = db.execute(
                    'SELECT used FROM blackboard_budget WHERE run_id=? AND intent_id=?',
                    (run_id, scope),
                ).fetchone()
                counts[scope] = row[0] if row else 0
            if ((run_limit is not None and counts[''] >= run_limit)
                    or (intent_limit is not None and counts[intent_id] >= intent_limit)):
                db.rollback()
                return False
            for scope in ('', intent_id):
                db.execute(
                    'INSERT INTO blackboard_budget (run_id, intent_id, used) VALUES (?, ?, 1) '
                    'ON CONFLICT(run_id, intent_id) DO UPDATE SET used=used+1',
                    (run_id, scope),
                )
            db.commit()
        return True

    def blackboard_calls_used(self, run_id: str) -> int:
        with closing(sqlite3.connect(self.path, timeout=10)) as db:
            row = db.execute('SELECT used FROM blackboard_budget WHERE run_id=? AND intent_id=?',
                             (run_id, '')).fetchone()
        return int(row[0]) if row else 0

    def get(self, key: str, default: Any = None) -> Any:
        with closing(sqlite3.connect(self.path)) as db:
            row = db.execute('SELECT value FROM state WHERE key=?', (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def put(self, key: str, value: Any) -> None:
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute('INSERT INTO state VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',
                       (key, json.dumps(value, ensure_ascii=False)))

    def append(self, kind: str, value: Any) -> None:
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute('INSERT INTO receipts(kind,value) VALUES (?,?)', (kind, json.dumps(value, ensure_ascii=False)))

    def restore_incident_logs(self, logs: list[dict]) -> None:
        """Recover snapshot logs absent from receipts after an upgrade or crash."""
        if not logs:
            return
        with closing(sqlite3.connect(self.path, timeout=10)) as db:
            db.execute('BEGIN IMMEDIATE')
            known = {row[0] for row in db.execute(
                "SELECT json_extract(value, '$.sequence') FROM receipts WHERE kind='incident'")}
            for event in sorted(logs, key=lambda item: item.get('sequence', -1)):
                sequence = event.get('sequence')
                if type(sequence) is not int or sequence < 0 or sequence in known:
                    continue
                db.execute('INSERT INTO receipts(kind,value) VALUES (?,?)',
                           ('incident', json.dumps(event, ensure_ascii=False)))
                known.add(sequence)
            db.commit()

    def items(self, prefix: str) -> list[tuple[str, dict]]:
        with closing(sqlite3.connect(self.path)) as db:
            rows = db.execute('SELECT key,value FROM state WHERE key LIKE ?', (prefix + '%',)).fetchall()
        return [(key, json.loads(value)) for key, value in rows]

    def recent(self, kind: str, limit: int = 100, offset: int = 0) -> list[dict]:
        with closing(sqlite3.connect(self.path)) as db:
            ordering = "json_extract(value, '$.sequence') DESC, id DESC" if kind == 'incident' else 'id DESC'
            rows = db.execute(f'SELECT value FROM receipts WHERE kind=? ORDER BY {ordering} LIMIT ? OFFSET ?',
                              (kind, limit, offset)).fetchall()
        return [json.loads(row[0]) for row in rows]

    def receipt_count(self, kind: str) -> int:
        with closing(sqlite3.connect(self.path)) as db:
            return db.execute('SELECT COUNT(*) FROM receipts WHERE kind=?', (kind,)).fetchone()[0]
