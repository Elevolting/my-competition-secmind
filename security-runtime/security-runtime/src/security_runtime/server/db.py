from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Generator

DEFAULT_DB = Path.home() / ".local" / "share" / "security_runtime" / "security_runtime.db"

_db_path: Path | None = None

SCHEMA = """\
CREATE TABLE IF NOT EXISTS settings (
    intent_timeout INTEGER NOT NULL DEFAULT 15,
    reason_timeout INTEGER NOT NULL DEFAULT 15
);

INSERT OR IGNORE INTO settings (rowid, intent_timeout, reason_timeout) VALUES (1, 15, 15);

CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    bootstrap_enabled INTEGER NOT NULL DEFAULT 1,
    dispatcher_enabled INTEGER NOT NULL DEFAULT 1,
    dispatcher_activation_hash TEXT,
    creation_key TEXT,
    creation_payload_hash TEXT,
    created_at TEXT NOT NULL,
    reason_worker TEXT,
    reason_attempt_id TEXT,
    reason_decision_pending INTEGER NOT NULL DEFAULT 0,
    reason_trigger TEXT,
    reason_started_at TEXT,
    reason_last_heartbeat_at TEXT
);

CREATE TABLE IF NOT EXISTS facts (
    id TEXT NOT NULL,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    description TEXT NOT NULL,
    title TEXT,
    items_json TEXT NOT NULL DEFAULT '[]',
    PRIMARY KEY (id, project_id)
);

CREATE TABLE IF NOT EXISTS intents (
    id TEXT NOT NULL,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    to_fact_id TEXT,
    description TEXT NOT NULL,
    tool_name TEXT,
    creator TEXT NOT NULL,
    worker TEXT,
    last_heartbeat_at TEXT,
    created_at TEXT NOT NULL,
    concluded_at TEXT,
    attempt_id TEXT,
    execution_status TEXT NOT NULL DEFAULT 'waiting',
    source_relation TEXT NOT NULL DEFAULT 'evidence',
    success_criteria TEXT,
    title TEXT,
    verification_target TEXT,
    decision_id TEXT,
    decision_summary TEXT,
    PRIMARY KEY (id, project_id)
);

CREATE TABLE IF NOT EXISTS intent_sources (
    intent_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    fact_id TEXT NOT NULL,
    PRIMARY KEY (intent_id, project_id, fact_id),
    FOREIGN KEY (intent_id, project_id) REFERENCES intents(id, project_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS hints (
    id TEXT NOT NULL,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    content TEXT NOT NULL,
    creator TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (id, project_id)
);

CREATE TABLE IF NOT EXISTS counters (
    name TEXT PRIMARY KEY,
    value INTEGER NOT NULL DEFAULT 0
);

INSERT OR IGNORE INTO counters (name, value) VALUES ('project', 0);

CREATE TABLE IF NOT EXISTS scoped_counters (
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    value INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (project_id, kind)
);

CREATE TABLE IF NOT EXISTS project_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    intent_id TEXT,
    attempt_id TEXT,
    event_type TEXT NOT NULL,
    worker TEXT,
    timestamp TEXT NOT NULL,
    payload_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_project_events_project_sequence ON project_events(project_id, sequence);

CREATE TABLE IF NOT EXISTS planning_decisions (
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    decision_id TEXT NOT NULL,
    snapshot_hash TEXT NOT NULL,
    response_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (project_id, decision_id)
);
"""


def configure(path: Path) -> None:
    global _db_path
    if _db_path is not None:
        return
    _db_path = path
    _db_path.parent.mkdir(parents=True, exist_ok=True)
    with get_conn() as conn:
        conn.executescript(SCHEMA)
        _ensure_project_columns(conn)


def _ensure_project_columns(conn: sqlite3.Connection) -> None:
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(projects)")}
    if "reason_attempt_id" not in columns:
        conn.execute("ALTER TABLE projects ADD COLUMN reason_attempt_id TEXT")
    if "reason_decision_pending" not in columns:
        conn.execute("ALTER TABLE projects ADD COLUMN reason_decision_pending INTEGER NOT NULL DEFAULT 0")
    if "bootstrap_enabled" not in columns:
        conn.execute("ALTER TABLE projects ADD COLUMN bootstrap_enabled INTEGER NOT NULL DEFAULT 1")
        if "bootstrap_mode" in columns:
            conn.execute(
                "UPDATE projects SET bootstrap_enabled = CASE WHEN bootstrap_mode = 'disabled' THEN 0 ELSE 1 END"
            )
    if "dispatcher_enabled" not in columns:
        conn.execute("ALTER TABLE projects ADD COLUMN dispatcher_enabled INTEGER NOT NULL DEFAULT 1")
        # Projects created by the unified workbench before this column was
        # added already had their own assigned Worker. Preserve that ownership
        # across the migration instead of admitting them to the Dispatcher.
        conn.execute(
            "UPDATE projects SET dispatcher_enabled = 0 WHERE bootstrap_enabled = 0 "
            "AND id IN (SELECT project_id FROM facts WHERE id = 'origin' "
            "AND description LIKE '统一工作台任务 %；模块：%')"
        )
    if "dispatcher_activation_hash" not in columns:
        conn.execute("ALTER TABLE projects ADD COLUMN dispatcher_activation_hash TEXT")
    for column in ('creation_key', 'creation_payload_hash'):
        if column not in columns:
            conn.execute(f'ALTER TABLE projects ADD COLUMN {column} TEXT')
    conn.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_project_creation_key '
                 'ON projects(creation_key) WHERE creation_key IS NOT NULL')
    intent_columns = {row["name"] for row in conn.execute("PRAGMA table_info(intents)")}
    if "tool_name" not in intent_columns:
        conn.execute("ALTER TABLE intents ADD COLUMN tool_name TEXT")
    if "attempt_id" not in intent_columns:
        conn.execute("ALTER TABLE intents ADD COLUMN attempt_id TEXT")
    if "execution_status" not in intent_columns:
        conn.execute("ALTER TABLE intents ADD COLUMN execution_status TEXT NOT NULL DEFAULT 'waiting'")
    if "source_relation" not in intent_columns:
        conn.execute("ALTER TABLE intents ADD COLUMN source_relation TEXT NOT NULL DEFAULT 'evidence'")
    if "source_relations_json" not in intent_columns:
        conn.execute("ALTER TABLE intents ADD COLUMN source_relations_json TEXT NOT NULL DEFAULT '{}'")
    if "success_criteria" not in intent_columns:
        conn.execute("ALTER TABLE intents ADD COLUMN success_criteria TEXT")
    for column in ("title", "verification_target", "decision_id", "decision_summary"):
        if column not in intent_columns:
            conn.execute(f"ALTER TABLE intents ADD COLUMN {column} TEXT")
    if "step_id" not in intent_columns:
        conn.execute("ALTER TABLE intents ADD COLUMN step_id TEXT")
    for column, default in (("depends_on_json", "[]"), ("required_outputs_json", "{}"),
                            ("validated_outputs_json", "[]")):
        if column not in intent_columns:
            conn.execute(f"ALTER TABLE intents ADD COLUMN {column} TEXT NOT NULL DEFAULT '{default}'")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_project_step_id "
                 "ON intents(project_id,step_id) WHERE step_id IS NOT NULL")
    fact_columns = {row["name"] for row in conn.execute("PRAGMA table_info(facts)")}
    if "title" not in fact_columns:
        conn.execute("ALTER TABLE facts ADD COLUMN title TEXT")
    if "items_json" not in fact_columns:
        conn.execute("ALTER TABLE facts ADD COLUMN items_json TEXT NOT NULL DEFAULT '[]'")
    conn.execute("""CREATE TABLE IF NOT EXISTS project_events (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id TEXT NOT NULL UNIQUE,
        project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
        intent_id TEXT,
        attempt_id TEXT,
        event_type TEXT NOT NULL,
        worker TEXT,
        timestamp TEXT NOT NULL,
        payload_json TEXT NOT NULL DEFAULT '{}'
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_project_events_project_sequence ON project_events(project_id, sequence)")
    conn.execute("""CREATE TABLE IF NOT EXISTS planning_decisions (
        project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
        decision_id TEXT NOT NULL,
        snapshot_hash TEXT NOT NULL,
        response_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY (project_id, decision_id)
    )""")


@contextmanager
def get_conn() -> Generator[sqlite3.Connection, None, None]:
    assert _db_path is not None
    conn = sqlite3.connect(str(_db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
