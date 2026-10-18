"""Transactional execution journal. Event IDs and attempts survive restarts."""
from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import uuid4


def record(conn, project_id, intent_id, event_type, *, worker=None, payload=None):
    row = conn.execute("SELECT attempt_id FROM intents WHERE project_id=? AND id=?", (project_id, intent_id)).fetchone()
    attempt_id = row["attempt_id"] if row else None
    event_id = str(uuid4())
    conn.execute(
        "INSERT INTO project_events (event_id,project_id,intent_id,attempt_id,event_type,worker,timestamp,payload_json) VALUES (?,?,?,?,?,?,?,?)",
        (event_id, project_id, intent_id, attempt_id, event_type, worker,
         datetime.now(UTC).isoformat(), json.dumps(payload or {}, ensure_ascii=False)),
    )
    return event_id


def claim(conn, project_id, intent_id, worker):
    previous = conn.execute("SELECT attempt_id FROM intents WHERE project_id=? AND id=?", (project_id, intent_id)).fetchone()
    attempt_id = str(uuid4())
    conn.execute("UPDATE intents SET attempt_id=?, execution_status='running' WHERE project_id=? AND id=?", (attempt_id, project_id, intent_id))
    record(conn, project_id, intent_id, "claimed", worker=worker)
    if previous and previous["attempt_id"]:
        record(conn, project_id, intent_id, "retry", worker=worker, payload={"previous_attempt_id": previous["attempt_id"]})
    return attempt_id


def fact_from_row(row):
    from security_runtime.server.models import Fact
    return Fact(id=row["id"], description=row["description"], title=row["title"], items=json.loads(row["items_json"] or "[]"))


def normalize_items(fact_id, items):
    # The producing Worker can report a candidate, but cannot confer verification.
    result = []
    used = set()
    for index, item in enumerate(items):
        suffix = item.id or str(index + 1)
        base = suffix
        counter = index + 1
        while suffix in used:
            suffix = f"{base}:{counter}"
            counter += 1
        used.add(suffix)
        status = item.verification_status
        if status in {"confirmed", "ruled_out"}:
            status = "pending" if item.evidence_ids else "insufficient"
        result.append(item.model_copy(update={"id": f"{fact_id}:{suffix}", "verification_status": status}))
    return result
