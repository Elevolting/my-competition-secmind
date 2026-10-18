import json

from fastapi import APIRouter, HTTPException

from security_runtime.server.db import get_conn
from security_runtime.server.execution import claim, normalize_items, record, fact_from_row
from security_runtime.server.routers.projects import is_workbench_project
from security_runtime.server.models import (
    ConcludeRequest,
    ConcludeResponse,
    CreateIntentRequest,
    Fact,
    HeartbeatRequest,
    Intent,
    StageRequest,
)
from security_runtime.server.services import (
    check_project_active,
    get_claimable_open_intent_or_404,
    get_releasable_open_intent_or_404,
    intent_to_model,
    next_fact_id,
    next_intent_id,
    utcnow,
    validate_facts_exist,
    validate_intent_creator_worker,
    validate_goal_not_in_sources,
)

router = APIRouter(tags=["intents"])


def check_attempt(conn, project_id: str, row, attempt_id: str | None, *, claiming: bool = False) -> None:
    workbench = is_workbench_project(conn, project_id)
    if not workbench and attempt_id is None:
        return
    if row["attempt_id"] != attempt_id:
        raise HTTPException(409, "Intent execution attempt has changed")
    if workbench:
        if row["worker"] is None and not claiming:
            raise HTTPException(409, "Intent must be claimed before this operation")
        if row["worker"] is not None and attempt_id is None:
            raise HTTPException(409, "Intent execution attempt is required")


@router.post(
    "/projects/{project_id}/intents",
    response_model=Intent,
    status_code=201,
)
def create_intent(project_id: str, body: CreateIntentRequest):
    with get_conn() as conn:
        check_project_active(conn, project_id)
        if is_workbench_project(conn, project_id):
            raise HTTPException(403, "Workbench directions must come from an authenticated planning decision")
        validate_facts_exist(conn, project_id, body.from_)
        validate_goal_not_in_sources(body.from_)
        validate_intent_creator_worker(body.creator, body.worker)

        now = utcnow()
        iid = next_intent_id(conn, project_id)
        claimed = body.worker is not None
        conn.execute(
            "INSERT INTO intents (id, project_id, to_fact_id, description, tool_name, creator, worker, last_heartbeat_at, created_at, concluded_at, source_relation, success_criteria, title, verification_target) VALUES (?, ?, NULL, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?)",
            (
                iid,
                project_id,
                body.description,
                body.tool_name,
                body.creator,
                body.worker,
                now if claimed else None,
                now,
                body.source_relation,
                body.success_criteria,
                body.title,
                body.verification_target,
            ),
        )
        conn.execute("UPDATE intents SET source_relations_json=? WHERE project_id=? AND id=?", (json.dumps({fid: relation for fid, relation in body.source_relations.items() if fid in body.from_}), project_id, iid))
        for fid in body.from_:
            conn.execute(
                "INSERT INTO intent_sources (intent_id, project_id, fact_id) VALUES (?, ?, ?)",
                (iid, project_id, fid),
            )
        record(conn, project_id, iid, "created", worker=body.worker, payload={"sources": body.from_})
        attempt_id = claim(conn, project_id, iid, body.worker) if claimed else None

        return Intent(
            id=iid,
            **{"from": body.from_},
            to=None,
            description=body.description,
            tool_name=body.tool_name,
            creator=body.creator,
            worker=body.worker,
            last_heartbeat_at=now if claimed else None,
            created_at=now,
            concluded_at=None,
            attempt_id=attempt_id,
            execution_status="running" if claimed else "waiting",
            source_relation=body.source_relation,
            source_relations=body.source_relations,
            success_criteria=body.success_criteria,
            title=body.title,
            verification_target=body.verification_target,
        )


@router.post(
    "/projects/{project_id}/intents/{intent_id}/heartbeat",
    response_model=Intent,
)
def heartbeat(project_id: str, intent_id: str, body: HeartbeatRequest):
    with get_conn() as conn:
        conn.execute('BEGIN IMMEDIATE')
        check_project_active(conn, project_id)
        row = get_claimable_open_intent_or_404(conn, project_id, intent_id, body.worker)
        check_attempt(conn, project_id, row, body.attempt_id, claiming=body.claim)
        if row['worker'] is None and row['execution_status'] in {'failed', 'timeout', 'cancelled'} and is_workbench_project(conn, project_id):
            raise HTTPException(409, 'A workbench planning decision must schedule this retry')

        now = utcnow()
        conn.execute(
            "UPDATE intents SET worker = ?, last_heartbeat_at = ? WHERE id = ? AND project_id = ?",
            (body.worker, now, intent_id, project_id),
        )
        if row["worker"] is None:
            claim(conn, project_id, intent_id, body.worker)

        updated = conn.execute(
            "SELECT * FROM intents WHERE id = ? AND project_id = ?",
            (intent_id, project_id),
        ).fetchone()
        return intent_to_model(conn, updated, project_id)


@router.post(
    "/projects/{project_id}/intents/{intent_id}/release",
    response_model=Intent,
)
def release(project_id: str, intent_id: str, body: HeartbeatRequest):
    with get_conn() as conn:
        conn.execute('BEGIN IMMEDIATE')
        check_project_active(conn, project_id)
        row = get_releasable_open_intent_or_404(conn, project_id, intent_id, body.worker)
        check_attempt(conn, project_id, row, body.attempt_id)

        if row["worker"] == body.worker:
            # Generic release failures must preserve an already observed timeout or cancellation.
            outcome = row["execution_status"] if body.outcome in {"waiting", "failed"} and row["execution_status"] in {"failed", "cancelled", "timeout"} else body.outcome
            conn.execute(
                "UPDATE intents SET worker = NULL, execution_status=? WHERE id = ? AND project_id = ?",
                (outcome, intent_id, project_id),
            )
            record(conn, project_id, intent_id, "released" if outcome == "waiting" else outcome,
                   worker=body.worker, payload={"reason": body.reason} if body.reason else {})
            row = conn.execute(
                "SELECT * FROM intents WHERE id = ? AND project_id = ?",
                (intent_id, project_id),
            ).fetchone()

        return intent_to_model(conn, row, project_id)


@router.post(
    "/projects/{project_id}/intents/{intent_id}/conclude",
    response_model=ConcludeResponse,
    response_model_exclude_defaults=True,
)
def conclude(project_id: str, intent_id: str, body: ConcludeRequest):
    with get_conn() as conn:
        conn.execute('BEGIN IMMEDIATE')
        previous = conn.execute('SELECT * FROM intents WHERE project_id=? AND id=?', (project_id, intent_id)).fetchone()
        if previous is not None:
            check_attempt(conn, project_id, previous, body.attempt_id)
        if previous and previous['to_fact_id'] and previous['worker'] == body.worker:
            fact_row = conn.execute('SELECT * FROM facts WHERE project_id=? AND id=?',
                                    (project_id, previous['to_fact_id'])).fetchone()
            fact = fact_from_row(fact_row) if fact_row else None
            if (fact and fact.description == body.description and fact.title == body.title
                    and fact.items == normalize_items(fact.id, body.items)):
                return ConcludeResponse(fact=fact, intent=intent_to_model(conn, previous, project_id))
            raise HTTPException(409, 'Intent conclusion was already written with different content')
        check_project_active(conn, project_id)
        row = get_claimable_open_intent_or_404(conn, project_id, intent_id, body.worker)
        check_attempt(conn, project_id, row, body.attempt_id)
        if row["worker"] is None:
            claim(conn, project_id, intent_id, body.worker)

        now = utcnow()
        fid = next_fact_id(conn, project_id)

        items = normalize_items(fid, body.items)
        conn.execute(
            "INSERT INTO facts (id, project_id, description, title, items_json) VALUES (?, ?, ?, ?, ?)",
            (fid, project_id, body.description, body.title, json.dumps([item.model_dump() for item in items], ensure_ascii=False)),
        )
        conn.execute(
            "UPDATE intents SET to_fact_id = ?, worker = ?, last_heartbeat_at = ?, concluded_at = ?, execution_status=? WHERE id = ? AND project_id = ?",
            (fid, body.worker, now, now, body.execution_status, intent_id, project_id),
        )
        record(conn, project_id, intent_id, "completed", worker=body.worker,
               payload={"fact_id": fid, "item_ids": [item.id for item in items], "status": body.execution_status})

        updated = conn.execute(
            "SELECT * FROM intents WHERE id = ? AND project_id = ?",
            (intent_id, project_id),
        ).fetchone()

        return ConcludeResponse(
            fact=Fact(id=fid, description=body.description, title=body.title, items=items),
            intent=intent_to_model(conn, updated, project_id),
        )


@router.post("/projects/{project_id}/intents/{intent_id}/stage", response_model=Intent)
def record_stage(project_id: str, intent_id: str, body: StageRequest):
    worker = body.worker
    phase = body.phase
    with get_conn() as conn:
        conn.execute('BEGIN IMMEDIATE')
        check_project_active(conn, project_id)
        row = get_claimable_open_intent_or_404(conn, project_id, intent_id, worker)
        check_attempt(conn, project_id, row, body.attempt_id)
        if row["worker"] != worker:
            raise HTTPException(409, "Intent is not claimed by worker")
        record(conn, project_id, intent_id, "stage", worker=worker,
               payload={"phase": phase, "call_id": body.call_id, "status": body.status})
        if body.status != "completed":
            conn.execute("UPDATE intents SET execution_status=? WHERE project_id=? AND id=?", (body.status, project_id, intent_id))
            row = conn.execute("SELECT * FROM intents WHERE project_id=? AND id=?", (project_id, intent_id)).fetchone()
        return intent_to_model(conn, row, project_id)
