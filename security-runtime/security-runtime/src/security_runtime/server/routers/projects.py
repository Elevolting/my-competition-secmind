import hashlib
import hmac
import json
import os
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Header

from security_runtime.server.db import get_conn
from security_runtime.server.models import (
    ActivateDispatcherRequest,
    ApplyPlanningDecisionRequest,
    ApplyPlanningDecisionResponse,
    CompleteRequest,
    CreateProjectRequest,
    Fact,
    HeartbeatRequest,
    Hint,
    Intent,
    ProjectDetail,
    ProjectEvent,
    ProjectMeta,
    ProjectSummary,
    ReasonClaimRequest,
    ReopenRequest,
    ReopenResponse,
    UpdateProjectStatusRequest,
    UpdateProjectTitleRequest,
)
from security_runtime.server.services import (
    build_intents,
    check_project_active,
    check_project_completed,
    clear_project_reason,
    expire_reason_leases,
    expire_workers,
    get_completion_intent_or_409,
    get_project_or_404,
    intent_to_model,
    next_fact_id,
    next_hint_id,
    next_intent_id,
    next_project_id,
    project_meta_from_row,
    project_reason_from_row,
    utcnow,
    validate_facts_exist,
    validate_goal_not_in_sources,
    planning_snapshot_hash,
)
from security_runtime.server.execution import fact_from_row, record

router = APIRouter(tags=["projects"])


def check_reason_attempt(conn, project_id: str, row, attempt_id: str | None, *, require_claim: bool = True) -> None:
    workbench = is_workbench_project(conn, project_id)
    if row["reason_attempt_id"] != attempt_id and (workbench or attempt_id is not None):
        raise HTTPException(409, "Project reason execution attempt has changed")
    if workbench and require_claim and (row["reason_worker"] is None or attempt_id is None):
        raise HTTPException(409, "Current project reason execution attempt is required")


def is_workbench_project(conn, project_id: str) -> bool:
    return conn.execute(
        "SELECT 1 FROM hints WHERE project_id=? AND creator='unified-workbench' "
        "AND content LIKE 'workbench_planner:run_id=%;schema=1.1' LIMIT 1",
        (project_id,),
    ).fetchone() is not None


def require_planner_token(token: str | None) -> None:
    expected = os.environ.get("SECURITY_RUNTIME_CALLBACK_TOKEN", "")
    if not expected or not token or not hmac.compare_digest(expected, token):
        raise HTTPException(403, "Authenticated workbench planning credential is required")


@router.get("/projects", response_model=list[ProjectSummary])
def list_projects():
    with get_conn() as conn:
        expire_workers(conn)
        expire_reason_leases(conn)
        rows = conn.execute("""
            SELECT p.*,
                (SELECT COUNT(*) FROM facts WHERE project_id = p.id) AS fact_count,
                (SELECT COUNT(*) FROM intents WHERE project_id = p.id) AS intent_count,
                (SELECT COUNT(*) FROM intents WHERE project_id = p.id AND concluded_at IS NULL AND worker IS NOT NULL) AS working_intent_count,
                (SELECT COUNT(*) FROM intents WHERE project_id = p.id AND concluded_at IS NULL AND worker IS NULL) AS unclaimed_intent_count,
                (SELECT COUNT(*) FROM hints WHERE project_id = p.id) AS hint_count
            FROM projects p
            ORDER BY p.created_at
        """).fetchall()
        return [
            ProjectSummary(
                id=row["id"],
                title=row["title"],
                status=row["status"],
                bootstrap_enabled=bool(row["bootstrap_enabled"]),
                dispatcher_enabled=bool(row["dispatcher_enabled"]),
                created_at=row["created_at"],
                reason_attempt_id=row["reason_attempt_id"],
                reason_decision_pending=bool(row["reason_decision_pending"]),
                reason=project_reason_from_row(row),
                fact_count=row["fact_count"],
                intent_count=row["intent_count"],
                working_intent_count=row["working_intent_count"],
                unclaimed_intent_count=row["unclaimed_intent_count"],
                hint_count=row["hint_count"],
            )
            for row in rows
        ]


@router.post("/projects", response_model=ProjectDetail, status_code=201)
def create_project(body: CreateProjectRequest):
    if body.dispatcher_activation_token and body.dispatcher_enabled:
        raise HTTPException(422, "Activation token requires a disabled dispatcher")
    with get_conn() as conn:
        conn.execute('BEGIN IMMEDIATE')
        payload_hash = hashlib.sha256(body.model_dump_json().encode()).hexdigest()
        if body.idempotency_key:
            previous = conn.execute('SELECT * FROM projects WHERE creation_key=?',
                                    (body.idempotency_key,)).fetchone()
            if previous:
                if previous['creation_payload_hash'] != payload_hash:
                    raise HTTPException(409, 'Project creation key was reused with different content')
                facts = conn.execute('SELECT * FROM facts WHERE project_id=?', (previous['id'],)).fetchall()
                hints = conn.execute('SELECT * FROM hints WHERE project_id=? ORDER BY created_at',
                                     (previous['id'],)).fetchall()
                return ProjectDetail(project=project_meta_from_row(previous),
                    facts=[fact_from_row(f) for f in facts], intents=build_intents(conn, previous['id']),
                    hints=[Hint(**dict(h)) for h in hints])
        pid = next_project_id(conn)
        now = utcnow()

        conn.execute(
            "INSERT INTO projects (id, title, status, bootstrap_enabled, dispatcher_enabled, "
            "dispatcher_activation_hash, creation_key, creation_payload_hash, created_at) "
            "VALUES (?, ?, 'active', ?, ?, ?, ?, ?, ?)",
            (pid, body.title, body.bootstrap_enabled, body.dispatcher_enabled,
             hashlib.sha256(body.dispatcher_activation_token.encode()).hexdigest()
             if body.dispatcher_activation_token else None, body.idempotency_key, payload_hash, now),
        )
        conn.execute(
            "INSERT INTO facts (id, project_id, description) VALUES (?, ?, ?)",
            ("origin", pid, body.origin),
        )
        conn.execute(
            "INSERT INTO facts (id, project_id, description) VALUES (?, ?, ?)",
            ("goal", pid, body.goal),
        )

        hints = []
        if body.hints:
            for h in body.hints:
                hid = next_hint_id(conn, pid)
                conn.execute(
                    "INSERT INTO hints (id, project_id, content, creator, created_at) VALUES (?, ?, ?, ?, ?)",
                    (hid, pid, h.content, h.creator, now),
                )
                hints.append(Hint(id=hid, content=h.content, creator=h.creator, created_at=now))

        return ProjectDetail(
            project=ProjectMeta(
                id=pid,
                title=body.title,
                status="active",
                bootstrap_enabled=body.bootstrap_enabled,
                dispatcher_enabled=body.dispatcher_enabled,
                created_at=now,
                reason=None,
            ),
            facts=[
                Fact(id="origin", description=body.origin),
                Fact(id="goal", description=body.goal),
            ],
            intents=[],
            hints=hints,
        )


@router.get("/projects/{project_id}", response_model=ProjectDetail)
def get_project(project_id: str):
    with get_conn() as conn:
        expire_workers(conn, project_id)
        expire_reason_leases(conn, project_id)
        row = get_project_or_404(conn, project_id)

        facts = conn.execute(
            "SELECT * FROM facts WHERE project_id = ?", (project_id,)
        ).fetchall()
        hints = conn.execute(
            "SELECT * FROM hints WHERE project_id = ? ORDER BY created_at",
            (project_id,),
        ).fetchall()

        return ProjectDetail(
            project=project_meta_from_row(row),
            facts=[fact_from_row(f) for f in facts],
            intents=build_intents(conn, project_id),
            hints=[Hint(**dict(h)) for h in hints],
        )


@router.get("/projects/{project_id}/events", response_model=dict)
def project_events(project_id: str, after: int = 0, limit: int = 200):
    if after < 0 or not 1 <= limit <= 1000:
        raise HTTPException(422, "Invalid event cursor or limit")
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        expire_workers(conn, project_id)
        rows = conn.execute(
            "SELECT * FROM project_events WHERE project_id=? AND sequence>? ORDER BY sequence LIMIT ?",
            (project_id, after, limit),
        ).fetchall()
        events = [ProjectEvent(
            sequence=row["sequence"], event_id=row["event_id"], project_id=row["project_id"],
            intent_id=row["intent_id"], attempt_id=row["attempt_id"], event_type=row["event_type"],
            worker=row["worker"], timestamp=row["timestamp"], payload=json.loads(row["payload_json"]),
        ) for row in rows]
        return {"events": [event.model_dump() for event in events], "next_cursor": rows[-1]["sequence"] if rows else after}


@router.delete("/projects/{project_id}", status_code=204)
def delete_project(project_id: str):
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        conn.execute("DELETE FROM projects WHERE id = ?", (project_id,))


@router.put("/projects/{project_id}/title", response_model=ProjectMeta)
def update_project_title(project_id: str, body: UpdateProjectTitleRequest):
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        conn.execute(
            "UPDATE projects SET title = ? WHERE id = ?",
            (body.title, project_id),
        )
        updated = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
        return project_meta_from_row(updated)


@router.put("/projects/{project_id}/status", response_model=ProjectMeta)
def update_project_status(project_id: str, body: UpdateProjectStatusRequest):
    with get_conn() as conn:
        expire_reason_leases(conn, project_id)
        row = get_project_or_404(conn, project_id)
        current_status = row["status"]
        if current_status == "completed":
            raise HTTPException(409, "Completed projects cannot change status")
        if current_status == body.status:
            return project_meta_from_row(row)

        conn.execute(
            "UPDATE projects SET status = ? WHERE id = ?",
            (body.status, project_id),
        )
        if body.status == "stopped":
            open_rows = conn.execute("SELECT id,worker FROM intents WHERE project_id=? AND concluded_at IS NULL", (project_id,)).fetchall()
            for intent in open_rows:
                record(conn, project_id, intent["id"], "cancelled", worker=intent["worker"], payload={"reason": "project_stopped"})
            conn.execute(
                "UPDATE intents SET worker = NULL, execution_status='cancelled' WHERE project_id = ? AND concluded_at IS NULL",
                (project_id,),
            )
            clear_project_reason(conn, project_id)
        record(conn, project_id, None, "project_status", payload={"status": body.status})
        updated = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
        return project_meta_from_row(updated)


@router.post("/projects/{project_id}/dispatcher/activate", response_model=ProjectMeta)
def activate_project_dispatcher(project_id: str, body: ActivateDispatcherRequest):
    with get_conn() as conn:
        row = get_project_or_404(conn, project_id)
        if row["title"] != body.title or row["status"] != "active":
            raise HTTPException(409, "Project identity or status does not permit dispatcher activation")
        # Once enabled, activation is an idempotent read.  The credential was
        # consumed by the first successful transition and is not needed again.
        if row["dispatcher_enabled"]:
            return project_meta_from_row(row)
        if body.activation_token is None:
            raise HTTPException(403, "Dispatcher activation credential is required")
        digest = hashlib.sha256(body.activation_token.encode()).hexdigest()
        stored = row["dispatcher_activation_hash"]
        if not isinstance(stored, str) or not hmac.compare_digest(stored, digest):
            raise HTTPException(403, "Invalid dispatcher activation credential")
        conn.execute(
            "UPDATE projects SET dispatcher_enabled = 1, dispatcher_activation_hash = NULL "
            "WHERE id = ? AND status = 'active' "
            "AND title = ? AND dispatcher_activation_hash = ?",
            (project_id, body.title, digest),
        )
        row = get_project_or_404(conn, project_id)
        if row["status"] != "active" or row["title"] != body.title:
            raise HTTPException(409, "Project identity or status changed during dispatcher activation")
        if not row["dispatcher_enabled"]:
            raise HTTPException(409, "Dispatcher activation was superseded by another request")
        return project_meta_from_row(row)


@router.post(
    "/projects/{project_id}/planning/decisions",
    response_model=ApplyPlanningDecisionResponse,
)
def apply_planning_decision(project_id: str, body: ApplyPlanningDecisionRequest,
                            planner_token: str | None = Header(default=None, alias="X-Security-Runtime-Token")):
    """Atomically apply one idempotent workbench planning round."""
    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        # Resolve replays before the active-state guard. A lost HTTP response
        # can be retried after the decision completed the project; returning
        # the original response is the idempotent contract in that case.
        get_project_or_404(conn, project_id)
        if is_workbench_project(conn, project_id):
            require_planner_token(planner_token)
        previous = conn.execute(
            "SELECT snapshot_hash,response_json FROM planning_decisions WHERE project_id=? AND decision_id=?",
            (project_id, body.decision_id),
        ).fetchone()
        if previous is not None:
            if previous["snapshot_hash"] != body.snapshot_hash:
                raise HTTPException(409, "Planning decision ID was reused with a different snapshot")
            current = get_project_or_404(conn, project_id)
            if current["status"] == "active" and current["reason_decision_pending"] and is_workbench_project(conn, project_id):
                expire_reason_leases(conn, project_id)
                current = get_project_or_404(conn, project_id)
                check_reason_attempt(conn, project_id, current, body.reason_attempt_id)
                conn.execute("UPDATE projects SET reason_decision_pending=0 WHERE id=?", (project_id,))
            saved = ApplyPlanningDecisionResponse.model_validate_json(previous["response_json"])
            return saved.model_copy(update={"status": "replayed"})

        check_project_active(conn, project_id)

        expire_reason_leases(conn, project_id)
        project = get_project_or_404(conn, project_id)

        if is_workbench_project(conn, project_id):
            check_reason_attempt(conn, project_id, project, body.reason_attempt_id)

        current_row = get_project_or_404(conn, project_id)
        fact_rows = conn.execute("SELECT * FROM facts WHERE project_id=?", (project_id,)).fetchall()
        hint_rows = conn.execute("SELECT * FROM hints WHERE project_id=? ORDER BY created_at", (project_id,)).fetchall()
        current_detail = ProjectDetail(
            project=project_meta_from_row(current_row),
            facts=[fact_from_row(item) for item in fact_rows],
            intents=build_intents(conn, project_id),
            hints=[Hint(**dict(item)) for item in hint_rows],
        )
        if planning_snapshot_hash(current_detail) != body.snapshot_hash:
            raise HTTPException(409, "Planning snapshot is stale; request a fresh decision")

        if body.completion_validated and body.intents:
            raise HTTPException(422, "A planning round cannot add directions and complete at the same time")
        if body.completion_validated and not body.completion_fact_ids:
            raise HTTPException(422, "Validated completion requires source facts")
        if body.completion_validated and not body.completion_reason:
            raise HTTPException(422, "Validated completion requires an auditable summary")
        if body.stop_reason and body.intents:
            raise HTTPException(422, "A stop decision cannot include new directions")

        from security_runtime.server.planning_dependencies import confirm_outputs, validate_graph
        if body.validated_outputs or any(p.step_id or p.depends_on or p.required_outputs for p in body.intents):
            require_planner_token(planner_token)
        validate_graph(conn, project_id, body.intents)
        confirm_outputs(conn, project_id, body.validated_outputs)

        existing_facts = {row["id"] for row in conn.execute(
            "SELECT id FROM facts WHERE project_id=? AND id!='goal'", (project_id,)
        ).fetchall()}
        intent_ids: list[str] = []
        now = utcnow()
        for index, proposal in enumerate(body.intents):
            if any(source not in existing_facts for source in proposal.from_):
                raise HTTPException(404, "Planning intent references a fact outside this project")
            if "goal" in proposal.from_:
                raise HTTPException(400, "goal cannot be used in planning intent sources")
            if any(source not in proposal.from_ for source in proposal.source_relations):
                raise HTTPException(422, "Source relation keys must be included in the source facts")
            if proposal.retry_intent_id:
                retry = conn.execute('SELECT * FROM intents WHERE project_id=? AND id=?',
                                     (project_id, proposal.retry_intent_id)).fetchone()
                if not retry or retry['to_fact_id'] or retry['worker'] or retry['execution_status'] not in {'failed', 'timeout'}:
                    raise HTTPException(409, 'Only a released failed or timed-out intent may be retried')
                sources = {r['fact_id'] for r in conn.execute(
                    'SELECT fact_id FROM intent_sources WHERE project_id=? AND intent_id=?',
                    (project_id, proposal.retry_intent_id))}
                if sources != set(proposal.from_):
                    raise HTTPException(422, 'Retry must preserve the original source facts')
                conn.execute("UPDATE intents SET execution_status='waiting',decision_id=?,decision_summary=? "
                             "WHERE project_id=? AND id=?",
                             (body.decision_id, body.summary, project_id, proposal.retry_intent_id))
                record(conn, project_id, proposal.retry_intent_id, 'retry_scheduled', worker='workbench_planner',
                       payload={'decision_id': body.decision_id, 'summary': body.summary})
                intent_ids.append(proposal.retry_intent_id)
                continue
            intent_id = next_intent_id(conn, project_id)
            creator = "workbench_planner"
            conn.execute(
                "INSERT INTO intents (id,project_id,to_fact_id,description,tool_name,creator,worker,created_at,"
                "source_relation,success_criteria,title,verification_target,decision_id,decision_summary) "
                "VALUES (?,?,NULL,?,?,?,NULL,?,?,?,?,?,?,?)",
                (intent_id, project_id, proposal.description, proposal.tool_name, creator, now,
                 proposal.source_relation, "; ".join(proposal.success_criteria)[:4000] or None,
                 proposal.title, proposal.verification_target, body.decision_id, body.summary),
            )
            conn.execute(
                "UPDATE intents SET source_relations_json=? WHERE project_id=? AND id=?",
                (json.dumps({fid: relation for fid, relation in proposal.source_relations.items()}, ensure_ascii=False),
                 project_id, intent_id),
            )
            conn.execute('UPDATE intents SET step_id=?,depends_on_json=?,required_outputs_json=? '
                         'WHERE project_id=? AND id=?',
                         (proposal.step_id, json.dumps(proposal.depends_on), json.dumps(proposal.required_outputs),
                          project_id, intent_id))
            for fact_id in proposal.from_:
                conn.execute(
                    "INSERT INTO intent_sources (intent_id,project_id,fact_id) VALUES (?,?,?)",
                    (intent_id, project_id, fact_id),
                )
            record(conn, project_id, intent_id, "created", worker=creator,
                   payload={"sources": proposal.from_, "decision_id": body.decision_id,
                            "title": proposal.title, "verification_target": proposal.verification_target})
            intent_ids.append(intent_id)

        if body.completion_validated:
            if any(fact_id not in existing_facts for fact_id in body.completion_fact_ids):
                raise HTTPException(404, "Completion references a fact outside this project")
            unfinished_rows = conn.execute(
                "SELECT id,worker FROM intents WHERE project_id=? AND to_fact_id IS NULL "
                "AND execution_status NOT IN ('failed','timeout','cancelled')", (project_id,)
            ).fetchall()
            for unfinished in unfinished_rows:
                record(conn, project_id, unfinished["id"], "cancelled",
                       worker=unfinished["worker"] or "workbench_planner",
                       payload={"reason": "Goal verified", "decision_id": body.decision_id})
            conn.execute(
                "UPDATE intents SET execution_status='cancelled',worker=NULL "
                "WHERE project_id=? AND to_fact_id IS NULL "
                "AND execution_status NOT IN ('failed','timeout','cancelled')", (project_id,),
            )
            completion_id = next_intent_id(conn, project_id)
            conn.execute(
                "INSERT INTO intents (id,project_id,to_fact_id,description,creator,worker,last_heartbeat_at,"
                "created_at,concluded_at,execution_status,decision_id,decision_summary) "
                "VALUES (?,?, 'goal', ?, ?, ?, ?, ?, ?, 'completed', ?, ?)",
                (completion_id, project_id, body.completion_reason, "workbench_planner", "workbench_planner",
                 now, now, now, body.decision_id, body.summary),
            )
            for fact_id in body.completion_fact_ids:
                conn.execute(
                    "INSERT INTO intent_sources (intent_id,project_id,fact_id) VALUES (?,?,?)",
                    (completion_id, project_id, fact_id),
                )
            conn.execute("UPDATE projects SET status='completed' WHERE id=?", (project_id,))
            clear_project_reason(conn, project_id)
            record(conn, project_id, completion_id, "completed", worker="workbench_planner",
                   payload={"fact_id": "goal", "project_completed": True,
                            "decision_id": body.decision_id, "source_facts": body.completion_fact_ids})
            status = "completed"
        elif body.stop_reason:
            open_rows = conn.execute(
                "SELECT id,worker FROM intents WHERE project_id=? AND to_fact_id IS NULL", (project_id,)
            ).fetchall()
            for intent in open_rows:
                record(conn, project_id, intent["id"], "cancelled", worker=intent["worker"],
                       payload={"reason": body.stop_reason, "decision_id": body.decision_id})
            conn.execute("UPDATE intents SET execution_status='cancelled',worker=NULL "
                         "WHERE project_id=? AND to_fact_id IS NULL", (project_id,))
            conn.execute("UPDATE projects SET status='stopped' WHERE id=?", (project_id,))
            clear_project_reason(conn, project_id)
            record(conn, project_id, None, "project_status", worker="workbench_planner",
                   payload={"status": "stopped", "reason": body.stop_reason,
                            "decision_id": body.decision_id})
            status = "stopped"
        else:
            status = "created"

        conn.execute("UPDATE projects SET reason_decision_pending=0 WHERE id=?", (project_id,))

        result = ApplyPlanningDecisionResponse(
            decision_id=body.decision_id, project_id=project_id, status=status,
            intent_ids=intent_ids, summary=body.summary, stop_reason=body.stop_reason,
        )
        conn.execute(
            "INSERT INTO planning_decisions(project_id,decision_id,snapshot_hash,response_json,created_at) "
            "VALUES (?,?,?,?,?)",
            (project_id, body.decision_id, body.snapshot_hash,
             result.model_dump_json(), now),
        )
        record(conn, project_id, None, "planning_decision", worker="workbench_planner",
               payload={"decision_id": body.decision_id, "snapshot_hash": body.snapshot_hash,
                        "trigger": body.trigger, "summary": body.summary,
                        "intent_ids": intent_ids, "completion_validated": body.completion_validated,
                        "stop_reason": body.stop_reason})
        return result


@router.post("/projects/{project_id}/reason/claim", response_model=ProjectMeta)
def claim_project_reason(project_id: str, body: ReasonClaimRequest):
    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        check_project_active(conn, project_id)
        expire_reason_leases(conn, project_id)
        row = get_project_or_404(conn, project_id)
        check_reason_attempt(conn, project_id, row, body.attempt_id, require_claim=False)
        current_worker = row["reason_worker"]
        if current_worker is not None and current_worker != body.worker:
            raise HTTPException(409, f"Project reason is currently claimed by {current_worker}")
        if current_worker == body.worker:
            return project_meta_from_row(row)

        now = utcnow()
        decision_pending = is_workbench_project(conn, project_id)
        conn.execute(
            """
            UPDATE projects
            SET reason_worker = ?,
                reason_attempt_id = ?,
                reason_decision_pending = ?,
                reason_trigger = ?,
                reason_started_at = ?,
                reason_last_heartbeat_at = ?
            WHERE id = ?
            """,
            (body.worker, str(uuid4()), decision_pending, body.trigger, now, now, project_id),
        )
        updated = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
        return project_meta_from_row(updated)


@router.post("/projects/{project_id}/reason/heartbeat", response_model=ProjectMeta)
def heartbeat_project_reason(project_id: str, body: HeartbeatRequest):
    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        check_project_active(conn, project_id)
        expire_reason_leases(conn, project_id)
        row = get_project_or_404(conn, project_id)
        check_reason_attempt(conn, project_id, row, body.attempt_id)
        current_worker = row["reason_worker"]
        if current_worker is None:
            raise HTTPException(409, "Project reason is not currently claimed")
        if current_worker != body.worker:
            raise HTTPException(409, f"Project reason is currently claimed by {current_worker}")

        now = utcnow()
        conn.execute(
            "UPDATE projects SET reason_last_heartbeat_at = ? WHERE id = ?",
            (now, project_id),
        )
        updated = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
        return project_meta_from_row(updated)


@router.post("/projects/{project_id}/reason/release", response_model=ProjectMeta)
def release_project_reason(project_id: str, body: HeartbeatRequest):
    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        check_project_active(conn, project_id)
        expire_reason_leases(conn, project_id)
        row = get_project_or_404(conn, project_id)
        check_reason_attempt(conn, project_id, row, body.attempt_id)
        current_worker = row["reason_worker"]
        if current_worker is None:
            return project_meta_from_row(row)
        if current_worker != body.worker:
            raise HTTPException(409, f"Project reason is currently claimed by {current_worker}")

        clear_project_reason(conn, project_id)
        updated = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
        return project_meta_from_row(updated)


@router.post("/projects/{project_id}/complete", response_model=Intent)
def complete_project(project_id: str, body: CompleteRequest):
    with get_conn() as conn:
        check_project_active(conn, project_id)
        if is_workbench_project(conn, project_id):
            raise HTTPException(403, "Workbench projects require a validated planning decision to complete")
        expire_reason_leases(conn, project_id)
        validate_facts_exist(conn, project_id, body.from_)
        validate_goal_not_in_sources(body.from_)

        now = utcnow()
        iid = next_intent_id(conn, project_id)

        conn.execute(
            "INSERT INTO intents (id, project_id, to_fact_id, description, creator, worker, last_heartbeat_at, created_at, concluded_at) VALUES (?, ?, 'goal', ?, ?, ?, ?, ?, ?)",
            (iid, project_id, body.description, body.worker, body.worker, now, now, now),
        )
        for fid in body.from_:
            conn.execute(
                "INSERT INTO intent_sources (intent_id, project_id, fact_id) VALUES (?, ?, ?)",
                (iid, project_id, fid),
            )
        conn.execute(
            """
            UPDATE projects
            SET status = 'completed',
                reason_worker = NULL,
                reason_trigger = NULL,
                reason_started_at = NULL,
                reason_last_heartbeat_at = NULL
            WHERE id = ?
            """,
            (project_id,),
        )
        conn.execute("UPDATE intents SET execution_status='completed' WHERE project_id=? AND id=?", (project_id, iid))
        for unfinished in conn.execute("SELECT id,worker FROM intents WHERE project_id=? AND concluded_at IS NULL", (project_id,)).fetchall():
            record(conn, project_id, unfinished["id"], "cancelled", worker=unfinished["worker"], payload={"reason": "project_completed"})
        conn.execute("UPDATE intents SET execution_status='cancelled',worker=NULL WHERE project_id=? AND concluded_at IS NULL", (project_id,))
        record(conn, project_id, iid, "completed", worker=body.worker, payload={"fact_id": "goal", "project_completed": True})

        return Intent(
            id=iid,
            **{"from": body.from_},
            to="goal",
            description=body.description,
            creator=body.worker,
            worker=body.worker,
            last_heartbeat_at=now,
            created_at=now,
            concluded_at=now,
            execution_status="completed",
        )


@router.post("/projects/{project_id}/reopen", response_model=ReopenResponse, response_model_exclude_defaults=True)
def reopen_project(project_id: str, body: ReopenRequest):
    with get_conn() as conn:
        expire_reason_leases(conn, project_id)
        check_project_completed(conn, project_id)
        completion = get_completion_intent_or_409(conn, project_id)

        source_rows = conn.execute(
            "SELECT fact_id FROM intent_sources WHERE intent_id = ? AND project_id = ? ORDER BY rowid",
            (completion["id"], project_id),
        ).fetchall()
        source_ids = [row["fact_id"] for row in source_rows]
        if not source_ids:
            raise HTTPException(409, "Completion intent is missing its source facts")

        now = utcnow()
        fact_id = next_fact_id(conn, project_id)
        intent_id = next_intent_id(conn, project_id)
        description = body.description
        creator = body.creator

        conn.execute(
            "DELETE FROM intents WHERE id = ? AND project_id = ?",
            (completion["id"], project_id),
        )
        conn.execute(
            "INSERT INTO facts (id, project_id, description) VALUES (?, ?, ?)",
            (fact_id, project_id, description),
        )
        conn.execute(
            "INSERT INTO intents (id, project_id, to_fact_id, description, creator, worker, last_heartbeat_at, created_at, concluded_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (intent_id, project_id, fact_id, "external_feedback", creator, creator, now, now, now),
        )
        for source_id in source_ids:
            conn.execute(
                "INSERT INTO intent_sources (intent_id, project_id, fact_id) VALUES (?, ?, ?)",
                (intent_id, project_id, source_id),
            )
        clear_project_reason(conn, project_id)
        conn.execute(
            "UPDATE projects SET status = 'active' WHERE id = ?",
            (project_id,),
        )

        updated_project = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
        updated_intent = conn.execute(
            "SELECT * FROM intents WHERE id = ? AND project_id = ?",
            (intent_id, project_id),
        ).fetchone()
        assert updated_project is not None
        assert updated_intent is not None
        return ReopenResponse(
            project=project_meta_from_row(updated_project),
            fact=Fact(id=fact_id, description=description),
            intent=intent_to_model(conn, updated_intent, project_id),
        )
