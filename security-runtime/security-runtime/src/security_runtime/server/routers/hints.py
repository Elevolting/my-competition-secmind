import json
from typing import Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from security_runtime.server.db import get_conn
from security_runtime.server.models import CreateHintRequest, Hint
from security_runtime.server.services import check_project_hint_writable, next_hint_id, utcnow

router = APIRouter(tags=["hints"])


class WorkbenchSettings(BaseModel):
    run_id: str = Field(min_length=1)
    revision: int = Field(ge=0)
    target_scope: list[str] = Field(max_length=50)
    autonomy_policy: Literal["graded", "approval_all", "automatic", "automatic_r3"]


@router.put("/projects/{project_id}/workbench-settings")
def update_workbench_settings(project_id: str, body: WorkbenchSettings):
    with get_conn() as conn:
        project = check_project_hint_writable(conn, project_id)
        if project["title"] != "sec-task-" + body.run_id:
            raise HTTPException(409, "Workbench project identity mismatch")
        conn.execute(
            "DELETE FROM hints WHERE project_id=? AND creator='unified-workbench' "
            "AND (content LIKE 'planner_scope_json:%' OR content LIKE 'planner_policy_json:%' "
            "OR content LIKE '授权目标范围：%')", (project_id,),
        )
        now = utcnow()
        for content in (
            "planner_scope_json:" + json.dumps(body.target_scope, ensure_ascii=False),
            "planner_policy_json:" + json.dumps({"autonomy_policy": body.autonomy_policy,
                                                 "target_scope": body.target_scope}, ensure_ascii=False),
            "planner_settings_revision:" + str(body.revision),
        ):
            conn.execute(
                "INSERT INTO hints (id, project_id, content, creator, created_at) VALUES (?, ?, ?, ?, ?)",
                (next_hint_id(conn, project_id), project_id, content, "unified-workbench", now),
            )
        return {"project_id": project_id, "target_scope": body.target_scope,
                "autonomy_policy": body.autonomy_policy}


@router.post(
    "/projects/{project_id}/hints",
    response_model=Hint,
    status_code=201,
)
def create_hint(project_id: str, body: CreateHintRequest):
    with get_conn() as conn:
        check_project_hint_writable(conn, project_id)

        now = utcnow()
        hid = next_hint_id(conn, project_id)
        conn.execute(
            "INSERT INTO hints (id, project_id, content, creator, created_at) VALUES (?, ?, ?, ?, ?)",
            (hid, project_id, body.content, body.creator, now),
        )
        return Hint(id=hid, content=body.content, creator=body.creator, created_at=now)
