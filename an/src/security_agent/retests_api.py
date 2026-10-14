"""Focused retest creation and task-linked progress reads."""
from __future__ import annotations

import asyncio
import logging
from typing import Literal
from uuid import NAMESPACE_URL, uuid5

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field

from security_agent.budget_policy import MAX_MODEL_CALLS, MAX_RUNTIME_SECONDS, MAX_TOOL_CALLS
from security_agent.retests import RetestStore, prepare_retest_task
from security_agent.schemas import AttachmentRef, RunStatus
from security_agent.trace_redaction import redact_trace

LOG = logging.getLogger(__name__)


class RetestCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_kind: Literal["finding", "conclusion"]
    source_ref: str = Field(min_length=1, max_length=512)
    request_id: str = Field(min_length=16, max_length=100, pattern=r"^[a-zA-Z0-9_-]+$")
    notes: str = Field(default="", max_length=2000)
    attachments: list[AttachmentRef] = Field(default_factory=list, max_length=20)
    max_runtime_seconds: int | None = Field(default=None, ge=60, le=MAX_RUNTIME_SECONDS)
    max_tool_calls: int | None = Field(default=None, ge=1, le=MAX_TOOL_CALLS)
    max_model_calls: int | None = Field(default=None, ge=1, le=MAX_MODEL_CALLS)


class RetestResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    verdict: Literal["reproduced", "fixed", "supported", "refuted", "inconclusive"]
    summary: str = Field(min_length=1, max_length=4000)
    checks: dict[str, list[str]] = Field(default_factory=dict, max_length=8)


def register_retests(app, service, settings):
    store = RetestStore(service.ledger)
    app.state.retests = store

    def refresh(record):
        child = service.ledger.load_state(record["child_run_id"])
        if child is None:
            return record
        if child.status in {RunStatus.PENDING, RunStatus.RUNNING, RunStatus.WAITING_APPROVAL}:
            status = "running"
        elif child.status == RunStatus.PARTIAL and child.external_execution.get("status") in {
            "cancelled", "cancellation_requested", "cancellation_unconfirmed",
        }:
            status = "stopped"
        elif child.status in {RunStatus.COMPLETED, RunStatus.PARTIAL}:
            status = "awaiting_result"
        else:
            status = "failed"
        if record["status"] in {"pending", "dispatching", "running"} and status != record["status"]:
            return {**record, **store.set_status(record["retest_id"], status,
                child.last_error if status == "failed" else None)}
        return record

    def dispatch(record, source):
        retest_id = record["retest_id"]
        child_run_id = record["child_run_id"]
        if service.ledger.load_state(child_run_id) is not None:
            return refresh(record)
        if not store.claim_dispatch(retest_id):
            return store.get(source.run_id, retest_id)
        try:
            saved = store.parameters(retest_id)
            params = RetestCreate.model_validate({"request_id": retest_id.replace("-", ""), **saved})
            snapshot = record["snapshot"]
            if (redact_trace(source.task.target_scope) != snapshot["target_scope"]
                    or source.task.network_policy != snapshot["network_policy"]):
                raise ValueError("原任务授权范围已变化，不能接续复核")
            task = prepare_retest_task(source, record, settings, params.notes, params.attachments)
            context = {"retest": {
                "retest_id": retest_id, "source_run_id": source.run_id,
                "source_kind": record["source_kind"], "source_ref": record["source_ref"],
                "module_route": snapshot["module_route"],
                "snapshot_sha256": record["snapshot_sha256"],
                "original": snapshot["original"], "historical_evidence": snapshot["evidence"][:20],
            }}
            service.submit(task, run_id=child_run_id, retry_context=context,
                           max_runtime_seconds=params.max_runtime_seconds,
                           max_tool_calls=params.max_tool_calls,
                           max_model_calls=params.max_model_calls)
            service.ledger.append(child_run_id, "retest.created", {
                "retest_id": retest_id, "source_run_id": source.run_id,
                "snapshot_sha256": record["snapshot_sha256"]}, actor="api",
                event_id=str(uuid5(NAMESPACE_URL, f"retest-created:{retest_id}")))
            return {**record, **store.set_status(retest_id, "running")}
        except (OSError, ValueError):
            if service.ledger.load_state(child_run_id) is None:
                store.set_status(retest_id, "failed", "复核子任务提交失败")
                raise
            return refresh(store.get(source.run_id, retest_id))

    async def recover_pending():
        for record in store.dispatchable():
            source = service.ledger.load_state(record["source_run_id"])
            if source is None:
                store.set_status(record["retest_id"], "failed", "原任务已不存在")
                continue
            try:
                dispatch(record, source)
            except (OSError, ValueError):
                LOG.exception("Could not resume retest %s", record["retest_id"])

    async def recover_claims_after_restart():
        while any(service.ledger.load_state(item["child_run_id"]) is None
                  for item in store.dispatching()):
            await asyncio.sleep(60)
            await recover_pending()

    def start_claim_recovery():
        if any(service.ledger.load_state(item["child_run_id"]) is None
               for item in store.dispatching()):
            service._spawn(recover_claims_after_restart())

    app.state.recover_retests = recover_pending
    app.state.recover_retest_claims = start_claim_recovery

    @app.post("/api/v1/runs/{run_id}/retests", status_code=202)
    async def create(run_id: str, payload: RetestCreate):
        source = service.ledger.load_state(run_id)
        if source is None:
            raise HTTPException(404, "来源任务不存在")
        if source.status in {RunStatus.PENDING, RunStatus.RUNNING, RunStatus.WAITING_APPROVAL}:
            raise HTTPException(409, "来源任务尚未结束，请等待历史报告生成")
        async with service.run_lock(run_id):
            source = service.ledger.load_state(run_id)
            if source is None:
                raise HTTPException(404, "来源任务不存在")
            safe_notes = redact_trace(payload.notes.strip())
            parameters = payload.model_dump(mode="json", exclude={"request_id"})
            parameters["notes"] = safe_notes
            try:
                record, _ = store.reserve(source, payload.source_kind, payload.source_ref,
                                          payload.request_id, parameters)
                return {"schema_version": "1.0", **refresh(dispatch(record, source))}
            except KeyError as exc:
                raise HTTPException(404, "复核来源对象不存在") from exc
            except (OSError, ValueError) as exc:
                raise HTTPException(409, str(exc)) from exc

    @app.get("/api/v1/runs/{run_id}/retests")
    async def list_retests(run_id: str):
        if service.ledger.load_state(run_id) is None:
            raise HTTPException(404, "来源任务不存在")
        return {"schema_version": "1.0", "retests": [refresh(item) for item in store.list(run_id)]}

    @app.get("/api/v1/runs/{run_id}/retests/{retest_id}")
    async def detail(run_id: str, retest_id: str):
        try:
            return {"schema_version": "1.0", **refresh(store.get(run_id, retest_id))}
        except KeyError as exc:
            raise HTTPException(404, "复核记录不存在") from exc

    @app.post("/api/v1/runs/{run_id}/retests/{retest_id}/result")
    async def record_result(run_id: str, retest_id: str, payload: RetestResult):
        try:
            record = refresh(store.get(run_id, retest_id))
            child = service.ledger.load_state(record["child_run_id"])
            if child is None:
                raise ValueError("复核子任务不存在")
            if child.status in {RunStatus.PENDING, RunStatus.RUNNING, RunStatus.WAITING_APPROVAL}:
                raise ValueError("复核子任务尚未生成可用报告")
            async with service.run_lock(child.run_id):
                child = service.state(child.run_id)
                result = store.finish(run_id, retest_id, child, payload.verdict,
                                      payload.summary, payload.checks)
            event = service.ledger.append(run_id, "retest.result.recorded", {
                "retest_id": retest_id, "child_run_id": child.run_id,
                "verdict": result["verdict"], "evidence_ids": result["evidence_ids"]},
                actor="operator", event_id=retest_id)
            await service.event_hub.publish(event.model_dump(mode="json"))
            return {"schema_version": "1.0", **result}
        except KeyError as exc:
            raise HTTPException(404, "复核记录不存在") from exc
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.post("/api/v1/runs/{run_id}/retests/{retest_id}/cancel")
    async def cancel_retest(run_id: str, retest_id: str):
        try:
            record = refresh(store.get(run_id, retest_id))
            if record["status"] == "dispatching":
                raise ValueError("复核子任务正在提交，请稍后取消")
            if record["status"] not in {"pending", "running", "awaiting_result"}:
                return {"schema_version": "1.0", **record}
            child = service.ledger.load_state(record["child_run_id"])
            if child is not None and child.status in {
                RunStatus.PENDING, RunStatus.RUNNING, RunStatus.WAITING_APPROVAL,
            }:
                await service.cancel(child.run_id, "用户取消独立复核")
            return {"schema_version": "1.0", **store.set_status(retest_id, "stopped")}
        except KeyError as exc:
            raise HTTPException(404, "复核记录不存在") from exc
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
