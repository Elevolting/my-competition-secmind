"""HTTP adapter for independent, snapshot-bound side questions."""

from __future__ import annotations

import asyncio
from typing import Annotated, Any
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

from secmind.config import Settings
from secmind.model_snapshots import SnapshotParent
from secmind.runtime import ApplicationRuntime
from secmind.side_questions import (
    SideQuestionBudgetExceeded,
    SideQuestionConflict,
    SideQuestionError,
)


class SideQuestionCreateRequest(BaseModel):
    question: str = Field(min_length=1, max_length=8_000)
    snapshot_id: str | None = Field(default=None, min_length=1, max_length=36)
    request_key: str | None = Field(default=None, min_length=1, max_length=200)
    estimated_input_tokens: int = Field(default=256, ge=1, le=2_000_000)


def register_side_questions(app: FastAPI, runtime: ApplicationRuntime, settings: Settings) -> None:
    tasks: set[asyncio.Task[Any]] = set()
    app.state.side_question_tasks = tasks

    def resources():
        """Resolve runtime-owned resources after application startup."""

        return runtime.side_questions, runtime.gateway, runtime.side_question_runner

    async def call_model(snapshot: dict[str, Any], question: str):
        callback = getattr(app.state, "side_question_call_model", None)
        if callback is not None:
            return await callback(snapshot, question)
        _, gateway, _ = resources()
        return await gateway.answer_side_question(snapshot, question)

    def check_run(run_id: str) -> None:
        try:
            runtime.service.state(run_id)
        except KeyError as exc:
            raise HTTPException(404, "Run not found") from exc

    def resolve_snapshot(run_id: str, snapshot_id: str | None) -> tuple[dict[str, Any], SnapshotParent]:
        check_run(run_id)
        store, _, _ = resources()
        snapshot = (
            store.snapshot_store.get(snapshot_id)
            if snapshot_id
            else store.snapshot_store.latest_for_run(run_id, "secmind")
        )
        if snapshot is None:
            raise HTTPException(409, "No model request snapshot is available; this run cannot be queried")
        parent_data = snapshot["parent"]
        if parent_data["run_id"] != run_id or parent_data["source"] != "secmind":
            raise HTTPException(409, "Snapshot does not belong to this SecMind run")
        return snapshot, SnapshotParent(
            run_id,
            "secmind",
            parent_data.get("step_id"),
            parent_data.get("worker_id"),
        )

    def check_question(question_id: str, run_id: str) -> dict[str, Any]:
        check_run(run_id)
        store, _, _ = resources()
        row = store.get(question_id)
        if row is None or row["parent"]["run_id"] != run_id or row["parent"]["source"] != "secmind":
            raise HTTPException(404, "Side-question request not found")
        return row

    def consume(task: asyncio.Task[Any]) -> None:
        tasks.discard(task)
        if not task.cancelled():
            try:
                task.exception()
            except (asyncio.CancelledError, SideQuestionError):
                pass

    @app.post("/api/v1/runs/{run_id}/side-questions", status_code=202)
    async def create_side_question(run_id: str, request: SideQuestionCreateRequest) -> dict[str, Any]:
        snapshot, parent = resolve_snapshot(run_id, request.snapshot_id)
        store, gateway, runner = resources()
        configuration = gateway.snapshot_configuration(snapshot["model_id"])
        if configuration.identity != snapshot["configuration_identity"]:
            raise HTTPException(409, "Model configuration changed; run the main task to refresh its snapshot")
        request_key = request.request_key or str(uuid4())
        try:
            reserved = store.reserve(
                parent=parent,
                snapshot_id=snapshot["snapshot_id"],
                configuration=configuration,
                request_key=request_key,
                question=request.question,
                estimated_input_tokens=request.estimated_input_tokens,
            )
        except (SideQuestionBudgetExceeded, SideQuestionConflict, ValueError) as exc:
            raise HTTPException(409, str(exc)) from exc
        if reserved["status"] == "queued":
            task = asyncio.create_task(runner.ask(
                parent=parent,
                snapshot_id=snapshot["snapshot_id"],
                configuration=configuration,
                request_key=request_key,
                question=request.question,
                estimated_input_tokens=request.estimated_input_tokens,
                call_model=call_model,
            ))
            tasks.add(task)
            task.add_done_callback(consume)
        return {"question": reserved, "accepted": reserved["status"] == "queued"}

    @app.get("/api/v1/runs/{run_id}/side-questions")
    async def list_side_questions(
        run_id: str,
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
    ) -> dict[str, Any]:
        check_run(run_id)
        store, _, _ = resources()
        return {"run_id": run_id, "items": store.history(run_id, limit=limit)}

    @app.get("/api/v1/runs/{run_id}/side-questions/{question_id}")
    async def get_side_question(run_id: str, question_id: str) -> dict[str, Any]:
        return {"question": check_question(question_id, run_id)}

    @app.get("/api/v1/runs/{run_id}/side-questions/{question_id}/events")
    async def get_side_question_events(
        run_id: str,
        question_id: str,
        after_sequence: Annotated[int, Query(ge=0)] = 0,
    ) -> dict[str, Any]:
        check_question(question_id, run_id)
        store, _, _ = resources()
        return {"question_id": question_id, "events": store.output_events(question_id, after_sequence=after_sequence)}

    @app.post("/api/v1/runs/{run_id}/side-questions/{question_id}/cancel")
    async def cancel_side_question(run_id: str, question_id: str) -> dict[str, Any]:
        check_question(question_id, run_id)
        store, _, _ = resources()
        try:
            return {"question": store.cancel(question_id)}
        except LookupError as exc:
            raise HTTPException(404, "Side-question request not found") from exc

    @app.post("/api/v1/runs/{run_id}/side-questions/{question_id}/clear")
    async def clear_side_question(run_id: str, question_id: str) -> dict[str, Any]:
        check_question(question_id, run_id)
        store, _, _ = resources()
        try:
            return {"question": store.clear_output(question_id)}
        except LookupError as exc:
            raise HTTPException(404, "Side-question request not found") from exc
