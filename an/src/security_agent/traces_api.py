from __future__ import annotations

import asyncio

from fastapi import HTTPException, Query


def register_traces(app, store):
    app.state.traces = store

    @app.get("/api/v1/runs/{run_id}/traces")
    async def search(run_id: str, keyword: str = Query("", max_length=500), module: str | None = None,
                     worker: str | None = None, cursor: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=100)):
        try:
            return await asyncio.to_thread(store.search, run_id, keyword=keyword, module=module,
                                           worker=worker, cursor=cursor, limit=limit)
        except KeyError as exc:
            raise HTTPException(404, "任务不存在") from exc

    @app.get("/api/v1/runs/{run_id}/traces/{trace_id}")
    async def detail(run_id: str, trace_id: str):
        try:
            return await asyncio.to_thread(store.detail, run_id, trace_id)
        except KeyError as exc:
            raise HTTPException(404, "执行记录不存在于此任务") from exc
