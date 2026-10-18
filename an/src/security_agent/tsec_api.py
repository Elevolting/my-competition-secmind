"""Thin local API adapter; no automatic starts, hints, submissions or scoring."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, FastAPI, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from security_agent.config import Settings
from security_agent.tsec_benchmark import TSecBenchmarkClient, TSecConfig, TSecError


class FlagSubmission(BaseModel):
    unique_code: str = Field(min_length=1)
    flag: str = Field(min_length=1, max_length=4096)


def register_tsec(app: FastAPI, settings: Settings) -> None:
    client = TSecBenchmarkClient(TSecConfig(settings.tsec_base_url, settings.tsec_token))
    app.state.tsec_client = client
    router = APIRouter(prefix="/api/v1/tsec/challenges", tags=["TSec 评测"])

    @app.exception_handler(TSecError)
    async def tsec_error_handler(request, exc: TSecError):
        if exc.code == "validation_error" and isinstance(exc.detail, list):
            return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
        return JSONResponse(status_code=exc.status_code,
                            content={"code": exc.code, "message": exc.message, "detail": exc.detail})

    @router.get("")
    async def challenges():
        return await client.list_challenges()

    @router.post("/start")
    async def start(unique_code: Annotated[str, Query(min_length=1)]):
        return await client.start(unique_code)

    @router.get("/hint", description="调用会按平台规则扣分；仅在需要提示时显式调用。")
    async def hint(unique_code: Annotated[str, Query(min_length=1)]):
        return await client.hint(unique_code)

    @router.post("/submit")
    async def submit(payload: FlagSubmission):
        return await client.submit(payload.unique_code, payload.flag)

    @router.post("/close")
    async def close(unique_code: Annotated[str, Query(min_length=1)]):
        return await client.close(unique_code)

    app.include_router(router)
