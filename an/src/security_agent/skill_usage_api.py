"""Read-only skill statistics bridge; the analysis engine owns the facts."""

from __future__ import annotations

import asyncio
from typing import Annotated
from urllib.parse import quote

import httpx
from fastapi import HTTPException, Query
from pydantic import BaseModel, Field


class UsageEvent(BaseModel):
    event_id: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    payload: dict


class SkillCounts(BaseModel):
    skill_id: str = Field(min_length=1)
    loads: int = Field(ge=0, strict=True)
    load_failures: int = Field(ge=0, strict=True)
    calls: int = Field(ge=0, strict=True)
    succeeded: int = Field(ge=0, strict=True)
    failed: int = Field(ge=0, strict=True)
    pending: int = Field(ge=0, strict=True)


class UsageTotals(BaseModel):
    loads: int = Field(ge=0, strict=True)
    load_failures: int = Field(ge=0, strict=True)
    calls: int = Field(ge=0, strict=True)


class UsageListing(BaseModel):
    events: list[UsageEvent]
    skills: list[SkillCounts]
    totals: UsageTotals
    total_events: int = Field(ge=0, strict=True)


def register_skill_usage(app, ledger, settings):
    async def remote_get(path: str, params=None, *, schema):
        headers = (
            {"Authorization": f"Bearer {settings.secmind_operator_token}"} if settings.secmind_operator_token else {}
        )
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(20, connect=5), headers=headers, follow_redirects=False, trust_env=False
            ) as client:
                response = await client.get(settings.reverse_base_url.rstrip("/") + path, params=params)
                response.raise_for_status()
                result = response.json()
                schema.model_validate(result)
                return result
        except httpx.HTTPStatusError as exc:
            code = 404 if exc.response.status_code == 404 else 502
            raise HTTPException(code, "技能事件不存在" if code == 404 else "分析引擎技能统计查询失败") from exc
        except (httpx.HTTPError, ValueError) as exc:
            raise HTTPException(502, "分析引擎技能统计暂不可用") from exc

    async def run_links():
        states = await asyncio.to_thread(ledger.list_states, limit=None)
        links = {}
        for state in states:
            remote_id = state.external_execution.get("remote_run_id")
            if remote_id:
                links.setdefault(remote_id, []).append(state.run_id)
        return links

    @app.get("/api/v1/skills/usage")
    async def list_usage(
        run_id: Annotated[str | None, Query(max_length=100)] = None,
        skill_id: Annotated[str | None, Query(max_length=100)] = None,
        role: Annotated[str | None, Query(max_length=100)] = None,
        event_type: Annotated[
            str | None, Query(pattern=r"^(skill\.(loaded|load_failed)|tool\.(invoked|completed|failed))$")
        ] = None,
        limit: Annotated[int, Query(ge=1, le=200)] = 50,
        offset: Annotated[int, Query(ge=0)] = 0,
    ):
        params = {"limit": limit, "offset": offset}
        for key, value in (("skill_id", skill_id), ("role", role), ("event_type", event_type)):
            if value:
                params[key] = value
        if run_id:
            state = await asyncio.to_thread(ledger.load_state, run_id)
            if state is None:
                raise HTTPException(404, "任务不存在")
            remote_id = state.external_execution.get("remote_run_id")
            if not remote_id:
                return {
                    "skills": [],
                    "events": [],
                    "totals": {"loads": 0, "load_failures": 0, "calls": 0},
                    "total_events": 0,
                    "limit": limit,
                    "offset": offset,
                    "has_more": False,
                    "unavailable_reason": "此任务没有独立分析引擎任务引用",
                    "workbench_run_id": run_id,
                }
            params["run_id"] = remote_id
        result = await remote_get("/api/v1/skills/usage", params, schema=UsageListing)
        links = await run_links()
        for event in result.get("events", []):
            event["workbench_run_ids"] = links.get(event["run_id"], [])
        result["workbench_run_id"] = run_id
        result["source"] = "secmind_execution_ledger"
        return result

    @app.get("/api/v1/skills/usage/events/{event_id}")
    async def event_detail(event_id: str):
        event = await remote_get("/api/v1/skills/usage/events/" + quote(event_id, safe=""), schema=UsageEvent)
        event["workbench_run_ids"] = (await run_links()).get(event["run_id"], [])
        return event
