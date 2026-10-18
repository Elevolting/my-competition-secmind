from __future__ import annotations

import asyncio
import json
from typing import Literal

from fastapi import HTTPException, Response
from pydantic import BaseModel, ConfigDict, Field

from security_agent.traffic_evidence import EvidenceCorrupt, TrafficEvidenceStore


class TrafficCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_kind: Literal["har", "mcp", "ledger"]
    source_ref: str = Field(min_length=1, max_length=512)
    entry_index: int = Field(default=0, ge=0, le=10_000)


class TrafficBind(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: str = Field(min_length=1, max_length=200)
    role: Literal["baseline", "proof", "verification", "supporting"]
    note: str = Field(default="", max_length=1000)


def register_traffic_evidence(app, ledger, settings, operations):
    store = TrafficEvidenceStore(ledger, settings, operations)
    app.state.traffic_evidence = store

    def failure(exc):
        if isinstance(exc, KeyError):
            raise HTTPException(404, "任务或来源记录不存在") from exc
        if isinstance(exc, EvidenceCorrupt):
            raise HTTPException(409, str(exc)) from exc
        if isinstance(exc, (ValueError, UnicodeError)):
            raise HTTPException(422, str(exc)) from exc
        raise HTTPException(503, "流量证据存储不可用") from exc

    @app.post("/api/v1/runs/{run_id}/traffic-evidence", status_code=201)
    async def create(run_id: str, payload: TrafficCreate):
        try:
            return await asyncio.to_thread(store.create, run_id, payload.source_kind,
                                           payload.source_ref, payload.entry_index)
        except (KeyError, ValueError, UnicodeError, OSError) as exc:
            failure(exc)

    @app.get("/api/v1/runs/{run_id}/traffic-evidence/{evidence_id}")
    async def detail(run_id: str, evidence_id: str):
        try:
            return await asyncio.to_thread(store.get, run_id, evidence_id)
        except (KeyError, ValueError, OSError) as exc:
            failure(exc)

    @app.get("/api/v1/runs/{run_id}/traffic-evidence/{evidence_id}/export")
    async def export(run_id: str, evidence_id: str):
        try:
            evidence = await asyncio.to_thread(store.get, run_id, evidence_id)
        except (KeyError, ValueError, OSError) as exc:
            failure(exc)
        return Response(content=json.dumps(evidence["snapshot"], ensure_ascii=False, indent=2),
            media_type="application/json", headers={
                "Content-Disposition": f'attachment; filename="traffic-{evidence_id}.json"'})

    @app.post("/api/v1/runs/{run_id}/findings/{finding_id}/traffic-bindings", status_code=201)
    async def bind(run_id: str, finding_id: str, payload: TrafficBind):
        try:
            return await asyncio.to_thread(store.bind, run_id, finding_id,
                                           payload.evidence_id, payload.role, payload.note)
        except (KeyError, ValueError, OSError) as exc:
            failure(exc)
