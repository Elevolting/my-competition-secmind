"""Read-only cross-run asset inventory APIs."""
from __future__ import annotations

import asyncio
from typing import Annotated, Literal

from fastapi import HTTPException, Query

from security_agent.asset_library import AssetLibrary


def register_asset_library(app, ledger, operations):
    library = AssetLibrary(ledger, operations)
    app.state.asset_library = library

    @app.get("/api/v1/assets")
    async def list_assets(
        search: Annotated[str, Query(max_length=200)] = "",
        kind: Literal["domain", "ip", "service", "endpoint"] | None = None,
        run_id: Annotated[str | None, Query(max_length=100)] = None,
        coverage: Literal["observed", "unobserved"] | None = None,
        limit: Annotated[int, Query(ge=1, le=200)] = 100,
        offset: Annotated[int, Query(ge=0)] = 0,
    ):
        await asyncio.to_thread(library.sync_all)
        return await asyncio.to_thread(library.list, query=search, kind=kind, run_id=run_id,
                                       coverage=coverage, limit=limit, offset=offset)

    @app.get("/api/v1/assets/{asset_id}")
    async def asset_detail(asset_id: str):
        await asyncio.to_thread(library.sync_all)
        try:
            return await asyncio.to_thread(library.detail, asset_id)
        except KeyError as exc:
            raise HTTPException(404, "资产不存在") from exc
