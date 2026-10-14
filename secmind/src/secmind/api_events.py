from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect

from secmind.config import Settings
from secmind.runtime import ApplicationRuntime
from secmind.schemas import SCHEMA_VERSION


def register_event_routes(
    app: FastAPI,
    runtime: ApplicationRuntime,
    settings: Settings,
    *,
    strict: bool,
    operator_token_valid: Callable[[Any, str], bool],
) -> None:
    @app.websocket("/api/v1/runs/{run_id}/events")
    async def events_socket(websocket: WebSocket, run_id: str, after_sequence: int = 0) -> None:
        if not strict:
            origin = websocket.headers.get("origin")
            allowed = {f"{websocket.url.scheme.replace('ws', 'http')}://{websocket.url.netloc}"}
            allowed.update(
                f"http://{host}:{port}"
                for host in ("127.0.0.1", "localhost")
                for port in (5173, settings.api_port)
            )
            allowed.update(item.strip() for item in settings.allowed_browser_origins.split(",") if item.strip())
            if origin is not None and origin not in allowed:
                await websocket.close(code=4403, reason="Origin is not allowed")
                return
        if strict:
            origin = websocket.headers.get("origin", "")
            allowed_origins = {
                item.strip().rstrip("/") for item in settings.allowed_websocket_origins.split(",") if item.strip()
            }
            if not operator_token_valid(websocket.headers, settings.operator_token):
                await websocket.close(code=4401, reason="Operator authentication required")
                return
            if not origin or origin.rstrip("/") not in allowed_origins:
                await websocket.close(code=4403, reason="Origin is not allowed")
                return
        service = runtime.service
        if service.ledger.load_state(run_id) is None:
            await websocket.close(code=4404, reason="Run not found")
            return
        await websocket.accept()
        try:
            async with service.event_hub.subscribe(run_id) as queue:
                last_sequence = after_sequence
                for stored_event in service.ledger.events(run_id, after_sequence=after_sequence):
                    await websocket.send_text(stored_event.model_dump_json())
                    last_sequence = stored_event.sequence
                while True:
                    try:
                        live_event = await asyncio.wait_for(queue.get(), timeout=1.0)
                    except TimeoutError:
                        for stored_event in service.ledger.events(run_id, after_sequence=last_sequence):
                            await websocket.send_text(stored_event.model_dump_json())
                            last_sequence = stored_event.sequence
                        continue
                    if live_event.get("event_type") == "stream.gap":
                        await websocket.send_text(json.dumps(live_event, ensure_ascii=False))
                        await websocket.close(code=1013, reason="Event gap; reconnect with after_sequence")
                        return
                    sequence = int(live_event.get("sequence", 0))
                    if sequence <= last_sequence:
                        continue
                    if sequence != last_sequence + 1:
                        await websocket.send_text(
                            json.dumps(
                                {
                                    "schema_version": SCHEMA_VERSION,
                                    "run_id": run_id,
                                    "event_type": "stream.gap",
                                    "expected_sequence": last_sequence + 1,
                                    "observed_sequence": sequence,
                                },
                                ensure_ascii=False,
                            )
                        )
                        await websocket.close(code=1013, reason="Event gap; reconnect with after_sequence")
                        return
                    await websocket.send_text(json.dumps(live_event, ensure_ascii=False))
                    last_sequence = sequence
        except WebSocketDisconnect:
            return


__all__ = ["register_event_routes"]
