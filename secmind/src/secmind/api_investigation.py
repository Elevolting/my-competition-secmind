"""Read-only, scrubbed API projections for the v0.6 investigation domain."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from itertools import islice
from typing import Annotated, Any, Literal

from fastapi import FastAPI, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from secmind.investigation.contracts import SCHEMA_VERSION_V15
from secmind.investigation.store import (
    CompletionReceiptRow,
    CompletionSnapshotRow,
    UsageReservationRow,
    UsageSettlementRow,
)
from secmind.runtime import ApplicationRuntime
from secmind.secret_scrubber import TRUNCATED, scrub_value

_DEFAULT_LIMIT = 50
_MAX_LIMIT = 100
_BLOCKED_FIELDS = frozenset(
    {
        "analysis",
        "chain_of_thought",
        "cot",
        "hidden_reasoning",
        "hidden_thoughts",
        "prompt",
        "reasoning",
        "reasoning_trace",
        "system_prompt",
        "thoughts",
        "user_prompt",
    }
)


def _normalized_key(value: str) -> str:
    return value.casefold().replace("-", "_").replace(".", "_")


def _is_blocked_field(key: str) -> bool:
    normalized = _normalized_key(key)
    if "prompt" in normalized or normalized in _BLOCKED_FIELDS:
        return True
    if normalized.startswith("raw_") and not normalized.endswith("_digest"):
        return True
    return normalized.endswith(("_chain_of_thought", "_reasoning_trace"))


def _observable_projection(value: Any) -> Any:
    """Remove non-observable cognition fields, then apply the shared scrubber."""

    return scrub_value(_drop_non_observable(value))


def _drop_non_observable(value: Any, *, depth: int = 0, max_depth: int = 12, max_items: int = 100) -> Any:
    if depth >= max_depth:
        return TRUNCATED
    if isinstance(value, Mapping):
        projected = {
            str(key): _drop_non_observable(item, depth=depth + 1, max_depth=max_depth, max_items=max_items)
            for key, item in islice(value.items(), max_items)
            if not _is_blocked_field(str(key))
        }
        if len(value) > max_items:
            projected["_secmind_truncated"] = TRUNCATED
        return projected
    if isinstance(value, list):
        sequence = [
            _drop_non_observable(item, depth=depth + 1, max_depth=max_depth, max_items=max_items)
            for item in islice(value, max_items)
        ]
        return [*sequence, TRUNCATED] if len(value) > max_items else sequence
    if isinstance(value, tuple):
        sequence = [
            _drop_non_observable(item, depth=depth + 1, max_depth=max_depth, max_items=max_items)
            for item in islice(value, max_items)
        ]
        return [*sequence, TRUNCATED] if len(value) > max_items else sequence
    return value


def _require_store(runtime: ApplicationRuntime, run_id: str) -> Any:
    try:
        runtime.service.state(run_id)
    except KeyError as exc:
        raise HTTPException(404, "Run not found") from exc
    store = runtime.service.investigation_store
    if store is None:
        raise HTTPException(503, "Investigation store is unavailable")
    return store


def _generic_objects(store: Any, run_id: str, object_types: Iterable[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    record_types = {
        "usage_reservation": "reservation",
        "usage_settlement": "settlement",
        "completion_snapshot": "snapshot",
        "completion_receipt": "receipt",
    }
    try:
        for object_type in object_types:
            for item in store.list_objects(run_id, object_type):
                if isinstance(item, dict):
                    rows.append({**item, "record_type": record_types.get(object_type, object_type)})
    except (SQLAlchemyError, TypeError, ValueError, RuntimeError) as exc:
        raise HTTPException(503, "Investigation read model is unavailable") from exc
    return rows


def _database_usage(store: Any, run_id: str) -> list[dict[str, Any]] | None:
    engine = getattr(store, "engine", None)
    if engine is None:
        return None
    with Session(engine) as session:
        reservations = session.scalars(
            select(UsageReservationRow)
            .where(UsageReservationRow.run_id == run_id)
            .order_by(UsageReservationRow.created_at, UsageReservationRow.reservation_id)
        ).all()
        settlements = session.scalars(
            select(UsageSettlementRow)
            .where(UsageSettlementRow.run_id == run_id)
            .order_by(UsageSettlementRow.settled_at, UsageSettlementRow.settlement_id)
        ).all()
    return [
        *({"record_type": "reservation", **json.loads(item.payload_json)} for item in reservations),
        *({"record_type": "settlement", **json.loads(item.payload_json)} for item in settlements),
    ]


def _database_completion(store: Any, run_id: str) -> list[dict[str, Any]] | None:
    engine = getattr(store, "engine", None)
    if engine is None:
        return None
    with Session(engine) as session:
        snapshots = session.scalars(
            select(CompletionSnapshotRow)
            .where(CompletionSnapshotRow.run_id == run_id)
            .order_by(CompletionSnapshotRow.created_at, CompletionSnapshotRow.snapshot_id)
        ).all()
        receipts = session.scalars(
            select(CompletionReceiptRow)
            .where(CompletionReceiptRow.run_id == run_id)
            .order_by(CompletionReceiptRow.decided_at, CompletionReceiptRow.receipt_id)
        ).all()
    return [
        *({"record_type": "snapshot", **json.loads(item.payload_json)} for item in snapshots),
        *({"record_type": "receipt", **json.loads(item.payload_json)} for item in receipts),
    ]


def _objects(runtime: ApplicationRuntime, run_id: str, object_types: tuple[str, ...]) -> list[dict[str, Any]]:
    store = _require_store(runtime, run_id)
    try:
        if object_types == ("usage_reservation", "usage_settlement"):
            database_rows = _database_usage(store, run_id)
            rows = database_rows if database_rows is not None else _generic_objects(store, run_id, object_types)
        elif object_types == ("completion_snapshot", "completion_receipt"):
            database_rows = _database_completion(store, run_id)
            rows = database_rows if database_rows is not None else _generic_objects(store, run_id, object_types)
        else:
            rows = _generic_objects(store, run_id, object_types)
    except (json.JSONDecodeError, SQLAlchemyError, TypeError, ValueError, RuntimeError) as exc:
        raise HTTPException(503, "Investigation read model is unavailable") from exc
    # InvestigationStore and the dedicated queries both return a stable
    # insertion/creation order.  Preserving it makes the last item the latest
    # revision without guessing chronology from unrelated object identifiers.
    return rows


def _filtered(items: Iterable[dict[str, Any]], **filters: str | int | None) -> list[dict[str, Any]]:
    active = {key: value for key, value in filters.items() if value is not None}
    return [item for item in items if all(item.get(key) == value for key, value in active.items())]


def _latest_response(run_id: str, object_type: str, items: list[dict[str, Any]]) -> dict[str, Any]:
    if not items:
        raise HTTPException(404, f"{object_type.replace('_', ' ').title()} not found")
    projected = _observable_projection(items[-1])
    return {
        "schema_version": SCHEMA_VERSION_V15,
        "run_id": run_id,
        "object_type": object_type,
        "item": projected,
    }


def _page_response(
    run_id: str,
    object_type: str,
    base_items: list[dict[str, Any]],
    filtered_items: list[dict[str, Any]],
    *,
    offset: int,
    limit: int,
) -> dict[str, Any]:
    if not base_items:
        raise HTTPException(404, f"{object_type.replace('_', ' ').title()} not found")
    page = filtered_items[offset : offset + limit]
    next_offset = offset + len(page)
    has_more = next_offset < len(filtered_items)
    return {
        "schema_version": SCHEMA_VERSION_V15,
        "run_id": run_id,
        "object_type": object_type,
        "items": _observable_projection(page),
        "offset": offset,
        "limit": limit,
        "total": len(filtered_items),
        "next_offset": next_offset if has_more else None,
        "has_more": has_more,
    }


def register_investigation_routes(app: FastAPI, runtime: ApplicationRuntime) -> None:
    """Register read-only v0.6 endpoints; authentication remains an app concern."""

    @app.get("/api/v1/runs/{run_id}/intent")
    async def get_intent(run_id: str) -> dict[str, Any]:
        return _latest_response(run_id, "security_intent", _objects(runtime, run_id, ("security_intent",)))

    @app.get("/api/v1/runs/{run_id}/plan-contract")
    async def get_plan_contract(
        run_id: str,
        revision: Annotated[int | None, Query(ge=0, le=2)] = None,
    ) -> dict[str, Any]:
        items = _objects(runtime, run_id, ("plan_contract",))
        selected = _filtered(items, revision=revision)
        if items and not selected:
            raise HTTPException(404, "Plan contract revision not found")
        return _latest_response(run_id, "plan_contract", selected)

    @app.get("/api/v1/runs/{run_id}/team")
    async def get_team(
        run_id: str,
        strategy: Annotated[str | None, Query(max_length=40)] = None,
    ) -> dict[str, Any]:
        items = _objects(runtime, run_id, ("team_plan",))
        selected = _filtered(items, strategy=strategy)
        if items and not selected:
            raise HTTPException(404, "Team strategy not found")
        return _latest_response(run_id, "team_plan", selected)

    @app.get("/api/v1/runs/{run_id}/hypotheses")
    async def get_hypotheses(
        run_id: str,
        status: Annotated[str | None, Query(max_length=40)] = None,
        producer: Annotated[str | None, Query(max_length=100)] = None,
        offset: Annotated[int, Query(ge=0)] = 0,
        limit: Annotated[int, Query(ge=1, le=_MAX_LIMIT)] = _DEFAULT_LIMIT,
    ) -> dict[str, Any]:
        items = _objects(runtime, run_id, ("hypothesis",))
        return _page_response(
            run_id,
            "hypothesis",
            items,
            _filtered(items, status=status, producer=producer),
            offset=offset,
            limit=limit,
        )

    @app.get("/api/v1/runs/{run_id}/evidence-requests")
    async def get_evidence_requests(
        run_id: str,
        status: Annotated[str | None, Query(max_length=40)] = None,
        reason_code: Annotated[str | None, Query(max_length=100)] = None,
        offset: Annotated[int, Query(ge=0)] = 0,
        limit: Annotated[int, Query(ge=1, le=_MAX_LIMIT)] = _DEFAULT_LIMIT,
    ) -> dict[str, Any]:
        items = _objects(runtime, run_id, ("evidence_request",))
        return _page_response(
            run_id,
            "evidence_request",
            items,
            _filtered(items, status=status, reason_code=reason_code),
            offset=offset,
            limit=limit,
        )

    @app.get("/api/v1/runs/{run_id}/critiques")
    async def get_critiques(
        run_id: str,
        verdict: Annotated[str | None, Query(max_length=40)] = None,
        target_type: Annotated[str | None, Query(max_length=80)] = None,
        critic_profile: Annotated[str | None, Query(max_length=100)] = None,
        offset: Annotated[int, Query(ge=0)] = 0,
        limit: Annotated[int, Query(ge=1, le=_MAX_LIMIT)] = _DEFAULT_LIMIT,
    ) -> dict[str, Any]:
        items = _objects(runtime, run_id, ("critique",))
        return _page_response(
            run_id,
            "critique",
            items,
            _filtered(items, verdict=verdict, target_type=target_type, critic_profile=critic_profile),
            offset=offset,
            limit=limit,
        )

    @app.get("/api/v1/runs/{run_id}/usage")
    async def get_usage(
        run_id: str,
        record_type: Annotated[Literal["reservation", "settlement"] | None, Query()] = None,
        kind: Annotated[Literal["run", "step", "tool", "model"] | None, Query()] = None,
        status: Annotated[str | None, Query(max_length=40)] = None,
        offset: Annotated[int, Query(ge=0)] = 0,
        limit: Annotated[int, Query(ge=1, le=_MAX_LIMIT)] = _DEFAULT_LIMIT,
    ) -> dict[str, Any]:
        items = _objects(runtime, run_id, ("usage_reservation", "usage_settlement"))
        return _page_response(
            run_id,
            "usage",
            items,
            _filtered(items, record_type=record_type, kind=kind, status=status),
            offset=offset,
            limit=limit,
        )

    @app.get("/api/v1/runs/{run_id}/completion")
    async def get_completion(
        run_id: str,
        record_type: Annotated[Literal["snapshot", "receipt"] | None, Query()] = None,
        decision: Annotated[str | None, Query(max_length=40)] = None,
        offset: Annotated[int, Query(ge=0)] = 0,
        limit: Annotated[int, Query(ge=1, le=_MAX_LIMIT)] = _DEFAULT_LIMIT,
    ) -> dict[str, Any]:
        items = _objects(runtime, run_id, ("completion_snapshot", "completion_receipt"))
        return _page_response(
            run_id,
            "completion",
            items,
            _filtered(items, record_type=record_type, decision=decision),
            offset=offset,
            limit=limit,
        )


__all__ = ["register_investigation_routes"]
