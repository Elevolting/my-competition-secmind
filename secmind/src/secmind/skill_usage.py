"""Skill load instrumentation and read-only projections over the event ledger."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from sqlalchemy import select
from sqlalchemy.orm import Session

from secmind.ledger import EventRow, LedgerStore, canonical_json

USAGE_EVENTS = ("skill.loaded", "skill.load_failed", "tool.invoked", "tool.completed", "tool.failed")


@dataclass(frozen=True)
class SkillLoadScope:
    operation_id: str
    purpose: str
    step_id: str | None
    role: str | None
    attempt: int
    emit: Callable[[str, dict[str, Any], str], None]


_load_scope: ContextVar[SkillLoadScope | None] = ContextVar("skill_load_scope", default=None)


@contextmanager
def skill_load_scope(scope: SkillLoadScope) -> Iterator[None]:
    token = _load_scope.set(scope)
    try:
        yield
    finally:
        _load_scope.reset(token)


def record_skill_load(skill_id: str, version: str | None, *, error: Exception | None = None) -> None:
    scope = _load_scope.get()
    if scope is None:
        return  # Discovery and administrative reads have no task execution identity.
    operation = str(
        uuid5(
            NAMESPACE_URL,
            canonical_json(
                [
                    scope.operation_id,
                    scope.purpose,
                    skill_id,
                    version,
                ]
            ),
        )
    )
    event_type = "skill.load_failed" if error is not None else "skill.loaded"
    scope.emit(
        event_type,
        {
            "usage_id": operation,
            "skill_id": skill_id,
            "version": version,
            "step_id": scope.step_id,
            "role": scope.role,
            "attempt": scope.attempt,
            "purpose": scope.purpose,
            "error_type": type(error).__name__ if error else None,
        },
        f"skill-load:{operation}:{event_type}",
    )


def tool_usage(context: Any, invocation_attempt: int, contract: Any = None) -> dict[str, Any]:
    identity = str(
        uuid5(
            NAMESPACE_URL,
            canonical_json(
                [
                    context.run_id,
                    context.idempotency_key,
                    invocation_attempt,
                ]
            ),
        )
    )
    bindings = (
        [
            {"skill_id": item.skill_id, "version": item.version, "digest": item.digest}
            for item in contract.skill_bindings
        ]
        if contract is not None
        else []
    )
    return {
        "usage_id": identity,
        "step_id": context.step_id,
        "invocation_id": context.invocation_id,
        "invocation_attempt": invocation_attempt,
        "step_attempt": context.attempt,
        "role": contract.profile_id if contract is not None else None,
        "skills": bindings,
        "attribution": "verified_work_contract" if bindings else "unknown",
        "work_contract_id": contract.contract_id if contract is not None else None,
    }


def _dimensions(event: dict[str, Any]) -> tuple[list[str], str | None]:
    payload = event["payload"]
    usage = payload.get("skill_usage", payload)
    skills = (
        [str(payload["skill_id"])]
        if event["event_type"].startswith("skill.")
        else [str(item["skill_id"]) for item in usage.get("skills", [])]
    )
    return sorted(set(skills)) or ["unknown"], usage.get("role")


def query_skill_usage(
    ledger: LedgerStore,
    *,
    run_id: str | None = None,
    skill_id: str | None = None,
    role: str | None = None,
    event_type: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    """Counts derive from invocation-boundary facts, never from selected skill IDs."""
    statement = select(EventRow).where(EventRow.event_type.in_(USAGE_EVENTS))
    if run_id:
        statement = statement.where(EventRow.run_id == run_id)
    events: list[dict[str, Any]] = []
    calls: dict[tuple[str, str], dict[str, Any]] = {}
    stats: dict[str, dict[str, Any]] = {}
    loads: set[tuple[str, str, str]] = set()
    total_events = 0

    def stat(skill: str) -> dict[str, Any]:
        return stats.setdefault(
            skill,
            {"skill_id": skill, "loads": 0, "load_failures": 0, "calls": 0, "succeeded": 0, "failed": 0, "pending": 0},
        )

    with Session(ledger.engine) as session:
        rows = session.scalars(
            statement.order_by(
                EventRow.timestamp.desc(),
                EventRow.sequence.desc(),
                EventRow.event_id.desc(),
            )
        ).yield_per(500)
        for row in rows:
            event = ledger._to_event(row).model_dump(mode="json")
            payload = event["payload"]
            usage = payload.get("skill_usage", payload) or {}
            if not usage.get("usage_id"):
                continue  # Legacy starts and results cannot establish execution or attribution.
            skills, event_role = _dimensions(event)
            if skill_id and skill_id not in skills or role and role != (event_role or "unknown"):
                continue
            if event_type is None or event_type == event["event_type"]:
                if offset <= total_events < offset + limit:
                    events.append({**event, "skill_ids": skills, "role": event_role or "unknown"})
                total_events += 1
            if event["event_type"].startswith("skill."):
                identity = (row.run_id, usage["usage_id"], row.event_type)
                if identity not in loads:
                    loads.add(identity)
                    stat(skills[0])["loads" if row.event_type == "skill.loaded" else "load_failures"] += 1
            else:
                key = (row.run_id, usage["usage_id"])
                call = calls.setdefault(key, {"skills": skills, "started": False, "result": None})
                if row.event_type == "tool.invoked":
                    call["started"] = True
                    call["skills"] = skills
                elif row.event_type == "tool.completed" and call["result"] is None:
                    call["result"] = "succeeded" if payload.get("status") == "success" else "failed"
                elif row.event_type == "tool.failed" and call["result"] is None:
                    call["result"] = "failed"
    counted_calls = 0
    for call in calls.values():
        if not call["started"]:
            continue
        counted_calls += 1
        for skill in call["skills"]:
            stat(skill)["calls"] += 1
            stat(skill)[call["result"] or "pending"] += 1
    return {
        "run_id": run_id,
        "skills": sorted(stats.values(), key=lambda item: (-item["calls"], item["skill_id"])),
        "totals": {
            "loads": sum(item["loads"] for item in stats.values()),
            "load_failures": sum(item["load_failures"] for item in stats.values()),
            "calls": counted_calls,
        },
        "events": events,
        "total_events": total_events,
        "offset": offset,
        "limit": limit,
        "has_more": offset + limit < total_events,
        "event_filter_applies_to": "event_list_only",
        "legacy_events_included": False,
    }


def skill_usage_event(ledger: LedgerStore, event_id: str) -> dict[str, Any]:
    with Session(ledger.engine) as session:
        row = session.get(EventRow, event_id)
        if row is None or row.event_type not in USAGE_EVENTS:
            raise KeyError(event_id)
        event = ledger._to_event(row).model_dump(mode="json")
        if not event["payload"].get("usage_id") and not (event["payload"].get("skill_usage") or {}).get("usage_id"):
            raise KeyError(event_id)
        return event
