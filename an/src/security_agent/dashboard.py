"""Dashboard projections of persisted runs; no inferred security scores."""
from collections import Counter
from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

from security_agent.schemas import AgentState
from security_agent.service import canonical_module_route


def run_bucket(state: AgentState) -> str:
    external = state.external_execution
    status = str(external.get("status", "")).lower()
    route = canonical_module_route(state.module_route, state.scenario.value)
    if state.status == "completed" and (route != "penetration" or state.routing.get('execution_backend') == 'mcp' or (
        status in {"completed", "complete", "success", "succeeded"}
        and external.get("objective_reached") is True
    )):
        return "completed"
    if status in {"timeout", "unavailable", "poll_error"}:
        return "unavailable" if status == "poll_error" else status
    if state.status in {"failed", "denied"} or status in {"failed", "denied", "cancelled", "canceled", "error"}:
        return "failed"
    if state.status in {"partial", "waiting_approval"}:
        return str(state.status)
    return "running"


def dashboard_snapshot(states: list[AgentState], now: datetime | None = None) -> dict:
    zone = ZoneInfo("Asia/Shanghai")
    now = (now or datetime.now(UTC)).astimezone(zone)
    scenes = Counter()
    statuses = Counter()
    days = {(now.date() - timedelta(days=i)).isoformat(): 0 for i in range(6, -1, -1)}
    for state in states:
        route = canonical_module_route(state.module_route, state.scenario.value)
        scenes[route] += 1
        statuses[run_bucket(state)] += 1
        started = state.started_at
        if started.tzinfo is None:
            started = started.replace(tzinfo=UTC)
        day = started.astimezone(zone).date().isoformat()
        if day in days:
            days[day] += 1
    return {
        "source": "persisted_runs", "scope": "all_runs", "timezone": "Asia/Shanghai",
        "generated_at": now.isoformat(), "total": len(states),
        "active": statuses["running"], "completed": statuses["completed"],
        "needs_attention": sum(statuses[key] for key in ("failed", "partial", "timeout", "unavailable", "waiting_approval")),
        "pending_approvals": statuses["waiting_approval"],
        "scenes": dict(scenes), "statuses": dict(statuses),
        "daily_created": [{"date": day, "count": count} for day, count in days.items()],
        "risk_score": None,
    }
