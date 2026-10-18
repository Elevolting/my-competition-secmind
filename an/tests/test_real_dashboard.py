from datetime import UTC, datetime

from fastapi.testclient import TestClient

from security_agent.api import _usage_series, _usage_totals, create_app
from security_agent.dashboard import dashboard_snapshot
from security_agent.incident_response import IncidentManager
from security_agent.ledger import LedgerStore
from security_agent.schemas import AgentState, TaskRequest


def make_state(name, **kwargs):
    return AgentState(run_id=name, task=TaskRequest(objective="Audit uploaded source"), **kwargs)


def test_dashboard_handles_zero_timezone_and_unverified_external_completion():
    now = datetime(2026, 9, 29, 0, tzinfo=UTC)
    empty = dashboard_snapshot([], now)
    assert empty["total"] == empty["active"] == empty["completed"] == 0
    assert empty["risk_score"] is None
    assert len(empty["daily_created"]) == 7
    states = [
        make_state("audit", status="completed", started_at=datetime(2026, 9, 28, 18, tzinfo=UTC)),
        make_state("pentest", module_route="penetration", status="completed",
                   external_execution={"status": "running"}, started_at=now),
        make_state("failed", status="failed", started_at=now),
    ]
    snapshot = dashboard_snapshot(states, now)
    assert snapshot["daily_created"][-1]["count"] == 3
    assert snapshot["completed"] == 1
    assert snapshot["active"] == 1
    assert snapshot["needs_attention"] == 1
    assert sum(snapshot["scenes"].values()) == snapshot["total"]


def test_dashboard_counts_all_runs_and_startup_creates_no_monitor_events(settings):
    app = create_app(settings)
    for i in range(105):
        app.state.service.ledger.save_state(make_state(str(i), status="completed"))
    with TestClient(app) as client:
        assert len(client.get("/api/v1/runs").json()["runs"]) == 100
        assert client.get("/api/v1/dashboard").json()["total"] == 105
        assert client.get("/api/v1/incident/logs").json()["logs"] == []
        assert client.get("/api/v1/incident/status").json()["mode"] == "local_host"
        tools = client.get("/api/v1/tools").json()["tools"]
        assert any(tool["name"] == "bandit_python_audit" for tool in tools)


def test_global_usage_deduplicates_receipts_like_run_detail(tmp_path):
    ledger = LedgerStore(f"sqlite:///{tmp_path / 'ledger.db'}")
    ledger.append("run", "llm.stream.started", {"trace_id": "call"})
    ledger.append("run", "llm.stream.completed", {"trace_id": "call", "usage": {"total_tokens": 12}})
    ledger.append("run", "llm.stream.failed", {"trace_id": "call", "usage": {"total_tokens": 999}})
    totals = _usage_totals(ledger, [])
    assert totals["total_tokens"] == 12
    assert totals["model_call_count"] == 1
    assert _usage_series(ledger)["daily"][-1]["tokens"] == 12
    assert _usage_series(ledger)["daily"][-1]["calls"] == 1


async def test_real_evidence_and_no_invented_anomaly(tmp_path):
    manager = IncidentManager(tmp_path / "incident")
    result = await manager.submit_command("collect_evidence")
    assert result["action"]["status"] == "completed"
    assert (manager.root / "evidence" / (result["action"]["result"]["evidence_id"] + ".json")).is_file()
    assert all(event["event_type"] != "monitor.anomaly" for event in manager.logs())
    assert manager.snapshot()["collector_connected"] is True
