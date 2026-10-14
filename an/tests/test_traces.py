from __future__ import annotations

import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

import httpx
import pytest
from fastapi import FastAPI

from security_agent.ledger import LedgerStore
from security_agent.operations import OperationsStore
from security_agent.receipt_traces import ReceiptTraceImporter
from security_agent.schemas import AgentState, TaskRequest, ToolContext, ToolStatus
from security_agent.trace_redaction import redact_trace
from security_agent.trace_tools import TraceTool
from security_agent.traces import TraceStore
from security_agent.traces_api import register_traces
from security_agent.worker_traces import WorkerTraceImporter


def setup(settings):
    ledger = LedgerStore(settings.database_url)
    for run in ("one", "two"):
        ledger.save_state(AgentState(run_id=run, task=TaskRequest(objective="Audit target"), module_route="reverse"))
    return ledger, TraceStore(ledger)


def test_scoped_search_drilldown_cursor_and_rebuild(settings):
    ledger, store = setup(settings)
    first = ledger.append("one", "mcp.call.completed", {"worker": "alice", "tool": "http",
        "blackboard": {"intent_id": "i1", "attempt_id": "a1", "step_id": "s1"},
        "result": {"content": [{"type": "text", "text": "A" * 30000 + "buried-marker"}]}})
    ledger.append("one", "tool.completed", {"worker": "bob", "data": {
        "output": "buried-marker", "output_truncated": True}})
    ledger.append("one", "runtime.started", {"worker": "bob"})
    ledger.append("two", "tool.completed", {"output": "buried-marker other task"})
    page = store.search("one", keyword="buried-marker", limit=1)
    assert len(page["items"]) == 1 and page["next_cursor"] == first.sequence
    assert "buried-marker" in page["items"][0]["match_excerpt"]
    assert len(page["items"][0]["summary"]) <= 700 and "payload" not in page["items"][0]
    detail = store.detail("one", first.event_id)
    assert detail["attempt_id"] == "a1" and detail["step_id"] == "s1"
    assert detail["output_state"] == "complete" and "buried-marker" in str(detail["payload"])
    second = store.search("one", keyword="buried-marker", cursor=page["next_cursor"])
    assert len(second["items"]) == 1 and second["items"][0]["output_state"] == "truncated"
    assert not store.search("one", keyword="other task")["items"]
    assert len(store.search("one", worker="bob", module="reverse")["items"]) == 2
    assert not store.search("one", module="code_audit")["items"]
    assert store.search("one", exclude_intent="i1")["items"][0]["worker"] == "bob"
    assert store.search("one")["items"][-1]["output_state"] == "unavailable"
    with pytest.raises(KeyError):
        store.detail("two", first.event_id)
    before = store.search("one")
    store.sync("one", rebuild=True)
    assert store.search("one") == before
    assert ledger.verify("one")


def test_trace_redaction_structured_encoded_and_text_is_idempotent():
    value = {"headers": [{"name": "Cookie", "value": "super-cookie"},
                         {"name": "X-Api-Key", "value": "super-key"}],
             "nested": {"access_token": "super-token"},
             "request": "GET https://user:pass@example.test/?token=super-query\n"
                        "Authorization: Basic c2VjcmV0\nCookie: super-cookie\n",
             "encoded": json.dumps({"headers": [{"name": "Set-Cookie", "value": "super-setcookie"}]}),
             "output": 'password="super-password" secret=super-secret'}
    safe = redact_trace(value)
    assert redact_trace(safe) == safe
    assert "super-" not in json.dumps(safe)
    assert "GET https://" in safe["request"] and "[REDACTED]" in safe["request"]


def test_historical_secrets_do_not_enter_projection_and_literal_wildcards(settings):
    ledger, store = setup(settings)
    event = ledger.append("one", "tool.completed", {"output": "literal 100% and a_b", "Cookie": "secret-cookie"})
    assert not store.search("one", keyword="secret-cookie")["items"]
    assert len(store.search("one", keyword="100%")["items"]) == 1
    assert not store.search("one", keyword="a%b")["items"]
    assert "[REDACTED]" in str(store.detail("one", event.event_id))


def test_concurrent_projection_is_deduplicated(settings):
    ledger, store = setup(settings)
    for index in range(30):
        ledger.append("one", "tool.completed", {"output": str(index)})
    with ThreadPoolExecutor(max_workers=5) as pool:
        pages = list(pool.map(lambda _: store.search("one"), range(10)))
    assert all(len(page["items"]) == 30 for page in pages)
    assert len({item["trace_id"] for item in pages[0]["items"]}) == 30


async def test_api_and_tool_cannot_redirect_task_scope(settings):
    ledger, store = setup(settings)
    event = ledger.append("two", "tool.completed", {"output": "other-run"})
    app = FastAPI()
    register_traces(app, store)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        assert (await client.get("/api/v1/runs/one/traces?cursor=-1")).status_code == 422
        assert (await client.get("/api/v1/runs/missing/traces")).status_code == 404
        assert (await client.get("/api/v1/runs/one/traces/" + event.event_id)).status_code == 404
        assert (await client.get("/api/v1/runs/two/traces?keyword=other-run")).json()["items"]
    context = ToolContext(run_id="one", step_id="step", workspace="workspace", allowed_paths=[])
    search = TraceTool(store)
    assert (await search.invoke({"run_id": "two"}, context)).status == ToolStatus.ERROR
    assert not (await search.invoke({"keyword": "other-run"}, context)).data["items"]
    assert (await TraceTool(store, detail=True).invoke(
        {"trace_id": event.event_id}, context)).status == ToolStatus.ERROR


def test_worker_import_requires_task_attempt_binding_and_survives_restart(settings, tmp_path):
    ledger, _ = setup(settings)
    ledger.update_state("one", lambda state: state.external_execution.update(blackboard={"project_id": "proj"}))
    ledger.append("one", "runtime.claimed", {"attempt_id": "valid-attempt"})
    journal = tmp_path / "worker.db"
    with sqlite3.connect(journal) as conn:
        conn.execute("CREATE TABLE worker_traces(sequence INTEGER PRIMARY KEY,trace_id TEXT,"
                     "project_id TEXT,payload_json TEXT)")
        for index, attempt in enumerate(("valid-attempt", "other-attempt")):
            conn.execute("INSERT INTO worker_traces VALUES (?,?,?,?)", (index, f"trace-{index}", "proj",
                json.dumps({"project_id": "proj", "attempt_id": attempt, "worker": "pi",
                            "status": "completed", "output": "fresh marker",
                            "occurred_at": datetime.now(UTC).isoformat()})))
    store = TraceStore(ledger, WorkerTraceImporter(ledger, journal))
    assert len(store.search("one", keyword="fresh marker")["items"]) == 1
    restarted = LedgerStore(settings.database_url)
    store = TraceStore(restarted, WorkerTraceImporter(restarted, journal))
    assert len(store.search("one", keyword="fresh marker")["items"]) == 1
    assert ledger.verify("one")


def test_historical_mcp_receipt_backfills_once_and_survives_source_deletion(settings, tmp_path):
    ledger, _ = setup(settings)
    operations = OperationsStore(tmp_path / "operations.db")
    operations.put("call:old", {"call_id": "old", "run_id": "one", "status": "completed",
                                "result": {"content": [{"type": "text", "text": "old observation"}]},
                                "arguments": {"Authorization": "Bearer secret-key"}})
    operations.put("call:foreign", {"call_id": "foreign", "run_id": "two", "status": "completed",
                                    "result": {"content": [{"type": "text", "text": "foreign observation"}]}})
    store = TraceStore(ledger, ReceiptTraceImporter(ledger, operations))
    assert len(store.search("one", keyword="old observation")["items"]) == 1
    assert not store.search("one", keyword="foreign observation")["items"]
    assert not store.search("one", keyword="secret-key")["items"]
    count = len(ledger.events("one"))
    assert len(store.search("one", keyword="old observation")["items"]) == 1
    assert len(ledger.events("one")) == count
    with sqlite3.connect(operations.path) as conn:
        conn.execute("DELETE FROM state WHERE key='call:old'")
    restarted = TraceStore(LedgerStore(settings.database_url), ReceiptTraceImporter(ledger, operations))
    assert len(restarted.search("one", keyword="old observation")["items"]) == 1
