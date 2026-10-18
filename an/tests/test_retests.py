from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from sqlalchemy.orm import Session

from security_agent.agents import TaskInterpreterAgent
from security_agent.api import create_app
from security_agent.ingest import InputIngestor
from security_agent.ledger import LedgerStore
from security_agent.retests import (
    DISPATCH_LEASE,
    RetestRow,
    RetestStore,
    prepare_retest_task,
    source_snapshot,
)
from security_agent.schemas import (
    AgentReport,
    AgentState,
    AttachmentRef,
    Evidence,
    Finding,
    RunStatus,
    TaskRequest,
    ToolResult,
    ToolStatus,
)


def source_state() -> AgentState:
    evidence = Evidence(evidence_id="original-evidence", source="audit", summary="Password: source-secret")
    finding = Finding(finding_id="finding-1", rule_id="TEST", path="src/auth.py", title="Session issue",
                      description="Password: finding-secret", evidence_ids=[evidence.evidence_id])
    state = AgentState(run_id="source-run", task=TaskRequest(objective="Audit authentication code",
        constraints=["Only inspect the provided source"], network_policy="none"),
        status=RunStatus.COMPLETED, findings=[finding], evidence=[evidence])
    state.report = AgentReport(run_id=state.run_id, status=state.status,
        executive_summary="A session issue remains", findings=[finding], evidence=[evidence],
        worker_reports=["Inspect authentication handling"])
    return state


def test_source_snapshot_freezes_finding_without_secret_values():
    state = source_state()
    snapshot = source_snapshot(state, "finding", "finding-1")
    assert snapshot["source_run_id"] == "source-run"
    assert snapshot["original"]["description"] == "Password: [REDACTED]"
    assert snapshot["evidence"][0]["summary"] == "Password: [REDACTED]"
    assert snapshot["network_policy"] == "none"
    with pytest.raises(KeyError):
        source_snapshot(state, "finding", "other-finding")


def test_report_conclusion_reference_requires_current_text_hash():
    state = source_state()
    text = state.report.worker_reports[0]
    reference = f"worker_reports:0:{hashlib.sha256(text.encode()).hexdigest()}"
    assert source_snapshot(state, "conclusion", reference)["original"]["text"] == text
    with pytest.raises(ValueError, match="已变化"):
        source_snapshot(state, "conclusion", "worker_reports:0:" + "0" * 64)


def test_retest_reservation_is_durable_idempotent_and_one_active_per_source(settings):
    settings.prepare_directories()
    ledger = LedgerStore(settings.database_url)
    state = source_state()
    ledger.save_state(state)
    store = RetestStore(ledger)
    first, created = store.reserve(state, "finding", "finding-1", "request-123456789", {"note": "First"})
    assert created and first["status"] == "pending"
    assert first["snapshot_sha256"]
    state.findings[0].description = "Changed since the retest started"
    same, created = store.reserve(state, "finding", "finding-1", "request-123456789", {"note": "First"})
    assert not created and same["retest_id"] == first["retest_id"]
    assert same["snapshot"] == first["snapshot"]
    active, created = store.reserve(state, "finding", "finding-1", "request-987654321", {"note": "Second"})
    assert not created and active["retest_id"] == first["retest_id"]
    with pytest.raises(ValueError, match="不同的来源或参数"):
        store.reserve(state, "finding", "finding-1", "request-123456789", {"note": "Different"})
    assert len(RetestStore(ledger).list("source-run")) == 1
    with pytest.raises(KeyError):
        store.get("another-run", first["retest_id"])
    assert store.set_status(first["retest_id"], "running")["started_at"]
    assert store.set_status(first["retest_id"], "failed", "Execution failed")["finished_at"]
    next_item, created = store.reserve(state, "finding", "finding-1", "request-987654321", {"note": "Second"})
    assert created and next_item["retest_id"] != first["retest_id"]


def test_retest_dispatch_claim_is_atomic_and_expired_claim_can_be_recovered(settings):
    settings.prepare_directories()
    ledger = LedgerStore(settings.database_url)
    store = RetestStore(ledger)
    record, _ = store.reserve(source_state(), "finding", "finding-1", "request-123456789", {})
    with ThreadPoolExecutor(max_workers=2) as executor:
        claims = list(executor.map(lambda _: RetestStore(ledger).claim_dispatch(record["retest_id"]), range(2)))
    assert sorted(claims) == [False, True]
    assert store.get("source-run", record["retest_id"])["status"] == "dispatching"
    assert not store.claim_dispatch(record["retest_id"])
    with Session(ledger.engine) as session:
        row = session.get(RetestRow, record["retest_id"])
        row.started_at = datetime.now(UTC) - DISPATCH_LEASE - timedelta(seconds=1)
        session.commit()
    assert store.claim_dispatch(record["retest_id"])
    assert store.dispatchable() == []


def test_retest_requires_terminal_report():
    state = source_state()
    state.status = RunStatus.RUNNING
    with pytest.raises(ValueError, match="历史报告"):
        source_snapshot(state, "finding", "finding-1")


def test_retest_reuses_verified_source_files_after_upload_is_removed(settings):
    settings.prepare_directories()
    original_upload = settings.upload_root / "original.py"
    original_upload.write_text("print('fixture')", encoding="utf-8")
    state = source_state()
    workspace, artifacts = InputIngestor(settings).ingest(state.run_id, [AttachmentRef(ref=original_upload.name)])
    state.workspace, state.input_artifacts = str(workspace), artifacts
    original_upload.unlink()
    record, _ = RetestStore(LedgerStore(settings.database_url)).reserve(
        state, "finding", "finding-1", "request-123456789", {"note": "Review fix"})
    fixed_upload = settings.upload_root / "fixed.py"
    fixed_upload.write_text("print('fixed')", encoding="utf-8")
    task = prepare_retest_task(state, record, settings, "Check the fix", [AttachmentRef(ref="fixed.py")])
    assert task.target_scope == state.task.target_scope
    assert task.network_policy == state.task.network_policy
    child_workspace, child_artifacts = InputIngestor(settings).ingest(record["child_run_id"], task.attachments)
    assert child_artifacts[0].sha256 == artifacts[0].sha256
    assert (child_workspace / child_artifacts[0].relative_path).read_text() == "print('fixture')"
    assert (child_workspace / "fixed.py").read_text() == "print('fixed')"
    assert prepare_retest_task(state, record, settings, "Check the fix",
                               [AttachmentRef(ref="fixed.py")]).attachments == task.attachments
    (workspace / artifacts[0].relative_path).write_text("tampered", encoding="utf-8")
    with pytest.raises(ValueError, match="校验失败"):
        prepare_retest_task(state, record, settings, "Check the fix", [])


def test_retest_does_not_reuse_one_time_post_grant_or_unuploaded_material(settings):
    settings.prepare_directories()
    state = source_state()
    record, _ = RetestStore(LedgerStore(settings.database_url)).reserve(
        state, "finding", "finding-1", "request-123456789", {})
    state.task.network_policy = "scoped_file_post"
    with pytest.raises(ValueError, match="单次 POST 授权"):
        prepare_retest_task(state, record, settings, "", [])
    state.task.network_policy = "none"
    with pytest.raises(ValueError, match="上传引用"):
        prepare_retest_task(state, record, settings, "", [AttachmentRef(ref="../other.txt")])


@pytest.mark.parametrize("module,verdict,checks", [
    ("penetration", "fixed", {"trigger": ["new-evidence"], "baseline": ["baseline-evidence"],
                              "conditions": ["new-evidence"]}),
    ("code_audit", "fixed", {"path_coverage": ["new-evidence"], "validation": ["new-evidence"]}),
    ("reverse", "refuted", {"verification": ["new-evidence"]}),
    ("log_analysis", "supported", {"verification": ["new-evidence"],
                                   "material_scope": ["new-evidence"]}),
    ("incident_response", "supported", {"verification": ["new-evidence"],
                                        "material_scope": ["new-evidence"]}),
])
def test_result_requires_child_receipt_and_module_checks(settings, module, verdict, checks):
    settings.prepare_directories()
    ledger = LedgerStore(settings.database_url)
    store = RetestStore(ledger)
    source = source_state()
    source.module_route = module
    record, _ = store.reserve(source, "finding", "finding-1", "request-123456789", {})
    store.set_status(record["retest_id"], "awaiting_result")
    evidence = Evidence(evidence_id="new-evidence", source="tool", summary="New observation")
    baseline = Evidence(evidence_id="baseline-evidence", source="tool", summary="Normal control")
    current = [evidence, baseline] if module == "penetration" else [evidence]
    child = AgentState(run_id=record["child_run_id"], task=source.task,
                       status=RunStatus.COMPLETED, evidence=current,
                       report=AgentReport(run_id=record["child_run_id"], status=RunStatus.COMPLETED,
                                          executive_summary="Checked", evidence=current))
    with pytest.raises(ValueError, match="来源回执"):
        store.finish(source.run_id, record["retest_id"], child, verdict, "Checked", checks)
    child.observations.append(ToolResult(status=ToolStatus.SUCCESS, evidence=current))
    with pytest.raises(ValueError, match="缺少"):
        store.finish(source.run_id, record["retest_id"], child, verdict, "Checked", {})
    result = store.finish(source.run_id, record["retest_id"], child, verdict, "Checked", checks)
    assert result["status"] == "completed"
    assert result["checks"] == checks
    assert result["evidence_ids"] == list(dict.fromkeys(eid for ids in checks.values() for eid in ids))
    assert store.finish(source.run_id, record["retest_id"], child, verdict, "Checked", checks) == result
    with pytest.raises(ValueError, match="不能改写"):
        store.finish(source.run_id, record["retest_id"], child, "inconclusive", "Changed", {})


def test_retest_status_cannot_regress_after_child_finishes(settings):
    settings.prepare_directories()
    store = RetestStore(LedgerStore(settings.database_url))
    record, _ = store.reserve(source_state(), "finding", "finding-1", "request-123456789", {})
    store.set_status(record["retest_id"], "awaiting_result")
    with pytest.raises(ValueError, match="不能回退"):
        store.set_status(record["retest_id"], "running")
    assert store.set_status(record["retest_id"], "stopped")["status"] == "stopped"


def test_concurrent_result_writes_cannot_replace_saved_verdict(settings):
    settings.prepare_directories()
    ledger = LedgerStore(settings.database_url)
    store = RetestStore(ledger)
    source = source_state()
    record, _ = store.reserve(source, "finding", "finding-1", "request-123456789", {})
    store.set_status(record["retest_id"], "awaiting_result")
    evidence = Evidence(evidence_id="new-evidence", source="tool", summary="Checked")
    child = AgentState(run_id=record["child_run_id"], task=source.task, status=RunStatus.COMPLETED,
                       evidence=[evidence], observations=[ToolResult(status=ToolStatus.SUCCESS, evidence=[evidence])],
                       report=AgentReport(run_id=record["child_run_id"], status=RunStatus.COMPLETED,
                                          executive_summary="Checked", evidence=[evidence]))

    def save(summary):
        try:
            return store.finish(source.run_id, record["retest_id"], child, "reproduced", summary,
                                {"validation": [evidence.evidence_id]})["summary"]
        except ValueError:
            return None

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(save, ["First result", "Second result"]))
    assert len([value for value in outcomes if value is not None]) == 1
    assert store.get(source.run_id, record["retest_id"])["summary"] in outcomes


def test_partial_child_cannot_record_definitive_result(settings):
    settings.prepare_directories()
    store = RetestStore(LedgerStore(settings.database_url))
    source = source_state()
    record, _ = store.reserve(source, "finding", "finding-1", "request-123456789", {})
    store.set_status(record["retest_id"], "awaiting_result")
    evidence = Evidence(evidence_id="new-evidence", source="tool", summary="Checked")
    child = AgentState(run_id=record["child_run_id"], task=source.task, status=RunStatus.PARTIAL,
                       evidence=[evidence], observations=[ToolResult(status=ToolStatus.SUCCESS, evidence=[evidence])],
                       report=AgentReport(run_id=record["child_run_id"], status=RunStatus.PARTIAL,
                                          executive_summary="Partial", evidence=[evidence]))
    with pytest.raises(ValueError, match="部分完成"):
        store.finish(source.run_id, record["retest_id"], child, "reproduced", "Still present",
                     {"validation": [evidence.evidence_id]})
    result = store.finish(source.run_id, record["retest_id"], child, "inconclusive", "Tool budget exhausted", {})
    assert result["verdict"] == "inconclusive"


@pytest.mark.parametrize("module", ["code_audit", "reverse", "penetration", "log_analysis", "incident_response"])
async def test_real_api_retest_creates_one_budgeted_child_and_preserves_route(settings, monkeypatch, module):
    app = create_app(settings)
    service = app.state.service
    source = source_state()
    source.module_route = module
    source.task.target_scope = ["https://target.test/app"] if module == "penetration" else []
    service.ledger.save_state(source)
    spawned = []

    def capture(coroutine):
        spawned.append(coroutine)
        coroutine.close()

    monkeypatch.setattr(service, "_spawn", capture)
    payload = {"source_kind": "finding", "source_ref": "finding-1",
               "request_id": "request-123456789", "notes": "Review just this finding",
               "max_runtime_seconds": 120, "max_model_calls": 5, "max_tool_calls": 8}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        first = await client.post("/api/v1/runs/source-run/retests", json=payload)
        assert first.status_code == 202, first.text
        second = await client.post("/api/v1/runs/source-run/retests", json={
            **payload, "request_id": "request-987654321", "max_model_calls": 10})
        assert second.status_code == 202, second.text
        assert first.json()["child_run_id"] == second.json()["child_run_id"]
        assert len(spawned) == 1
        child = service.state(first.json()["child_run_id"])
        assert child.budget.max_runtime_seconds == 120
        assert child.budget.max_model_calls == 5
        assert child.budget.max_tool_calls == 8
        assert child.task.target_scope == source.task.target_scope
        assert child.task.network_policy == source.task.network_policy
        classified = await TaskInterpreterAgent(service.orchestrator.gateway).run(child)
        assert classified.module_route == ("log_analysis" if module == "incident_response" else module)
        assert classified.routing["source"] == "retest_snapshot"
        history = await client.get("/api/v1/runs/source-run/retests")
        assert len(history.json()["retests"]) == 1
        denied = await client.get(f"/api/v1/runs/other-run/retests/{first.json()['retest_id']}")
        assert denied.status_code == 404
        assert service.state(source.run_id).report == source.report


async def test_api_resumes_reserved_retest_from_saved_request(settings, monkeypatch):
    app = create_app(settings)
    service = app.state.service
    source = source_state()
    service.ledger.save_state(source)
    store = app.state.retests
    saved = {"source_kind": "finding", "source_ref": "finding-1", "notes": "Original focus",
             "attachments": [], "max_runtime_seconds": 120, "max_tool_calls": 8, "max_model_calls": 5}
    record, _ = store.reserve(source, "finding", "finding-1", "request-123456789", saved)
    spawned = []

    def capture(coroutine):
        spawned.append(coroutine)
        coroutine.close()

    monkeypatch.setattr(service, "_spawn", capture)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        resumed = await client.post("/api/v1/runs/source-run/retests", json={
            "source_kind": "finding", "source_ref": "finding-1", "request_id": "request-987654321",
            "notes": "Different request", "max_model_calls": 10})
        assert resumed.status_code == 202, resumed.text
        assert resumed.json()["retest_id"] == record["retest_id"]
        assert len(spawned) == 1
        child = service.state(record["child_run_id"])
        assert child.budget.max_model_calls == 5
        assert child.budget.max_tool_calls == 8
        assert "Original focus" in child.task.constraints[-1]
        assert "Different request" not in child.task.constraints[-1]


async def test_retest_redacted_scope_still_matches_original_authorization(settings, monkeypatch):
    app = create_app(settings)
    source = source_state()
    source.module_route = "penetration"
    source.task.target_scope = ["https://target.test/app?token=private-token"]
    app.state.service.ledger.save_state(source)
    monkeypatch.setattr(app.state.service, "_spawn", lambda coroutine: coroutine.close())
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        result = await client.post("/api/v1/runs/source-run/retests", json={
            "source_kind": "finding", "source_ref": "finding-1", "request_id": "request-123456789"})
        assert result.status_code == 202, result.text
        assert result.json()["status"] == "running"
        assert "private-token" not in str(result.json()["snapshot"])


async def test_startup_recovers_reserved_retest_without_client_retry(settings, monkeypatch):
    app = create_app(settings)
    service = app.state.service
    source = source_state()
    service.ledger.save_state(source)
    record, _ = app.state.retests.reserve(source, "finding", "finding-1", "request-123456789", {
        "source_kind": "finding", "source_ref": "finding-1", "notes": "Resume after restart",
        "attachments": [], "max_runtime_seconds": 120, "max_tool_calls": 8, "max_model_calls": 5,
    })
    spawned = []

    def capture(coroutine):
        spawned.append(coroutine)
        coroutine.close()

    monkeypatch.setattr(service, "_spawn", capture)
    async with app.router.lifespan_context(app):
        await app.state.recover_retests()
    assert len(spawned) == 1
    assert service.state(record["child_run_id"]).budget.max_runtime_seconds == 120
    assert app.state.retests.get("source-run", record["retest_id"])["status"] == "running"


async def test_api_retest_rejects_active_source_before_taking_execution_lock(settings, monkeypatch):
    app = create_app(settings)
    source = source_state()
    source.status = RunStatus.RUNNING
    app.state.service.ledger.save_state(source)

    def unexpected_lock(_run_id):
        raise AssertionError("Active source must be rejected before taking its execution lock")

    monkeypatch.setattr(app.state.service, "run_lock", unexpected_lock)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        result = await client.post("/api/v1/runs/source-run/retests", json={
            "source_kind": "finding", "source_ref": "finding-1", "request_id": "request-123456789"})
        assert result.status_code == 409, result.text


async def test_result_rejects_active_child_without_waiting_for_execution(settings, monkeypatch):
    app = create_app(settings)
    service = app.state.service
    source = source_state()
    service.ledger.save_state(source)
    record, _ = app.state.retests.reserve(source, "finding", "finding-1", "request-123456789", {})
    service.ledger.save_state(AgentState(run_id=record["child_run_id"], task=source.task,
                                       status=RunStatus.RUNNING))

    def unexpected_lock(_run_id):
        raise AssertionError("Active child must be rejected before taking its execution lock")

    monkeypatch.setattr(service, "run_lock", unexpected_lock)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        result = await client.post(f"/api/v1/runs/source-run/retests/{record['retest_id']}/result", json={
            "verdict": "inconclusive", "summary": "Too early"})
        assert result.status_code == 409, result.text


async def test_api_result_projects_into_report_without_rewriting_history(settings, monkeypatch):
    app = create_app(settings)
    service = app.state.service
    source = source_state()
    service.ledger.save_state(source)

    def capture(coroutine):
        coroutine.close()

    monkeypatch.setattr(service, "_spawn", capture)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        created = await client.post("/api/v1/runs/source-run/retests", json={
            "source_kind": "finding", "source_ref": "finding-1", "request_id": "request-123456789"})
        assert created.status_code == 202, created.text
        record = created.json()
        child = service.state(record["child_run_id"])
        child.status = RunStatus.COMPLETED
        evidence = Evidence(evidence_id="child-observation", source="tool", summary="Checked target")
        child.evidence = [evidence]
        child.observations = [ToolResult(status=ToolStatus.SUCCESS, evidence=[evidence])]
        child.report = AgentReport(run_id=child.run_id, status=child.status,
                                   executive_summary="Checked", evidence=[evidence])
        service.ledger.save_state(child)
        payload = {"verdict": "reproduced", "summary": "Issue still present",
                   "checks": {"validation": [evidence.evidence_id]}}
        accepted = await client.post(
            f"/api/v1/runs/source-run/retests/{record['retest_id']}/result", json=payload)
        assert accepted.status_code == 200, accepted.text
        assert accepted.json()["status"] == "completed"
        same = await client.post(
            f"/api/v1/runs/source-run/retests/{record['retest_id']}/result", json=payload)
        assert same.status_code == 200, same.text
        invalid = await client.post(
            f"/api/v1/runs/source-run/retests/{record['retest_id']}/result",
            json={"verdict": "fixed", "summary": "Changed", "checks": payload["checks"]})
        assert invalid.status_code == 409
        report = await client.get("/api/v1/runs/source-run/report")
        assert report.status_code == 200
        assert report.json()["retests"][0]["verdict"] == "reproduced"
        assert report.json()["retests"][0]["original_evidence_ids"] == ["original-evidence"]
        assert report.json()["executive_summary"] == source.report.executive_summary
        assert service.state(source.run_id).report == source.report
        assert len([item for item in service.ledger.events(source.run_id)
                    if item.event_type == "retest.result.recorded"]) == 1


async def test_trace_traffic_binding_and_retest_report_round_trip(settings, monkeypatch):
    app = create_app(settings)
    service = app.state.service
    source = source_state()
    source.module_route = "penetration"
    source.task.target_scope = ["https://target.test"]
    service.ledger.save_state(source)
    receipt = service.ledger.append("source-run", "tool.completed", {"worker": "web-worker", "result": {
        "request": {"method": "GET", "url": "https://target.test/auth", "headers": {}, "body": ""},
        "response": {"status": 200, "headers": {}, "body": "session-check-marker"},
    }})
    monkeypatch.setattr(service, "_spawn", lambda coroutine: coroutine.close())
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        traces = await client.get("/api/v1/runs/source-run/traces", params={"keyword": "session-check-marker"})
        assert traces.status_code == 200, traces.text
        assert any(item["trace_id"] == receipt.event_id for item in traces.json()["items"])
        traffic = await client.post("/api/v1/runs/source-run/traffic-evidence", json={
            "source_kind": "ledger", "source_ref": receipt.event_id})
        assert traffic.status_code == 201, traffic.text
        original_id = traffic.json()["evidence_id"]
        bound = await client.post("/api/v1/runs/source-run/findings/finding-1/traffic-bindings",
                                  json={"evidence_id": original_id, "role": "proof"})
        assert bound.status_code == 201, bound.text
        created = await client.post("/api/v1/runs/source-run/retests", json={
            "source_kind": "finding", "source_ref": "finding-1", "request_id": "request-123456789"})
        assert created.status_code == 202, created.text
        record = created.json()
        assert set(record["original_evidence_ids"]) == {"original-evidence", original_id}
        child = service.state(record["child_run_id"])
        current = Evidence(evidence_id="retest-proof", source="tool", summary="Observed again")
        child.status = RunStatus.COMPLETED
        child.evidence = [current]
        child.observations = [ToolResult(status=ToolStatus.SUCCESS, evidence=[current])]
        child.report = AgentReport(run_id=child.run_id, status=child.status,
                                   executive_summary="Rechecked", evidence=[current])
        service.ledger.save_state(child)
        result = await client.post(f"/api/v1/runs/source-run/retests/{record['retest_id']}/result", json={
            "verdict": "reproduced", "summary": "Observed with current evidence",
            "checks": {"proof": [current.evidence_id]}})
        assert result.status_code == 200, result.text
        report = (await client.get("/api/v1/runs/source-run/report")).json()
        assert set(report["retests"][0]["original_evidence_ids"]) == {"original-evidence", original_id}
        assert report["retests"][0]["evidence_ids"] == [current.evidence_id]
        assert service.ledger.verify("source-run")


async def test_api_retest_cancel_is_durable_and_releases_source(settings, monkeypatch):
    app = create_app(settings)
    service = app.state.service
    source = source_state()
    service.ledger.save_state(source)
    monkeypatch.setattr(service, "_spawn", lambda coroutine: coroutine.close())
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        created = await client.post("/api/v1/runs/source-run/retests", json={
            "source_kind": "finding", "source_ref": "finding-1", "request_id": "request-123456789"})
        assert created.status_code == 202
        retest_id = created.json()["retest_id"]
        cancelled = await client.post(f"/api/v1/runs/source-run/retests/{retest_id}/cancel")
        assert cancelled.status_code == 200, cancelled.text
        assert cancelled.json()["status"] == "stopped"
        assert RetestStore(service.ledger).get("source-run", retest_id)["status"] == "stopped"
        second = await client.post("/api/v1/runs/source-run/retests", json={
            "source_kind": "finding", "source_ref": "finding-1", "request_id": "request-987654321"})
        assert second.status_code == 202, second.text
        assert second.json()["retest_id"] != retest_id
