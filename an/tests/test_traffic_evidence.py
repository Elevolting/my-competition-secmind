from __future__ import annotations

import base64
import json
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from security_agent.api import create_app
from security_agent.ledger import LedgerStore
from security_agent.operations import OperationsStore
from security_agent.schemas import AgentReport, AgentState, Finding, RunStatus, TaskRequest
from security_agent.traffic_evidence import EvidenceCorrupt, TrafficEvidenceStore
from security_agent.traffic_evidence_api import register_traffic_evidence


def setup(settings):
    settings.prepare_directories()
    ledger = LedgerStore(settings.database_url)
    finding = Finding(finding_id="finding-1", rule_id="TEST", path="/", title="Header issue",
                      description="Observed response")
    state = AgentState(run_id="run-one", task=TaskRequest(objective="Review captured HTTP flow"),
                       status=RunStatus.COMPLETED, findings=[finding])
    state.report = AgentReport(run_id=state.run_id, status=state.status,
                               executive_summary="Review complete", findings=[finding])
    ledger.save_state(state)
    ledger.save_state(AgentState(run_id="run-two", task=TaskRequest(objective="Another task")))
    operations = OperationsStore(settings.run_root.parent / "operations-test.db")
    return ledger, operations, TrafficEvidenceStore(ledger, settings, operations)


def har_fixture():
    return {"log": {"entries": [{"startedDateTime": "2026-10-15T01:00:00Z",
        "request": {"method": "POST", "url": "https://target.test/login?token=query-secret",
                    "httpVersion": "HTTP/1.1", "headers": [
                        {"name": "Authorization", "value": "Bearer request-secret"},
                        {"name": "Content-Type", "value": "application/json"}],
                    "postData": {"text": '{"password":"body-secret"}'}},
        "response": {"status": 401, "httpVersion": "HTTP/1.1", "headers": [
            {"name": "Set-Cookie", "value": "session=response-secret"}],
            "content": {"text": "Login rejected"}}}]}}


def test_har_snapshot_binding_survives_source_deletion_and_does_not_confirm(settings):
    ledger, _, store = setup(settings)
    upload = settings.upload_root / "captured.har"
    upload.write_text(json.dumps(har_fixture()), encoding="utf-8")
    created = store.create("run-one", "har", upload.name)
    evidence_id = created["evidence_id"]
    state = ledger.load_state("run-one")
    artifact = Path(state.evidence[0].artifact_ref)
    assert artifact.is_file() and state.evidence[0].sha256 == created["sha256"]
    stored = artifact.read_text(encoding="utf-8")
    assert all(value not in stored for value in
               ("query-secret", "request-secret", "body-secret", "response-secret"))
    assert created["snapshot"]["status_code"] == 401
    assert created["snapshot"]["request_sha256"] and created["snapshot"]["response_sha256"]
    assert store.create("run-one", "har", upload.name)["evidence_id"] == evidence_id
    assert len(ledger.load_state("run-one").evidence) == 1
    upload.unlink()
    assert store.get("run-one", evidence_id)["snapshot"] == created["snapshot"]
    bound = store.bind("run-one", "finding-1", evidence_id, "proof", "Cookie: note-secret")
    assert bound["role"] == "proof" and "note-secret" not in bound["note"]
    store.bind("run-one", "finding-1", evidence_id, "proof")
    state = ledger.load_state("run-one")
    assert state.findings[0].evidence_ids == [evidence_id]
    assert len(state.findings[0].raw["traffic_bindings"]) == 1
    assert state.report.confirmed_findings == []
    assert len(state.report.candidate_findings) == 1
    assert state.report.evidence[0].evidence_id == evidence_id
    assert [event.event_type for event in ledger.events("run-one")].count("traffic.evidence.bound") == 1
    assert ledger.verify("run-one")


def test_workbench_stale_snapshot_keeps_durable_traffic_binding(settings):
    ledger, _, store = setup(settings)
    ledger.update_state("run-one", lambda state: state.external_execution.update(
        blackboard={"planning_mode": "workbench"}))
    stale = ledger.load_state("run-one")
    upload = settings.upload_root / "captured.har"
    upload.write_text(json.dumps(har_fixture()), encoding="utf-8")
    evidence_id = store.create("run-one", "har", upload.name)["evidence_id"]
    store.bind("run-one", "finding-1", evidence_id, "proof")

    ledger.save_state(stale)
    current = ledger.load_state("run-one")
    assert current.findings[0].evidence_ids == [evidence_id]
    assert current.findings[0].raw["traffic_bindings"] == [
        {"evidence_id": evidence_id, "role": "proof", "note": ""}]
    assert current.report.findings[0].evidence_ids == [evidence_id]
    assert current.report.evidence[0].evidence_id == evidence_id
    assert current.report.confirmed_findings == []


def test_mcp_raw_http_and_ledger_exchange_are_task_bound(settings):
    ledger, operations, store = setup(settings)
    operations.put("call:burp-1", {"call_id": "burp-1", "run_id": "run-one", "status": "completed",
        "arguments": {"content": "GET /app HTTP/1.1\r\nHost: target.test\r\nCookie: secret-cookie\r\n\r\n",
                      "targetHostname": "target.test", "targetPort": 443, "useHttps": True},
        "result": {"content": [{"type": "text", "text":
            "HTTP/1.1 200 OK\r\nSet-Cookie: secret-response\r\n\r\nHello"}]}})
    mcp = store.create("run-one", "mcp", "burp-1")
    assert mcp["snapshot"]["url"] == "https://target.test:443/app"
    assert mcp["snapshot"]["status_code"] == 200
    assert store.create("run-one", "mcp", "burp-1")["evidence_id"] == mcp["evidence_id"]
    assert "secret-cookie" not in json.dumps(mcp)
    assert "secret-response" not in json.dumps(mcp)
    event = ledger.append("run-one", "tool.completed", {"result": {
        "request": {"method": "GET", "url": "https://target.test/app", "headers": {}, "body": ""},
        "response": {"status": 204, "headers": {}, "body": ""}}})
    platform = store.create("run-one", "ledger", event.event_id)
    assert platform["snapshot"]["status_code"] == 204
    with pytest.raises(KeyError):
        store.create("run-two", "mcp", "burp-1")
    with pytest.raises(KeyError):
        store.create("run-two", "ledger", event.event_id)
    with pytest.raises(KeyError):
        store.get("run-two", mcp["evidence_id"])
    with pytest.raises(KeyError):
        store.bind("run-two", "finding-1", mcp["evidence_id"], "proof")


def test_nested_mcp_exchange_and_missing_body_are_recorded(settings):
    _, operations, store = setup(settings)
    operations.put("call:nested", {"run_id": "run-one", "arguments": {},
        "result": {"structuredContent": {"result": {"content": [{"type": "text", "text":
            json.dumps({"request": {"method": "GET", "url": "https://target.test/health"},
                        "response": {"status": 200, "headers": {"Content-Type": "text/plain"}}})}]}}}})
    snapshot = store.create("run-one", "mcp", "nested")["snapshot"]
    assert snapshot["status_code"] == 200
    assert snapshot["missing"] == {"request_body": True, "response_body": True}


def test_metadata_only_ledger_event_and_unfinished_mcp_receipt_are_rejected(settings):
    ledger, operations, store = setup(settings)
    event = ledger.append("run-one", "tool.completed", {"tool": "http", "status": "completed"})
    with pytest.raises(ValueError, match="没有 HTTP 交换内容"):
        store.create("run-one", "ledger", event.event_id)
    operations.put("call:pending", {"run_id": "run-one", "status": "running", "result": {
        "request": {"method": "GET", "url": "https://target.test/"},
        "response": {"status": 200}}})
    with pytest.raises(ValueError, match="未成功完成"):
        store.create("run-one", "mcp", "pending")


def test_har_invalid_body_shape_and_truncation(settings):
    _, _, store = setup(settings)
    upload = settings.upload_root / "captured.har"
    invalid = har_fixture()
    invalid["log"]["entries"][0]["response"]["content"] = "broken"
    upload.write_text(json.dumps(invalid), encoding="utf-8")
    with pytest.raises(ValueError, match="正文格式无效"):
        store.create("run-one", "har", upload.name)

    incomplete = har_fixture()
    entry = incomplete["log"]["entries"][0]
    entry["request"].pop("postData")
    entry["response"].pop("content")
    entry["_truncated"] = True
    upload.write_text(json.dumps(incomplete), encoding="utf-8")
    snapshot = store.create("run-one", "har", upload.name)["snapshot"]
    assert snapshot["missing"] == {"request_body": True, "response_body": True}
    assert snapshot["truncated"] is True


def test_har_base64_body_is_decoded_before_redaction(settings):
    ledger, _, store = setup(settings)
    data = har_fixture()
    body_text = '{"access_token":"encoded-secret","result":"ok"}'
    encoded = base64.b64encode(body_text.encode()).decode()
    data["log"]["entries"][0]["response"]["content"] = {"text": encoded, "encoding": "base64"}
    upload = settings.upload_root / "encoded.har"
    upload.write_text(json.dumps(data), encoding="utf-8")
    created = store.create("run-one", "har", upload.name)
    stored = Path(ledger.load_state("run-one").evidence[0].artifact_ref).read_text(encoding="utf-8")
    assert "encoded-secret" not in stored and encoded not in stored
    assert json.loads(created["snapshot"]["response"]["body"]) == {
        "access_token": "[REDACTED]", "result": "ok"}
    assert created["snapshot"]["response"]["body_encoding"] == "utf-8"


def test_har_binary_body_is_omitted_and_bad_base64_is_rejected(settings):
    _, _, store = setup(settings)
    data = har_fixture()
    content = data["log"]["entries"][0]["response"]["content"]
    content.update(text=base64.b64encode(b"\xff\xfe\x00").decode(), encoding="base64")
    upload = settings.upload_root / "binary.har"
    upload.write_text(json.dumps(data), encoding="utf-8")
    snapshot = store.create("run-one", "har", upload.name)["snapshot"]
    assert snapshot["response"]["body"] is None
    assert snapshot["response"]["body_encoding"] == "binary-omitted"
    assert snapshot["missing"]["response_body"] is True
    content["text"] = "invalid-base64"
    upload.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="base64"):
        store.create("run-one", "har", upload.name)


def test_body_size_limit_and_invalid_entry_index(settings, monkeypatch):
    import security_agent.traffic_evidence as module
    monkeypatch.setattr(module, "MAX_BODY_BYTES", 8)
    _, _, store = setup(settings)
    data = har_fixture()
    upload = settings.upload_root / "truncated.har"
    upload.write_text(json.dumps(data), encoding="utf-8")
    snapshot = store.create("run-one", "har", upload.name)["snapshot"]
    assert snapshot["truncated"] is True
    assert len(snapshot["response"]["body"].encode()) <= 8
    with pytest.raises(ValueError, match="索引超出范围"):
        store.create("run-one", "har", upload.name, 9)


def test_missing_or_corrupt_snapshot_fails_closed(settings):
    ledger, _, store = setup(settings)
    upload = settings.upload_root / "captured.har"
    upload.write_text(json.dumps(har_fixture()), encoding="utf-8")
    created = store.create("run-one", "har", upload.name)
    path = Path(ledger.load_state("run-one").evidence[0].artifact_ref)
    path.write_text("tampered", encoding="utf-8")
    with pytest.raises(EvidenceCorrupt):
        store.get("run-one", created["evidence_id"])
    with pytest.raises(EvidenceCorrupt):
        store.bind("run-one", "finding-1", created["evidence_id"], "proof")
    with pytest.raises(EvidenceCorrupt):
        store.create("run-one", "har", upload.name)
    path.unlink()
    with pytest.raises(EvidenceCorrupt):
        store.get("run-one", created["evidence_id"])


async def test_traffic_api_rejects_cross_task_refs_and_exports_redacted_snapshot(settings):
    _, operations, store = setup(settings)
    upload = settings.upload_root / "captured.har"
    upload.write_text(json.dumps(har_fixture()), encoding="utf-8")
    app = FastAPI()
    register_traffic_evidence(app, store.ledger, settings, operations)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        result = await client.post("/api/v1/runs/run-one/traffic-evidence", json={
            "source_kind": "har", "source_ref": upload.name})
        assert result.status_code == 201, result.text
        evidence_id = result.json()["evidence_id"]
        cross = await client.get(f"/api/v1/runs/run-two/traffic-evidence/{evidence_id}")
        assert cross.status_code == 404
        exported = await client.get(f"/api/v1/runs/run-one/traffic-evidence/{evidence_id}/export")
        assert exported.status_code == 200
        assert "request-secret" not in exported.text and "[REDACTED]" in exported.text
        bound = await client.post("/api/v1/runs/run-one/findings/finding-1/traffic-bindings",
                                  json={"evidence_id": evidence_id, "role": "baseline"})
        assert bound.status_code == 201 and bound.json()["role"] == "baseline"
        assert (await client.post("/api/v1/runs/run-one/findings/finding-1/traffic-bindings",
            json={"evidence_id": evidence_id, "role": "invalid"})).status_code == 422


def test_real_api_upload_bind_and_report_round_trip(settings):
    app = create_app(settings)
    finding = Finding(finding_id="finding-1", rule_id="TEST", path="/", title="Header issue",
                      description="Observed response")
    state = AgentState(run_id="run-one", task=TaskRequest(objective="Review captured HTTP flow"),
                       status=RunStatus.COMPLETED, findings=[finding])
    state.report = AgentReport(run_id=state.run_id, status=state.status,
                               executive_summary="Review complete", findings=[finding])
    app.state.service.ledger.save_state(state)
    with TestClient(app) as client:
        uploaded = client.post("/api/v1/uploads", files={"file": (
            "captured.har", json.dumps(har_fixture()).encode(), "application/json")})
        assert uploaded.status_code == 201, uploaded.text
        created = client.post("/api/v1/runs/run-one/traffic-evidence", json={
            "source_kind": "har", "source_ref": uploaded.json()["ref"]})
        assert created.status_code == 201, created.text
        evidence_id = created.json()["evidence_id"]
        bound = client.post("/api/v1/runs/run-one/findings/finding-1/traffic-bindings", json={
            "evidence_id": evidence_id, "role": "proof"})
        assert bound.status_code == 201, bound.text
        report = client.get("/api/v1/runs/run-one/report")
        assert report.status_code == 200
        assert report.json()["candidate_findings"][0]["evidence_ids"] == [evidence_id]
        assert report.json()["evidence"][0]["sha256"] == created.json()["sha256"]
        assert report.json()["confirmed_findings"] == []
