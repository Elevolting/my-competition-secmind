from __future__ import annotations

import hashlib
import json
from pathlib import Path
from uuid import uuid4

import httpx

from security_agent.agents import TaskInterpreterAgent
from security_agent.api import create_app
from security_agent.ingest import sha256_file


async def test_completed_incident_receipt_becomes_a_durable_retest_source(settings, monkeypatch):
    app = create_app(settings)
    incident = app.state.incident_manager
    service = app.state.service
    action_id = str(uuid4())
    action = {"action_id": action_id, "command": "collect_indicators", "label": "检查监听暴露与基线变化",
              "status": "completed", "target": "local", "completed_at": "2026-10-15T02:00:00+00:00",
              "result": {"collected_at": "2026-10-15T02:00:00Z", "findings": [
                  {"message": "检查 443 端口的访问控制"}], "errors": []}}
    incident._actions.append(action)
    incident._save()
    spawned = []

    def capture(coroutine):
        spawned.append(coroutine)
        coroutine.close()

    monkeypatch.setattr(service, "_spawn", capture)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        first = await client.post(f"/api/v1/incident/actions/{action_id}/review-source")
        assert first.status_code == 201, first.text
        second = await client.post(f"/api/v1/incident/actions/{action_id}/review-source")
        assert second.status_code == 201 and second.json() == first.json()
        source_id = first.json()["run_id"]
        source = service.state(source_id)
        assert source.module_route == "incident_response"
        assert source.report.worker_reports == ["检查 443 端口的访问控制"]
        assert len(source.input_artifacts) == 1
        artifact_path = Path(source.workspace) / source.input_artifacts[0].relative_path
        assert sha256_file(artifact_path) == source.input_artifacts[0].sha256
        assert json.loads(artifact_path.read_text(encoding="utf-8")) == action["result"]
        assert service.ledger.verify(source_id)
        summary = source.report.executive_summary
        reference = f"executive_summary:0:{hashlib.sha256(summary.encode()).hexdigest()}"
        created = await client.post(f"/api/v1/runs/{source_id}/retests", json={
            "source_kind": "conclusion", "source_ref": reference, "request_id": "request-123456789"})
        assert created.status_code == 202, created.text
        child = service.state(created.json()["child_run_id"])
        assert child.task.network_policy == "none"
        assert len(child.task.attachments) == 1
        classified = await TaskInterpreterAgent(service.orchestrator.gateway).run(child)
        assert classified.module_route == "log_analysis"
        assert len(spawned) == 1
        report = await client.get(f"/api/v1/runs/{source_id}/report")
        assert report.status_code == 200 and report.json()["executive_summary"] == summary
        artifact_path.write_text('{"tampered":true}', encoding="utf-8")
        damaged = await client.post(f"/api/v1/incident/actions/{action_id}/review-source")
        assert damaged.status_code == 409
        action["result"]["findings"][0]["message"] = "Changed after import"
        changed = await client.post(f"/api/v1/incident/actions/{action_id}/review-source")
        assert changed.status_code == 409
        assert service.state(source_id).report.executive_summary == summary


async def test_incident_review_rejects_incomplete_or_tampered_evidence(settings):
    app = create_app(settings)
    incident = app.state.incident_manager
    action_id = str(uuid4())
    action = {"action_id": action_id, "command": "collect_evidence", "label": "保存本机取证快照",
              "status": "completed", "target": "local", "completed_at": "2026-10-15T02:00:00+00:00",
              "result": {"evidence_id": action_id, "sha256": "0" * 64}}
    incident._actions.append(action)
    incident._save()
    path = incident.root / "evidence" / f"{action_id}.json"
    path.write_text('{"sample":"fixture"}', encoding="utf-8")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        invalid = await client.post(f"/api/v1/incident/actions/{action_id}/review-source")
        assert invalid.status_code == 409
        action["result"]["sha256"] = sha256_file(path)
        valid = await client.post(f"/api/v1/incident/actions/{action_id}/review-source")
        assert valid.status_code == 201, valid.text
        path.write_text('{"sample":"changed"}', encoding="utf-8")
        tampered = await client.post(f"/api/v1/incident/actions/{action_id}/review-source")
        assert tampered.status_code == 409
        action["status"] = "executing"
        incomplete = await client.post(f"/api/v1/incident/actions/{action_id}/review-source")
        assert incomplete.status_code == 409


async def test_completed_response_action_is_reviewable_without_reexecuting_it(settings):
    app = create_app(settings)
    incident = app.state.incident_manager
    action_id = str(uuid4())
    incident._actions.append({"action_id": action_id, "command": "block_indicator",
        "label": "Windows 防火墙阻断远端 IP", "status": "completed", "target": "192.0.2.1",
        "completed_at": "2026-10-15T02:00:00+00:00",
        "result": {"rule_name": "SecMind-test", "exit_code": 0}})
    incident._save()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        result = await client.post(f"/api/v1/incident/actions/{action_id}/review-source")
        assert result.status_code == 201, result.text
        source = app.state.service.state(result.json()["run_id"])
        assert source.task.network_policy == "none"
        assert "不得执行隔离、恢复或防火墙处置命令" in source.task.constraints[-1]
        assert source.report.evidence[0].metadata["command"] == "block_indicator"
        assert app.state.service.ledger.verify(source.run_id)
