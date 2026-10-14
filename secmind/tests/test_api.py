from __future__ import annotations

import io
import time
import zipfile

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from secmind.admission import AdmissionService
from secmind.api import create_app
from secmind.api_runs import _redacted_report
from secmind.schemas import SCHEMA_VERSION, AgentReport, RunStatus
from secmind.secret_scrubber import ArtifactLeakageError


def test_report_redaction_fails_with_controlled_response(monkeypatch) -> None:
    def reject_artifact(*args, **kwargs):
        raise ArtifactLeakageError("synthetic unsafe artifact")

    monkeypatch.setattr("secmind.api_runs.scrub_artifact", reject_artifact)
    report = AgentReport(run_id="run-redaction-test", status=RunStatus.COMPLETED, executive_summary="test")
    with pytest.raises(HTTPException) as error:
        _redacted_report(report)
    assert error.value.status_code == 409
    assert error.value.detail == "report cannot be safely redacted"


def test_local_browser_boundary(settings) -> None:
    app = create_app(settings)
    with TestClient(app, base_url="http://127.0.0.1") as client:
        assert client.get("/api/v1/tools", headers={"Host": "attacker.example"}).status_code == 400
        assert client.get("/api/v1/tools").status_code == 200
        for origin in ("https://attacker.example", "null", "http://localhost.attacker.example:5173"):
            assert client.post("/api/v1/tasks", json={}, headers={"Origin": origin}).status_code == 403
        # Valid local and nonbrowser requests reach normal request validation.
        assert client.post("/api/v1/tasks", json={}).status_code == 422
        assert client.post("/api/v1/tasks", json={}, headers={"Origin": "http://127.0.0.1:5173"}).status_code == 422
        with pytest.raises(WebSocketDisconnect) as denied:
            with client.websocket_connect("ws://127.0.0.1/api/v1/runs/unknown/events", headers={"Origin": "https://attacker.example"}):
                pass
        assert denied.value.code == 4403
        with pytest.raises(WebSocketDisconnect) as local:
            with client.websocket_connect("ws://127.0.0.1/api/v1/runs/unknown/events", headers={"Origin": "http://127.0.0.1"}):
                pass
        assert local.value.code == 4404
        with pytest.raises(WebSocketDisconnect) as host:
            with client.websocket_connect("ws://127.0.0.1/api/v1/runs/unknown/events", headers={"Host": "attacker.example"}):
                pass
        assert host.value.status_code == 400


@pytest.mark.parametrize("nested_bundle", [False, True])
def test_health_and_task_flow(settings, nested_bundle: bool) -> None:
    settings.prepare_directories()
    app = create_app(settings)
    with TestClient(app, base_url="http://127.0.0.1") as client:
        health = client.get("/health")
        assert health.status_code == 200
        source = b"import subprocess\nsubprocess.Popen('x', shell=True)\n"
        filename = "bad.py"
        if nested_bundle:
            bundle = io.BytesIO()
            with zipfile.ZipFile(bundle, "w") as archive:
                archive.writestr(
                    "1de3c834-77dc-453b-b458-036e9f0058b6-release-synthetic-20261012/synthetic_audit.py",
                    source,
                )
            source = bundle.getvalue()
            filename = "workspace.zip"
        upload = client.post(
            "/api/v1/uploads",
            files={"file": (filename, source)},
        )
        assert upload.status_code == 201
        task = client.post(
            "/api/v1/tasks",
            json={
                "objective": "audit uploaded python code",
                "attachments": [{"ref": upload.json()["ref"]}],
            },
        )
        assert task.status_code == 202
        run_id = task.json()["run_id"]
        status = None
        for _ in range(100):
            response = client.get(f"/api/v1/runs/{run_id}")
            summary = response.json()
            status = summary["status"]
            if status in {"completed", "partial", "failed", "denied"}:
                break
            time.sleep(0.02)
        assert status == "completed"
        assert summary["verified_claims"] > 0
        assert summary["insufficient_claims"] == 0
        assert summary["conflicted_claims"] == 0
        report = client.get(f"/api/v1/runs/{run_id}/report")
        assert report.status_code == 200
        assert report.json()["findings"]
        assert report.json()["evidence"]
        assert report.json()["claim_ids"]
        if nested_bundle:
            paths = [finding.get("path") for finding in report.json()["findings"]]
            assert any(path and path.endswith("/synthetic_audit.py") for path in paths), paths
        service = app.state.runtime.service
        state = service.state(run_id)
        assert state.sealed_admission is not None
        sealed_report = AdmissionService.project(state.sealed_admission)
        state.report = AgentReport(
            run_id=run_id,
            status=RunStatus.COMPLETED,
            executive_summary="MUTABLE-REPORT-MUST-NOT-LEAK",
        )
        service.ledger.save_state(state)
        projected = client.get(f"/api/v1/runs/{run_id}/report")
        assert projected.status_code == 200
        assert projected.json() == _redacted_report(sealed_report).model_dump(mode="json")
        assert client.get(f"/api/v1/runs/{run_id}/admission").json()["report"] == projected.json()
        ledger = client.get(f"/api/v1/runs/{run_id}/ledger")
        assert ledger.status_code == 200
        assert ledger.json()["chain_valid"] is True
        assert ledger.json()["schema_version"] == SCHEMA_VERSION
        first_page = client.get(f"/api/v1/runs/{run_id}/ledger?limit=1").json()
        assert first_page["has_more"] is True
        assert first_page["next_sequence"] == 1
