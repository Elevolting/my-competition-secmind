from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from secmind.api import create_app
from secmind.config import Settings


def _wait(client: TestClient, run_id: str) -> dict:
    payload: dict = {}
    for _ in range(200):
        response = client.get(f"/api/v1/runs/{run_id}")
        assert response.status_code == 200
        payload = response.json()
        if payload["status"] in {"completed", "partial", "failed", "denied"}:
            return payload
        time.sleep(0.02)
    raise AssertionError(f"run did not terminate: {payload}")


def test_log_timeline_governed_view_and_retention_hold(settings) -> None:
    settings.prepare_directories()
    app = create_app(settings)
    with TestClient(app, base_url="http://127.0.0.1") as client:
        uploaded = client.post(
            "/api/v1/uploads",
            files={
                "file": (
                    "auth.jsonl",
                    b'{"timestamp":"2026-07-14T01:00:00Z","message":"Failed password from 192.0.2.3"}\n',
                    "application/x-ndjson",
                )
            },
        )
        assert uploaded.status_code == 201
        created = client.post(
            "/api/v1/tasks",
            json={
                "objective": "analyze the uploaded security log",
                "attachments": [{"ref": uploaded.json()["ref"]}],
                "target_scope": ["."],
            },
        )
        assert created.status_code == 202
        run_id = created.json()["run_id"]
        terminal = _wait(client, run_id)
        assert terminal["status"] in {"completed", "partial"}

        timeline = client.get(f"/api/v1/runs/{run_id}/timeline")
        assert timeline.status_code == 200
        assert timeline.json()["source_count"] == 1
        assert timeline.json()["raw_log_content_included"] is False
        assert timeline.json()["sources"][0]["timeline"]

        governed = client.get(f"/api/v1/runs/{run_id}/logs?layer=L1&view=observable")
        assert governed.status_code == 200
        assert governed.json()["raw_content_included"] is False
        assert governed.json()["events"]
        assert client.get(f"/api/v1/runs/{run_id}/logs?layer=L5&view=raw_restricted").status_code == 409

        expiry = datetime.now(UTC) + timedelta(days=7)
        hold = client.post(
            f"/api/v1/runs/{run_id}/retention-holds",
            json={
                "client_request_id": "hold-review-0001",
                "reason": "preserve evidence for review",
                "expires_at": expiry.isoformat(),
            },
        )
        assert hold.status_code == 201
        assert hold.json()["retention_hold"]["actor"] == "operator"
        retried_hold = client.post(
            f"/api/v1/runs/{run_id}/retention-holds",
            json={
                "client_request_id": "hold-review-0001",
                "reason": "preserve evidence for review",
                "expires_at": expiry.isoformat(),
            },
        )
        assert retried_hold.status_code == 201
        assert retried_hold.json()["retention_hold"]["hold_id"] == hold.json()["retention_hold"]["hold_id"]
        holds = client.get(f"/api/v1/runs/{run_id}/retention-holds")
        assert holds.status_code == 200
        assert [item["hold_id"] for item in holds.json()["holds"]] == [hold.json()["retention_hold"]["hold_id"]]
        assert client.get(f"/api/v1/runs/{run_id}/recovery-assessment").status_code == 409
        assessment = client.post(f"/api/v1/runs/{run_id}/recovery-assessment")
        assert assessment.status_code == 201
        assert assessment.json()["assessment_digest"]
        assert assessment.json()["reason_codes"]
        latest_assessment = client.get(f"/api/v1/runs/{run_id}/recovery-assessment")
        assert latest_assessment.status_code == 200
        assert latest_assessment.json()["assessment_id"] == assessment.json()["assessment_id"]


def test_input_envelope_api_is_run_bound_and_never_returns_execution_arguments(settings) -> None:
    from secmind.schemas import AgentState, BudgetState, RunStatus, TaskRequest, ToolInputEnvelope

    settings.prepare_directories()
    app = create_app(settings)
    with TestClient(app, base_url="http://127.0.0.1") as client:
        service = app.state.runtime.service
        run_id = "00000000-0000-4000-8000-000000000701"
        other_run_id = "00000000-0000-4000-8000-000000000702"
        for current in (run_id, other_run_id):
            assert service.unit_of_work is not None
            service.unit_of_work.submit_run(
                AgentState(
                    run_id=current,
                    task=TaskRequest(objective="audit input provenance"),
                    status=RunStatus.PENDING,
                    budget=BudgetState(),
                )
            )
        envelope = ToolInputEnvelope(
            invocation_id="00000000-0000-4000-8000-000000000703",
            run_id=run_id,
            step_id="scan",
            raw_input_ref="1" * 64,
            observable_input={"target": "."},
            execution_input_ref="2" * 64,
            raw_digest="1" * 64,
            observable_digest="3" * 64,
            execution_digest="2" * 64,
            scope_binding=["/workspace"],
        )
        assert service.unit_of_work.record_tool_input_envelope(envelope)

        response = client.get(f"/api/v1/runs/{run_id}/input-envelopes/{envelope.invocation_id}")
        assert response.status_code == 200
        assert response.json()["execution_arguments_included"] is False
        assert response.json()["input_envelope"]["observable_input"] == {"target": "."}
        assert "secret-command-line" not in response.text
        assert client.get(f"/api/v1/runs/{other_run_id}/input-envelopes/{envelope.invocation_id}").status_code == 404


def test_recovery_command_consumes_current_assessment_once(tmp_path) -> None:
    settings = Settings(
        runtime_role="api",
        unsafe_development_tools=True,
        database_url=f"sqlite:///{(tmp_path / 'recovery-api.db').as_posix()}",
        input_root=tmp_path / "inputs",
        upload_root=tmp_path / "uploads",
        run_root=tmp_path / "runs",
        artifact_root=tmp_path / "artifacts",
    )
    with TestClient(create_app(settings), base_url="http://127.0.0.1") as client:
        created = client.post("/api/v1/tasks", json={"objective": "audit a queued recovery fixture"})
        assert created.status_code == 202
        run_id = created.json()["run_id"]

        generated = client.post(f"/api/v1/runs/{run_id}/recovery-assessment")
        assert generated.status_code == 201
        assessment = generated.json()
        assert assessment["action"] == "REQUEUE_SAFE_STEP"

        wrong = client.post(
            f"/api/v1/runs/{run_id}/recover",
            json={"assessment_id": assessment["assessment_id"], "assessment_digest": "0" * 64},
        )
        assert wrong.status_code == 409

        request = {
            "assessment_id": assessment["assessment_id"],
            "assessment_digest": assessment["assessment_digest"],
        }
        recovered = client.post(f"/api/v1/runs/{run_id}/recover", json=request)
        assert recovered.status_code == 202
        assert recovered.json()["consumption_id"]
        retried = client.post(f"/api/v1/runs/{run_id}/recover", json=request)
        assert retried.status_code == 202
        assert retried.json()["consumption_id"] == recovered.json()["consumption_id"]
