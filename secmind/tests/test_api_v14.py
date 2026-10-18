from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from secmind.api import create_app
from secmind.schemas import SCHEMA_VERSION, ClarificationResponse, Scenario


def _wait_for_status(client: TestClient, run_id: str, expected: set[str]) -> dict:
    payload: dict = {}
    for _ in range(150):
        response = client.get(f"/api/v1/runs/{run_id}")
        assert response.status_code == 200
        payload = response.json()
        if payload["status"] in expected:
            return payload
        time.sleep(0.02)
    raise AssertionError(f"run {run_id} did not reach one of {sorted(expected)}; last={payload}")


def test_v14_parser_scenario_taskspec_and_route_read_models(settings) -> None:
    settings.prepare_directories()
    with TestClient(create_app(settings), base_url="http://127.0.0.1") as client:
        parsers = client.get("/api/v1/parsers")
        scenarios = client.get("/api/v1/scenarios")
        assert parsers.status_code == scenarios.status_code == 200
        assert parsers.json()["schema_version"] == SCHEMA_VERSION
        assert {item["parser_id"] for item in parsers.json()["parsers"]} >= {
            "text-markdown",
            "json",
            "csv-tsv",
            "ndjson",
            "openapi-json",
            "postman-json",
        }
        code_audit = next(item for item in scenarios.json()["scenarios"] if item["scenario_id"] == "code_audit")
        assert code_audit["enabled"] is True

        upload = client.post(
            "/api/v1/uploads",
            files={"file": ("sample.json", b'{"task": "audit python code"}', "application/json")},
        )
        assert upload.status_code == 201
        created = client.post(
            "/api/v1/tasks",
            json={
                "objective": "audit the uploaded code",
                "attachments": [{"ref": upload.json()["ref"]}],
                "target_scope": ["."],
            },
        )
        assert created.status_code == 202
        run_id = created.json()["run_id"]
        _wait_for_status(client, run_id, {"completed", "partial"})

        task_spec = client.get(f"/api/v1/runs/{run_id}/task-spec")
        routes = client.get(f"/api/v1/runs/{run_id}/routes")
        assert task_spec.status_code == routes.status_code == 200
        # Investigation TaskSpec remains on its independently versioned v1.5 contract.
        assert task_spec.json()["schema_version"] == "1.5"
        assert task_spec.json()["primary_scenario"] == "code_audit"
        assert task_spec.json()["authorized_scope"] == ["."]
        assert task_spec.json()["parser_run_ids"]
        assert routes.json()["routes"][0]["task_spec_digest"] == task_spec.json()["content_digest"]


def test_v14_clarification_is_run_bound_idempotent_and_one_shot(settings) -> None:
    settings.prepare_directories()
    with TestClient(create_app(settings), base_url="http://127.0.0.1") as client:
        created = client.post("/api/v1/tasks", json={"objective": "review this material"})
        assert created.status_code == 202
        run_id = created.json()["run_id"]
        waiting = _wait_for_status(client, run_id, {"waiting_clarification"})
        request = waiting["pending_clarification"]
        assert request["run_id"] == run_id

        response = {
            "confirmed_scenario": "code_audit",
            "confirmed_scope": ["."],
            "answers": {"objective": "audit the provided workspace"},
        }
        first = client.post(
            f"/api/v1/runs/{run_id}/clarifications/{request['request_id']}",
            json=response,
        )
        assert first.status_code == 202
        duplicate = client.post(
            f"/api/v1/runs/{run_id}/clarifications/{request['request_id']}",
            json=response,
        )
        assert duplicate.status_code == 202
        assert duplicate.json()["resolution_id"] == first.json()["resolution_id"]

        _wait_for_status(client, run_id, {"completed", "partial"})
        revised = client.get(f"/api/v1/runs/{run_id}/task-spec").json()
        assert revised["revision"] == 2
        assert revised["parent_revision_digest"]
        assert revised["clarification_request_ids"] == [request["request_id"]]

        late = client.post(
            f"/api/v1/runs/{run_id}/clarifications/{request['request_id']}",
            json={**response, "answers": {"objective": "change it again"}},
        )
        assert late.status_code == 409


def test_clarification_retry_repairs_crash_between_resolution_and_wake(settings, monkeypatch) -> None:
    settings.prepare_directories()
    app = create_app(settings)
    with TestClient(app, base_url="http://127.0.0.1") as client:
        created = client.post("/api/v1/tasks", json={"objective": "review this material"})
        run_id = created.json()["run_id"]
        waiting = _wait_for_status(client, run_id, {"waiting_clarification"})
        request_id = waiting["pending_clarification"]["request_id"]
        response = ClarificationResponse(confirmed_scenario=Scenario.CODE_AUDIT, confirmed_scope=["."])
        coordinator = app.state.runtime.service.coordinator
        original = coordinator.ensure_job_awake

        def fail_after_resolution(_run_id: str) -> bool:
            raise RuntimeError("synthetic crash window")

        monkeypatch.setattr(coordinator, "ensure_job_awake", fail_after_resolution)
        with pytest.raises(RuntimeError, match="synthetic crash"):
            app.state.runtime.service.submit_clarification_resolution(run_id, request_id, response)

        monkeypatch.setattr(coordinator, "ensure_job_awake", original)
        resolution_id, changed = app.state.runtime.service.submit_clarification_resolution(
            run_id,
            request_id,
            response,
        )
        assert resolution_id
        assert changed is False
        _wait_for_status(client, run_id, {"completed", "partial"})
