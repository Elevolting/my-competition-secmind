from __future__ import annotations

import asyncio
import threading
import time
from dataclasses import replace

from fastapi.testclient import TestClient

from secmind.api import create_app
from secmind.model_snapshots import SnapshotParent
from secmind.schemas import AgentState, RunStatus, TaskRequest
from secmind.side_questions import SideQuestionBudget


def _run(app, run_id: str) -> None:
    app.state.runtime.service.ledger.save_state(
        AgentState(run_id=run_id, task=TaskRequest(objective="answer a bounded question"), status=RunStatus.RUNNING)
    )


def _snapshot(app, settings, run_id: str) -> dict:
    runtime = app.state.runtime
    parent = SnapshotParent(run_id, "secmind")
    configuration = runtime.gateway.snapshot_configuration(settings.planner_model)
    return runtime.side_questions.snapshot_store.capture(
        parent=parent,
        configuration=configuration,
        request={
            "model": settings.planner_model,
            "messages": [{"role": "user", "content": "执行上下文"}],
        },
        provenance={"call_id": "api-test", "attempt": 1},
    )


def _wait_for(client: TestClient, run_id: str, question_id: str, status: str) -> dict:
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        response = client.get(f"/api/v1/runs/{run_id}/side-questions/{question_id}")
        assert response.status_code == 200
        document = response.json()["question"]
        if document["status"] == status:
            return document
        time.sleep(0.02)
    raise AssertionError(f"side question did not reach {status}")


def test_side_question_api_requires_snapshot_and_completes_independently(settings):
    app = create_app(settings)
    app.state.side_question_call_model = lambda *_: None
    with TestClient(app, base_url="http://127.0.0.1") as client:
        run_id = "secmind-api-complete"
        _run(app, run_id)
        response = client.post(
            f"/api/v1/runs/{run_id}/side-questions",
            json={"request_key": "missing-snapshot", "question": "依据是什么？"},
        )
        assert response.status_code == 409
        snapshot = _snapshot(app, settings, run_id)

        async def answer(context, question):
            assert context["snapshot_id"] == snapshot["snapshot_id"]
            assert question == "依据是什么？"
            return "独立引擎回答", {"input_tokens": 8, "output_tokens": 12}

        app.state.side_question_call_model = answer
        created = client.post(
            f"/api/v1/runs/{run_id}/side-questions",
            json={"snapshot_id": snapshot["snapshot_id"], "request_key": "complete-1", "question": "依据是什么？"},
        )
        assert created.status_code == 202
        question_id = created.json()["question"]["question_id"]
        completed = _wait_for(client, run_id, question_id, "completed")
        assert completed["answer"] == "独立引擎回答"
        assert completed["snapshot"]["captured_at"]
        assert app.state.runtime.service.state(run_id).status == RunStatus.RUNNING
        assert [item["type"] for item in client.get(
            f"/api/v1/runs/{run_id}/side-questions/{question_id}/events"
        ).json()["events"]] == ["delta"]


def test_side_question_api_source_configuration_and_parent_fences(settings):
    app = create_app(settings)
    with TestClient(app, base_url="http://127.0.0.1") as client:
        _run(app, "secmind-api-fence")
        snapshot = _snapshot(app, settings, "secmind-api-fence")
        gateway = app.state.runtime.gateway
        gateway.policy = replace(gateway.policy, base_url="https://changed-model.test/v1")
        response = client.post(
            "/api/v1/runs/secmind-api-fence/side-questions",
            json={
                "snapshot_id": snapshot["snapshot_id"],
                "request_key": "changed-config",
                "question": "还能用吗？",
            },
        )
        assert response.status_code == 409
        assert "configuration" in response.json()["detail"].lower()

        response = client.post(
            "/api/v1/runs/secmind-api-fence/side-questions",
            json={
                "snapshot_id": snapshot["snapshot_id"],
                "request_key": "source-boundary",
                "question": "越界？",
            },
        )
        assert response.status_code == 409


def test_side_question_api_cancel_does_not_change_main_run(settings):
    app = create_app(settings)
    entered = threading.Event()
    release = threading.Event()

    async def answer(_context, _question):
        entered.set()
        await asyncio.to_thread(release.wait, 3)
        return "迟到回答", SideQuestionBudget(10, 10, 1)

    app.state.side_question_call_model = answer
    with TestClient(app, base_url="http://127.0.0.1") as client:
        run_id = "secmind-api-cancel"
        _run(app, run_id)
        snapshot = _snapshot(app, settings, run_id)
        created = client.post(
            f"/api/v1/runs/{run_id}/side-questions",
            json={"snapshot_id": snapshot["snapshot_id"], "request_key": "cancel-1", "question": "停止吗？"},
        )
        question_id = created.json()["question"]["question_id"]
        assert entered.wait(2)
        assert client.post(f"/api/v1/runs/{run_id}/side-questions/{question_id}/cancel").status_code == 200
        release.set()
        final = _wait_for(client, run_id, question_id, "cancelled")
        assert final["answer"] is None
        assert app.state.runtime.service.state(run_id).status == RunStatus.RUNNING


def test_side_question_api_fault_matrix_and_refresh_reconnect(settings):
    app = create_app(settings)
    run_id = "secmind-api-fault-matrix"

    async def answer(_context, question):
        return f"回答：{question}", {"input_tokens": 4, "output_tokens": 5}

    app.state.side_question_call_model = answer
    with TestClient(app, base_url="http://127.0.0.1") as client:
        _run(app, run_id)
        snapshot = _snapshot(app, settings, run_id)
        first = client.post(
            f"/api/v1/runs/{run_id}/side-questions",
            json={"snapshot_id": snapshot["snapshot_id"], "request_key": "fault-key", "question": "第一个问题"},
        )
        assert first.status_code == 202
        question_id = first.json()["question"]["question_id"]
        _wait_for(client, run_id, question_id, "completed")
        conflict = client.post(
            f"/api/v1/runs/{run_id}/side-questions",
            json={"snapshot_id": snapshot["snapshot_id"], "request_key": "fault-key", "question": "不同问题"},
        )
        assert conflict.status_code == 409
        budget = client.post(
            f"/api/v1/runs/{run_id}/side-questions",
            json={
                "snapshot_id": snapshot["snapshot_id"], "request_key": "budget-key",
                "question": "预算不足", "estimated_input_tokens": settings.side_question_input_token_budget + 1,
            },
        )
        assert budget.status_code == 409

        app.state.runtime.side_questions.max_concurrency = 1
        concurrency_run_id = "secmind-api-fault-concurrency"
        _run(app, concurrency_run_id)
        concurrency_snapshot = _snapshot(app, settings, concurrency_run_id)
        entered = threading.Event()
        release = threading.Event()

        async def blocked(_context, _question):
            entered.set()
            await asyncio.to_thread(release.wait, 3)
            return "完成", SideQuestionBudget(2, 2, 1)

        app.state.side_question_call_model = blocked
        running = client.post(
            f"/api/v1/runs/{concurrency_run_id}/side-questions",
            json={
                "snapshot_id": concurrency_snapshot["snapshot_id"],
                "request_key": "concurrency-1",
                "question": "占用并发",
            },
        )
        assert running.status_code == 202
        running_id = running.json()["question"]["question_id"]
        assert entered.wait(2)
        limited = client.post(
            f"/api/v1/runs/{concurrency_run_id}/side-questions",
            json={
                "snapshot_id": concurrency_snapshot["snapshot_id"],
                "request_key": "concurrency-2",
                "question": "超过并发",
            },
        )
        assert limited.status_code == 409
        assert client.post(f"/api/v1/runs/{concurrency_run_id}/side-questions/{running_id}/cancel").status_code == 200
        release.set()
        _wait_for(client, concurrency_run_id, running_id, "cancelled")

    refreshed = create_app(settings)
    with TestClient(refreshed, base_url="http://127.0.0.1") as client:
        history = client.get(f"/api/v1/runs/{run_id}/side-questions")
        assert history.status_code == 200
        assert any(item["question_id"] == question_id for item in history.json()["items"])

