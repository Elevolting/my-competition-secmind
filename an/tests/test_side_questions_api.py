from __future__ import annotations

import asyncio
import threading
import time

import httpx
from fastapi.testclient import TestClient

from security_agent.api import create_app
from security_agent.llm import ModelGateway
from security_agent.model_snapshots import ModelConfiguration, SnapshotParent
from security_agent.schemas import AgentState, RunStatus, TaskRequest
from security_agent.side_questions import SideQuestionBudget


def _run(app, run_id: str) -> None:
    app.state.service.ledger.save_state(
        AgentState(run_id=run_id, task=TaskRequest(objective="answer a bounded question"), status=RunStatus.RUNNING)
    )


def _configuration(settings) -> ModelConfiguration:
    return ModelConfiguration(
        base_url=settings.model_base_url,
        provider="compatible-api",
        model_id=settings.planner_model,
        planner_model=settings.planner_model,
        worker_model=settings.worker_model,
        fallback_model=settings.fallback_model,
    )


def _snapshot(app, settings, run_id: str, *, source: str = "workbench") -> dict:
    parent = SnapshotParent(run_id, source)
    return app.state.side_questions.snapshot_store.capture(
        parent=parent,
        configuration=_configuration(settings),
        request={
            "model": settings.planner_model,
            "messages": [{"role": "user", "content": "执行上下文"}],
        },
        provenance={"call_id": "api-test", "attempt": 1},
    )


def _wait_for(client: TestClient, run_id: str, question_id: str, status: str) -> dict:
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        value = client.get(f"/api/v1/runs/{run_id}/side-questions/{question_id}")
        assert value.status_code == 200
        document = value.json()["question"]
        if document["status"] == status:
            return document
        time.sleep(0.02)
    raise AssertionError(f"side question did not reach {status}")


def test_side_question_api_requires_snapshot_and_fences_parent(settings):
    app = create_app(settings)
    with TestClient(app) as client:
        _run(app, "api-no-snapshot")
        response = client.post(
            "/api/v1/runs/api-no-snapshot/side-questions",
            json={"request_key": "no-snapshot", "question": "依据是什么？"},
        )
        assert response.status_code == 409
        assert "snapshot" in response.json()["detail"].lower()

        _run(app, "api-source-run")
        _snapshot(app, settings, "api-source-run")
        response = client.post(
            "/api/v1/runs/api-other-run/side-questions",
            json={"request_key": "wrong-run", "question": "越界？"},
        )
        assert response.status_code == 404

        response = client.post(
            "/api/v1/runs/api-source-run/side-questions",
            json={
                "snapshot_id": _snapshot(app, settings, "api-source-run", source="secmind")["snapshot_id"],
                "request_key": "wrong-source",
                "question": "越界？",
            },
        )
        assert response.status_code == 409


def test_side_question_api_completes_and_preserves_parent(settings):
    app = create_app(settings)
    run_id = "api-complete"
    seen: list[tuple[str, str]] = []

    async def answer(context, question, _on_delta):
        seen.append((context["snapshot_id"], question))
        return "回答来自冻结上下文", {"input_tokens": 8, "output_tokens": 12}

    app.state.side_question_call_model = answer
    with TestClient(app) as client:
        _run(app, run_id)
        snapshot = _snapshot(app, settings, run_id)
        created = client.post(
            f"/api/v1/runs/{run_id}/side-questions",
            json={"snapshot_id": snapshot["snapshot_id"], "request_key": "complete-1", "question": "依据是什么？"},
        )
        assert created.status_code == 202
        question = created.json()["question"]
        assert question["snapshot"]["captured_at"]
        completed = _wait_for(client, run_id, question["question_id"], "completed")
        assert completed["answer"] == "回答来自冻结上下文"
        assert completed["settled"] == {"input_tokens": 8, "output_tokens": 12, "provider_requests": 1}
        assert seen == [(snapshot["snapshot_id"], "依据是什么？")]
        assert app.state.service.state(run_id).status == RunStatus.RUNNING

        history = client.get(f"/api/v1/runs/{run_id}/side-questions")
        assert history.status_code == 200
        assert history.json()["items"][0]["question_id"] == question["question_id"]
        events = client.get(f"/api/v1/runs/{run_id}/side-questions/{question['question_id']}/events")
        assert [item["type"] for item in events.json()["events"]] == ["delta"]

        repeated = client.post(
            f"/api/v1/runs/{run_id}/side-questions",
            json={"snapshot_id": snapshot["snapshot_id"], "request_key": "complete-1", "question": "依据是什么？"},
        )
        assert repeated.status_code == 202
        assert repeated.json()["question"]["question_id"] == question["question_id"]
        assert client.get(f"/api/v1/runs/{run_id}/side-questions/{question['question_id']}/clear").status_code == 405


def test_side_question_real_gateway_shape_records_usage_and_safe_failure(settings):
    settings.demo_mode = False
    settings.model_api_key = "test-key"
    app = create_app(settings)
    run_id = "api-streaming-gateway"

    def handler(request: httpx.Request) -> httpx.Response:
        import json
        body = json.loads(request.content)
        assert body["stream"] is True
        if body["messages"][-1]["content"] == "失败问题":
            return httpx.Response(429, json={"error": {"message": "sensitive provider details"}})
        return httpx.Response(200, headers={"content-type": "text/event-stream"}, text=(
            'data: {"choices":[{"delta":{"content":"已回答"}}]}\n\n'
            'data: {"choices":[],"usage":{"prompt_tokens":500,"completion_tokens":3}}\n\n'
            'data: [DONE]\n\n'
        ))

    model_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    with TestClient(app) as client:
        gateway = ModelGateway(settings, model_client)
        app.state.side_question_call_model = gateway.answer_side_question
        _run(app, run_id)
        snapshot = _snapshot(app, settings, run_id)
        response = client.post(
            f"/api/v1/runs/{run_id}/side-questions",
            json={"snapshot_id": snapshot["snapshot_id"], "question": "成功问题"},
        )
        assert response.status_code == 202
        result = _wait_for(client, run_id, response.json()["question"]["question_id"], "completed")
        assert result["answer"] == "已回答"
        assert result["settled"]["input_tokens"] == 500
        assert result["settled"]["output_tokens"] == 3

        response = client.post(
            f"/api/v1/runs/{run_id}/side-questions",
            json={"snapshot_id": snapshot["snapshot_id"], "question": "失败问题"},
        )
        assert response.status_code == 202
        failed = _wait_for(client, run_id, response.json()["question"]["question_id"], "failed")
        assert failed["error_type"] == "model_rate_limited"
        assert "限流" in failed["error_message"]
        assert "sensitive provider details" not in str(failed)
        assert app.state.service.state(run_id).status == RunStatus.RUNNING
    asyncio.run(model_client.aclose())


def test_side_question_api_exposes_live_output_before_completion(settings):
    app = create_app(settings)
    run_id = "api-live-output"
    first_chunk = threading.Event()
    release = threading.Event()

    async def answer(_context, _question, on_delta):
        await on_delta("正在回答")
        first_chunk.set()
        await asyncio.to_thread(release.wait, 3)
        await on_delta("，已完成。")
        return "正在回答，已完成。", {"prompt_tokens": 15, "completion_tokens": 8}

    app.state.side_question_call_model = answer
    with TestClient(app) as client:
        _run(app, run_id)
        snapshot = _snapshot(app, settings, run_id)
        created = client.post(
            f"/api/v1/runs/{run_id}/side-questions",
            json={"snapshot_id": snapshot["snapshot_id"], "question": "进度如何？"},
        )
        assert created.status_code == 202
        question_id = created.json()["question"]["question_id"]
        assert first_chunk.wait(2)
        partial = client.get(f"/api/v1/runs/{run_id}/side-questions/{question_id}").json()["question"]
        assert partial["status"] == "running"
        assert partial["answer"] == "正在回答"
        events = client.get(f"/api/v1/runs/{run_id}/side-questions/{question_id}/events").json()["events"]
        assert [event["delta"] for event in events] == ["正在回答"]
        release.set()
        completed = _wait_for(client, run_id, question_id, "completed")
        assert completed["answer"] == "正在回答，已完成。"
        assert completed["settled"]["input_tokens"] == 15
        assert app.state.service.state(run_id).status == RunStatus.RUNNING


def test_side_question_api_cancel_and_clear_do_not_cancel_parent(settings):
    app = create_app(settings)
    run_id = "api-cancel"
    entered = threading.Event()
    release = threading.Event()

    async def answer(_context, _question, _on_delta):
        entered.set()
        await asyncio.to_thread(release.wait, 3)
        return "迟到回答", SideQuestionBudget(10, 10, 1)

    app.state.side_question_call_model = answer
    with TestClient(app) as client:
        _run(app, run_id)
        snapshot = _snapshot(app, settings, run_id)
        created = client.post(
            f"/api/v1/runs/{run_id}/side-questions",
            json={"snapshot_id": snapshot["snapshot_id"], "request_key": "cancel-1", "question": "停止吗？"},
        )
        question_id = created.json()["question"]["question_id"]
        assert entered.wait(2)
        cancelled = client.post(f"/api/v1/runs/{run_id}/side-questions/{question_id}/cancel")
        assert cancelled.status_code == 200
        release.set()
        final = _wait_for(client, run_id, question_id, "cancelled")
        assert final["answer"] is None
        assert app.state.service.state(run_id).status == RunStatus.RUNNING

    app = create_app(settings)
    run_id = "api-clear"
    entered = threading.Event()
    release = threading.Event()

    async def delayed_answer(_context, _question, _on_delta):
        entered.set()
        await asyncio.to_thread(release.wait, 3)
        return "清理后回答", {"input_tokens": 4, "output_tokens": 5}

    app.state.side_question_call_model = delayed_answer
    with TestClient(app) as client:
        _run(app, run_id)
        snapshot = _snapshot(app, settings, run_id)
        created = client.post(
            f"/api/v1/runs/{run_id}/side-questions",
            json={"snapshot_id": snapshot["snapshot_id"], "request_key": "clear-1", "question": "清理输出？"},
        )
        question_id = created.json()["question"]["question_id"]
        assert entered.wait(2)
        cleared = client.post(f"/api/v1/runs/{run_id}/side-questions/{question_id}/clear")
        assert cleared.status_code == 200
        assert cleared.json()["question"]["clear_version"] == 1
        release.set()
        final = _wait_for(client, run_id, question_id, "completed")
        assert final["answer"] == "清理后回答"
        events = client.get(f"/api/v1/runs/{run_id}/side-questions/{question_id}/events")
        assert [item["type"] for item in events.json()["events"]] == ["clear", "delta"]
        assert app.state.service.state(run_id).status == RunStatus.RUNNING


def test_side_question_api_rejects_configuration_change(settings):
    app = create_app(settings)
    run_id = "api-config-fence"
    with TestClient(app) as client:
        _run(app, run_id)
        snapshot = _snapshot(app, settings, run_id)
        settings.model_base_url = "https://changed-model.test/v1"
        response = client.post(
            f"/api/v1/runs/{run_id}/side-questions",
            json={"snapshot_id": snapshot["snapshot_id"], "request_key": "changed-config", "question": "还能用吗？"},
        )
        assert response.status_code == 409
        assert "configuration" in response.json()["detail"].lower()


def test_side_question_api_fault_matrix_and_refresh_reconnect(settings):
    app = create_app(settings)
    run_id = "api-fault-matrix"

    async def answer(_context, question, _on_delta):
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

        settings.side_question_max_concurrency = 1
        app.state.side_questions.max_concurrency = 1
        concurrency_run_id = "api-fault-concurrency"
        _run(app, concurrency_run_id)
        concurrency_snapshot = _snapshot(app, settings, concurrency_run_id)
        entered = threading.Event()
        release = threading.Event()

        async def blocked(_context, _question, _on_delta):
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

