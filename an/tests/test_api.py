from __future__ import annotations

import time
import zipfile
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, update
from starlette.websockets import WebSocketDisconnect

from security_agent.api import _run_usage, create_app
from security_agent.ledger import LedgerStore
from security_agent.schemas import AgentState, ApprovalRequest, RiskLevel, RunStatus, TaskRequest, TaskSettingsUpdate
from security_agent.side_questions import SideQuestionOutputEvent, SideQuestionRow


def test_task_create_request_id_replays_same_run(settings, monkeypatch) -> None:
    settings.prepare_directories()
    app = create_app(settings)
    monkeypatch.setattr(app.state.mcp_runtime, "agent_servers", lambda: [])
    headers = {"X-Request-Id": "task-request-0001"}
    with TestClient(app) as client:
        first = client.post("/api/v1/tasks", json={"objective": "audit local fixture"}, headers=headers)
        replay = client.post("/api/v1/tasks", json={"objective": "audit local fixture"}, headers=headers)
        changed = client.post("/api/v1/tasks", json={"objective": "audit another fixture"}, headers=headers)
    assert first.status_code == replay.status_code == 202
    assert first.json()["run_id"] == replay.json()["run_id"]
    assert changed.status_code == 409


def test_task_settings_update_is_immediate_and_revision_checked(settings) -> None:
    app = create_app(settings)
    run_id = "task-settings-live"
    app.state.service.ledger.save_state(AgentState(
        run_id=run_id, status=RunStatus.RUNNING,
        task=TaskRequest(name="旧名称", objective="inspect supplied files",
                         target_scope=["old.example"], autonomy_policy="graded"),
    ))
    with TestClient(app) as client:
        before = client.get(f"/api/v1/runs/{run_id}/settings")
        assert before.status_code == 200 and before.json()["revision"] == 0
        payload = {"expected_revision": 0, "name": "新名称", "autonomy_policy": "approval_all",
                   "target_scope": ["new.example"]}
        changed = client.patch(f"/api/v1/runs/{run_id}/settings", json=payload)
        assert changed.status_code == 200
        assert changed.json()["revision"] == 1
        assert client.get(f"/api/v1/runs/{run_id}/settings").json()["target_scope"] == ["new.example"]
        assert client.get(f"/api/v1/runs/{run_id}").json()["name"] == "新名称"
        assert client.patch(f"/api/v1/runs/{run_id}/settings", json=payload).status_code == 409


def test_delete_task_removes_local_records_and_rejects_active_work(settings) -> None:
    app = create_app(settings)
    service = app.state.service
    run_id = "task-to-delete"
    other_id = "task-to-keep"
    workspace = settings.run_root / run_id
    workspace.mkdir(parents=True)
    (workspace / "report.txt").write_text("private task artifact", encoding="utf-8")

    with TestClient(app) as client:
        for identity, status in ((run_id, RunStatus.RUNNING), (other_id, RunStatus.COMPLETED)):
            service.ledger.save_state(AgentState(
                run_id=identity, status=status,
                task=TaskRequest(name=identity, objective="inspect supplied files"),
            ))
            service.ledger.append(identity, "test.event", {"run_id": identity})

        assert client.delete(f"/api/v1/runs/{run_id}").status_code == 409
        assert workspace.exists()
        service.ledger.update_state(run_id, lambda state: setattr(state, "status", RunStatus.COMPLETED))

        now = datetime.now(UTC).isoformat()
        with service.ledger.engine.begin() as connection:
            connection.execute(SideQuestionRow.__table__.insert().values(
                question_id="question-to-delete", request_key="delete-test-request",
                parent_key=run_id, run_id=run_id, source="workbench",
                snapshot_id="snapshot-test", snapshot_version=1,
                configuration_identity="configuration-test", question_sha256="digest-test",
                question_text="What happened?", status="running",
                reserved_input_tokens=10, reserved_output_tokens=10,
                created_at=now, updated_at=now,
            ))
            connection.execute(SideQuestionOutputEvent.__table__.insert().values(
                question_id="question-to-delete", event_sequence=1, event_type="delta",
                clear_version=0, delta_text="answer", cumulative_text="answer", created_at=now,
            ))

        assert client.delete(f"/api/v1/runs/{run_id}").status_code == 409
        assert (workspace / "report.txt").exists()
        with service.ledger.engine.begin() as connection:
            connection.execute(update(SideQuestionRow).where(SideQuestionRow.run_id == run_id)
                               .values(status="completed"))

        assert client.delete(f"/api/v1/runs/{run_id}").status_code == 204
        assert client.delete(f"/api/v1/runs/{run_id}").status_code == 404
        assert client.get(f"/api/v1/runs/{run_id}").status_code == 404
        listing = client.get("/api/v1/runs").json()
        assert listing["total"] == 1
        assert [item["run_id"] for item in listing["runs"]] == [other_id]
        assert not workspace.exists()
        assert service.ledger.events(run_id) == []
        assert service.ledger.events(other_id)
        with service.ledger.engine.connect() as connection:
            assert connection.execute(select(SideQuestionRow.question_id)
                                      .where(SideQuestionRow.run_id == run_id)).first() is None
            assert connection.execute(
                select(SideQuestionOutputEvent.question_id)
                .where(SideQuestionOutputEvent.question_id == "question-to-delete")
            ).first() is None


def test_settings_change_invalidates_waiting_local_approval(settings) -> None:
    app = create_app(settings)
    run_id = "task-settings-approval"
    pending = ApprovalRequest(run_id=run_id, step_id="step-1", tool_name="some_tool",
                              parameters={"target": "old.example"}, target="old.example",
                              risk_level=RiskLevel.R2, reason="approval required", expected_impact="tool call")
    app.state.service.ledger.save_state(AgentState(
        run_id=run_id, status=RunStatus.WAITING_APPROVAL, pending_approval=pending,
        task=TaskRequest(name="待审批", objective="inspect supplied files", target_scope=["old.example"]),
    ))
    stale_snapshot = app.state.service.state(run_id)
    app.state.service.update_task_settings(run_id, TaskSettingsUpdate(
        expected_revision=0, name="待审批", autonomy_policy="approval_all",
        target_scope=["new.example"],
    ))
    state = app.state.service.state(run_id)
    assert state.task_revision == 1
    assert state.pending_approval is None
    assert state.resume_node == "guardrail"
    assert state.status == RunStatus.RUNNING
    app.state.service.ledger.save_state(stale_snapshot)
    assert app.state.service.state(run_id).pending_approval is None
    assert app.state.service.state(run_id).status == RunStatus.RUNNING


def test_running_secmind_contract_rejects_unsynchronized_setting_change(settings) -> None:
    app = create_app(settings)
    run_id = "task-settings-secmind"
    app.state.service.ledger.save_state(AgentState(
        run_id=run_id, status=RunStatus.RUNNING,
        task=TaskRequest(name="分析", objective="inspect supplied files", target_scope=["old.example"]),
        external_execution={"remote_run_id": "remote-analysis-1"},
    ))
    with TestClient(app) as client:
        settings_response = client.get(f"/api/v1/runs/{run_id}/settings")
        assert settings_response.json()["can_edit_approval_policy"] is False
        response = client.patch(f"/api/v1/runs/{run_id}/settings", json={
            "expected_revision": 0, "name": "分析", "autonomy_policy": "approval_all",
            "target_scope": ["new.example"],
        })
    assert response.status_code == 409
    assert app.state.service.state(run_id).task.target_scope == ["old.example"]


@pytest.mark.parametrize("status", [RunStatus.PENDING, RunStatus.RUNNING, RunStatus.WAITING_APPROVAL])
def test_report_refresh_rejects_active_run_without_waiting_for_execution_lock(settings, monkeypatch, status):
    app = create_app(settings)
    app.state.service.ledger.save_state(AgentState(
        run_id="active-refresh-run", task=TaskRequest(objective="authorized security review"), status=status,
    ))

    def unexpected_lock(_run_id):
        raise AssertionError("report refresh must reject active runs before requesting their execution lock")

    monkeypatch.setattr(app.state.service, "run_lock", unexpected_lock)
    with TestClient(app) as client:
        response = client.post("/api/v1/runs/active-refresh-run/report/refresh")
    assert response.status_code == 409
    assert "仍在执行或等待审批" in response.json()["detail"]


def test_upload_rejects_control_characters_in_filename(settings) -> None:
    app = create_app(settings)
    with TestClient(app, raise_server_exceptions=False) as client:
        for filename in ("bad\x00name.py", "bad\x01name.py", "CON.txt"):
            body = (b'--test\r\nContent-Disposition: form-data; name="file"; filename="'
                    + filename.encode() + b'"\r\nContent-Type: application/octet-stream\r\n\r\ndata\r\n--test--\r\n')
            response = client.post("/api/v1/uploads", content=body,
                                   headers={"Content-Type": "multipart/form-data; boundary=test"})
            assert response.status_code == 400
    assert list(settings.upload_root.iterdir()) == []


@pytest.mark.parametrize('path', [
    '/api/v1/incident/events', '/api/v1/model-usage/events',
    '/api/v1/question-banks/missing/events', '/api/v1/evaluations/missing/events',
    '/api/v1/runs/missing/events',
])
def test_websocket_rejects_other_websites_before_handshake(settings, path) -> None:
    app = create_app(settings)
    with TestClient(app) as client:
        with pytest.raises(WebSocketDisconnect) as denied:
            with client.websocket_connect(path, headers={'origin': 'https://other.example'}):
                pass
    assert denied.value.code == 1008


def test_incident_websocket_accepts_configured_ui_origin(settings) -> None:
    settings.allowed_browser_origins = 'http://127.0.0.1:5199'
    app = create_app(settings)
    with TestClient(app) as client:
        with client.websocket_connect('/api/v1/incident/events',
                                      headers={'origin': 'http://127.0.0.1:5199'}) as socket:
            assert socket.receive_json()['type'] == 'incident.snapshot'


def test_other_website_cannot_cancel_run_or_upload_material(settings) -> None:
    app = create_app(settings)
    app.state.service.ledger.save_state(AgentState(
        run_id='cross-site-cancel', task=TaskRequest(objective='keep this record'),
        status=RunStatus.COMPLETED,
    ))
    with TestClient(app) as client:
        headers = {'origin': 'https://other.example'}
        cancelled = client.post('/api/v1/runs/cross-site-cancel/cancel', headers=headers)
        uploaded = client.post('/api/v1/uploads', headers=headers,
                               files={'file': ('sample.txt', b'cross-site upload')})
    assert cancelled.status_code == uploaded.status_code == 403
    assert app.state.service.state('cross-site-cancel').status == RunStatus.COMPLETED
    assert list(settings.upload_root.iterdir()) == []


def test_api_rejects_untrusted_host_even_for_reads(settings) -> None:
    app = create_app(settings)
    with TestClient(app) as client:
        denied = client.get('/api/v1/model-config', headers={'host': 'attacker.example'})
        allowed = client.get('/api/v1/model-config', headers={'host': '127.0.0.1:8001'})
    assert denied.status_code == 400
    assert allowed.status_code == 200


def test_websocket_rejects_untrusted_host(settings) -> None:
    app = create_app(settings)
    with TestClient(app) as client:
        with pytest.raises(WebSocketDisconnect) as denied:
            with client.websocket_connect('/api/v1/incident/events', headers={'host': 'attacker.example'}):
                pass
    assert denied.value.status_code == 400


def test_run_usage_uses_provider_events_without_estimation(tmp_path) -> None:
    ledger = LedgerStore(f"sqlite:///{(tmp_path / 'usage.db').as_posix()}")
    run_id = "usage-run"
    ledger.append(run_id, "llm.stream.started", {"trace_id": "trace-1", "model": "demo"}, actor="model")
    ledger.append(
        run_id,
        "llm.stream.completed",
        {
            "trace_id": "trace-1",
            "usage": {
                "prompt_tokens": 100,
                "completion_tokens": 40,
                "total_tokens": 140,
                "prompt_cache_hit_tokens": 25,
            },
        },
        actor="model",
    )
    # A duplicate failure for the same trace must not double-count usage.
    ledger.append(
        run_id,
        "llm.stream.failed",
        {
            "trace_id": "trace-1",
            "usage": {"prompt_tokens": 999, "completion_tokens": 999, "total_tokens": 1998},
        },
        actor="model",
    )

    usage = _run_usage(ledger, run_id)
    assert usage["total_tokens"] == 140
    assert usage["cache_read_tokens"] == 25
    assert usage["token_usage_available"] is True
    assert usage["usage_estimated"] is False
    assert usage["usage_source"] == "provider_ledger"


def test_run_list_pages_include_older_tasks(settings) -> None:
    app = create_app(settings)
    for number in range(3):
        app.state.service.ledger.save_state(AgentState(
            run_id=f'page-run-{number}', task=TaskRequest(objective=f'inspect {number}')))
    with TestClient(app) as client:
        pages = [client.get('/api/v1/runs', params={'limit': 1, 'offset': offset}).json()
                 for offset in range(3)]
        assert {page['runs'][0]['run_id'] for page in pages} == {f'page-run-{number}' for number in range(3)}
        assert all(page['total'] == 3 for page in pages)
        assert [page['has_more'] for page in pages] == [True, True, False]
        # A state update must not move an old task across a pagination boundary.
        oldest = app.state.service.ledger.load_state('page-run-0')
        app.state.service.ledger.save_state(oldest)
        refreshed = [client.get('/api/v1/runs', params={'limit': 1, 'offset': offset}).json()
                     for offset in range(3)]
        assert [page['runs'][0]['run_id'] for page in refreshed] == [page['runs'][0]['run_id'] for page in pages]
        app.state.service.ledger.save_state(AgentState(
            run_id='page-run-new', task=TaskRequest(objective='new task')))
        cursor_pages = [pages[0]]
        while cursor_pages[-1]['next_cursor']:
            cursor_pages.append(client.get('/api/v1/runs', params={
                'limit': 1, 'before': cursor_pages[-1]['next_cursor']}).json())
        assert [page['runs'][0]['run_id'] for page in cursor_pages] == [
            page['runs'][0]['run_id'] for page in pages]
        assert client.get('/api/v1/runs', params={'before': 'bad'}).status_code == 422
        assert client.get('/api/v1/runs', params={'offset': -1}).status_code == 422


def test_event_socket_replays_more_than_one_ledger_page(settings) -> None:
    app = create_app(settings)
    run_id = 'long-ledger-run'
    ledger = app.state.service.ledger
    ledger.save_state(AgentState(run_id=run_id, task=TaskRequest(objective='Replay long ledger')))
    for index in range(1005):
        ledger.append(run_id, 'audit.recorded', {'number': index})
    with TestClient(app) as client:
        with client.websocket_connect(f'/api/v1/runs/{run_id}/events?after_sequence=0') as socket:
            received = [socket.receive_json()['sequence'] for _ in range(1005)]
            ledger.append(run_id, 'audit.recorded', {'number': 1005})
            latest = ledger.append(run_id, 'audit.recorded', {'number': 1006})
            # A bounded subscriber queue may lose an earlier notification.
            # The next event must recover the missing durable sequence.
            client.portal.call(app.state.service.event_hub.publish, latest.model_dump(mode='json'))
            recovered = [socket.receive_json()['sequence'] for _ in range(2)]
        with client.websocket_connect(f'/api/v1/runs/{run_id}/events?after_sequence=1000') as socket:
            remaining = [socket.receive_json()['sequence'] for _ in range(7)]
    assert received == list(range(1, 1006))
    assert recovered == [1006, 1007]
    assert remaining == list(range(1001, 1008))


def test_health_and_task_flow(settings, monkeypatch) -> None:
    settings.prepare_directories()
    app = create_app(settings)
    # This offline API flow must not wait for the built-in live SecMind MCP probe.
    monkeypatch.setattr(app.state.mcp_runtime, "agent_servers", lambda: [])
    with TestClient(app) as client:
        health = client.get("/health")
        assert health.status_code == 200
        model_config = client.get("/api/v1/model-config")
        assert model_config.status_code == 200
        assert model_config.json()["api_key_configured"] is False
        assert "model_api_key" not in model_config.json()
        updated = client.put(
            "/api/v1/model-config",
            json={
                "base_url": "https://example.test/v1",
                "api_key": "test-secret-key",
                "planner_model": "custom-planner",
                "worker_model": "custom-worker",
                "fallback_model": "custom-fallback",
            },
        )
        assert updated.status_code == 200
        assert updated.json()["api_key_configured"] is True
        assert "test-secret-key" not in updated.text
        refreshed = client.get("/api/v1/model-config")
        assert refreshed.json()["base_url"] == "https://example.test/v1"
        assert refreshed.json()["planner_model"] == "custom-planner"
        assert refreshed.json()["worker_model"] == "custom-worker"
        assert refreshed.json()["fallback_model"] == "custom-fallback"
        assert refreshed.json()["demo_mode"] is False
        assert "test-secret-key" not in refreshed.text

        prompts = client.get("/api/v1/prompts")
        assert prompts.status_code == 200
        assert prompts.json()["runtime_injected"] is True
        if prompts.json()["prompts"]:
            prompt_key = prompts.json()["prompts"][0]["key"]
            prompt_detail = client.get(f"/api/v1/prompts/{prompt_key}")
            assert prompt_detail.status_code == 200
            assert prompt_detail.json()["runtime_injected"] is True
            assert prompt_detail.json()["content"]
        invalid = client.put(
            "/api/v1/model-config",
            json={"base_url": "file:///tmp/model", "api_key": "test-secret-key"},
        )
        assert invalid.status_code == 422
        cleared = client.put(
            "/api/v1/model-config",
            json={"base_url": "https://example.test/v1", "clear_api_key": True},
        )
        assert cleared.status_code == 200
        assert cleared.json()["api_key_configured"] is False
        upload = client.post(
            "/api/v1/uploads",
            files={"file": ("bad.py", b"import subprocess\nsubprocess.Popen('x', shell=True)\n")},
        )
        assert upload.status_code == 201
        question_bank_source = settings.upload_root / "question-bank.zip"
        with zipfile.ZipFile(question_bank_source, "w") as archive:
            archive.writestr(
                "question-bank.json",
                '{"questions":[{"root":"bank/WEB/web-1","type":"web"},'
                '{"root":"bank/CRYPTO/crypto-1","type":"crypto"}]}',
            )
            archive.writestr("bank/WEB/web-1/package.json", "{}")
            archive.writestr("bank/WEB/web-1/index.html", "hello")
            archive.writestr("bank/CRYPTO/crypto-1/solve.py", "from Crypto.PublicKey import RSA")
        question_bank_upload = client.post(
            "/api/v1/uploads",
            files={"file": ("question-bank.zip", question_bank_source.read_bytes())},
        )
        assert question_bank_upload.status_code == 201
        bank_attachment = {
            "ref": question_bank_upload.json()["ref"],
            "name": "question-bank.zip",
        }
        inspection = client.post(
            "/api/v1/question-banks/inspect",
            json={"name": "API question bank", "attachments": [bank_attachment]},
        )
        assert inspection.status_code == 202
        bank = inspection.json()
        for _ in range(100):
            bank = client.get(f"/api/v1/question-banks/{bank['bank_id']}/inspection").json()
            if bank["status"] != "inspecting":
                break
            time.sleep(0.02)
        assert bank["status"] == "awaiting_confirmation"
        assert bank["statistics"]["detected_question_count"] == 2
        blocked = client.post(
            "/api/v1/tasks",
            json={
                "name": "Unconfirmed bank",
                "objective": "audit question bank",
                "attachments": [bank_attachment],
                "question_bank_id": bank["bank_id"],
            },
        )
        assert blocked.status_code == 409
        confirmed = client.post(
            f"/api/v1/question-banks/{bank['bank_id']}/confirm",
            json={
                "questions": [
                    {
                        "candidate_id": item["candidate_id"],
                        "root": item["root"],
                        "question_type": item["question_type"],
                    }
                    for item in bank["questions"]
                ]
            },
        )
        assert confirmed.status_code == 200
        accepted = client.post(
            "/api/v1/tasks",
            json={
                "name": "Confirmed bank",
                "objective": "audit question bank",
                "attachments": [bank_attachment],
                "question_bank_id": bank["bank_id"],
            },
        )
        assert accepted.status_code == 202
        task = client.post(
            "/api/v1/tasks",
            json={
                "name": "Uploaded source audit",
                "objective": "audit uploaded python code",
                "attachments": [{"ref": upload.json()["ref"]}],
            },
        )
        assert task.status_code == 202
        run_id = task.json()["run_id"]
        runs = client.get("/api/v1/runs")
        assert runs.status_code == 200
        listed = next(item for item in runs.json()["runs"] if item["run_id"] == run_id)
        assert {"status", "scenario", "module_route", "external_execution"}.issubset(listed)
        assert {"total_tokens", "cache_read_tokens", "token_usage_available", "usage_estimated"}.issubset(listed["usage"])
        assert listed["usage"]["usage_estimated"] is False
        assert listed["module_route"] == "code_audit"
        status = None
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            response = client.get(f"/api/v1/runs/{run_id}")
            status = response.json()["status"]
            if status in {"completed", "partial", "failed", "denied"}:
                break
            time.sleep(0.05)
        assert status == "completed"
        assert response.json()["name"] == "Uploaded source audit"
        assert response.json()["scenario"] == "code_audit"
        assert response.json()["module_route"] == "code_audit"
        assert response.json()["external_execution"] == {}
        assert response.json()["usage"]["usage_estimated"] is False
        assert response.json()["usage"]["token_usage_available"] is False
        assert response.json()["budget"]["tool_calls_used"] >= 1
        assert response.json()["budget"]["model_calls_used"] == 0
        report = client.get(f"/api/v1/runs/{run_id}/report")
        assert report.status_code == 200
        assert report.json()["findings"]
        ledger = client.get(f"/api/v1/runs/{run_id}/ledger")
        assert ledger.status_code == 200
        assert ledger.json()["chain_valid"] is True
        usage = client.get("/api/v1/model-usage")
        assert usage.status_code == 200
        assert usage.json()["run_count"] == 2
        assert usage.json()["token_usage_available"] is False
        assert usage.json()["total_tokens"] == 0
        assert set(usage.json()["quota"]) == {"hourly", "daily", "monthly"}
        assert set(usage.json()["series"]) == {"hourly", "daily", "monthly"}
        quota = client.put(
            "/api/v1/model-usage/quota",
            json={"hourly_tokens": 1000, "daily_tokens": 5000, "monthly_tokens": 20000},
        )
        assert quota.status_code == 200
        assert quota.json()["quota"] == {"hourly": 1000, "daily": 5000, "monthly": 20000}
        assert client.get("/api/v1/model-usage").json()["quota"]["daily"] == 5000
        event_types = [item["event_type"] for item in ledger.json()["events"]]
        assert "agent.started" in event_types
        assert "agent.instruction" in event_types
        assert "agent.thought" in event_types
        assert "agent.completed" in event_types
        thoughts = client.get(f"/api/v1/runs/{run_id}/thoughts/export")
        assert thoughts.status_code == 200
        assert "text/markdown" in thoughts.headers["content-type"]
        assert "Uploaded source audit" in thoughts.text
        assert "可审计思考过程" in thoughts.text
        assert "编排指令" in thoughts.text
        assert "隐藏推理" in thoughts.text


def test_cancel_run_endpoint_is_idempotent_for_terminal_run(settings, monkeypatch) -> None:
    settings.prepare_directories()
    app = create_app(settings)
    run_id = "already-partial"
    app.state.service.ledger.save_state(AgentState(
        run_id=run_id,
        task=TaskRequest(objective="cancel test"),
        status=RunStatus.PARTIAL,
        last_error="prior stop",
    ))
    monkeypatch.setattr(app.state.mcp_runtime, "agent_servers", lambda: [])
    with TestClient(app) as client:
        response = client.post(f"/api/v1/runs/{run_id}/cancel")
        assert response.status_code == 200
        assert response.json()["accepted"] is True
        assert response.json()["status"] == RunStatus.PARTIAL.value
        assert client.post("/api/v1/runs/missing/cancel").status_code == 404


def test_mcp_catalog_crud_preserves_unconnected_metadata(settings, tmp_path) -> None:
    settings.prepare_directories()
    app = create_app(settings)
    app.state.mcp_catalog.storage_path = tmp_path / "mcp-catalog.json"
    with TestClient(app) as client:
        created_server = client.post(
            "/api/v1/mcp/servers",
            json={
                "server_id": "demo-server",
                "name": "Demo Server",
                "purpose": "仅用于页面展示",
                "category": "demo",
                "transport": "display_only",
                "url": "",
                "icon": "safety",
            },
        )
        assert created_server.status_code == 201
        assert created_server.json()["server"]["enabled"] is False
        created_tool = client.post(
            "/api/v1/mcp/servers/demo-server/tools",
            json={
                "name": "demo_tool",
                "display_name": "演示工具",
                "purpose": "展示工具详情",
                "input": "演示输入",
                "returns": "演示输出",
                "invocation_timing": "仅在详情页展示",
                "risk_level": "R0",
                "icon": "tool",
            },
        )
        assert created_tool.status_code == 201
        assert created_tool.json()["tool"]["runtime_exposed"] is False
        updated_tool = client.put(
            "/api/v1/mcp/servers/demo-server/tools/demo_tool",
            json={
                "name": "demo_tool",
                "display_name": "已编辑的演示工具",
                "purpose": "展示编辑后的详情",
                "input": "编辑后的输入",
                "returns": "编辑后的输出",
                "invocation_timing": "仍然只用于展示",
                "risk_level": "R1",
                "icon": "experiment",
            },
        )
        assert updated_tool.status_code == 200
        assert updated_tool.json()["tool"]["runtime_exposed"] is False
        catalog = client.get("/api/v1/mcp/catalog")
        assert catalog.status_code == 200
        assert catalog.json()["runtime_enabled"] is True
        assert catalog.json()["invocation_enabled"] is True
        assert {item["server_id"] for item in catalog.json()["servers"]} >= {"demo-server"}
        assert client.delete("/api/v1/mcp/servers/demo-server/tools/demo_tool").status_code == 204
        assert client.delete("/api/v1/mcp/servers/demo-server").status_code == 204
        assert client.get("/api/v1/mcp/servers/demo-server").status_code == 404


def test_mcp_management_invoke_cannot_bypass_task_approval(settings, monkeypatch) -> None:
    settings.prepare_directories()
    app = create_app(settings)
    monkeypatch.setattr(app.state.mcp_runtime, "agent_servers", lambda: [])
    calls = []

    async def invoke(*args, **kwargs):
        calls.append((args, kwargs))
        return {"status": "completed"}

    monkeypatch.setattr(app.state.mcp_runtime, "invoke", invoke)
    with TestClient(app) as client:
        denied = client.post("/api/v1/mcp/servers/secmind-local/invoke", json={
            "tool": "hash_file", "arguments": {"path": "example.txt"}, "approved": True,
        })
        assert denied.status_code == 403
        linked = client.post("/api/v1/mcp/servers/secmind-local/invoke", json={
            "tool": "decode_base64", "arguments": {"text": "aGVsbG8="},
            "approved": True, "run_id": "some-run",
        })
        assert linked.status_code == 403
        assert calls == []
