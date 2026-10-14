from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from conftest import seal_execution_contract
from fastapi import HTTPException
from fastapi.testclient import TestClient
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from sqlalchemy import text
from starlette.websockets import WebSocketDisconnect

from secmind.api import _purge_expired_uploads, _safe_upload_name, create_app
from secmind.config import Settings
from secmind.coordinator import CoordinatorConflict, RunLease
from secmind.runtime import ApplicationRuntime, build_runtime
from secmind.schemas import ApprovalRequest, RiskLevel, RunStatus, StepRuntime, TaskRequest


def _settings(tmp_path, **updates) -> Settings:
    values = {
        "runtime_role": "api",
        "unsafe_development_tools": True,
        "database_url": f"sqlite:///{(tmp_path / 'branches.db').as_posix()}",
        "input_root": tmp_path / "inputs",
        "upload_root": tmp_path / "uploads",
        "run_root": tmp_path / "runs",
        "artifact_root": tmp_path / "artifacts",
        "worker_poll_seconds": 0.05,
    }
    values.update(updates)
    return Settings(**values)


def test_api_error_branches_and_upload_helpers(tmp_path, monkeypatch) -> None:
    settings = _settings(tmp_path)
    settings.prepare_directories()
    directory = settings.upload_root / "directory"
    directory.mkdir()
    assert _purge_expired_uploads(settings.upload_root, ttl_seconds=1, now=0) == 0
    for name in (None, "", ".", "..", "a" * 256, "bad\x00.py", "bad.py.", "/abs.py"):
        with pytest.raises(HTTPException):
            _safe_upload_name(name)

    app = create_app(settings)
    with TestClient(app, base_url="http://127.0.0.1") as client:
        run_id = client.post("/api/v1/tasks", json={"objective": "queued audit"}).json()["run_id"]
        assert client.get("/api/v1/runs/missing/report").status_code == 404
        assert client.get(f"/api/v1/runs/{run_id}/report").status_code == 409
        assert client.get("/api/v1/runs/missing/ledger").status_code == 404
        assert client.get("/api/v1/runs/missing/ledger/export").status_code == 404
        assert client.post("/api/v1/runs/missing/recover").status_code == 404
        assert client.post("/api/v1/runs/missing/approvals/request", json={"decision": "deny"}).status_code == 404
        already = client.post(
            f"/api/v1/runs/{run_id}/approvals/request",
            json={"decision": "deny"},
        )
        assert already.status_code == 202
        assert already.json()["resolution_status"] == "already_resolved"
        assert client.get(f"/api/v1/runs/missing/artifacts/{'0' * 64}").status_code == 404

        stored = app.state.runtime.service.artifact_store.put(b"will be corrupted")
        state = app.state.runtime.service.state(run_id)
        state.step_runtime["x"] = StepRuntime(step_id="x", artifact_ids=[stored.artifact_id])
        app.state.runtime.service.ledger.save_state(state)
        app.state.runtime.service.artifact_store.path_for(stored.artifact_id).write_bytes(b"corrupt")
        # Ownerless artifacts are raw/restricted by default.  Authorization is
        # evaluated before byte integrity so the endpoint cannot become a
        # presence/corruption oracle for unclassified internal data.
        assert client.get(f"/api/v1/runs/{run_id}/artifacts/{stored.artifact_id}").status_code == 403


def test_ready_runner_success_and_failure(tmp_path, monkeypatch) -> None:
    settings = _settings(tmp_path, sandbox_runner_url="http://runner.internal", sandbox_token=tmp_path.name)

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def aclose(self):
            return None

        async def get(self, _url):
            return SimpleNamespace(status_code=200)

    monkeypatch.setattr("secmind.api_system.httpx.AsyncClient", FakeClient)
    healthy_app = create_app(settings)
    with TestClient(healthy_app, base_url="http://127.0.0.1") as client:
        ready_payload = client.get("/health/ready")
        assert ready_payload.status_code == 200
        assert ready_payload.json()["runtime_profile"]["name"] == settings.runtime_profile
        assert len(ready_payload.json()["runtime_profile"]["digest"]) == 64
        health_payload = client.get("/health").json()
        assert health_payload["runtime_profile"]["digest"] == ready_payload.json()["runtime_profile"]["digest"]
        assert health_payload["runtime_profile"]["effective_settings"]["model_structured_output_mode"] == (
            settings.model_structured_output_mode
        )
        assert health_payload["runtime_profile"]["secret_bindings"]["qwen_api_key"] is False
        healthy_app.state.runtime.service.coordinator.enqueue_outbox(
            "readiness-run",
            transition_id="readiness-transition",
            event_type="readiness.test",
            payload={},
        )
        with healthy_app.state.runtime.service.coordinator.engine.begin() as connection:
            connection.execute(text("UPDATE outbox_events SET status = 'failed'"))
        failed = client.get("/health/ready")
        assert failed.status_code == 503
        assert failed.json()["detail"]["checks"]["projector"] is False
        with healthy_app.state.runtime.service.coordinator.engine.begin() as connection:
            connection.execute(text("UPDATE outbox_events SET status = 'dead_letter'"))
        degraded = client.get("/health/ready")
        assert degraded.status_code == 200
        assert degraded.json()["status"] == "degraded"
        assert degraded.json()["checks"]["outbox_dead_letter"] == 1

    class BrokenClient(FakeClient):
        async def get(self, _url):
            raise OSError("runner unavailable")

    monkeypatch.setattr("secmind.api_system.httpx.AsyncClient", BrokenClient)
    broken_settings = _settings(
        tmp_path / "broken",
        sandbox_runner_url="http://runner",
        sandbox_token=tmp_path.name,
    )
    with TestClient(create_app(broken_settings), base_url="http://127.0.0.1") as client:
        response = client.get("/health/ready")
        assert response.status_code == 503
        assert response.json()["detail"]["checks"]["error_type"] == "OSError"


def test_websocket_replay_live_gap_and_not_found(tmp_path) -> None:
    app = create_app(_settings(tmp_path))
    with TestClient(app, base_url="http://127.0.0.1") as client:
        run_id = client.post("/api/v1/tasks", json={"objective": "queued websocket audit"}).json()["run_id"]
        with pytest.raises(WebSocketDisconnect) as missing:
            with client.websocket_connect("ws://127.0.0.1/api/v1/runs/missing/events"):
                pass
        assert missing.value.code == 4404

        with client.websocket_connect(f"ws://127.0.0.1/api/v1/runs/{run_id}/events") as socket:
            replayed = json.loads(socket.receive_text())
            assert replayed["sequence"] == 1
            client.portal.call(
                app.state.runtime.service.event_hub.publish,
                {"run_id": run_id, "sequence": 2, "event_type": "live"},
            )
            assert json.loads(socket.receive_text())["event_type"] == "live"
            client.portal.call(
                app.state.runtime.service.event_hub.publish,
                {"run_id": run_id, "sequence": 4, "event_type": "out-of-order"},
            )
            assert json.loads(socket.receive_text())["event_type"] == "stream.gap"
            with pytest.raises(WebSocketDisconnect) as gap:
                socket.receive_text()
            assert gap.value.code == 1013

        with client.websocket_connect(f"ws://127.0.0.1/api/v1/runs/{run_id}/events?after_sequence=1") as socket:
            client.portal.call(
                app.state.runtime.service.event_hub.publish,
                {"run_id": run_id, "sequence": 2, "event_type": "stream.gap"},
            )
            assert json.loads(socket.receive_text())["event_type"] == "stream.gap"


async def test_worker_control_flow_and_retry(tmp_path, monkeypatch) -> None:
    service, gateway = build_runtime(_settings(tmp_path))
    try:
        run_id = service.submit(TaskRequest(objective="worker branches"))
        lease = service.coordinator.claim_jobs("worker", limit=1, lease_seconds=30)[0]
        waiting = service.state(run_id)
        waiting.status = RunStatus.WAITING_APPROVAL
        monkeypatch.setattr(service.orchestrator, "start", AsyncMock(return_value=waiting))
        await service.worker._run(lease)
        assert service.coordinator.job_status(run_id)[0] == "waiting"

        service.coordinator.wake_job(run_id)
        resumed_lease = service.coordinator.claim_jobs("worker", limit=1, lease_seconds=30)[0]
        persisted = service.state(run_id)
        persisted.status = RunStatus.WAITING_APPROVAL
        persisted.pending_approval = ApprovalRequest(
            run_id=run_id,
            step_id="scan",
            tool_name="bandit_python_audit",
            parameters={"target": "."},
            target=".",
            risk_level=RiskLevel.R2,
            reason="approval",
            expected_impact="scan",
        )
        service.ledger.save_state(persisted)
        response = SimpleNamespace(decision="approve")
        monkeypatch.setattr(service.orchestrator.broker, "approval_response", lambda *_args, **_kw: response)
        recovered = persisted.model_copy(deep=True)
        recovered.status = RunStatus.RECOVERY_REQUIRED
        monkeypatch.setattr(service.orchestrator, "resume", AsyncMock(return_value=recovered))
        await service.worker._run(resumed_lease)
        assert service.coordinator.job_status(run_id)[0] == "recovery_required"

        service.coordinator.wake_job(run_id)
        recovery_lease = service.coordinator.claim_jobs("worker", limit=1, lease_seconds=30)[0]
        complete = persisted.model_copy(deep=True)
        complete.status = RunStatus.COMPLETED
        complete.pending_approval = None
        complete.cancel_requested = True
        monkeypatch.setattr(service.orchestrator, "recover", AsyncMock(return_value=complete))
        current = service.state(run_id)
        current.status = RunStatus.RUNNING
        current.pending_approval = None
        service.ledger.save_state(current)
        await service.worker._run(recovery_lease)
        assert service.coordinator.job_status(run_id)[0] == "cancelled"

        retry_id = service.submit(TaskRequest(objective="retry branch"))
        semantic_version = service.state(retry_id).state_version
        retry_lease = service.coordinator.claim_jobs("worker", limit=1, lease_seconds=30)[0]
        monkeypatch.setattr(service.orchestrator, "start", AsyncMock(side_effect=ValueError("boom")))
        await service.worker._run(retry_lease)
        assert service.coordinator.job_status(retry_id)[0] == "retry"
        assert service.state(retry_id).state_version == semantic_version
        assert service.state(retry_id).last_error is None
        assert "ValueError" in (service.summary(retry_id).last_error or "")

        missing_id = "missing-state"
        service.coordinator.enqueue_run(missing_id)
        missing_lease = service.coordinator.claim_jobs("worker", limit=1, lease_seconds=30)[0]
        await service.worker._run(missing_lease)
        assert service.coordinator.job_status(missing_id)[0] == "cancelled"
    finally:
        await gateway.close()
        await service.shutdown()


async def test_run_summary_uses_bounded_public_coverage(tmp_path) -> None:
    service, gateway = build_runtime(_settings(tmp_path))
    try:
        run_id = service.submit(TaskRequest(objective="bounded run summary"))
        state = service.state(run_id)
        state.audit_coverage["candidate_store"] = {
            "records": [{"candidate_id": f"candidate-{index}", "body": "x" * 4096} for index in range(256)],
            "events": [{"event": "transition", "body": "y" * 2048} for _ in range(256)],
            "store_digest": "a" * 64,
        }
        service.ledger.save_state(state)

        summary = service.summary(run_id)
        serialized = summary.model_dump_json().encode("utf-8")
        assert len(serialized) < 256 * 1024
        assert summary.audit_coverage["candidate_store"]["record_count"] == 256
        assert "records" not in summary.audit_coverage["candidate_store"]
        assert len(service.state(run_id).audit_coverage["candidate_store"]["records"]) == 256
    finally:
        await gateway.close()
        await service.shutdown()


async def test_worker_start_stop_loop_heartbeat_and_conflict(tmp_path, monkeypatch) -> None:
    service, gateway = build_runtime(_settings(tmp_path))
    try:
        await service.worker.start()
        await service.worker.start()
        service.worker.notify()
        await asyncio.sleep(0.03)
        await service.worker.stop()

        lease = RunLease(
            run_id="r",
            owner_id="owner",
            fence=1,
            lease_until=datetime.now(UTC) + timedelta(seconds=30),
            attempts=1,
        )
        monkeypatch.setattr(service.coordinator, "heartbeat", MagicMock(side_effect=CoordinatorConflict("stale")))
        monkeypatch.setattr(asyncio, "sleep", AsyncMock())
        with pytest.raises(CoordinatorConflict):
            await service.worker._heartbeat(lease)
    finally:
        await gateway.close()
        await service.shutdown()


async def test_worker_retry_budget_fails_closed_without_an_infinite_queue(tmp_path, monkeypatch) -> None:
    service, gateway = build_runtime(_settings(tmp_path, worker_max_attempts=1))
    try:
        run_id = service.submit(TaskRequest(objective="bounded retry"))
        lease = service.coordinator.claim_jobs("worker", limit=1, lease_seconds=30)[0]
        monkeypatch.setattr(service.orchestrator, "start", AsyncMock(side_effect=ValueError("deterministic failure")))

        await service.worker._run(lease)

        assert service.coordinator.job_status(run_id)[0] == "recovery_required"
        state = service.state(run_id)
        assert state.status == RunStatus.RECOVERY_REQUIRED
        assert state.last_error == "Worker retry budget exhausted: ValueError"
    finally:
        await gateway.close()
        await service.shutdown()


async def test_service_approval_recovery_cancel_runner_and_queue_fallback(tmp_path, monkeypatch) -> None:
    settings = _settings(
        tmp_path,
        sandbox_runner_url="http://runner",
        sandbox_token=tmp_path.name,
        sandbox_control_token=f"control-{tmp_path.name}",
    )
    service, gateway = build_runtime(settings)
    try:
        with pytest.raises(KeyError):
            service.submit_approval("missing", "request", {"decision": "deny"})  # type: ignore[arg-type]

        run_id = service.submit(TaskRequest(objective="approval and recovery"))
        state = service.state(run_id)
        state.status = RunStatus.RECOVERY_REQUIRED
        service.ledger.save_state(state)
        assessment = await service.recovery_assessment(run_id)
        with pytest.raises(RuntimeError, match="operator investigation"):
            await service.recover(
                run_id,
                assessment_id=assessment.assessment_id,
                assessment_digest=assessment.assessment_digest,
            )
        assert service.state(run_id).status == RunStatus.RECOVERY_REQUIRED

        state = service.state(run_id)
        state.pending_approval = ApprovalRequest(
            request_id="expected",
            run_id=run_id,
            step_id="scan",
            tool_name="bandit_python_audit",
            parameters={"target": "."},
            target=".",
            risk_level=RiskLevel.R2,
            reason="approval",
            expected_impact="scan",
        )
        seal_execution_contract(state)
        service.orchestrator.broker.register_approval(state.pending_approval)
        service.ledger.save_state(state)
        with pytest.raises(RuntimeError, match="different approval"):
            service.submit_approval(run_id, "wrong", {"decision": "deny"})  # type: ignore[arg-type]

        from secmind.schemas import ApprovalResponse

        approval = ApprovalResponse(decision="approve")
        with pytest.raises(RuntimeError, match="duplicate"):
            service.submit_approvals_batch(run_id, [("expected", approval), ("expected", approval)])
        with pytest.raises(RuntimeError, match="not active"):
            service.submit_approvals_batch(run_id, [("unknown", approval)])
        batch = service.submit_approvals_batch(run_id, [("expected", approval)])
        assert batch[0]["resolution_status"] == "accepted"
        assert batch[0]["resolution_id"]
        assert service.submit_approval(run_id, "expected", approval) is False

        monkeypatch.setattr(service.orchestrator.broker, "active_invocation_ids", lambda _run_id: ["inv-1"])
        service.orchestrator.project_outbox = AsyncMock()
        deleted: list[str] = []

        class FakeClient:
            def __init__(self, *args, **kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return None

            async def delete(self, url, **_kwargs):
                deleted.append(url)

        monkeypatch.setattr("secmind.service.httpx.AsyncClient", FakeClient)
        await service.cancel(run_id)
        assert deleted == ["http://runner/internal/v1/invocations/inv-1"]

        monkeypatch.setattr(service.coordinator, "job_status", MagicMock(side_effect=KeyError("gone")))
        assert service._queue_status(run_id).value == "complete"
    finally:
        await gateway.close()
        await service.shutdown()


async def test_application_runtime_lifecycle_and_postgres_cleanup(tmp_path, monkeypatch) -> None:
    settings = _settings(tmp_path)
    runtime = ApplicationRuntime(settings)
    with pytest.raises(RuntimeError, match="not been started"):
        _ = runtime.service
    await runtime.startup()
    await runtime.startup()
    assert runtime.service is not None
    await runtime.shutdown()

    events: list[str] = []

    class FakeCheckpointer:
        async def setup(self):
            events.append("setup")

    class FakeContext:
        async def __aenter__(self):
            events.append("enter")
            return FakeCheckpointer()

        async def __aexit__(self, *_args):
            events.append("exit")

    fake_service = SimpleNamespace(
        recover_incomplete=AsyncMock(),
        startup=AsyncMock(),
        shutdown=AsyncMock(),
    )
    fake_gateway = SimpleNamespace(close=AsyncMock())
    monkeypatch.setattr(AsyncPostgresSaver, "from_conn_string", lambda _url: FakeContext())
    monkeypatch.setattr("secmind.runtime.build_runtime", lambda *_args: (fake_service, fake_gateway))
    monkeypatch.setattr("secmind.runtime.close_gateway_safely", AsyncMock())
    postgres_runtime = ApplicationRuntime(_settings(tmp_path / "pg", checkpoint_database_url="postgresql://ignored"))
    await postgres_runtime.startup()
    await postgres_runtime.shutdown()
    assert events == ["enter", "setup", "exit"]
    fake_service.recover_incomplete.assert_awaited_once()
    fake_service.startup.assert_awaited_once()
    fake_service.shutdown.assert_awaited_once()


async def test_application_runtime_checkpoint_setup_failure(tmp_path, monkeypatch) -> None:
    events: list[str] = []

    class BrokenCheckpointer:
        async def setup(self):
            raise RuntimeError("setup failed")

    class FakeContext:
        async def __aenter__(self):
            return BrokenCheckpointer()

        async def __aexit__(self, *_args):
            events.append("exit")

    monkeypatch.setattr(AsyncPostgresSaver, "from_conn_string", lambda _url: FakeContext())
    runtime = ApplicationRuntime(_settings(tmp_path, checkpoint_database_url="postgresql://ignored"))
    with pytest.raises(RuntimeError, match="setup failed"):
        await runtime.startup()
    assert events == ["exit"]


def test_strict_runtime_verifies_migration_and_builds_runner_tools(tmp_path, monkeypatch) -> None:
    checked: list[str] = []
    monkeypatch.setattr("secmind.runtime.verify_database_at_head", lambda url, _path: checked.append(url))
    settings = _settings(
        tmp_path,
        env="competition",
        unsafe_development_tools=False,
        sandbox_runner_url="http://runner",
        sandbox_token=tmp_path.name,
        sandbox_control_token=f"control-{tmp_path.name}",
        sandbox_ticket_private_key_file=tmp_path / "placeholder.pem",
    )
    monkeypatch.setattr("secmind.runtime.CapabilityTicketIssuer.from_pem", lambda _pem: MagicMock())
    settings.sandbox_ticket_private_key_file.write_bytes(b"not-a-real-key")
    service, gateway = build_runtime(settings)
    assert checked == [settings.database_url]
    assert service.orchestrator.broker.registry.get("bandit_python_audit").manifest.version == "sandbox-1"
    asyncio.run(gateway.close())
    service.orchestrator.broker.close()
    service.ledger.close()
    service.coordinator.close()
