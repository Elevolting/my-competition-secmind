from __future__ import annotations

import os
import time
from contextlib import asynccontextmanager
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from secmind.api import create_app
from secmind.config import Settings
from secmind.investigation.contracts import ArtifactDataClass, ArtifactSecurityLabel, ArtifactView
from secmind.schemas import SCHEMA_VERSION, DataView, LogLayer


def _wait_for_terminal(client: TestClient, run_id: str) -> dict:
    body = {}
    for _ in range(150):
        body = client.get(f"/api/v1/runs/{run_id}").json()
        if body.get("status") in {"completed", "partial", "failed", "denied"}:
            return body
        time.sleep(0.02)
    return body


def test_v12_discovery_idempotency_artifact_and_export(settings) -> None:
    app = create_app(settings)
    with TestClient(app, base_url="http://127.0.0.1") as client:
        assert client.get("/health/live").json()["schema_version"] == SCHEMA_VERSION
        assert client.get("/health/ready").status_code == 200
        assert client.get("/metrics").status_code == 200
        tools = client.get("/api/v1/tools").json()["tools"]
        assert {item["name"] for item in tools} >= {
            "bandit_python_audit",
            "project_inventory",
            "secret_pattern_scan",
        }

        uploaded = client.post(
            "/api/v1/uploads",
            files={"file": ("secret.py", b'API_KEY = "a-redacted-test-secret"\n')},
        ).json()
        request = {
            "client_request_id": "stable-request-0001",
            "objective": "audit uploaded python code",
            "attachments": [{"ref": uploaded["ref"]}],
        }
        first = client.post("/api/v1/tasks", json=request).json()
        second = client.post("/api/v1/tasks", json=request).json()
        assert first["run_id"] == second["run_id"]
        run_id = first["run_id"]
        # The requested audit is complete even when an optional independent
        # corroboration target remains open.  The finding keeps its lower
        # assurance; an enhancement goal must not redefine terminal status.
        assert _wait_for_terminal(client, run_id)["status"] == "completed"
        gaps = client.get(f"/api/v1/runs/{run_id}/evidence-gaps")
        assert gaps.status_code == 200
        assert gaps.json()["run_id"] == run_id
        admission = client.get(f"/api/v1/runs/{run_id}/admission")
        assert admission.status_code == 200
        assert admission.json()["run_id"] == run_id
        assert "# SecMind" in client.get(f"/api/v1/runs/{run_id}/report?format=markdown").text
        sarif = client.get(f"/api/v1/runs/{run_id}/report?format=sarif").json()
        assert sarif["version"] == "2.1.0"
        assert sarif["runs"][0]["tool"]["driver"]["semanticVersion"] == "0.8.7"

        listing = client.get("/api/v1/runs?status=completed").json()
        assert any(item["run_id"] == run_id for item in listing["items"])
        assert client.get(f"/api/v1/runs/{run_id}/ledger/export").status_code == 200

        service = app.state.runtime.service
        stored = service.artifact_store.put(
            b"verified artifact",
            media_type="text/plain",
            run_id=run_id,
            data_view=DataView.OBSERVABLE,
        )
        assert service.investigation_store is not None
        service.investigation_store.label_artifact(
            ArtifactSecurityLabel(
                artifact_id=stored.artifact_id,
                owner_run_id=run_id,
                owner_step_id="test-projection",
                view=ArtifactView.OBSERVABLE,
                data_class=ArtifactDataClass.REPORT,
                retention_policy_id="test",
                allowed_purposes=["download"],
                created_by="test",
                content_sha256=stored.sha256,
                size=stored.size_bytes,
                media_type=stored.media_type,
            )
        )
        state = service.state(run_id)
        step_runtime = next(iter(state.step_runtime.values()))
        step_runtime.artifact_ids.append(stored.artifact_id)
        service.ledger.save_state(state)
        original_read = service.artifact_store.read
        reads: list[str] = []

        def tracked_read(artifact_id: str) -> bytes:
            reads.append(artifact_id)
            return original_read(artifact_id)

        service.artifact_store.read = tracked_read  # type: ignore[method-assign]
        artifact = client.get(f"/api/v1/runs/{run_id}/artifacts/{stored.artifact_id}")
        assert artifact.status_code == 200
        assert artifact.content == b"verified artifact"
        assert artifact.headers["etag"] == f'"sha256:{stored.artifact_id}"'
        unchanged = client.get(
            f"/api/v1/runs/{run_id}/artifacts/{stored.artifact_id}",
            headers={"If-None-Match": artifact.headers["etag"]},
        )
        assert unchanged.status_code == 304
        assert reads == [stored.artifact_id]
        raw = service.artifact_store.put(
            b"synthetic raw tool output",
            media_type="text/plain",
            run_id=run_id,
            data_view=DataView.RAW_RESTRICTED,
            log_layer=LogLayer.RAW_SECURITY,
        )
        service.investigation_store.label_artifact(
            ArtifactSecurityLabel(
                artifact_id=raw.artifact_id,
                owner_run_id=run_id,
                owner_step_id="test-projection",
                view=ArtifactView.RAW_RESTRICTED,
                data_class=ArtifactDataClass.TOOL_OUTPUT,
                retention_policy_id="test",
                allowed_purposes=["analysis", "forensics"],
                created_by="test",
                content_sha256=raw.sha256,
                size=raw.size_bytes,
                media_type=raw.media_type,
            )
        )
        state = service.state(run_id)
        next(iter(state.step_runtime.values())).artifact_ids.append(raw.artifact_id)
        service.ledger.save_state(state)
        raw_download = client.get(
            f"/api/v1/runs/{run_id}/artifacts/{raw.artifact_id}",
            params={"view": "raw_restricted"},
            headers={"X-SecMind-Access-Purpose": "forensics"},
        )
        assert raw_download.status_code == 403
        assert reads == [stored.artifact_id]
        assert client.get(f"/api/v1/runs/{run_id}/artifacts/{'0' * 64}").status_code == 404
        assert client.get(f"/api/v1/runs/{run_id}/artifacts/not-a-digest").status_code == 404


def test_cancel_and_recover_contract_without_embedded_worker(tmp_path) -> None:
    settings = Settings(
        runtime_role="api",
        unsafe_development_tools=True,
        database_url=f"sqlite:///{(tmp_path / 'api.db').as_posix()}",
        input_root=tmp_path / "inputs",
        upload_root=tmp_path / "uploads",
        run_root=tmp_path / "runs",
        artifact_root=tmp_path / "artifacts",
    )
    app = create_app(settings)
    with TestClient(app, base_url="http://127.0.0.1") as client:
        run_id = client.post("/api/v1/tasks", json={"objective": "audit queued code"}).json()["run_id"]
        assert client.post(f"/api/v1/runs/{run_id}/recover").status_code == 409
        cancelled = client.post(f"/api/v1/runs/{run_id}/cancel")
        assert cancelled.status_code == 202
        assert client.get(f"/api/v1/runs/{run_id}").json()["cancel_requested"] is True
        assert client.get("/api/v1/runs/does-not-exist").status_code == 404
        assert client.post("/api/v1/runs/does-not-exist/cancel").status_code == 404


def test_upload_rejects_unsafe_names_enforces_total_quota_and_purges_expired(tmp_path) -> None:
    settings = Settings(
        unsafe_development_tools=True,
        database_url=f"sqlite:///{(tmp_path / 'uploads.db').as_posix()}",
        input_root=tmp_path / "inputs",
        upload_root=tmp_path / "uploads",
        run_root=tmp_path / "runs",
        artifact_root=tmp_path / "artifacts",
        max_upload_bytes=1024,
        max_upload_total_bytes=1024,
        upload_ttl_seconds=60,
    )
    settings.prepare_directories()
    expired = settings.upload_root / "expired.bin"
    expired.write_bytes(b"x" * 900)
    old = time.time() - 120
    os.utime(expired, (old, old))

    with TestClient(create_app(settings), base_url="http://127.0.0.1") as client:
        accepted = client.post("/api/v1/uploads", files={"file": ("safe.py", b"x" * 900)})
        assert accepted.status_code == 201
        assert not expired.exists()
        quota = client.post("/api/v1/uploads", files={"file": ("other.py", b"x" * 200)})
        assert quota.status_code == 413
        assert not list(settings.upload_root.glob(".upload-*"))
        assert client.post("/api/v1/uploads", files={"file": ("CON.txt", b"x")}).status_code == 400
        assert client.post("/api/v1/uploads", files={"file": ("bad\\name.py", b"x")}).status_code == 400


def test_task_conflict_pagination_and_openapi_security(settings) -> None:
    settings.runtime_role = "api"
    with TestClient(create_app(settings), base_url="http://127.0.0.1") as client:
        first = client.post(
            "/api/v1/tasks",
            json={"client_request_id": "duplicate-key", "objective": "audit first project"},
        )
        assert first.status_code == 202
        conflict = client.post(
            "/api/v1/tasks",
            json={"client_request_id": "duplicate-key", "objective": "audit another project"},
        )
        assert conflict.status_code == 409
        client.post("/api/v1/tasks", json={"objective": "audit second project"})
        page = client.get("/api/v1/runs?limit=1").json()
        assert len(page["items"]) == 1
        assert page["has_more"] is True
        assert page["next_offset"] == 1
        schema = client.get("/openapi.json").json()
        assert schema["components"]["securitySchemes"]["OperatorBearer"]["scheme"] == "bearer"
        assert schema["paths"]["/api/v1/tasks"]["post"]["security"] == [{"OperatorBearer": []}]


def test_production_bearer_and_websocket_origin_are_fail_closed(tmp_path) -> None:
    operator_token = uuid4().hex
    settings = Settings(
        env="production",
        operator_token=operator_token,
        allowed_websocket_origins="https://workbench.example",
        database_url=f"sqlite:///{(tmp_path / 'strict.db').as_posix()}",
        input_root=tmp_path / "inputs",
        upload_root=tmp_path / "uploads",
        run_root=tmp_path / "runs",
        artifact_root=tmp_path / "artifacts",
    )
    app = create_app(settings)

    @asynccontextmanager
    async def no_runtime(_app):
        yield

    app.router.lifespan_context = no_runtime
    with TestClient(app, base_url="http://127.0.0.1") as client:
        unauthorized = client.get("/api/v1/tools")
        assert unauthorized.status_code == 401
        assert unauthorized.headers["www-authenticate"] == "Bearer"
        assert client.get("/api/v1/tools", headers={"Authorization": f"Basic {operator_token}"}).status_code == 401
        with pytest.raises(WebSocketDisconnect) as denied:
            with client.websocket_connect(
                "ws://127.0.0.1/api/v1/runs/unknown/events",
                headers={"Authorization": f"Bearer {operator_token}"},
            ):
                pass
        assert denied.value.code == 4403
