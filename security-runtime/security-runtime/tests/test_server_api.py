from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from security_runtime.server import db
from security_runtime.server.app import app


@pytest.fixture
def client(tmp_path, monkeypatch) -> TestClient:
    monkeypatch.setattr(db, "_db_path", None)
    db.configure(tmp_path / "security_runtime.db")
    with TestClient(app, base_url="http://127.0.0.1") as test_client:
        yield test_client


def _create_project(client: TestClient) -> str:
    response = client.post(
        "/projects",
        json={
            "title": "test",
            "origin": "starting point",
            "goal": "finish",
            "hints": [{"content": "initial clue", "creator": "human"}],
        },
    )
    assert response.status_code == 201
    assert response.json()["project"]["bootstrap_enabled"] is True
    return response.json()["project"]["id"]


def test_browser_boundary_rejects_foreign_host_and_writes(client: TestClient) -> None:
    assert client.get("/projects", headers={"Host": "attacker.example"}).status_code == 400
    before = client.get("/projects").json()
    payload = {"title": "blocked", "origin": "start", "goal": "finish"}
    for origin in ("https://attacker.example", "null", "http://localhost.attacker.example:8000"):
        assert client.post("/projects", json=payload, headers={"Origin": origin}).status_code == 403
    assert client.get("/projects").json() == before
    # Machine clients omit Origin; browser clients use the exact local origin.
    payload["title"] = "accepted"
    assert client.post("/projects", json=payload, headers={"Origin": "http://127.0.0.1"}).status_code == 201


def test_project_workflow_create_conclude_complete_and_reopen(client: TestClient) -> None:
    project_id = _create_project(client)

    response = client.post(
        f"/projects/{project_id}/intents",
        json={"from": ["origin"], "description": "investigate", "creator": "reasoner", "worker": None},
    )
    assert response.status_code == 201
    assert response.json()["id"] == "i001"

    response = client.post(
        f"/projects/{project_id}/intents/i001/heartbeat",
        json={"worker": "explorer"},
    )
    assert response.status_code == 200
    assert response.json()["worker"] == "explorer"

    response = client.post(
        f"/projects/{project_id}/intents/i001/conclude",
        json={"worker": "explorer", "description": "new fact"},
    )
    assert response.status_code == 200
    assert response.json()["fact"] == {"id": "f001", "description": "new fact"}

    response = client.post(
        f"/projects/{project_id}/complete",
        json={"from": ["f001"], "description": "solved", "worker": "reasoner"},
    )
    assert response.status_code == 200
    assert response.json()["to"] == "goal"

    response = client.post(
        f"/projects/{project_id}/reopen",
        json={"description": "human correction", "creator": "human"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["project"]["status"] == "active"
    assert payload["fact"] == {"id": "f002", "description": "human correction"}
    assert payload["intent"]["from"] == ["f001"]
    assert payload["intent"]["to"] == "f002"


def test_stopping_project_releases_claims_and_reason_but_keeps_hints_writable(client: TestClient) -> None:
    project_id = _create_project(client)
    client.post(
        f"/projects/{project_id}/intents",
        json={"from": ["origin"], "description": "work", "creator": "worker-a", "worker": "worker-a"},
    )
    client.post(
        f"/projects/{project_id}/reason/claim",
        json={"worker": "worker-b", "trigger": "facts:2->3"},
    )

    response = client.put(f"/projects/{project_id}/status", json={"status": "stopped"})
    assert response.status_code == 200
    assert response.json()["reason"] is None

    detail = client.get(f"/projects/{project_id}").json()
    assert detail["intents"][0]["worker"] is None
    assert client.post(
        f"/projects/{project_id}/hints",
        json={"content": "manual note", "creator": "human"},
    ).status_code == 201
    assert client.post(
        f"/projects/{project_id}/intents",
        json={"from": ["origin"], "description": "blocked", "creator": "reasoner", "worker": None},
    ).status_code == 403


def test_intent_creation_rejects_goal_source_and_mismatched_initial_worker(client: TestClient) -> None:
    project_id = _create_project(client)

    assert client.post(
        f"/projects/{project_id}/intents",
        json={"from": ["goal"], "description": "invalid", "creator": "reasoner", "worker": None},
    ).status_code == 400
    assert client.post(
        f"/projects/{project_id}/intents",
        json={"from": ["origin"], "description": "invalid", "creator": "reasoner", "worker": "explorer"},
    ).status_code == 400


def test_settings_and_export_are_backed_by_the_same_database(client: TestClient) -> None:
    project_id = _create_project(client)

    response = client.put("/settings", json={"intent_timeout": 30, "reason_timeout": 45})
    assert response.status_code == 200
    assert client.get("/settings").json() == {"intent_timeout": 30, "reason_timeout": 45}

    exported = client.get(f"/projects/{project_id}/export?format=yaml")
    assert exported.status_code == 200
    assert "origin: starting point" in exported.text
    assert "goal: finish" in exported.text
    assert client.get(f"/projects/{project_id}/export?format=invalid").status_code == 400


def test_expired_intent_and_reason_leases_can_be_reclaimed(client: TestClient) -> None:
    project_id = _create_project(client)
    client.post(
        f"/projects/{project_id}/intents",
        json={"from": ["origin"], "description": "work", "creator": "worker-a", "worker": "worker-a"},
    )
    client.post(
        f"/projects/{project_id}/reason/claim",
        json={"worker": "worker-a", "trigger": "bootstrap"},
    )
    with db.get_conn() as conn:
        conn.execute(
            "UPDATE intents SET last_heartbeat_at = '2000-01-01T00:00:00Z' WHERE project_id = ?",
            (project_id,),
        )
        conn.execute(
            "UPDATE projects SET reason_last_heartbeat_at = '2000-01-01T00:00:00Z' WHERE id = ?",
            (project_id,),
        )

    response = client.post(
        f"/projects/{project_id}/intents/i001/heartbeat",
        json={"worker": "worker-b"},
    )
    assert response.status_code == 200
    assert response.json()["worker"] == "worker-b"

    response = client.post(
        f"/projects/{project_id}/reason/claim",
        json={"worker": "worker-b", "trigger": "facts:2->3"},
    )
    assert response.status_code == 200
    assert response.json()["reason"]["worker"] == "worker-b"


def test_live_reason_lease_rejects_competing_worker(client: TestClient) -> None:
    project_id = _create_project(client)
    assert client.post(
        f"/projects/{project_id}/reason/claim",
        json={"worker": "worker-a", "trigger": "bootstrap"},
    ).status_code == 200

    response = client.post(
        f"/projects/{project_id}/reason/claim",
        json={"worker": "worker-b", "trigger": "facts:2->3"},
    )

    assert response.status_code == 409
    assert "worker-a" in response.json()["detail"]


def test_project_creation_persists_disabled_bootstrap_and_exports_it(client: TestClient) -> None:
    response = client.post(
        "/projects",
        json={
            "title": "no bootstrap",
            "origin": "start",
            "goal": "finish",
            "bootstrap_enabled": False,
        },
    )

    assert response.status_code == 201
    project_id = response.json()["project"]["id"]
    assert client.get(f"/projects/{project_id}").json()["project"]["bootstrap_enabled"] is False
    assert "bootstrap_enabled: false" in client.get(f"/projects/{project_id}/export?format=yaml").text


def test_external_project_does_not_enter_dispatcher_queue(client: TestClient) -> None:
    response = client.post(
        "/projects",
        json={
            "title": "external workbench",
            "origin": "start",
            "goal": "finish",
            "bootstrap_enabled": False,
            "dispatcher_enabled": False,
        },
    )
    assert response.status_code == 201
    project_id = response.json()["project"]["id"]
    assert response.json()["project"]["dispatcher_enabled"] is False
    assert client.get(f"/projects/{project_id}").json()["project"]["dispatcher_enabled"] is False
    assert next(item for item in client.get("/projects").json() if item["id"] == project_id)[
        "dispatcher_enabled"
    ] is False
    assert "dispatcher_enabled: false" in client.get(
        f"/projects/{project_id}/export?format=yaml"
    ).text


def test_dispatcher_activation_requires_active_matching_project(client: TestClient) -> None:
    response = client.post("/projects", json={
        "title": "sec-task-approved", "origin": "start", "goal": "finish",
        "bootstrap_enabled": False, "dispatcher_enabled": False,
        "dispatcher_activation_token": "t" * 32,
    })
    project_id = response.json()["project"]["id"]
    path = f"/projects/{project_id}/dispatcher/activate"
    assert client.post(path, json={"title": "wrong-task", "activation_token": "t" * 32}).status_code == 409
    assert client.get(f"/projects/{project_id}").json()["project"]["dispatcher_enabled"] is False
    activated = client.post(path, json={"title": "sec-task-approved", "activation_token": "t" * 32})
    assert activated.status_code == 200
    assert activated.json()["dispatcher_enabled"] is True
    assert client.post(path, json={"title": "sec-task-approved", "activation_token": "t" * 32}).json() == activated.json()
    assert client.post(path, json={"title": "sec-task-approved"}).json() == activated.json()
    assert client.put(f"/projects/{project_id}/status", json={"status": "stopped"}).status_code == 200
    assert client.post(path, json={"title": "sec-task-approved", "activation_token": "t" * 32}).status_code == 409


def test_dispatcher_activation_without_bound_credential_is_rejected(client: TestClient) -> None:
    response = client.post("/projects", json={
        "title": "sec-task-unbound", "origin": "start", "goal": "finish",
        "bootstrap_enabled": False, "dispatcher_enabled": False,
    })
    project_id = response.json()["project"]["id"]
    response = client.post(
        f"/projects/{project_id}/dispatcher/activate",
        json={"title": "sec-task-unbound", "activation_token": "t" * 32},
    )
    assert response.status_code == 403
    assert client.get(f"/projects/{project_id}").json()["project"]["dispatcher_enabled"] is False


def test_project_creation_rejects_invalid_bootstrap_enabled(client: TestClient) -> None:
    response = client.post(
        "/projects",
        json={
            "title": "invalid bootstrap",
            "origin": "start",
            "goal": "finish",
            "bootstrap_enabled": "sometimes",
        },
    )

    assert response.status_code == 422
