"""Dependency contracts exercised through the authenticated Runtime API."""

import importlib

import pytest
from tests.test_server_api import client as runtime_client

from tests.test_workbench_planning import decision, project

client = runtime_client
TOKEN = {"X-Security-Runtime-Token": "test-planning-token"}


def step(key, dependencies=None, outputs=None):
    return {
        "from": ["origin"],
        "step_id": key,
        "depends_on": dependencies or [],
        "required_outputs": outputs or {},
        "description": f"perform {key}",
        "title": key,
        "verification_target": key,
        "success_criteria": ["save evidence"],
    }


def apply(client, pid, key, proposals):
    body = decision(client, pid, key, intents=proposals)
    response = client.post(f"/projects/{pid}/planning/decisions", json=body, headers=TOKEN)
    return response, body


def claim(client, pid, iid, attempt=None):
    return client.post(
        f"/projects/{pid}/intents/{iid}/heartbeat", json={"worker": "worker", "claim": True, "attempt_id": attempt}
    )


def conclude(client, pid, iid, attempt, *, output=None, outcome="observed"):
    items = (
        [
            {
                "type": "artifact",
                "title": output,
                "summary": "recorded",
                "output_key": output,
                "outcome": outcome,
                "evidence_ids": ["receipt-1"],
            }
        ]
        if output
        else []
    )
    return client.post(
        f"/projects/{pid}/intents/{iid}/conclude",
        json={"worker": "worker", "attempt_id": attempt, "description": "step result", "items": items},
    )


def test_serial_chain_blocks_claim_before_predecessor_finishes(client, monkeypatch):
    monkeypatch.setenv("SECURITY_RUNTIME_CALLBACK_TOKEN", "test-planning-token")
    pid, _ = project(client)
    response, _ = apply(client, pid, "decision-chain", [step("A"), step("B", ["A"]), step("C", ["B"])])
    assert response.status_code == 200, response.text
    a, b, c = response.json()["intent_ids"]
    assert claim(client, pid, b).status_code == 409
    assert claim(client, pid, c).status_code == 409
    assert claim(client, pid, a).status_code == 200


@pytest.mark.parametrize(
    "proposals",
    [
        [step("A", ["missing"])],
        [step("A", ["A"])],
        [step("A", ["B"]), step("B", ["A"])],
        [step("A"), step("A")],
        [step("A"), step("B", ["A"], {"other": ["session"]})],
    ],
)
def test_invalid_dependency_graph_is_rejected_atomically(client, monkeypatch, proposals):
    monkeypatch.setenv("SECURITY_RUNTIME_CALLBACK_TOKEN", "test-planning-token")
    pid, _ = project(client)
    response, _ = apply(client, pid, "decision-invalid-graph", proposals)
    assert response.status_code == 422, response.text
    assert client.get(f"/projects/{pid}").json()["intents"] == []


def test_serial_chain_requires_confirmed_outputs_and_inherits_sources(client, monkeypatch):
    monkeypatch.setenv("SECURITY_RUNTIME_CALLBACK_TOKEN", "test-planning-token")
    pid, _ = project(client)
    response, _ = apply(
        client,
        pid,
        "decision-chain",
        [step("A"), step("B", ["A"], {"A": ["session"]}), step("C", ["B"], {"B": ["report"]})],
    )
    assert response.status_code == 200, response.text
    a, b, c = response.json()["intent_ids"]
    assert claim(client, pid, b).status_code == 409

    attempt_a = claim(client, pid, a).json()["attempt_id"]
    fact_a = conclude(client, pid, a, attempt_a, output="session").json()["fact"]["id"]
    assert claim(client, pid, b).status_code == 409
    detail = client.get(f"/projects/{pid}").json()
    assert "missing verified outputs session" in detail["intents"][1]["blocked_reasons"][0]
    confirm = decision(client, pid, "decision-confirm-a", validated_outputs={"A": ["session"]})
    assert client.post(f"/projects/{pid}/planning/decisions", json=confirm, headers=TOKEN).status_code == 200
    assert claim(client, pid, c).status_code == 409
    attempt_b = claim(client, pid, b).json()["attempt_id"]
    assert fact_a in client.get(f"/projects/{pid}").json()["intents"][1]["from"]
    fact_b = conclude(client, pid, b, attempt_b, output="report").json()["fact"]["id"]
    assert claim(client, pid, c).status_code == 409
    confirm = decision(client, pid, "decision-confirm-b", validated_outputs={"B": ["report"]})
    assert client.post(f"/projects/{pid}/planning/decisions", json=confirm, headers=TOKEN).status_code == 200
    assert claim(client, pid, c).status_code == 200
    assert fact_b in client.get(f"/projects/{pid}").json()["intents"][2]["from"]


def test_independent_branch_proceeds_while_other_branch_lacks_output(client, monkeypatch):
    monkeypatch.setenv("SECURITY_RUNTIME_CALLBACK_TOKEN", "test-planning-token")
    pid, _ = project(client)
    response, _ = apply(
        client, pid, "decision-branches", [step("A"), step("B", ["A"], {"A": ["session"]}), step("X"), step("Y", ["X"])]
    )
    assert response.status_code == 200, response.text
    a, b, x, y = response.json()["intent_ids"]
    assert claim(client, pid, b).status_code == 409
    assert claim(client, pid, y).status_code == 409
    attempt_x = claim(client, pid, x).json()["attempt_id"]
    assert conclude(client, pid, x, attempt_x).status_code == 200
    assert claim(client, pid, y).status_code == 200
    attempt_a = claim(client, pid, a).json()["attempt_id"]
    assert conclude(client, pid, a, attempt_a, output="session", outcome="negative").status_code == 200
    confirm = decision(client, pid, "decision-negative", validated_outputs={"A": ["session"]})
    assert client.post(f"/projects/{pid}/planning/decisions", json=confirm, headers=TOKEN).status_code == 422
    assert claim(client, pid, b).status_code == 409


def test_approval_wait_blocks_only_its_dependent_branch(client, monkeypatch):
    monkeypatch.setenv("SECURITY_RUNTIME_CALLBACK_TOKEN", "test-planning-token")
    pid, _ = project(client)
    response, _ = apply(
        client, pid, "decision-approval", [step("A"), step("B", ["A"]), step("X"), step("Y", ["X"])]
    )
    assert response.status_code == 200, response.text
    a, b, x, y = response.json()["intent_ids"]
    attempt = claim(client, pid, a).json()["attempt_id"]
    waiting = client.post(
        f"/projects/{pid}/intents/{a}/stage",
        json={"worker": "worker", "attempt_id": attempt, "phase": "等待工具审批", "status": "approval"},
    )
    assert waiting.status_code == 200 and waiting.json()["execution_status"] == "approval"
    assert claim(client, pid, b).status_code == 409
    assert "approval" in client.get(f"/projects/{pid}").json()["intents"][1]["blocked_reasons"][0]
    other_attempt = claim(client, pid, x).json()["attempt_id"]
    assert conclude(client, pid, x, other_attempt).status_code == 200
    assert claim(client, pid, y).status_code == 200
    assert conclude(client, pid, a, attempt).status_code == 200
    assert claim(client, pid, b).status_code == 200


@pytest.mark.parametrize("outcome", ["failed", "timeout"])
def test_failed_step_needs_explicit_retry_and_old_attempt_cannot_unlock(client, monkeypatch, outcome):
    monkeypatch.setenv("SECURITY_RUNTIME_CALLBACK_TOKEN", "test-planning-token")
    pid, _ = project(client)
    response, _ = apply(client, pid, "decision-retry-chain", [step("A"), step("B", ["A"])])
    a, b = response.json()["intent_ids"]
    first = claim(client, pid, a).json()["attempt_id"]
    assert (
        client.post(
            f"/projects/{pid}/intents/{a}/release", json={"worker": "worker", "attempt_id": first, "outcome": outcome}
        ).status_code
        == 200
    )
    assert claim(client, pid, a).status_code == 409
    assert claim(client, pid, b).status_code == 409
    retry = step("A") | {"retry_intent_id": a}
    response, _ = apply(client, pid, "decision-retry-a", [retry])
    assert response.status_code == 200, response.text
    second = claim(client, pid, a, first).json()["attempt_id"]
    assert second != first
    assert conclude(client, pid, a, first).status_code == 409
    assert claim(client, pid, b).status_code == 409
    assert conclude(client, pid, a, second).status_code == 200
    assert claim(client, pid, b).status_code == 200


def test_pending_dependencies_survive_database_reopen_and_project_stop(client, monkeypatch):
    from fastapi.testclient import TestClient
    from security_runtime.server import db

    app_module = importlib.import_module("security_runtime.server.app")
    original_app = app_module.app

    monkeypatch.setenv("SECURITY_RUNTIME_CALLBACK_TOKEN", "test-planning-token")
    pid, _ = project(client)
    response, body = apply(client, pid, "decision-reopen", [step("A"), step("B", ["A"])])
    a, b = response.json()["intent_ids"]
    path = db._db_path
    monkeypatch.setattr(db, "_db_path", None)
    db.configure(path)
    rebuilt_app = importlib.reload(app_module).app
    assert rebuilt_app is not original_app
    with TestClient(rebuilt_app, base_url="http://127.0.0.1") as reopened:
        assert (
            reopened.post(f"/projects/{pid}/planning/decisions", json=body, headers=TOKEN).json()["status"]
            == "replayed"
        )
        assert (
            reopened.post(
                f"/projects/{pid}/intents/{b}/heartbeat", json={"worker": "worker", "claim": True}
            ).status_code
            == 409
        )
        assert reopened.get(f"/projects/{pid}").json()["intents"][1]["depends_on"] == ["A"]
        assert reopened.put(f"/projects/{pid}/status", json={"status": "stopped"}).status_code == 200
        assert (
            reopened.post(
                f"/projects/{pid}/intents/{a}/heartbeat", json={"worker": "worker", "claim": True}
            ).status_code
            == 403
        )


def test_running_and_completed_chain_survive_service_and_scheduler_rebuild(client, monkeypatch, tmp_path):
    import yaml
    from conftest import make_config
    from fastapi.testclient import TestClient
    from security_runtime.dispatcher.models import ReasonCheckpoint
    from security_runtime.dispatcher.scheduler.loop import DispatcherLoop
    from security_runtime.server import db
    from security_runtime.server.models import ProjectDetail, ProjectSummary

    monkeypatch.setenv("SECURITY_RUNTIME_CALLBACK_TOKEN", "test-planning-token")
    pid, _ = project(client)
    response, body = apply(
        client, pid, "decision-rebuild", [step("A"), step("B", ["A"], {"A": ["session"]}), step("C", ["B"])]
    )
    a, b, c = response.json()["intent_ids"]
    attempt = claim(client, pid, a).json()["attempt_id"]
    path = db._db_path
    config_path = tmp_path / "dispatcher.yaml"
    config_path.write_text(yaml.safe_dump(make_config().model_dump(mode="json")), encoding="utf-8")

    def rebuild():
        monkeypatch.setattr(db, "_db_path", None)
        db.configure(path)
        return TestClient(
            importlib.reload(importlib.import_module("security_runtime.server.app")).app, base_url="http://127.0.0.1"
        )

    with rebuild() as reopened:
        assert (
            reopened.post(f"/projects/{pid}/planning/decisions", json=body, headers=TOKEN).json()["status"]
            == "replayed"
        )
        detail = reopened.get(f"/projects/{pid}").json()
        assert detail["intents"][0]["attempt_id"] == attempt
        assert claim(reopened, pid, b).status_code == 409
        assert (
            reopened.post(
                f"/projects/{pid}/intents/{a}/heartbeat", json={"worker": "other-worker", "claim": True}
            ).status_code
            == 409
        )
        loop = DispatcherLoop(config_path)
        try:
            loop.client.get_project = lambda _: ProjectDetail.model_validate(reopened.get(f"/projects/{pid}").json())
            snapshot = loop.client.get_project(pid)
            loop.reason_checkpoints[pid] = ReasonCheckpoint(
                fact_count=len(snapshot.facts), hint_count=len(snapshot.hints), open_intent_count=3
            )
            dispatched = []
            loop._dispatch_explore = lambda _project, _graph, intent: dispatched.append(intent.id) or True
            summary = next(
                ProjectSummary.model_validate(item) for item in reopened.get("/projects").json() if item["id"] == pid
            )
            assert not loop._try_dispatch_project(summary)
            assert dispatched == []
        finally:
            loop.close()
        assert conclude(reopened, pid, a, attempt, output="session").status_code == 200
        confirmation = decision(reopened, pid, "decision-rebuild-confirm", validated_outputs={"A": ["session"]})
        # Discard the applied response, just as a network interruption would.
        assert reopened.post(f"/projects/{pid}/planning/decisions", json=confirmation, headers=TOKEN).status_code == 200

    with rebuild() as restored:
        replay = restored.post(f"/projects/{pid}/planning/decisions", json=confirmation, headers=TOKEN)
        assert replay.json()["status"] == "replayed"
        snapshot = ProjectDetail.model_validate(restored.get(f"/projects/{pid}").json())
        assert len(snapshot.intents) == 3 and snapshot.intents[0].validated_outputs == ["session"]
        assert claim(restored, pid, a).status_code == 409
        loop = DispatcherLoop(config_path)
        try:
            loop.client.get_project = lambda _: snapshot
            loop.client.export_project = lambda _: "fixture graph"
            loop.reason_checkpoints[pid] = ReasonCheckpoint(
                fact_count=len(snapshot.facts), hint_count=len(snapshot.hints), open_intent_count=2
            )
            dispatched = []
            loop._dispatch_explore = lambda _project, _graph, intent: dispatched.append(intent.id) or True
            summary = next(
                ProjectSummary.model_validate(item) for item in restored.get("/projects").json() if item["id"] == pid
            )
            assert loop._try_dispatch_project(summary) and dispatched == [b]
        finally:
            loop.close()
        attempt_b = claim(restored, pid, b).json()["attempt_id"]
        assert conclude(restored, pid, b, attempt_b).status_code == 200
        assert claim(restored, pid, c).status_code == 200


def test_cancelled_upstream_does_not_restart_and_independent_branch_continues(client, monkeypatch):
    monkeypatch.setenv("SECURITY_RUNTIME_CALLBACK_TOKEN", "test-planning-token")
    pid, _ = project(client)
    response, _ = apply(client, pid, "decision-cancel", [step("A"), step("B", ["A"]), step("X")])
    a, b, x = response.json()["intent_ids"]
    attempt = claim(client, pid, a).json()["attempt_id"]
    assert (
        client.post(
            f"/projects/{pid}/intents/{a}/release",
            json={"worker": "worker", "attempt_id": attempt, "outcome": "cancelled"},
        ).status_code
        == 200
    )
    assert claim(client, pid, a).status_code == 409
    assert claim(client, pid, b).status_code == 409
    assert "cancelled" in client.get(f"/projects/{pid}").json()["intents"][1]["blocked_reasons"][0]
    assert claim(client, pid, x).status_code == 200
    assert conclude(client, pid, a, attempt).status_code == 409


@pytest.mark.parametrize("outcome,evidence", [("observed", []), ("negative", ["receipt"])])
def test_unobserved_or_unevidenced_output_cannot_be_confirmed(client, monkeypatch, outcome, evidence):
    monkeypatch.setenv("SECURITY_RUNTIME_CALLBACK_TOKEN", "test-planning-token")
    pid, _ = project(client)
    response, _ = apply(client, pid, "decision-no-output", [step("A"), step("B", ["A"], {"A": ["session"]})])
    a, b = response.json()["intent_ids"]
    attempt = claim(client, pid, a).json()["attempt_id"]
    assert (
        client.post(
            f"/projects/{pid}/intents/{a}/conclude",
            json={
                "worker": "worker",
                "attempt_id": attempt,
                "description": "result",
                "items": [
                    {
                        "type": "artifact",
                        "title": "session",
                        "summary": "result",
                        "output_key": "session",
                        "outcome": outcome,
                        "evidence_ids": evidence,
                    }
                ],
            },
        ).status_code
        == 200
    )
    body = decision(client, pid, "decision-bad-output", validated_outputs={"A": ["session"]})
    assert client.post(f"/projects/{pid}/planning/decisions", json=body, headers=TOKEN).status_code == 422
    assert claim(client, pid, b).status_code == 409


def test_output_confirmation_rolls_back_if_later_direction_is_invalid(client, monkeypatch):
    monkeypatch.setenv("SECURITY_RUNTIME_CALLBACK_TOKEN", "test-planning-token")
    pid, _ = project(client)
    response, _ = apply(client, pid, "decision-atomic", [step("A"), step("B", ["A"], {"A": ["session"]})])
    a, b = response.json()["intent_ids"]
    attempt = claim(client, pid, a).json()["attempt_id"]
    assert conclude(client, pid, a, attempt, output="session").status_code == 200
    bad = step("X") | {"from": ["foreign-fact"]}
    body = decision(client, pid, "decision-rollback", validated_outputs={"A": ["session"]}, intents=[bad])
    assert client.post(f"/projects/{pid}/planning/decisions", json=body, headers=TOKEN).status_code == 404
    detail = client.get(f"/projects/{pid}").json()
    assert len(detail["intents"]) == 2 and detail["intents"][0]["validated_outputs"] == []
    assert claim(client, pid, b).status_code == 409
    body["intents"] = [step("X")]
    assert client.post(f"/projects/{pid}/planning/decisions", json=body, headers=TOKEN).status_code == 200
    assert claim(client, pid, b).status_code == 200


def test_foreign_project_step_and_confirmation_are_rejected(client, monkeypatch):
    monkeypatch.setenv("SECURITY_RUNTIME_CALLBACK_TOKEN", "test-planning-token")
    pid, _ = project(client)
    response, _ = apply(client, pid, "decision-source", [step("A")])
    a = response.json()["intent_ids"][0]
    attempt = claim(client, pid, a).json()["attempt_id"]
    assert conclude(client, pid, a, attempt, output="session").status_code == 200
    other = client.post(
        "/projects",
        json={
            "title": "another",
            "origin": "start",
            "goal": "finish",
            "bootstrap_enabled": False,
            "hints": [{"creator": "unified-workbench", "content": "workbench_planner:run_id=another;schema=1.1"}],
        },
    ).json()["project"]["id"]
    response, _ = apply(client, other, "decision-cross-step", [step("B", ["A"])])
    assert response.status_code == 422
    body = decision(client, other, "decision-cross-output", validated_outputs={"A": ["session"]})
    assert client.post(f"/projects/{other}/planning/decisions", json=body, headers=TOKEN).status_code == 422
    assert client.get(f"/projects/{other}").json()["intents"] == []
