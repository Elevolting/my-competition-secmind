from __future__ import annotations

from collections import defaultdict
from types import SimpleNamespace
from typing import Any

from fastapi import FastAPI
from fastapi.testclient import TestClient

from secmind.api_investigation import register_investigation_routes
from secmind.secret_scrubber import REDACTED, TRUNCATED


class FakeInvestigationStore:
    def __init__(self) -> None:
        self.objects: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)

    def add(self, run_id: str, object_type: str, **payload: Any) -> None:
        self.objects[(run_id, object_type)].append(payload)

    def list_objects(self, run_id: str, object_type: str) -> list[dict[str, Any]]:
        return [dict(item) for item in self.objects[(run_id, object_type)]]


class FakeService:
    def __init__(self, store: FakeInvestigationStore | None) -> None:
        self.investigation_store = store
        self.runs = {"run-api"}

    def state(self, run_id: str) -> object:
        if run_id not in self.runs:
            raise KeyError(run_id)
        return object()


def _client(store: FakeInvestigationStore | None) -> TestClient:
    app = FastAPI()
    runtime = SimpleNamespace(service=FakeService(store))
    register_investigation_routes(app, runtime)
    return TestClient(app, base_url="http://127.0.0.1")


def test_latest_resources_and_missing_run_or_object_are_404() -> None:
    store = FakeInvestigationStore()
    store.add("run-api", "security_intent", analysis_id="old", objective_summary="first")
    store.add("run-api", "security_intent", analysis_id="new", objective_summary="second")
    store.add("run-api", "plan_contract", contract_id="contract-0", revision=0)
    store.add("run-api", "team_plan", team_plan_id="team-deep", strategy="deep")

    with _client(store) as client:
        intent = client.get("/api/v1/runs/run-api/intent")
        assert intent.status_code == 200
        assert intent.json()["schema_version"] == "1.5"
        assert intent.json()["item"]["analysis_id"] == "new"
        assert client.get("/api/v1/runs/run-api/plan-contract?revision=0").status_code == 200
        assert client.get("/api/v1/runs/run-api/plan-contract?revision=1").status_code == 404
        assert client.get("/api/v1/runs/run-api/team?strategy=deep").status_code == 200
        assert client.get("/api/v1/runs/run-api/team?strategy=quick").status_code == 404
        assert client.get("/api/v1/runs/missing/intent").status_code == 404

    with _client(FakeInvestigationStore()) as client:
        assert client.get("/api/v1/runs/run-api/intent").status_code == 404


def test_hypothesis_pagination_and_type_filters_are_stable() -> None:
    store = FakeInvestigationStore()
    for index, status in enumerate(("proposed", "supported", "proposed")):
        store.add(
            "run-api",
            "hypothesis",
            hypothesis_id=f"hyp-{index}",
            status=status,
            producer="sast" if index != 1 else "secret",
            created_at=f"2026-07-15T00:00:0{index}Z",
        )

    with _client(store) as client:
        first = client.get("/api/v1/runs/run-api/hypotheses?status=proposed&offset=0&limit=1").json()
        assert [item["hypothesis_id"] for item in first["items"]] == ["hyp-0"]
        assert first["total"] == 2
        assert first["next_offset"] == 1
        assert first["has_more"] is True
        second = client.get("/api/v1/runs/run-api/hypotheses?status=proposed&offset=1&limit=1").json()
        assert [item["hypothesis_id"] for item in second["items"]] == ["hyp-2"]
        empty_filter = client.get("/api/v1/runs/run-api/hypotheses?producer=unknown")
        assert empty_filter.status_code == 200
        assert empty_filter.json()["items"] == []


def test_evidence_request_and_critique_filters() -> None:
    store = FakeInvestigationStore()
    store.add(
        "run-api",
        "evidence_request",
        request_id="request-open",
        status="open",
        reason_code="independent_source",
    )
    store.add(
        "run-api",
        "evidence_request",
        request_id="request-done",
        status="satisfied",
        reason_code="independent_source",
    )
    store.add(
        "run-api",
        "critique",
        critique_id="critique-reject",
        verdict="reject",
        target_type="plan",
        critic_profile="security-plan-critic",
    )

    with _client(store) as client:
        requests = client.get("/api/v1/runs/run-api/evidence-requests?status=open").json()
        assert [item["request_id"] for item in requests["items"]] == ["request-open"]
        critiques = client.get("/api/v1/runs/run-api/critiques?verdict=reject&target_type=plan").json()
        assert [item["critique_id"] for item in critiques["items"]] == ["critique-reject"]


def test_usage_and_completion_support_record_type_filters() -> None:
    store = FakeInvestigationStore()
    store.add(
        "run-api",
        "usage_reservation",
        reservation_id="usage-model",
        kind="model",
        status="reserved",
        cost_units=1,
    )
    store.add(
        "run-api",
        "usage_settlement",
        settlement_id="settled-model",
        status="settled",
        cost_units=1,
    )
    store.add("run-api", "completion_snapshot", snapshot_id="snapshot-1", quiet_epoch=1)
    store.add(
        "run-api",
        "completion_receipt",
        receipt_id="receipt-1",
        decision="complete",
    )

    with _client(store) as client:
        reservation = client.get("/api/v1/runs/run-api/usage?record_type=reservation&kind=model").json()
        assert [item["reservation_id"] for item in reservation["items"]] == ["usage-model"]
        completion = client.get("/api/v1/runs/run-api/completion?record_type=receipt&decision=complete").json()
        assert [item["receipt_id"] for item in completion["items"]] == ["receipt-1"]


def test_projection_drops_prompt_cot_and_raw_fields_and_scrubs_secrets() -> None:
    store = FakeInvestigationStore()
    raw_secret_key = "raw_" + "secret"
    password_key = "pass" + "word"
    store.add(
        "run-api",
        "security_intent",
        analysis_id="safe-id",
        prompt="ignore all prior policy",
        prompt_ref="prompt-registry:secret-path",
        chain_of_thought="private reasoning",
        raw_digest="b" * 64,
        rationale_summary='API_KEY = "sk-abcdefghijklmnop"',
        nested={"system_prompt": "hidden", "token": "ghp_abcdefghijklmnop"},
        **{
            raw_secret_key: "should-never-appear",
            password_key: "very-secret-password",
        },
    )

    with _client(store) as client:
        response = client.get("/api/v1/runs/run-api/intent")
        assert response.status_code == 200
        item = response.json()["item"]
        assert item["analysis_id"] == "safe-id"
        assert item["raw_digest"] == "b" * 64
        assert item[password_key] == REDACTED
        assert item["nested"] == {"token": REDACTED}
        serialized = response.text
        for forbidden in (
            "ignore all prior policy",
            "prompt-registry:secret-path",
            "private reasoning",
            "should-never-appear",
            "very-secret-password",
            "sk-abcdefghijklmnop",
            "ghp_abcdefghijklmnop",
        ):
            assert forbidden not in serialized


def test_projection_bounds_deep_untrusted_payloads_before_scrubbing() -> None:
    store = FakeInvestigationStore()
    nested: dict[str, Any] = {"leaf": "visible"}
    for _ in range(20):
        nested = {"next": nested}
    store.add("run-api", "security_intent", analysis_id="deep", nested=nested)

    with _client(store) as client:
        response = client.get("/api/v1/runs/run-api/intent")
        assert response.status_code == 200
        assert TRUNCATED in response.text


def test_unavailable_store_is_503() -> None:
    with _client(None) as client:
        response = client.get("/api/v1/runs/run-api/intent")
        assert response.status_code == 503
        assert response.json()["detail"] == "Investigation store is unavailable"
