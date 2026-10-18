from __future__ import annotations

from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

from secmind.api_runs import register_run_routes
from secmind.config import Settings
from secmind.schemas import AgentReport, RunStatus, SealedAdmissionSnapshot
from secmind.secret_scrubber import REDACTED


def _runtime(exact_value: str) -> SimpleNamespace:
    report = AgentReport(
        run_id="run-exact-boundary",
        status=RunStatus.COMPLETED,
        executive_summary="sealed exact answer",
        answer_type="exact",
        answer_payload={"answer_kind": "exact", "values": [exact_value]},
    )
    snapshot = SealedAdmissionSnapshot(
        snapshot_id="admission-snapshot-" + "a" * 64,
        run_id=report.run_id,
        final_semantic_digest="b" * 64,
        report_integrity_digest="c" * 64,
        report=report,
    )
    return SimpleNamespace(
        service=SimpleNamespace(
            public_report=lambda run_id: report,
            public_admission_snapshot=lambda run_id: snapshot,
        )
    )


def test_ordinary_report_and_admission_redact_exact_values_but_bridge_release_is_attested() -> None:
    exact_value = "opaque-exact-answer-9f1c2a7b3d4e5f6g"
    settings = Settings()
    settings.evaluation_bridge_token = "-".join(("bridge", "only", "token"))
    app = FastAPI()
    register_run_routes(app, _runtime(exact_value), settings)

    with TestClient(app, base_url="http://127.0.0.1") as client:
        report = client.get("/api/v1/runs/run-exact-boundary/report")
        assert report.status_code == 200
        assert report.json()["answer_payload"]["values"] == [REDACTED]

        admission = client.get("/api/v1/runs/run-exact-boundary/admission")
        assert admission.status_code == 200
        assert admission.json()["report"]["answer_payload"]["values"] == [REDACTED]

        assert client.get("/api/v1/runs/run-exact-boundary/report?audience=evaluation").status_code == 403
        headers = {"X-SecMind-Evaluation-Bridge": settings.evaluation_bridge_token}
        released = client.get("/api/v1/runs/run-exact-boundary/report?audience=evaluation", headers=headers)
        assert released.status_code == 200
        assert released.json()["answer_payload"]["values"] == [exact_value]
        released_admission = client.get(
            "/api/v1/runs/run-exact-boundary/admission?audience=evaluation",
            headers=headers,
        )
        assert released_admission.status_code == 200
        assert released_admission.json()["report"]["answer_payload"]["values"] == [exact_value]
