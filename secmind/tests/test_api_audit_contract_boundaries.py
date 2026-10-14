from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

from fastapi import FastAPI
from fastapi.testclient import TestClient

from secmind.api_audit import register_audit_routes
from secmind.audit_kernel.patch_release import PatchIdentity, PatchReleaseRecord, PatchReleaseStatus
from secmind.audit_kernel.persistence import AuditPersistenceConflict


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _release(status: PatchReleaseStatus = PatchReleaseStatus.SHADOW) -> PatchReleaseRecord:
    identity = PatchIdentity.create(
        target_profile_digest=_digest("profile"),
        cwe=89,
        patch_kind="source-to-sink-addition",
        tool_name="semantic-sast",
        tool_version="1.0.0",
        rule_bundle_digest=_digest("rules"),
        parser_name="tree-sitter",
        parser_digest=_digest("parser"),
        critic_prompt_version="critic-v1",
        critic_model_policy_digest=_digest("policy"),
    )
    return PatchReleaseRecord.create(
        identity=identity,
        status=status,
        evaluation_dataset_digest=_digest("dataset"),
        baseline_arm_digest=_digest("baseline"),
        candidate_arm_digest=_digest("candidate"),
        sample_size=40,
        tp_fixed=4,
        fp_introduced=0,
        fn_introduced=0,
        precision=1,
        recall=0.9,
        f1_delta=0.05,
        coverage_delta=0,
        paired_bootstrap_ci_low=0.01,
        paired_bootstrap_ci_high=0.09,
        mcnemar_p=0.03,
        approved_by=("operator:test" if status != PatchReleaseStatus.SHADOW else None),
        expires_at=datetime(2100, 1, 1, tzinfo=UTC),
    )


class Unit:
    def __init__(self, unit_id: str, *, action: str, verdict: str) -> None:
        self.unit_id = unit_id
        self.baseline_verdict = "not_vulnerable"
        self.baseline_cwe = None
        self.final_verdict = verdict
        self.cwe = 89 if verdict == "vulnerable" else None
        self.action = action

    def model_dump(self, *, mode: str) -> dict[str, Any]:
        assert mode == "json"
        return vars(self).copy()


class Kernel:
    def __init__(self) -> None:
        self.releases: list[PatchReleaseRecord] = [_release()]

    def patch_releases(self) -> list[PatchReleaseRecord]:
        return list(self.releases)

    def publish_patch_release(self, evaluation_run_id: str, release: PatchReleaseRecord) -> PatchReleaseRecord:
        if evaluation_run_id == "conflict":
            raise AuditPersistenceConflict("immutable release conflict")
        if evaluation_run_id == "invalid":
            raise ValueError("invalid evaluation")
        self.releases.append(release)
        return release

    def revoke_patch_release(self, patch_release_id: str, reason: str) -> PatchReleaseRecord:
        if patch_release_id == "missing":
            raise KeyError(patch_release_id)
        if patch_release_id == "invalid":
            raise ValueError("release cannot be revoked")
        return self.releases[0].model_copy(
            update={"revoked_at": datetime.now(UTC), "revocation_reason": reason},
        )


def _client() -> TestClient:
    states = {
        "empty": SimpleNamespace(audit_units=[], audit_kernel={}, audit_coverage={}),
        "populated": SimpleNamespace(
            audit_units=[
                Unit("unit-b", action="keep_baseline", verdict="inconclusive"),
                Unit("unit-a", action="add_finding", verdict="vulnerable"),
            ],
            audit_kernel={"status": "completed"},
            audit_coverage={"units": 2},
        ),
        "sensitive": SimpleNamespace(
            audit_units=[],
            audit_kernel={},
            audit_coverage={
                "typed_answer_runtime": {"active_answer": {"values": ["flag{X9aQ7mP2vN8rT4kL6sD3zY1wC5}"]}}
            },
        ),
    }

    class Service:
        orchestrator = SimpleNamespace(java_audit_kernel=Kernel())

        @staticmethod
        def state(run_id: str) -> Any:
            if run_id not in states:
                raise KeyError(run_id)
            return states[run_id]

    app = FastAPI()
    register_audit_routes(app, SimpleNamespace(service=Service()))  # type: ignore[arg-type]
    return TestClient(app, base_url="http://127.0.0.1")


def test_audit_routes_publish_stable_unit_and_comparative_commitments() -> None:
    with _client() as client:
        missing = client.get("/api/v1/runs/missing/units")
        assert missing.status_code == 404
        assert missing.json()["detail"] == "Run not found"

        units = client.get("/api/v1/runs/populated/units")
        assert units.status_code == 200
        assert units.json()["count"] == 2
        assert units.json()["coverage"] == {"units": 2}

        no_result = client.get("/api/v1/runs/empty/comparative-result")
        assert no_result.status_code == 409
        comparative = client.get("/api/v1/runs/populated/comparative-result")
        assert comparative.status_code == 200
        payload = comparative.json()
        assert payload["changed_units"] == 1
        assert payload["decision_units"] == 2
        assert payload["scoreable_units"] == 1
        assert len(payload["baseline_commitment"]) == 64
        assert len(payload["final_commitment"]) == 64
        assert payload["gold_accessed"] is False


def test_units_route_does_not_publish_typed_answer_runtime() -> None:
    with _client() as client:
        response = client.get("/api/v1/runs/sensitive/units")

    assert response.status_code == 200
    payload = response.json()
    assert "flag{X9aQ7mP2vN8rT4kL6sD3zY1wC5}" not in json.dumps(payload, ensure_ascii=False)
    assert payload["coverage"]["typed_answer_runtime"]["projection"] == "summary"


def test_patch_release_routes_enforce_shadow_only_and_map_domain_conflicts() -> None:
    shadow = _release()
    authoritative = _release(PatchReleaseStatus.AUTHORITATIVE)
    with _client() as client:
        listed = client.get("/api/v1/patch-releases")
        assert listed.status_code == 200
        assert listed.json()["count"] == 1

        rejected = client.post(
            "/api/v1/patch-releases",
            json={"evaluation_run_id": "eval", "release": authoritative.model_dump(mode="json")},
        )
        assert rejected.status_code == 409
        assert "Only shadow" in rejected.json()["detail"]

        for evaluation_id, expected in (("conflict", "immutable release conflict"), ("invalid", "invalid evaluation")):
            response = client.post(
                "/api/v1/patch-releases",
                json={"evaluation_run_id": evaluation_id, "release": shadow.model_dump(mode="json")},
            )
            assert response.status_code == 409
            assert response.json()["detail"] == expected

        published = client.post(
            "/api/v1/patch-releases",
            json={"evaluation_run_id": "eval", "release": shadow.model_dump(mode="json")},
        )
        assert published.status_code == 200
        assert published.json()["patch_release"]["patch_release_id"] == shadow.patch_release_id


def test_patch_release_revocation_maps_missing_conflict_and_success() -> None:
    with _client() as client:
        missing = client.post("/api/v1/patch-releases/missing/revoke", json={"reason": "retired"})
        assert missing.status_code == 404
        conflict = client.post("/api/v1/patch-releases/invalid/revoke", json={"reason": "retired"})
        assert conflict.status_code == 409
        revoked = client.post("/api/v1/patch-releases/current/revoke", json={"reason": "superseded"})
        assert revoked.status_code == 200
        assert revoked.json()["patch_release"]["revocation_reason"] == "superseded"
