from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

from conftest import seal_execution_contract
from fastapi.testclient import TestClient

import secmind.api as api_module
from secmind.coordinator import RunLease
from secmind.replay import DeterministicReplayResult, ReplayVerification
from secmind.schemas import (
    AgentState,
    ApprovalRequest,
    Claim,
    ClaimStatus,
    ContextBudget,
    ContextPackRef,
    Evidence,
    EvidenceLink,
    PlanStep,
    ReplayBundleRef,
    RiskLevel,
    Scenario,
    StepRuntime,
    StepStatus,
    TaskRequest,
    ToolExecutionPolicy,
    ToolHealth,
    ToolManifest,
    VerificationResult,
)


class FakeCoordinator:
    def job_status(self, run_id: str) -> tuple[str, RunLease]:
        if run_id != "run-read":
            raise KeyError(run_id)
        return (
            "running",
            RunLease(
                run_id=run_id,
                owner_id="worker-read",
                fence=9,
                lease_until=datetime.now(UTC) + timedelta(minutes=1),
                attempts=2,
            ),
        )


class FakeLedger:
    def verify(self, run_id: str) -> bool:
        return run_id == "run-read"


class StaticCatalog:
    def __init__(self, items: list[dict[str, Any]]) -> None:
        self.items = items

    def catalog(self) -> list[dict[str, Any]]:
        return self.items


class FakeRegistry:
    def __init__(self, manifests: list[ToolManifest]) -> None:
        self._manifests = manifests

    def manifests(self) -> list[ToolManifest]:
        return self._manifests


class FakeService:
    def __init__(self, state: AgentState, *, include_cognitive_components: bool = True) -> None:
        self._state = state
        self.replay_ref = ReplayBundleRef(
            run_id=state.run_id,
            artifact_id="f" * 64,
            manifest_digest="a" * 64,
            ledger_head_hash="b" * 64,
        )
        self.artifact_store = SimpleNamespace(read=lambda _artifact_id: b"replay-archive")
        self.coordinator = FakeCoordinator()
        self.ledger = FakeLedger()
        orchestrator = SimpleNamespace()
        if include_cognitive_components:
            orchestrator.skill_registry = StaticCatalog(
                [
                    {
                        "skill_id": "python-security-audit",
                        "version": "1.0.0",
                        "description": "Review Python security evidence.",
                        "package_digest": "a" * 64,
                    }
                ]
            )
            orchestrator.capability_resolver = StaticCatalog(
                [
                    {
                        "capability_id": "sast",
                        "tool_name": "safe-sast",
                        "risk": 1,
                        "health": "healthy",
                        "version_digest": "b" * 64,
                    }
                ]
            )
            manifests = [
                tool_manifest("safe-sast", RiskLevel.R1),
                tool_manifest("network-audit", RiskLevel.R1, requires_network=True),
                tool_manifest("blocked", RiskLevel.R3),
            ]
            orchestrator.broker = SimpleNamespace(registry=FakeRegistry(manifests))
            orchestrator.policy_decision_point = SimpleNamespace(policy_version="pdp-test-v1.3")
        self.orchestrator = orchestrator

    def state(self, run_id: str) -> AgentState:
        if run_id != self._state.run_id:
            raise KeyError(run_id)
        return self._state.model_copy(deep=True)

    def get_replay_bundle(self, run_id: str) -> ReplayBundleRef:
        self.state(run_id)
        return self.replay_ref

    def build_replay_bundle(self, run_id: str) -> ReplayBundleRef:
        return self.get_replay_bundle(run_id)

    def verify_replay_bundle(self, run_id: str) -> ReplayVerification:
        replay_ref = self.get_replay_bundle(run_id)
        return ReplayVerification(
            run_id=run_id,
            artifact_id=replay_ref.artifact_id,
            manifest_digest=replay_ref.manifest_digest,
            ledger_head_hash=replay_ref.ledger_head_hash,
            entry_digests={"report.json": "c" * 64},
            ledger_events=(),
        )

    def deterministic_replay(self, run_id: str) -> DeterministicReplayResult:
        replay_ref = self.get_replay_bundle(run_id)
        return DeterministicReplayResult(
            run_id=run_id,
            ledger_events=(),
            step_patches=({"step_id": "sast"},),
            final_sequence=0,
            ledger_head_hash=replay_ref.ledger_head_hash,
        )

    def submit_approvals_batch(self, run_id: str, resolutions, *, actor: str):
        self.state(run_id)
        return [
            {
                "request_id": request_id,
                "resolution_id": response.resolution_id,
                "resolution_status": "accepted",
            }
            for request_id, response in resolutions
        ]


class FakeRuntime:
    def __init__(self, service: FakeService) -> None:
        self.service = service
        self.started = False

    async def startup(self) -> None:
        self.started = True

    async def shutdown(self) -> None:
        self.started = False


def tool_manifest(
    name: str,
    risk: RiskLevel,
    *,
    requires_network: bool = False,
) -> ToolManifest:
    return ToolManifest(
        name=name,
        version="1",
        description=f"{name} test tool",
        scenarios=[Scenario.CODE_AUDIT],
        input_schema={"type": "object"},
        output_schema={"type": "object"},
        risk_level=risk,
        requires_network=requires_network,
        execution=ToolExecutionPolicy(network_policy="restricted" if requires_network else "none"),
        capability_tags=["sast"],
        health_status=ToolHealth.HEALTHY,
    )


def run_state() -> AgentState:
    step = PlanStep(
        step_id="sast",
        objective="run SAST",
        agent_role="sast_specialist",
        capability="sast",
        tool_candidates=["safe-sast"],
        success_criteria=["verified finding"],
        risk_hint=RiskLevel.R1,
    )
    state = AgentState(
        run_id="run-read",
        task=TaskRequest(
            objective="audit a Python service",
            target_scope=["src"],
            constraints=["offline only"],
            autonomy_policy="approval_all",
        ),
        scenario=Scenario.CODE_AUDIT,
        plan=[step],
        step_runtime={
            "sast": StepRuntime(
                step_id="sast",
                status=StepStatus.SUCCEEDED,
                attempt=2,
                lease_fence=9,
                artifact_ids=["c" * 64],
            )
        },
    )
    state.claims = [
        Claim(
            claim_id="claim-verified",
            claim_type="vulnerability",
            statement="A verified issue exists.",
            subject_ref="src/app.py:10",
            status=ClaimStatus.VERIFIED,
            confidence=0.95,
            producer="sast-investigator",
        ),
        Claim(
            claim_id="claim-candidate",
            claim_type="vulnerability",
            statement="A candidate issue requires evidence.",
            subject_ref="src/app.py:20",
            status=ClaimStatus.CANDIDATE,
            confidence=0.4,
            producer="sast-investigator",
        ),
    ]
    state.evidence = [Evidence(evidence_id="evidence-1", source="safe-sast", summary="immutable proof")]
    state.evidence_links = [
        EvidenceLink(
            link_id="link-1",
            claim_id="claim-verified",
            evidence_id="evidence-1",
            verifier_status=ClaimStatus.VERIFIED,
        )
    ]
    state.verification_results = [
        VerificationResult(
            claim_id="claim-verified",
            status=ClaimStatus.VERIFIED,
            reason_summary="Evidence hash and location are valid.",
            verified_evidence_ids=["evidence-1"],
            confidence=0.95,
        )
    ]
    state.context_packs = [
        ContextPackRef(
            pack_id="pack-1",
            run_id=state.run_id,
            step_id="sast",
            agent_profile="sast-investigator",
            immutable_policy_refs=["policy-ref"],
            task_capsule={"objective": "audit", "scope": ["src"]},
            repository_slice_refs=["repository-ref"],
            evidence_handles=["evidence-1"],
            token_budget=ContextBudget(used_tokens=128),
            pack_digest="d" * 64,
        )
    ]
    state.pending_approvals = [
        ApprovalRequest(
            request_id="approval-read",
            run_id=state.run_id,
            step_id="sast",
            tool_name="safe-sast",
            parameters={"target": "src"},
            target="src",
            risk_level=RiskLevel.R2,
            reason="operator approval required",
            expected_impact="read-only sandbox scan",
        )
    ]
    return seal_execution_contract(state)


def make_client(monkeypatch, settings, *, include_cognitive_components: bool = True) -> TestClient:
    service = FakeService(run_state(), include_cognitive_components=include_cognitive_components)
    monkeypatch.setattr(api_module, "ApplicationRuntime", lambda _settings: FakeRuntime(service))
    return TestClient(api_module.create_app(settings), base_url="http://127.0.0.1")


def test_run_read_models_are_deterministic_and_reference_only(monkeypatch, settings) -> None:
    with make_client(monkeypatch, settings) as client:
        steps = client.get("/api/v1/runs/run-read/steps").json()
        assert steps["queue_status"] == "running"
        assert steps["lease"]["fence"] == 9
        assert steps["steps"][0]["runtime"]["attempt"] == 2

        verified = client.get("/api/v1/runs/run-read/claims?status=verified").json()
        assert [item["claim_id"] for item in verified["claims"]] == ["claim-verified"]
        assert verified["counts_by_status"]["candidate"] == 1

        graph = client.get("/api/v1/runs/run-read/evidence-graph").json()
        assert graph["integrity"] == {
            "dangling_claim_ids": [],
            "dangling_evidence_ids": [],
            "complete": True,
            "ledger_chain_valid": True,
        }
        assert graph["links"][0]["evidence_id"] == "evidence-1"

        packs = client.get("/api/v1/runs/run-read/context-packs?step_id=sast&agent_profile=sast-investigator").json()
        assert packs["count"] == 1
        assert packs["content_included"] is False
        assert "system_text" not in packs["context_packs"][0]
        assert "user_text" not in packs["context_packs"][0]
        assert "task_capsule" not in packs["context_packs"][0]
        assert "working_summary" not in packs["context_packs"][0]


def test_registry_and_effective_policy_read_models(monkeypatch, settings) -> None:
    with make_client(monkeypatch, settings) as client:
        skills = client.get("/api/v1/skills").json()
        assert skills["available"] is True
        assert skills["instructions_included"] is False
        assert skills["skills"][0]["skill_id"] == "python-security-audit"

        capabilities = client.get("/api/v1/capabilities").json()
        assert capabilities["available"] is True
        assert capabilities["capabilities"][0]["capability_id"] == "sast"

        policies = client.get("/api/v1/policies/effective?run_id=run-read").json()
        assert policies["available"] is True
        assert policies["policy_version"] == "pdp-test-v1.3"
        assert policies["run"]["target_scope"] == ["src"]
        by_tool = {item["tool_name"]: item for item in policies["tools"]}
        assert by_tool["safe-sast"]["action"] == "require_approval"
        assert by_tool["network-audit"]["effective_risk"] == 2
        assert by_tool["blocked"]["action"] == "deny"


def test_optional_cognitive_components_degrade_safely_and_missing_runs_are_404(
    monkeypatch,
    settings,
) -> None:
    with make_client(monkeypatch, settings, include_cognitive_components=False) as client:
        for path, collection in (
            ("/api/v1/skills", "skills"),
            ("/api/v1/capabilities", "capabilities"),
        ):
            payload = client.get(path).json()
            assert payload["available"] is False
            assert payload[collection] == []
            assert payload["error_type"] == "COMPONENT_NOT_CONFIGURED"

        policy = client.get("/api/v1/policies/effective").json()
        assert policy["available"] is False
        assert policy["tools"] == []
        assert policy["platform_rules"]["r3"] == "deny"

        for suffix in ("steps", "claims", "evidence-graph", "context-packs"):
            assert client.get(f"/api/v1/runs/missing/{suffix}").status_code == 404
        assert client.get("/api/v1/policies/effective?run_id=missing").status_code == 404


def test_replay_and_batch_approval_endpoints(monkeypatch, settings) -> None:
    with make_client(monkeypatch, settings) as client:
        metadata = client.get("/api/v1/runs/run-read/replay-bundle")
        assert metadata.status_code == 200
        assert metadata.json()["replay_bundle"]["artifact_id"] == "f" * 64

        archive = client.get("/api/v1/runs/run-read/replay-bundle?download=true")
        assert archive.status_code == 200
        assert archive.content == b"replay-archive"

        verified = client.post("/api/v1/runs/run-read/replay", json={"mode": "verify-only"})
        assert verified.status_code == 200
        assert verified.json()["result"]["model_calls"] == 0

        replayed = client.post(
            "/api/v1/runs/run-read/replay",
            json={"mode": "deterministic-replay"},
        )
        assert replayed.status_code == 200
        assert replayed.json()["result"]["step_patch_count"] == 1
        assert (
            client.post(
                "/api/v1/runs/run-read/replay",
                json={"mode": "checkpoint-fork"},
            ).status_code
            == 501
        )

        batch = client.post(
            "/api/v1/runs/run-read/approvals/batch",
            json={
                "items": [
                    {
                        "request_id": "approval-read",
                        "response": {"decision": "approve", "resolution_id": "resolution-read"},
                    }
                ]
            },
        )
        assert batch.status_code == 202
        assert batch.json()["resolutions"][0]["resolution_status"] == "accepted"
