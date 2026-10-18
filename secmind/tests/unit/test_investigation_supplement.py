from __future__ import annotations

from types import SimpleNamespace

from secmind.evidence_graph import EvidenceGraph, make_claim, make_link
from secmind.investigation.contracts import PlanContract, TeamMember, TeamPlan, seal_contract
from secmind.investigation.evidence import EvidenceGap, EvidenceGapKind, InvestigationEvidenceGraph
from secmind.investigation.store import InvestigationStore
from secmind.investigation.supplement import (
    EvidenceGapSupplementPlanner,
    build_lineage_graph_views,
    stable_plan_revision_id,
)
from secmind.orchestrator import SecMindOrchestrator
from secmind.outcomes import OutcomeContractCompiler
from secmind.schemas import (
    AgentState,
    ClaimStatus,
    Evidence,
    PlanStep,
    RiskLevel,
    Scenario,
    StrategyMode,
    TaskRequest,
    ToolHealth,
    ToolManifest,
    VerificationResult,
)
from secmind.tools import ToolRegistry


def _manifest(name: str, *, health: ToolHealth = ToolHealth.HEALTHY) -> ToolManifest:
    return ToolManifest(
        name=name,
        version="1.0.0",
        description=name,
        scenarios=[Scenario.CODE_AUDIT],
        input_schema={"type": "object"},
        output_schema={"type": "object"},
        risk_level=RiskLevel.R1,
        capability_tags=["sast"],
        evidence_types=["sast_finding"],
        health_status=health,
    )


def test_lineage_adapter_preserves_two_real_invocations_as_independent() -> None:
    first = Evidence(
        evidence_id="evidence-a",
        source="bandit:1.0.0",
        summary="first",
        sha256="a" * 64,
        metadata={"evidence_type": "sast_finding", "tool_name": "bandit"},
    )
    second = Evidence(
        evidence_id="evidence-b",
        source="semgrep:1.0.0",
        summary="second",
        sha256="b" * 64,
        metadata={"evidence_type": "sast_finding", "tool_name": "semgrep"},
    )
    claim = make_claim(
        claim_type="sast.finding",
        statement="command injection",
        subject_ref="finding-1",
        producer="scan-sast",
        severity="HIGH",
        confidence=1,
    )
    graph = EvidenceGraph(
        claims=[claim],
        evidence=[first, second],
        links=[
            make_link(claim_id=claim.claim_id, evidence_id=first.evidence_id),
            make_link(claim_id=claim.claim_id, evidence_id=second.evidence_id),
        ],
    )
    graph.apply_verification(
        VerificationResult(
            claim_id=claim.claim_id,
            status=ClaimStatus.VERIFIED,
            reason_summary="both checked",
            verified_evidence_ids=[first.evidence_id, second.evidence_id],
            confidence=1,
        )
    )

    views = build_lineage_graph_views(
        graph,
        {first.evidence_id: "invocation:first", second.evidence_id: "invocation:second"},
    )
    investigation = InvestigationEvidenceGraph(views)

    assert {item.graph_id for item in views} == {"invocation:first", "invocation:second"}
    assert len(investigation.independent_evidence([first.evidence_id, second.evidence_id])) == 2


def test_gap_planner_selects_only_unused_healthy_independent_source() -> None:
    claim = make_claim(
        claim_type="sast.finding",
        statement="command injection",
        subject_ref="finding-1",
        producer="scan-sast",
        severity="HIGH",
        confidence=1,
    )
    claim.status = ClaimStatus.VERIFIED
    step = PlanStep(
        step_id="scan-sast",
        objective="scan",
        agent_role="sast_specialist",
        capability="sast",
        tool_candidates=["bandit", "semgrep", "unavailable"],
        inputs={"target": "."},
        success_criteria=["verified"],
        risk_hint=RiskLevel.R1,
    )
    gap = EvidenceGap(
        gap_id="gap-independent",
        kind=EvidenceGapKind.HIGH_RISK_INDEPENDENT_VALIDATION,
        target_type="finding",
        target_id="finding-1",
        reason="second source required",
        required_count=2,
        observed_count=1,
    )

    proposals = EvidenceGapSupplementPlanner().propose(
        [gap],
        claims=[claim],
        plan=[step],
        manifests=[_manifest("bandit"), _manifest("semgrep"), _manifest("unavailable", health=ToolHealth.UNAVAILABLE)],
        scenario=Scenario.CODE_AUDIT,
        supplement_round=0,
    )

    assert len(proposals) == 1
    assert proposals[0].tool_name == "semgrep"
    assert proposals[0].target_claim_ids == (claim.claim_id,)
    assert proposals[0].independence_requirement == 2


def test_plan_revision_identity_is_stable_under_crash_replay() -> None:
    first = stable_plan_revision_id("run-1", 1, "a" * 64, "b" * 64)
    replayed = stable_plan_revision_id("run-1", 1, "a" * 64, "b" * 64)

    assert replayed == first
    assert stable_plan_revision_id("run-1", 2, "a" * 64, "b" * 64) != first
    assert stable_plan_revision_id("run-2", 1, "a" * 64, "b" * 64) != first


def _activation_fixture() -> tuple[SecMindOrchestrator, InvestigationStore, AgentState, PlanStep]:
    store = InvestigationStore("sqlite:///:memory:")
    registry = ToolRegistry()
    registry.register(SimpleNamespace(manifest=_manifest("bandit")))
    registry.register(SimpleNamespace(manifest=_manifest("semgrep")))
    orchestrator = object.__new__(SecMindOrchestrator)
    orchestrator.investigation_store = store
    orchestrator.broker = SimpleNamespace(registry=registry)
    orchestrator.contract_compiler = OutcomeContractCompiler()
    orchestrator.plan_validator = SimpleNamespace(validate=lambda *_args: [])

    original = PlanStep(
        step_id="scan-sast",
        objective="Produce evidence-backed SAST findings.",
        agent_role="sast_specialist",
        capability="sast",
        tool_candidates=["bandit", "semgrep"],
        inputs={"target": "."},
        success_criteria=["Every finding is linked to integrity-checked evidence."],
        risk_hint=RiskLevel.R1,
    )
    original_outcome = orchestrator._compile_outcome_contract(original)
    original.outcome_contract_id = original_outcome.contract_id
    plan = seal_contract(
        PlanContract,
        contract_id="plan-contract-original",
        run_id="run-replay",
        accepted_proposal_id="proposal-original",
        revision=0,
        immutable_task_scope_digest="1" * 64,
        dag_digest="2" * 64,
        allowed_capabilities=["sast"],
        allowed_tool_sets={"sast": ["bandit", "semgrep"], "scan-sast": ["bandit", "semgrep"]},
        outcome_contract_ids=[original_outcome.contract_id],
        budget_envelope={"estimated_steps": 1},
        approval_requirements=[],
        completion_policy="quiet-evidence-gate-v0.6",
        catalog_digest="3" * 64,
    )
    team = seal_contract(
        TeamPlan,
        team_plan_id="team-plan-original",
        run_id="run-replay",
        plan_contract_id=plan.contract_id,
        strategy=StrategyMode.BALANCED,
        members=[
            TeamMember(
                profile_id="sast_specialist",
                capability="sast",
                step_ids=[original.step_id],
                concurrency_key="sast",
                budget_units=1,
                purpose="Collect primary SAST evidence.",
            )
        ],
        rationale_summary="Minimal least-authority test team.",
    )
    store.put_object(
        plan,
        run_id="run-replay",
        object_type="plan_contract",
        object_id=plan.contract_id,
        logical_key="execution-plan",
        content_digest=plan.content_digest,
    )
    store.put_object(
        team,
        run_id="run-replay",
        object_type="team_plan",
        object_id=team.team_plan_id,
        logical_key="active-team",
        content_digest=team.content_digest,
    )
    state = AgentState(
        run_id="run-replay",
        task=TaskRequest(objective="Audit the supplied code."),
        scenario=Scenario.CODE_AUDIT,
        plan=[original],
        outcome_contracts=[original_outcome],
        plan_contract_id=plan.contract_id,
        team_plan_id=team.team_plan_id,
    )
    supplement = PlanStep(
        step_id="supplement-1-scan-sast-semgrep",
        objective="Collect an independent SAST evidence lineage.",
        agent_role="sast_specialist",
        capability="sast",
        dependencies=[original.step_id],
        tool_candidates=["semgrep"],
        inputs={"target": "."},
        success_criteria=["Verifier accepts independent integrity-checked evidence."],
        risk_hint=RiskLevel.R1,
    )
    return orchestrator, store, state, supplement


def test_supplement_authority_chain_is_idempotent_under_crash_replay() -> None:
    orchestrator, store, initial, supplement = _activation_fixture()
    replay = initial.model_copy(deep=True)

    assert orchestrator._activate_supplement_steps(initial, [supplement.model_copy(deep=True)])
    assert orchestrator._activate_supplement_steps(replay, [supplement.model_copy(deep=True)])

    assert replay.plan_contract_id == initial.plan_contract_id
    assert replay.team_plan_id == initial.team_plan_id
    assert replay.plan_revisions == initial.plan_revisions
    assert len(store.list_objects("run-replay", "plan_contract")) == 2
    assert len(store.list_objects("run-replay", "team_plan")) == 2
    assert len(store.list_objects("run-replay", "plan_revision")) == 1


def test_failed_supplement_activation_does_not_persist_open_request() -> None:
    orchestrator, store, state, _supplement = _activation_fixture()
    claim = make_claim(
        claim_type="sast.finding",
        statement="command injection",
        subject_ref="finding-1",
        producer="scan-sast",
        severity="HIGH",
        confidence=1,
    )
    claim.status = ClaimStatus.VERIFIED
    state.claims = [claim]
    orchestrator._activate_supplement_steps = lambda *_args: False
    batch = SimpleNamespace(
        needs_supplement=True,
        results=[
            VerificationResult(
                claim_id=claim.claim_id,
                status=ClaimStatus.VERIFIED,
                reason_summary="A second independent source is required.",
                verified_evidence_ids=[],
                requested_evidence_types=["sast_finding"],
                confidence=1,
            )
        ],
    )

    assert not orchestrator._materialize_evidence_supplement(state, batch)
    assert store.list_objects("run-replay", "evidence_request") == []
    assert state.active_evidence_request_ids == []
