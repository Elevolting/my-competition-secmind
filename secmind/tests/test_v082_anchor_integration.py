from __future__ import annotations

from contextvars import ContextVar
from types import SimpleNamespace
from typing import Any

import pytest
from conftest import seal_execution_contract

from secmind.admission import AdmissionService
from secmind.agent_profiles import AgentProfileRegistry
from secmind.agents import DeltaCriticAgent, DeltaCriticDecision
from secmind.artifact_store import ArtifactStoreError, ContentAddressedArtifactStore
from secmind.bounded_worker import BoundedWorker
from secmind.context_influence import build_context_influence
from secmind.context_manager import MaterializedContext
from secmind.dag import DagScheduler
from secmind.direct_anchor_pipeline import (
    DeltaAction,
    DeltaDisposition,
    TypedDelta,
    build_anchor_report,
    build_enhanced_report,
)
from secmind.guardrail import Guardrail
from secmind.model_router import ModelTaskKind
from secmind.orchestrator import SecMindOrchestrator
from secmind.primary_scout import DeterministicIndependentScout
from secmind.schemas import (
    AgentProfile,
    AgentState,
    ContextItemRef,
    ContextPackRef,
    ContextTaint,
    Evidence,
    Finding,
    InputArtifact,
    InstructionLayer,
    ModelUsage,
    PlanStep,
    RiskLevel,
    RunStatus,
    Scenario,
    TaskRequest,
    ToolContext,
    ToolManifest,
    ToolResult,
    ToolStatus,
)
from secmind.task_contract import seal_independence_proof
from secmind.tools import BaseTool, ToolBroker, ToolRegistry


def _finding(finding_id: str, path: str = "app.py", *, canonical: bool = False) -> Finding:
    return Finding(
        finding_id=finding_id,
        rule_id="CWE-89",
        severity="HIGH",
        confidence="HIGH",
        path=path,
        line=7,
        title="query construction",
        description="a query receives source data",
        evidence_ids=[f"evidence-{finding_id}"],
        raw={"canonical_primary": canonical},
    )


def _delta(
    delta_id: str,
    finding: Finding,
    *,
    action: DeltaAction,
    disposition: DeltaDisposition,
    target: str | None = None,
) -> TypedDelta:
    return TypedDelta(
        delta_id=delta_id,
        run_id="critic-run",
        cluster_id=f"cluster-{delta_id}",
        candidate_ids=(f"candidate-{delta_id}",),
        action=action,
        disposition=disposition,
        target_finding_id=target,
        finding=finding,
        evidence_ids=tuple(finding.evidence_ids),
        producer_ids=("independent-scout",),
        reason_code="typed-test",
        evidence_complete=True,
        semantic_checks={"source": True},
        admission_ready=disposition == DeltaDisposition.ACCEPTED,
        anchor_semantic_digest="a" * 64,
        gate_digest="b" * 64,
    )


class _RecordingGateway:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def structured(self, **kwargs: Any) -> tuple[DeltaCriticDecision, Any]:
        self.calls.append(kwargs)
        return (
            DeltaCriticDecision(
                status="accepted",
                rationale="bounded conflict reviewed",
                conflict_delta_ids=[item for item in kwargs["user_prompt"].split('"') if item.startswith("delta-")],
            ),
            SimpleNamespace(
                usage=ModelUsage(provider_requests=1),
                model_id="qwen-turbo",
                provider="dashscope",
                prompt_version="direct-delta-critic-v2",
                request_sha256="4" * 64,
                logical_call_id="critic-call-lineage",
                context_digest="5" * 64,
                route_profile="critic-bounded",
                route_lane="lightweight",
                route_task_kind=ModelTaskKind.CRITIC_REVIEW.value,
            ),
        )


@pytest.mark.asyncio
async def test_no_gap_path_runs_bounded_deterministic_scout(tmp_path) -> None:
    payload = b"print('clean')\n"
    store = ContentAddressedArtifactStore(tmp_path / "artifacts")
    stored = store.put(payload, run_id="scout-run")
    state = seal_execution_contract(
        AgentState(
            run_id="scout-run",
            task=TaskRequest(objective="audit source", autonomy_policy="automatic"),
            scenario=Scenario.CODE_AUDIT,
            status=RunStatus.RUNNING,
            workspace=".",
            input_artifacts=[
                InputArtifact(
                    artifact_id="clean-source",
                    original_name="clean.py",
                    relative_path="clean.py",
                    sha256=stored.sha256,
                    size_bytes=len(payload),
                    media_type="text/x-python",
                )
            ],
            audit_coverage={
                "direct_anchor_pipeline": True,
                "canonical_primary_attempted": True,
                "canonical_primary_completed": True,
                "evidence_gap_compiler": {"gap_codes": []},
            },
        )
    )
    orchestrator = object.__new__(SecMindOrchestrator)
    orchestrator._active_authority = ContextVar("test_authority", default=None)
    orchestrator.artifact_store = store
    orchestrator.independent_scout = DeterministicIndependentScout()

    async def checkpoint(
        current: AgentState,
        _event_type: str,
        _payload: dict[str, Any],
        route: str | None = None,
    ) -> dict[str, Any]:
        result: dict[str, Any] = {"agent": current.model_dump(mode="json")}
        if route is not None:
            result["route"] = route
        return result

    orchestrator._checkpoint = checkpoint  # type: ignore[method-assign]
    result = await orchestrator._independent_scout({"agent": state.model_dump(mode="json")})
    observed = AgentState.model_validate(result["agent"])

    summary = observed.audit_coverage["independent_scout"]
    assert summary["ran"] is True
    assert summary["candidate_count"] == 0
    assert summary["reason"] == "bounded deterministic coverage completed"
    assert observed.audit_coverage["independent_scout_candidate_ids"] == []


class _CaptureTool(BaseTool):
    def __init__(self) -> None:
        self.manifest = ToolManifest(
            name="capture-scan",
            version="1",
            description="captures governed context metadata",
            scenarios=[Scenario.CODE_AUDIT],
            input_schema={"type": "object"},
            output_schema={"type": "object"},
            risk_level=RiskLevel.R1,
            capability_tags=["sast"],
        )
        self.context: ToolContext | None = None

    async def invoke(self, _args: dict[str, Any], context: ToolContext) -> ToolResult:
        self.context = context.model_copy(deep=True)
        return ToolResult(invocation_id=context.invocation_id, status=ToolStatus.SUCCESS, data={"findings": []})


class _ContextProvider:
    def materialize(self, pack_id: str) -> MaterializedContext:
        return MaterializedContext(
            pack_id=pack_id,
            pack_digest="c" * 64,
            system_text="policy",
            user_text="task",
            token_estimate=32,
        )

    def request_context(self, _item: Any, _current_pack_id: str, _reason: str) -> str | None:
        return None


@pytest.mark.asyncio
async def test_context_influence_reaches_work_item_and_tool_node() -> None:
    knowledge = ContextItemRef(
        run_id="context-run",
        kind="knowledge",
        source="knowledge:sql",
        authority_level=InstructionLayer.RETRIEVED_KNOWLEDGE,
        taint=ContextTaint.ADVISORY,
        content_hash="a" * 64,
        metadata={"selection_hint": "sast sql"},
    )
    skill = ContextItemRef(
        run_id="context-run",
        kind="audit_skill",
        source="signed-sast@1",
        authority_level=InstructionLayer.SELECTED_SKILL,
        taint=ContextTaint.TRUSTED,
        content_hash="b" * 64,
        metadata={
            "skill_id": "signed-sast",
            "version": "1",
            "package_digest": "c" * 64,
            "capability_tags": ["sast"],
        },
    )
    manifest = _CaptureTool().manifest
    step = PlanStep(
        step_id="scan",
        objective="scan source",
        agent_role="sast_specialist",
        capability="sast",
        tool_candidates=["capture-scan"],
        skill_ids=["signed-sast"],
        success_criteria=["return normalized findings"],
    )
    influence = build_context_influence(
        context_items=[knowledge, skill],
        steps=[step],
        manifests={manifest.name: manifest},
    )
    pack = ContextPackRef(
        run_id="context-run",
        step_id="scan",
        agent_profile="sast-investigator",
        selected_skill_refs=[skill.context_id],
        knowledge_refs=[knowledge.context_id],
        pack_digest="d" * 64,
    )
    state = seal_execution_contract(
        AgentState(
            run_id="context-run",
            task=TaskRequest(objective="audit source", autonomy_policy="automatic"),
            scenario=Scenario.CODE_AUDIT,
            workspace=".",
            plan=[step],
            context_packs=[pack],
            audit_coverage={"context_influence": influence.influence.as_dict()},
        )
    )
    scheduler = DagScheduler()
    scheduler.initialize(state)
    item = scheduler.build_work_item(state, step)

    assert item.knowledge_refs == [knowledge.context_id]
    assert item.signed_skill_refs == [skill.context_id]
    assert item.context_pack_digest == "d" * 64
    assert item.context_influence_digest == influence.influence.context_digest

    tool = _CaptureTool()
    registry = ToolRegistry()
    registry.register(tool)
    worker = BoundedWorker(
        broker=ToolBroker(registry, Guardrail()),
        profile_registry=AgentProfileRegistry(
            [
                AgentProfile(
                    profile_id="sast-investigator",
                    purpose="bounded scanner",
                    allowed_capabilities=["sast"],
                    max_turns=1,
                    max_tool_calls=1,
                    max_context_tokens=1024,
                )
            ]
        ),
        context_provider=_ContextProvider(),
    )
    patch = await worker.run(item)

    assert patch.status.value == "succeeded"
    assert tool.context is not None
    first_key = BoundedWorker._invocation_key(
        item,
        turn=1,
        tool_name=item.tool_name,
        context_pack_id=item.context_pack_id or "",
        arguments=item.inputs,
        dependencies=[],
    )
    changed_item = item.model_copy(update={"context_influence_digest": "e" * 64})
    changed_key = BoundedWorker._invocation_key(
        changed_item,
        turn=1,
        tool_name=changed_item.tool_name,
        context_pack_id=changed_item.context_pack_id or "",
        arguments=changed_item.inputs,
        dependencies=[],
    )
    assert first_key != changed_key


@pytest.mark.asyncio
async def test_delta_critic_calls_gateway_only_for_non_java_conflict() -> None:
    primary = _finding("primary", canonical=True)
    non_java_delta = _delta(
        "delta-python",
        _finding("candidate-python"),
        action=DeltaAction.CORRECT,
        disposition=DeltaDisposition.QUARANTINED,
        target=primary.finding_id,
    )
    java_delta = _delta(
        "delta-java",
        _finding("candidate-java", "src/Main.java"),
        action=DeltaAction.CORRECT,
        disposition=DeltaDisposition.QUARANTINED,
        target=primary.finding_id,
    )
    gateway = _RecordingGateway()
    state = AgentState(
        run_id="critic-run",
        task=TaskRequest(objective="audit source", autonomy_policy="automatic"),
        scenario=Scenario.CODE_AUDIT,
        status=RunStatus.RUNNING,
        findings=[primary],
        audit_coverage={
            "direct_anchor_pipeline": True,
            "primary_finding_ids": [primary.finding_id],
            "primary_route": {
                "task_kind": "primary_review",
                "profile": "primary-strong",
                "model_id": "qwen-plus",
                "provider": "dashscope",
                "request_sha256": "1" * 64,
                "context_sha256": "2" * 64,
                "input_slice_digest": "3" * 64,
                "lineage_id": "primary-call-lineage",
                "prompt_version": "primary-v1",
            },
            "typed_deltas": [non_java_delta.model_dump(mode="json"), java_delta.model_dump(mode="json")],
        },
    )

    before = [item.model_dump(mode="json") for item in state.findings]
    await DeltaCriticAgent(gateway).run(state)  # type: ignore[arg-type]

    assert len(gateway.calls) == 1
    assert gateway.calls[0]["task_kind"] is ModelTaskKind.CRITIC_REVIEW
    assert gateway.calls[0]["role"] == "worker"
    assert state.audit_coverage["delta_critic"]["conflict_delta_ids"] == ["delta-python"]
    assert state.audit_coverage["delta_critic"]["route_profile"] == "critic-bounded"
    assert state.audit_coverage["delta_critic"]["route_is_independent"] is True
    assert state.audit_coverage["delta_critic"]["authorized_delta_ids"] == ["delta-python"]
    assert [item.model_dump(mode="json") for item in state.findings] == before

    no_conflict_gateway = _RecordingGateway()
    no_conflict = state.model_copy(deep=True)
    no_conflict.audit_coverage["typed_deltas"] = [
        _delta(
            "delta-java-only",
            _finding("candidate-java-only", "src/Main.java"),
            action=DeltaAction.CORRECT,
            disposition=DeltaDisposition.QUARANTINED,
            target=primary.finding_id,
        ).model_dump(mode="json")
    ]
    await DeltaCriticAgent(no_conflict_gateway).run(no_conflict)  # type: ignore[arg-type]
    assert no_conflict_gateway.calls == []
    assert no_conflict.audit_coverage["delta_critic"]["reason"] == "no_non_java_conflict"


@pytest.mark.asyncio
async def test_empty_primary_addition_does_not_spend_a_shadow_critic_call() -> None:
    candidate = _finding("candidate-only")
    delta = _delta(
        "delta-add-only",
        candidate,
        action=DeltaAction.ADD,
        disposition=DeltaDisposition.QUARANTINED,
    )
    gateway = _RecordingGateway()
    state = AgentState(
        run_id="critic-run",
        task=TaskRequest(objective="audit source", autonomy_policy="automatic"),
        scenario=Scenario.CODE_AUDIT,
        status=RunStatus.RUNNING,
        audit_coverage={
            "direct_anchor_pipeline": True,
            "primary_finding_ids": [],
            "typed_deltas": [delta.model_dump(mode="json")],
        },
    )

    await DeltaCriticAgent(gateway).run(state)  # type: ignore[arg-type]

    assert gateway.calls == []
    assert state.audit_coverage["delta_critic"]["reason"] == "no_non_java_conflict"


def test_correction_delta_requires_the_independent_critic_authorization() -> None:
    candidate = _finding("candidate-correction").model_copy(
        update={"raw": {"assurance_level": "semantically_corroborated"}}
    )
    delta = _delta(
        "delta-correction",
        candidate,
        action=DeltaAction.CORRECT,
        disposition=DeltaDisposition.ACCEPTED,
        target="primary",
    ).model_copy(update={"admission_ready": True})
    evidence = Evidence(
        evidence_id=candidate.evidence_ids[0],
        source="deterministic-sast",
        summary="source reaches the query sink",
        sha256="1" * 64,
        metadata={"assurance_level": "semantically_corroborated"},
    )
    state = AgentState(
        run_id="critic-run",
        task=TaskRequest(objective="audit source", autonomy_policy="automatic"),
        scenario=Scenario.CODE_AUDIT,
        status=RunStatus.RUNNING,
        audit_coverage={"delta_verification": {candidate.finding_id: True}},
    )
    evidence_by_id = {evidence.evidence_id: evidence}

    assert not AdmissionService._direct_delta_authorizes(
        state,
        delta,
        candidate,
        set(candidate.evidence_ids),
        evidence_by_id,
    )
    state.audit_coverage["delta_critic"] = {
        "status": "completed",
        "authorized_delta_ids": [delta.delta_id],
        "route_is_independent": True,
    }
    assert not AdmissionService._direct_delta_authorizes(
        state,
        delta,
        candidate,
        set(candidate.evidence_ids),
        evidence_by_id,
    )
    state.audit_coverage["delta_critic"] = {
        "status": "completed",
        "authorized_delta_ids": [delta.delta_id],
        "independence_proof": seal_independence_proof(
            provider="dashscope",
            model_family="qwen",
            model_id="qwen-turbo",
            method_family="canonical-primary-vs-delta-critic",
            primary_provider="dashscope",
            critic_provider="dashscope",
            primary_model_family="qwen",
            critic_model_family="qwen",
            primary_model_id="qwen-plus",
            critic_model_id="qwen-turbo",
            primary_request_lineage="1" * 64,
            critic_request_lineage="4" * 64,
            primary_method_lineage="primary-method-lineage",
            critic_method_lineage="critic-method-lineage",
            primary_input_slice_digest="2" * 64,
            critic_input_slice_digest="3" * 64,
            primary_context_digest="5" * 64,
            critic_context_digest="6" * 64,
            compared_lineage_ids=["primary:1", "critic:4"],
            independent=True,
        ).model_dump(mode="json"),
    }
    assert AdmissionService._direct_delta_authorizes(
        state,
        delta,
        candidate,
        set(candidate.evidence_ids),
        evidence_by_id,
    )


def test_anchor_and_enhanced_report_projection_references_are_append_only(tmp_path) -> None:
    store = ContentAddressedArtifactStore(tmp_path / "artifacts")
    orchestrator = object.__new__(SecMindOrchestrator)
    orchestrator.artifact_store = store
    state = AgentState(
        run_id="artifact-run",
        task=TaskRequest(objective="audit source", autonomy_policy="automatic"),
        audit_coverage={},
    )
    anchor = build_anchor_report(
        run_id=state.run_id,
        receipt_id="receipt-1",
        request_sha256="1" * 64,
        response_sha256="2" * 64,
        response_schema_sha256="3" * 64,
        prompt_version="primary-v1",
        prompt_artifact_id=None,
        context_sha256="4" * 64,
        response_artifact_id="5" * 64,
        findings=(),
        evidence=(),
        limitations=(),
        coverage={},
    )
    before = anchor.model_dump(mode="json")
    with pytest.raises((TypeError, ValueError)):
        anchor.response_sha256 = "f" * 64  # type: ignore[misc]
    assert anchor.model_dump(mode="json") == before

    anchor_artifact = orchestrator._persist_projection_artifact(
        state,
        before,
        media_type="application/vnd.secmind.anchor-report+json",
        reference_key="anchor_report_artifact_id",
    )
    state.audit_coverage["anchor_report_artifact_id"] = anchor_artifact.artifact_id
    anchor_bytes = store.read(anchor_artifact.artifact_id)
    enhanced = build_enhanced_report(
        anchor=anchor,
        deltas=(),
        findings=(),
        evidence=(),
        coverage={},
        precision_gate_met=True,
        publishable=True,
    )
    enhanced_artifact = orchestrator._persist_projection_artifact(
        state,
        enhanced.model_dump(mode="json"),
        media_type="application/vnd.secmind.enhanced-report+json",
        reference_key="enhanced_report_artifact_id",
    )
    state.audit_coverage["enhanced_report_artifact_id"] = enhanced_artifact.artifact_id

    assert len(anchor_artifact.artifact_id) == 64
    assert len(enhanced_artifact.artifact_id) == 64
    assert store.read(anchor_artifact.artifact_id) == anchor_bytes
    assert state.audit_coverage["anchor_report_artifact_id"] == anchor_artifact.artifact_id
    assert state.audit_coverage["enhanced_report_artifact_id"] == enhanced_artifact.artifact_id
    with pytest.raises(ArtifactStoreError, match="append-only"):
        orchestrator._persist_projection_artifact(
            state,
            {"changed": True},
            media_type="application/vnd.secmind.anchor-report+json",
            reference_key="anchor_report_artifact_id",
        )
