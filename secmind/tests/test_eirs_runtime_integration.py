from __future__ import annotations

import hashlib
from collections.abc import Iterable
from contextvars import ContextVar
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from secmind.admission import AdmissionService
from secmind.artifact_store import ContentAddressedArtifactStore
from secmind.bounded_worker import BoundedWorker
from secmind.capsule import FailureCapsuleStore
from secmind.context_manager import MaterializedContext
from secmind.evidence_graph import make_link
from secmind.gap_plan import GapDomain, execution_capability_for_domain
from secmind.guardrail import Guardrail
from secmind.investigation.supplement import (
    build_gap_investigation_result,
    compile_eirs_gap_plan,
    make_gap_observation,
)
from secmind.ledger import LedgerStore
from secmind.llm import QwenGateway
from secmind.orchestration.eirs_runtime import (
    gap_plan_steps,
    materialize_eirs_steps,
    publish_eirs_revision,
)
from secmind.orchestration.typed_answer_runtime import publish_baseline_answer
from secmind.orchestrator import SecMindOrchestrator
from secmind.schemas import (
    AgentReport,
    AgentState,
    BudgetState,
    Claim,
    ClaimStatus,
    Evidence,
    Finding,
    RunStatus,
    Scenario,
    StepPatch,
    TaskRequest,
    ToolContext,
    ToolManifest,
    ToolResult,
    ToolStatus,
)
from secmind.task_contract import BeliefState, compile_resolved_task_contract
from secmind.tools import BaseTool, ToolBroker, ToolRegistry


class SequenceGapTool(BaseTool):
    def __init__(
        self,
        name: str,
        capability: str,
        scenario: Scenario,
        results: Iterable[ToolResult],
    ) -> None:
        self.manifest = ToolManifest(
            name=name,
            version="test-1",
            description="bounded EIRS integration tool",
            scenarios=[scenario],
            input_schema={"type": "object"},
            output_schema={"type": "object"},
            risk_level=0,
            capability_tags=[capability],
            evidence_types=["finding"],
            concurrency_key=name,
        )
        self._results = list(results)
        self.calls: list[ToolContext] = []

    async def invoke(self, args: dict[str, Any], context: ToolContext) -> ToolResult:
        del args
        self.calls.append(context.model_copy(deep=True))
        result = self._results[min(len(self.calls) - 1, len(self._results) - 1)]
        return result.model_copy(update={"invocation_id": context.invocation_id})


class RefreshingContextProvider:
    def __init__(self) -> None:
        self.requests = 0

    def materialize(self, pack_id: str) -> MaterializedContext:
        return MaterializedContext(
            pack_id=pack_id,
            pack_digest=("a" if pack_id != "replacement" else "b") * 64,
            system_text="bounded policy",
            user_text="bounded task",
            token_estimate=128,
        )

    def request_context(self, item, current_pack_id: str, reason: str) -> str:
        del item, current_pack_id, reason
        self.requests += 1
        return "replacement"


def _state(run_id: str, scenario: Scenario, settings) -> AgentState:
    state = AgentState(
        run_id=run_id,
        task=TaskRequest(objective="run bounded evidence-gap investigation"),
        scenario=scenario,
        workspace=str(settings.input_root),
    )
    state.resolved_task_contract = compile_resolved_task_contract(
        {
            "task_spec_id": f"eirs-{run_id}",
            "run_id": run_id,
            "revision": 1,
            "content_digest": "a" * 64,
            "objectives": [state.task.objective],
            "primary_scenario": scenario.value,
            "primary_domain": "code_audit_and_patch",
            "secondary_scenarios": [],
            "secondary_capabilities": [],
            "scoring_mode": "security_finding",
            "interaction_mode": "unattended",
            "autonomy_policy": "automatic",
            "authorized_scope": ["artifact:fixture"],
            "constraints": [],
            "prohibited_actions": [],
            "expected_outputs": [],
            "success_criteria": [],
            "output_contract": {},
            "asset_ids": ["fixture"],
        },
        input_manifest_digest="b" * 64,
    )
    state.belief_state = BeliefState(open_obligation_ids=["obligation-eirs"], belief_digest="c" * 64)
    state.report = AgentReport(
        run_id=run_id,
        status=RunStatus.PARTIAL,
        executive_summary="bounded baseline",
        transition_id=f"transition-{run_id}",
        answer_payload={"answer": "baseline"},
        budget_reservation=BudgetState(),
    )
    return state


def _orchestrator(settings, tools: Iterable[BaseTool]) -> SecMindOrchestrator:
    settings.prepare_directories()
    registry = ToolRegistry()
    for tool in tools:
        registry.register(tool)
    return SecMindOrchestrator(
        settings,
        LedgerStore(settings.database_url),
        QwenGateway(settings),
        ToolBroker(registry, Guardrail()),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("domain", "scenario"),
    [
        (GapDomain.CODE, Scenario.CODE_AUDIT),
    ],
)
async def test_eirs_code_domain_executes_through_guardrail_and_bounded_worker(
    settings,
    domain: GapDomain,
    scenario: Scenario,
) -> None:
    capability = execution_capability_for_domain(domain)
    tool = SequenceGapTool(
        f"eirs-{domain.value}",
        capability,
        scenario,
        [ToolResult(status=ToolStatus.SUCCESS, data={"findings": []}, summary="observed")],
    )
    orchestrator = _orchestrator(settings, [tool])
    try:
        state = _state(f"eirs-domain-{domain.value}", scenario, settings)
        compiled = compile_eirs_gap_plan(state, domains=[domain], max_actions=3)
        assert compiled is not None
        steps, action_steps, deterministic = gap_plan_steps(orchestrator, state, compiled.plan)
        assert len(steps) == 1
        assert steps[0].capability == capability
        assert action_steps
        assert len(deterministic) == 2
        assert materialize_eirs_steps(orchestrator, state, steps)

        scheduled = await orchestrator._schedule({"agent": state.model_dump(mode="json")})
        assert scheduled["route"] == "workers"
        work_item = scheduled["work_items"][0]
        worker_result = await orchestrator._worker({"work_item": work_item})
        patch = StepPatch.model_validate(worker_result["worker_patches"][0])
        assert patch.status.value == "succeeded"
        assert patch.actual_tool_name == tool.manifest.name
        assert len(tool.calls) == 1
    finally:
        orchestrator.broker.close()


@pytest.mark.asyncio
async def test_eirs_tool_failure_changes_to_approved_equivalent(settings) -> None:
    primary = SequenceGapTool(
        "a-eirs-primary",
        "sast",
        Scenario.CODE_AUDIT,
        [ToolResult(status=ToolStatus.ERROR, error_code="TOOL_UNAVAILABLE")],
    )
    fallback = SequenceGapTool(
        "b-eirs-fallback",
        "sast",
        Scenario.CODE_AUDIT,
        [ToolResult(status=ToolStatus.SUCCESS, data={"findings": []}, summary="fallback")],
    )
    orchestrator = _orchestrator(settings, [primary, fallback])
    try:
        state = _state("eirs-fallback", Scenario.CODE_AUDIT, settings)
        state.audit_coverage["eirs_budgets"] = {
            "code": {"max_tool_calls": 2, "max_runtime_ms": 30_000, "recovery_reserve_ms": 1_000}
        }
        compiled = compile_eirs_gap_plan(
            state,
            domains=[GapDomain.CODE],
            max_actions=3,
            budgets=state.audit_coverage["eirs_budgets"],
        )
        assert compiled is not None
        steps, _, _ = gap_plan_steps(orchestrator, state, compiled.plan)
        assert steps[0].tool_candidates == [primary.manifest.name, fallback.manifest.name]
        assert materialize_eirs_steps(orchestrator, state, steps)
        scheduled = await orchestrator._schedule({"agent": state.model_dump(mode="json")})
        worker_result = await orchestrator._worker({"work_item": scheduled["work_items"][0]})
        patch = StepPatch.model_validate(worker_result["worker_patches"][0])
        assert patch.status.value == "succeeded"
        assert len(primary.calls) == 1
        assert len(fallback.calls) == 1
    finally:
        orchestrator.broker.close()


@pytest.mark.asyncio
async def test_eirs_context_observation_refreshes_once_before_retry(settings) -> None:
    tool = SequenceGapTool(
        "eirs-context",
        "sast",
        Scenario.CODE_AUDIT,
        [
            ToolResult(status=ToolStatus.ERROR, error_code="MISSING_CONTEXT"),
            ToolResult(status=ToolStatus.SUCCESS, data={"findings": []}, summary="context-retried"),
        ],
    )
    orchestrator = _orchestrator(settings, [tool])
    provider = RefreshingContextProvider()
    orchestrator.bounded_worker = BoundedWorker(
        broker=orchestrator.broker,
        profile_registry=orchestrator.agent_profiles,
        context_provider=provider,
    )
    orchestrator._ensure_context_pack = lambda run_id, pack_id: None
    try:
        state = _state("eirs-context", Scenario.CODE_AUDIT, settings)
        state.audit_coverage["eirs_budgets"] = {
            "code": {"max_tool_calls": 2, "max_runtime_ms": 30_000, "recovery_reserve_ms": 1_000}
        }
        compiled = compile_eirs_gap_plan(
            state,
            domains=[GapDomain.CODE],
            max_actions=3,
            budgets=state.audit_coverage["eirs_budgets"],
        )
        assert compiled is not None
        steps, _, _ = gap_plan_steps(orchestrator, state, compiled.plan)
        assert materialize_eirs_steps(orchestrator, state, steps)
        scheduled = await orchestrator._schedule({"agent": state.model_dump(mode="json")})
        worker_result = await orchestrator._worker({"work_item": scheduled["work_items"][0]})
        patch = StepPatch.model_validate(worker_result["worker_patches"][0])
        assert patch.status.value == "succeeded"
        assert provider.requests == 1
        assert len(tool.calls) == 2
    finally:
        orchestrator.broker.close()


def _revision_state() -> AgentState:
    state = AgentState(
        run_id="eirs-revision",
        task=TaskRequest(objective="publish bounded evidence revision"),
        scenario=Scenario.CODE_AUDIT,
    )
    state.resolved_task_contract = compile_resolved_task_contract(
        {
            "task_spec_id": "eirs-revision",
            "run_id": state.run_id,
            "revision": 1,
            "content_digest": "a" * 64,
            "objectives": [state.task.objective],
            "primary_scenario": "code_audit",
            "primary_domain": "code_audit_and_patch",
            "secondary_scenarios": [],
            "secondary_capabilities": [],
            "scoring_mode": "security_finding",
            "interaction_mode": "unattended",
            "autonomy_policy": "automatic",
            "authorized_scope": ["artifact:fixture"],
            "constraints": [],
            "prohibited_actions": [],
            "expected_outputs": [],
            "success_criteria": [],
            "output_contract": {},
            "asset_ids": ["fixture"],
        },
        input_manifest_digest="b" * 64,
    )
    state.belief_state = BeliefState(open_obligation_ids=["obligation-revision"], belief_digest="c" * 64)
    state.report = AgentReport(
        run_id=state.run_id,
        status=RunStatus.PARTIAL,
        executive_summary="baseline",
        transition_id="transition-revision",
        answer_payload={"answer": "baseline"},
        budget_reservation=BudgetState(),
    )
    claim = Claim(
        claim_id="claim-revision",
        claim_type="finding",
        statement="two tools support one bounded observation",
        subject_ref="subject-revision",
        status=ClaimStatus.VERIFIED,
        confidence=1.0,
        producer="verifier",
    )
    first = Evidence(
        evidence_id="eirs-evidence-a",
        source="tool-a:test-1",
        summary="first independent observation",
        metadata={
            "tool_name": "tool-a",
            "tool_version": "test-1",
            "invocation_id": "inv-a",
            "method_lineage": "method-a",
            "input_manifest_digest": "1" * 64,
            "context_pack_digest": "2" * 64,
            "evidence_type": "finding",
        },
    )
    second = Evidence(
        evidence_id="eirs-evidence-b",
        source="tool-b:test-1",
        summary="second independent observation",
        metadata={
            "tool_name": "tool-b",
            "tool_version": "test-1",
            "invocation_id": "inv-b",
            "method_lineage": "method-b",
            "input_manifest_digest": "3" * 64,
            "context_pack_digest": "4" * 64,
            "evidence_type": "finding",
        },
    )
    state.claims = [claim]
    state.evidence = [first, second]
    state.evidence_links = [
        make_link(claim_id=claim.claim_id, evidence_id=item.evidence_id).model_copy(
            update={"verifier_status": ClaimStatus.VERIFIED}
        )
        for item in (first, second)
    ]
    return state


@pytest.mark.asyncio
async def test_eirs_revision_is_materialized_in_the_report_projection(tmp_path: Path) -> None:
    state = _revision_state()
    orchestrator = SecMindOrchestrator.__new__(SecMindOrchestrator)
    orchestrator._active_authority = ContextVar("eirs-test-authority", default=None)
    orchestrator.admission_service = AdmissionService()
    artifact_store = ContentAddressedArtifactStore(tmp_path / "cas")
    capsule_store = FailureCapsuleStore(tmp_path / "capsules")
    orchestrator.artifact_store = artifact_store
    orchestrator.capsule_store = capsule_store
    baseline_finding = Finding(
        finding_id="subject-revision",
        rule_id="CWE-89",
        severity="HIGH",
        confidence="HIGH",
        path="fixture.py",
        line=1,
        title="fixture finding",
        description="bounded fixture finding",
        evidence_ids=["eirs-evidence-a"],
        raw={"canonical_primary": True},
    )
    state.findings = [baseline_finding]
    state.report = state.report.model_copy(
        update={
            "answer_type": "finding",
            "answer_payload": {
                "task_id": state.run_id,
                "status": "partial",
                "findings": [baseline_finding.model_dump(mode="json")],
                "checked_paths": ["fixture.py"],
            },
            "findings": [baseline_finding],
            "evidence": list(state.evidence),
        }
    )
    response = b'{"task_id":"eirs-revision","status":"partial","findings":[]}'
    response_digest = hashlib.sha256(response).hexdigest()
    artifact_store.put(
        response,
        expected_sha256=response_digest,
        media_type="application/vnd.secmind.canonical-primary+json",
        run_id=state.run_id,
    )
    for evidence in state.evidence:
        evidence_bytes = f"{evidence.evidence_id}:verified".encode()
        evidence_digest = hashlib.sha256(evidence_bytes).hexdigest()
        artifact_store.put(evidence_bytes, expected_sha256=evidence_digest, run_id=state.run_id)
        evidence.sha256 = evidence_digest
        evidence.artifact_ref = evidence_digest
    state.audit_coverage.update(
        {
            "canonical_primary_attempted": True,
            "canonical_primary_completed": True,
            "primary_route": {"provider": "test-provider"},
        }
    )
    orchestrator.admission_service.admit_baseline(
        state,
        artifact_store=artifact_store,
        capsule_store=capsule_store,
        model_id="test-model",
        prompt_version="test-prompt",
        prompt_artifact_id=None,
        request_sha256="1" * 64,
        response_sha256=response_digest,
        response_schema_sha256="2" * 64,
        context_sha256="3" * 64,
        response_artifact_id=response_digest,
        provider_requests=1,
        input_tokens=1,
        output_tokens=1,
        cost_units=0,
        status=RunStatus.PARTIAL,
        executive_summary="baseline",
        answer_type="finding",
        answer_payload=state.report.answer_payload,
        findings=state.findings,
        evidence=state.evidence,
        decisions=[],
        limitations=[],
        coverage=state.audit_coverage,
        bound_finding_ids={item.finding_id for item in state.findings},
    )
    assert publish_baseline_answer(state) is not None
    result = compile_eirs_gap_plan(state, domains=[GapDomain.CODE], max_actions=3)
    assert result is not None
    action = next(item for item in result.plan.actions if item.domain == GapDomain.CODE)
    observation = make_gap_observation(
        action_id=action.action_id,
        domain=action.domain,
        capability=action.capability,
        obligation_ids=action.obligation_ids,
        input_refs=action.input_refs,
        output_refs=["eirs-evidence-a", "eirs-evidence-b"],
        evidence_ids=["eirs-evidence-a", "eirs-evidence-b"],
        budget=action.budget,
    )
    folded = build_gap_investigation_result(result.plan, [observation])
    published, independent = publish_eirs_revision(orchestrator, state, folded)
    assert published is True
    assert set(independent) == {"eirs-evidence-a", "eirs-evidence-b"}
    assert state.report is not None
    assert state.report.answer_type == "finding"
    assert state.report.answer_payload["findings"][0]["evidence_ids"] == [
        "eirs-evidence-a",
        "eirs-evidence-b",
    ]
    assert state.audit_coverage["eirs_runtime"]["typed_revision_field"] == "findings"
    assert state.audit_coverage["typed_answer_runtime"]["revision_ids"]

    class ResettingReporter:
        async def run(self, report_state: AgentState) -> AgentState:
            assert report_state.report is not None
            report_state.report = report_state.report.model_copy(update={"answer_payload": {}})
            return report_state

    async def checkpoint(report_state: AgentState, *args: Any, **kwargs: Any) -> dict[str, Any]:
        del args, kwargs
        return {"agent": report_state.model_dump(mode="json")}

    orchestrator.reporter = ResettingReporter()
    orchestrator.admission_service = SimpleNamespace(seal=lambda *args, **kwargs: None)
    orchestrator._checkpoint = checkpoint
    projected = await orchestrator._report({"agent": state.model_dump(mode="json")})
    projected_state = AgentState.model_validate(projected["agent"])
    assert projected_state.report is not None
    assert projected_state.report.answer_payload["findings"][0]["evidence_ids"] == [
        "eirs-evidence-a",
        "eirs-evidence-b",
    ]
