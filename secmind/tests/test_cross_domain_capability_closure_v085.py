from __future__ import annotations

from types import SimpleNamespace

from secmind.evidence_graph import make_claim, make_link
from secmind.gap_plan import GapActionKind, GapDomain, compile_cross_domain_gap_plan
from secmind.orchestration.eirs_runtime import advance_eirs_runtime
from secmind.schemas import (
    AgentReport,
    AgentState,
    ClaimStatus,
    Evidence,
    RunStatus,
    Scenario,
    TaskRequest,
)
from secmind.task_contract import BeliefState, compile_resolved_task_contract


def _log_state() -> AgentState:
    state = AgentState(
        run_id="cross-domain-mainline",
        task=TaskRequest(objective="reconstruct the evidence-bound timeline"),
        scenario=Scenario.LOG_ANALYSIS,
    )
    state.resolved_task_contract = compile_resolved_task_contract(
        {
            "task_spec_id": "cross-domain-mainline",
            "run_id": state.run_id,
            "revision": 1,
            "content_digest": "a" * 64,
            "objectives": [state.task.objective],
            "primary_scenario": "log_analysis",
            "primary_domain": "logs_ir_hunting",
            "secondary_scenarios": [],
            "secondary_capabilities": [],
            "scoring_mode": "forensic_attribution",
            "interaction_mode": "unattended",
            "autonomy_policy": "automatic",
            "authorized_scope": ["artifact:fixture"],
            "constraints": [],
            "prohibited_actions": [],
            "expected_outputs": ["timeline"],
            "success_criteria": [],
            "output_contract": {},
            "asset_ids": ["fixture"],
        },
        input_manifest_digest="b" * 64,
    )
    state.belief_state = BeliefState(
        open_obligation_ids=["timeline-evidence"],
        belief_digest="c" * 64,
    )
    evidence = Evidence(
        evidence_id="timeline-evidence-1",
        source="deterministic-log-parser@1",
        summary="Bounded log event",
        metadata={"source_locator": {"source_ref": "fixture.jsonl", "record_number": 1}},
    )
    claim = make_claim(
        claim_type="timeline_event",
        statement="One source-bound authentication event was observed.",
        subject_ref="event-1",
        producer="deterministic-scenario-analyzer",
        confidence=1.0,
    ).model_copy(update={"status": ClaimStatus.VERIFIED})
    state.evidence = [evidence]
    state.claims = [claim]
    state.evidence_links = [make_link(claim_id=claim.claim_id, evidence_id=evidence.evidence_id)]
    semantic_delta = {
        "delta_id": "scenario-delta-log-1",
        "scenario": "log_analysis",
        "answer_kind": "timeline",
        "semantic_digest": "d" * 64,
        "disposition": "accepted",
        "admission_ready": True,
        "facts": [{"event_id": "event-1", "evidence_ids": [evidence.evidence_id]}],
        "evidence_ids": [evidence.evidence_id],
    }
    state.audit_coverage["scenario_semantic_delta"] = semantic_delta
    state.report = AgentReport(
        run_id=state.run_id,
        status=RunStatus.PARTIAL,
        executive_summary="Evidence-bound timeline remains readable.",
        answer_type="timeline",
        answer_payload={
            "answer_kind": "timeline",
            "events": [{"event_id": "event-1", "evidence_ids": [evidence.evidence_id]}],
            "semantic_delta": semantic_delta,
        },
    )
    return state


def test_noncode_gap_lanes_are_controlled_retrievals_not_generic_tools() -> None:
    state = _log_state()
    for domain in (
        GapDomain.LOG,
        GapDomain.API,
        GapDomain.FORENSICS,
        GapDomain.EXACT,
        GapDomain.PATCH,
        GapDomain.IR,
    ):
        plan = compile_cross_domain_gap_plan(state, domains=[domain], max_actions=2)
        assert plan is not None
        action = next(item for item in plan.actions if item.domain == domain)
        assert action.kind == GapActionKind.RETRIEVE_DOMAIN
        assert action.capability not in {"inventory", "sast"}
        assert action.budget is not None
        assert action.budget.risk_level.value == 0
        assert action.budget.max_tool_calls == 0


def test_scoring_contract_prioritizes_patch_and_incident_retrieval_lanes() -> None:
    patch_state = _log_state()
    patch_state.scenario = Scenario.CODE_AUDIT
    assert patch_state.resolved_task_contract is not None
    patch_state.resolved_task_contract = patch_state.resolved_task_contract.model_copy(
        update={"scoring_mode": "patch_validator", "primary_scenario": "code_audit"}
    )
    patch_plan = compile_cross_domain_gap_plan(patch_state, max_actions=2)
    assert patch_plan is not None
    patch_action = next(item for item in patch_plan.actions if item.kind == GapActionKind.RETRIEVE_DOMAIN)
    assert (patch_action.domain, patch_action.capability) == (
        GapDomain.PATCH,
        "patch_evidence_retrieval",
    )

    ir_state = _log_state()
    ir_state.scenario = Scenario.INCIDENT_RESPONSE
    assert ir_state.resolved_task_contract is not None
    ir_state.resolved_task_contract = ir_state.resolved_task_contract.model_copy(
        update={"primary_scenario": "incident_response"}
    )
    ir_plan = compile_cross_domain_gap_plan(ir_state, max_actions=2)
    assert ir_plan is not None
    ir_action = next(item for item in ir_plan.actions if item.kind == GapActionKind.RETRIEVE_DOMAIN)
    assert (ir_action.domain, ir_action.capability) == (
        GapDomain.IR,
        "incident_evidence_retrieval",
    )


def test_mainline_records_real_cross_domain_funnel_without_dynamic_execution() -> None:
    state = _log_state()
    host = SimpleNamespace(
        investigation_store=None,
        _rehash_evidence_artifacts=lambda _state: ({}, {}),
    )

    schedule, runtime = advance_eirs_runtime(host, state)

    assert schedule is False
    assert runtime["status"] in {"blocked", "published"}
    funnel = state.audit_coverage["cross_domain_capability_pipeline"]
    log = funnel["domains"]["log"]
    assert log == {
        "capability": "log_timeline_retrieval",
        "execution_mode": "controlled_retrieval",
        "candidate_count": 1,
        "correlated_count": 1,
        "verified_count": 1,
        "admitted_count": 1,
        "observation_count": 1,
        "evidence_ids": ["timeline-evidence-1"],
        "status": "admitted",
    }
    assert funnel["dynamic_or_attack_execution"] is False
    assert state.report is not None
    assert state.report.answer_payload["events"][0]["event_id"] == "event-1"
    assert state.report.coverage["cross_domain_capability_pipeline"] == funnel


def test_gap_free_typed_scenario_still_records_the_capability_funnel() -> None:
    state = _log_state()
    state.belief_state = BeliefState(open_obligation_ids=[], belief_digest="e" * 64)
    host = SimpleNamespace(
        investigation_store=None,
        _rehash_evidence_artifacts=lambda _state: ({}, {}),
    )

    schedule, runtime = advance_eirs_runtime(host, state)

    assert schedule is False
    assert runtime["status"] == "closed"
    assert runtime["reason"] == "no_open_obligations"
    assert runtime["accepted_delta_count"] == 1
    funnel = state.audit_coverage["cross_domain_capability_pipeline"]
    assert funnel["domains"]["log"]["admitted_count"] == 1
    assert funnel["candidate_count"] == funnel["correlated_count"] == 1
