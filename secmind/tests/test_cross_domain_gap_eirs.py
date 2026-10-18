from __future__ import annotations

import pytest

from secmind.evidence_gap import cross_domain_capability_catalog, domain_for_capability
from secmind.gap_plan import GapActionBudget, GapActionKind, GapDomain, compile_cross_domain_gap_plan
from secmind.investigation.supplement import (
    GapObservation,
    build_gap_investigation_result,
    compile_eirs_gap_plan,
    make_gap_observation,
)
from secmind.schemas import AgentState, RiskLevel, TaskRequest
from secmind.task_contract import BeliefState, compile_resolved_task_contract


def _state() -> AgentState:
    state = AgentState(run_id="run-gap-eirs", task=TaskRequest(objective="bound an evidence gap"))
    state.resolved_task_contract = compile_resolved_task_contract(
        {
            "task_spec_id": "task-gap-eirs",
            "run_id": state.run_id,
            "revision": 1,
            "content_digest": "a" * 64,
            "objectives": ["bound an evidence gap"],
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
    state.belief_state = BeliefState(
        open_obligation_ids=["obligation-gap-eirs"],
        belief_digest="c" * 64,
    )
    return state


def test_catalog_and_each_domain_have_a_bounded_observation_lane() -> None:
    catalog = cross_domain_capability_catalog()
    assert set(catalog) == set(GapDomain)
    assert domain_for_capability("firmware_strings") == GapDomain.FIRMWARE
    assert domain_for_capability("evtx_analysis") == GapDomain.LOG

    state = _state()
    for domain in GapDomain:
        result = compile_eirs_gap_plan(state, domains=[domain], max_actions=2)
        assert result is not None
        expected_kind = GapActionKind.OBSERVE_DOMAIN if domain == GapDomain.CODE else GapActionKind.RETRIEVE_DOMAIN
        assert any(item.kind == expected_kind and item.domain == domain for item in result.plan.actions)
        assert any(item.domain == domain for item in result.field_impacts)


def test_eirs_result_has_refs_budgets_stops_and_typed_revision_without_execution() -> None:
    state = _state()
    before = state.model_dump(mode="json")
    result = compile_eirs_gap_plan(state, domains=list(GapDomain), max_actions=4)

    assert result is not None
    assert 2 <= len(result.plan.actions) <= 4
    assert set(result.plan.supported_domains) == set(GapDomain)
    assert set(item.domain for item in result.field_impacts) == set(GapDomain)
    assert len(result.revision_proposals) == 1
    assert result.revision_proposals[0].status == "proposed"
    assert result.revision_proposals[0].field_impacts
    assert result.status == "proposed"
    assert result.plan.max_tool_calls <= 4
    for action in result.plan.actions:
        assert action.obligation_ids
        assert action.capability
        assert action.input_refs
        assert action.output_refs
        assert action.stop_condition
        assert action.budget is not None
        assert action.budget.risk_level <= RiskLevel.R1
        assert action.budget.max_tool_calls <= (1 if not action.budget.idempotent else 2)

    # Compilation is a pure value operation; no answer or belief field is
    # silently updated before the orchestrator's verifier/admission boundary.
    assert state.model_dump(mode="json") == before


def test_observation_feedback_updates_typed_proposal_and_field_impacts() -> None:
    state = _state()
    initial = compile_eirs_gap_plan(state, domains=[GapDomain.API], max_actions=2)
    assert initial is not None
    action = next(item for item in initial.plan.actions if item.kind == GapActionKind.RETRIEVE_DOMAIN)
    observation = make_gap_observation(
        action_id=action.action_id,
        domain=action.domain,
        capability=action.capability,
        obligation_ids=action.obligation_ids,
        input_refs=action.input_refs,
        output_refs=["cas:e-api-observation"],
        evidence_ids=["evidence-api"],
        budget=action.budget,
    )
    assert isinstance(observation, GapObservation)

    feedback = build_gap_investigation_result(initial.plan, [observation])
    assert feedback.status == "observed"
    assert feedback.revision_proposals[0].status == "proposed"
    assert "evidence-api" in feedback.revision_proposals[0].evidence_ids
    assert observation.observation_id in feedback.revision_proposals[0].observation_refs
    assert any(
        item.domain == GapDomain.API and item.evidence_ids == ["evidence-api"] for item in feedback.field_impacts
    )
    assert feedback.result_digest


def test_non_idempotent_budget_is_single_call_and_r2_is_rejected() -> None:
    state = _state()
    result = compile_eirs_gap_plan(
        state,
        domains=[GapDomain.CODE],
        max_actions=2,
        budgets={
            GapDomain.CODE.value: {
                "max_tool_calls": 2,
                "max_runtime_ms": 10_000,
                "idempotent": False,
                "risk_level": RiskLevel.R1,
            }
        },
    )
    assert result is not None
    action = next(item for item in result.plan.actions if item.domain == GapDomain.CODE)
    assert action.budget is not None
    assert action.budget.max_tool_calls == 1

    with pytest.raises(ValueError, match="non-idempotent"):
        GapActionBudget(max_tool_calls=2, idempotent=False)
    with pytest.raises(ValueError, match="R0/R1"):
        compile_cross_domain_gap_plan(
            state,
            domains=[GapDomain.CODE],
            max_actions=2,
            budgets={GapDomain.CODE.value: {"risk_level": RiskLevel.R2}},
        )
