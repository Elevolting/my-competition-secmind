from __future__ import annotations

import pytest
from pydantic import ValidationError

from secmind.gap_plan import (
    FieldImpact,
    GapAction,
    GapActionBudget,
    GapActionKind,
    GapDomain,
    GapPlan,
    _action_budget,
    _domain_budget,
    compile_cross_domain_gap_plan,
    domain_for_capability,
    make_gap_revision_proposal,
    normalize_gap_domain,
    supported_gap_domains,
)
from secmind.schemas import AgentReport, AgentState, RiskLevel, RunStatus, TaskRequest
from secmind.task_contract import AnswerRevisionAction, BeliefState, compile_resolved_task_contract


def _state() -> AgentState:
    state = AgentState(
        run_id="run-gap-boundary",
        task=TaskRequest(objective="resolve bounded evidence gaps"),
    )
    state.resolved_task_contract = compile_resolved_task_contract(
        {
            "task_spec_id": "gap-spec",
            "run_id": state.run_id,
            "revision": 1,
            "content_digest": "a" * 64,
            "objectives": ["resolve bounded evidence gaps"],
            "primary_scenario": "unknown",
            "primary_domain": "orchestration_recovery_uncertainty",
            "secondary_scenarios": [],
            "secondary_capabilities": [],
            "scoring_mode": "evidence_gap",
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
        revision=1,
        open_obligation_ids=["obligation-b", "obligation-a"],
        belief_digest="c" * 64,
    )
    state.report = AgentReport(
        run_id=state.run_id,
        status=RunStatus.PARTIAL,
        executive_summary="Evidence remains incomplete.",
        answer_payload={"evidence_gap": {"status": "open"}},
    )
    return state


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (GapDomain.CODE, GapDomain.CODE),
        ("code-audit", GapDomain.CODE),
        ("log_analysis", GapDomain.LOG),
        ("forensics_static_reverse", GapDomain.FORENSICS),
        (" firmware ", GapDomain.FIRMWARE),
    ],
)
def test_gap_domain_normalization_is_closed_and_alias_aware(value: GapDomain | str, expected: GapDomain) -> None:
    assert normalize_gap_domain(value) is expected
    assert len(supported_gap_domains()) == 9


def test_gap_capability_resolution_never_creates_an_unreviewed_route() -> None:
    assert domain_for_capability(" SAST ") is GapDomain.CODE
    assert domain_for_capability("pcap_analysis") is GapDomain.FORENSICS
    assert domain_for_capability("api") is GapDomain.API
    assert domain_for_capability("arbitrary_remote_shell") is None
    with pytest.raises(ValueError, match="unsupported cross-domain"):
        normalize_gap_domain("arbitrary_remote_shell")


def test_gap_budget_clamps_retry_and_rejects_high_risk_or_invalid_reserve() -> None:
    budget = _action_budget(
        max_tool_calls=9,
        max_model_calls=9,
        max_runtime_ms=999_999,
        recovery_reserve_ms=10,
        idempotent=False,
        risk_level=RiskLevel.R1,
    )
    assert budget.max_tool_calls == 1
    assert budget.max_model_calls == 1
    assert budget.max_runtime_ms == 120_000

    assert _action_budget(risk_level="invalid").risk_level == RiskLevel.R0  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="R0/R1"):
        _action_budget(risk_level=RiskLevel.R2)
    with pytest.raises(ValidationError, match="recovery reserve"):
        GapActionBudget(max_runtime_ms=10, recovery_reserve_ms=11)
    with pytest.raises(ValidationError, match="at most one"):
        GapActionBudget(max_tool_calls=2, idempotent=False)


def test_domain_budget_uses_defaults_mapping_and_existing_safe_budget() -> None:
    default = _domain_budget(GapDomain.CODE, None)
    assert default.max_tool_calls == 1
    configured = _domain_budget(
        GapDomain.CODE,
        {"code": {"max_tool_calls": 2, "max_runtime_ms": 40_000, "recovery_reserve_ms": 2_000}},
    )
    assert configured.max_tool_calls == 2
    assert configured.max_runtime_ms == 40_000
    existing = GapActionBudget(max_tool_calls=1, max_runtime_ms=1_000)
    assert _domain_budget(GapDomain.CODE, {"code": existing}) is existing


def test_gap_action_and_field_impact_validate_typed_boundaries() -> None:
    with pytest.raises(ValidationError, match="JSON pointer"):
        FieldImpact(domain=GapDomain.CODE, field_path="findings", rationale="invalid")
    with pytest.raises(ValidationError, match="RUN_TOOL"):
        GapAction(
            action_id="action",
            kind=GapActionKind.RUN_TOOL,
            obligation_ids=["obligation"],
            capability="sast",
            input_refs=["input"],
            output_refs=["output"],
            stop_condition="bounded",
        )
    with pytest.raises(ValidationError, match="cannot understate"):
        GapAction(
            action_id="action",
            kind=GapActionKind.OBSERVE_DOMAIN,
            obligation_ids=["obligation"],
            capability="sast",
            max_tool_calls=1,
            budget=GapActionBudget(max_tool_calls=2),
            input_refs=["input"],
            output_refs=["output"],
            stop_condition="bounded",
        )


def test_gap_revision_proposal_is_canonical_deduplicated_and_non_authoritative() -> None:
    proposal = make_gap_revision_proposal(
        run_id="run-gap",
        base_answer={"evidence_gap": None},
        action=AnswerRevisionAction.SUPPLEMENT,
        target_path="/evidence_gap",
        value={"status": "observed"},
        expected_old_value=None,
        obligation_ids=["b", "a", "a", ""],
        evidence_ids=["evidence-b", "evidence-a", "evidence-a"],
        observation_refs=["observation-1", "observation-1"],
    )
    assert proposal.status == "proposed"
    assert proposal.obligation_ids == ["a", "b"]
    assert proposal.evidence_ids == ["evidence-a", "evidence-b"]
    assert proposal.expected_old_digest is not None
    assert proposal.field_impacts[0].field_path == "/evidence_gap"
    assert proposal.proposal_id.startswith("gap-revision-")


@pytest.mark.parametrize("max_actions", [2, 3, 4])
def test_cross_domain_plan_is_bounded_replay_stable_and_preserves_all_impacts(max_actions: int) -> None:
    state = _state()
    first = compile_cross_domain_gap_plan(
        state,
        domains=(GapDomain.CODE, GapDomain.LOG, GapDomain.API),
        max_actions=max_actions,
        input_refs={"code": ["source:a.py"]},
        observation_refs={"code": ["observation:verified"]},
        budgets={"code": {"max_tool_calls": 1, "max_runtime_ms": 1_000, "recovery_reserve_ms": 100}},
    )
    second = compile_cross_domain_gap_plan(
        state,
        domains=(GapDomain.CODE, GapDomain.LOG, GapDomain.API),
        max_actions=max_actions,
        input_refs={"code": ["source:a.py"]},
        observation_refs={"code": ["observation:verified"]},
        budgets={"code": {"max_tool_calls": 1, "max_runtime_ms": 1_000, "recovery_reserve_ms": 100}},
    )
    assert first is not None and second is not None
    assert first.plan_digest == second.plan_digest
    assert len(first.actions) == max_actions
    assert first.max_tool_calls <= 4
    assert first.revision_proposals[0].status == "proposed"
    assert {impact.domain for impact in first.revision_proposals[0].field_impacts} == {
        GapDomain.CODE,
        GapDomain.LOG,
        GapDomain.API,
    }
    assert any(action.kind == GapActionKind.RESYNTHESIZE for action in first.actions)


def test_cross_domain_plan_infers_domains_and_refuses_missing_authority() -> None:
    state = _state()
    state.audit_coverage["gap_domains"] = ["log_analysis", "invalid", "log_analysis"]
    state.audit_coverage["pre_primary_scenario_projection"] = {"scenario": "api_assessment"}
    inferred = compile_cross_domain_gap_plan(state)
    assert inferred is not None
    assert inferred.revision_proposals[0].value["domains"] == ["log", "api", "evidence_gap"]

    state.resolved_task_contract = None
    assert compile_cross_domain_gap_plan(state) is None
    with pytest.raises(ValueError, match="between 2 and 4"):
        compile_cross_domain_gap_plan(_state(), max_actions=5)


def test_gap_plan_model_rejects_action_count_outside_declared_contract() -> None:
    action = GapAction(
        action_id="action",
        kind=GapActionKind.VERIFY_EVIDENCE,
        obligation_ids=["obligation"],
        capability="evidence_verification",
        input_refs=["input"],
        output_refs=["output"],
        stop_condition="bounded",
    )
    payload = {
        "plan_id": "plan",
        "run_id": "run",
        "contract_digest": "a" * 64,
        "belief_digest": "b" * 64,
        "max_actions": 2,
        "max_tool_calls": 0,
        "actions": [action],
        "stop_reasons": ["bounded"],
        "plan_digest": "c" * 64,
    }
    with pytest.raises(ValidationError, match="between 2 and 4"):
        GapPlan.model_validate(payload)
