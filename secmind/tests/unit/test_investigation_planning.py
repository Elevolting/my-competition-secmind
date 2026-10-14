from __future__ import annotations

import pytest

from secmind.investigation.contracts import ReviewVerdict, StrategyLevel
from secmind.investigation.planning import (
    PlanContractCompiler,
    PlanCouncil,
    PlanCouncilRejected,
    PlanningBudget,
    PlanValidationError,
    PlanValidator,
    SecurityIntentClassifier,
    expand_parallel_tool_steps,
)
from secmind.schemas import PlanStep, RiskLevel

_DIGEST = "a" * 64


def _classifier() -> SecurityIntentClassifier:
    return SecurityIntentClassifier()


def _intent(*, objective: str = "深入审计代码仓库并检查供应链"):
    return _classifier().classify(
        run_id="run-planning",
        task_spec_digest=_DIGEST,
        objective=objective,
        explicit_scope=["."],
        authorization_constraints=["read-only", "network disabled"],
        expected_deliverables=["JSON", "Markdown", "SARIF", "evidence map"],
    )


def _validator(
    *,
    risks: dict[str, RiskLevel] | None = None,
    budget: PlanningBudget | None = None,
    ceiling: RiskLevel = RiskLevel.R2,
) -> PlanValidator:
    return PlanValidator(
        role_capabilities={"scout": ["inventory"], "specialist": ["sast"]},
        capability_tools={"inventory": ["inventory-tool"], "sast": ["sast-a", "sast-b"]},
        tool_risks=risks or {"inventory-tool": RiskLevel.R0, "sast-a": RiskLevel.R1, "sast-b": RiskLevel.R1},
        budget=budget,
        risk_ceiling=ceiling,
    )


def _step(
    step_id: str,
    *,
    capability: str = "sast",
    role: str = "specialist",
    dependencies: list[str] | None = None,
    tools: list[str] | None = None,
    risk: RiskLevel = RiskLevel.R1,
    attempts: int = 1,
) -> PlanStep:
    return PlanStep(
        step_id=step_id,
        objective=f"Collect {capability} evidence",
        agent_role=role,
        capability=capability,
        dependencies=dependencies or [],
        tool_candidates=tools or (["inventory-tool"] if capability == "inventory" else ["sast-a"]),
        inputs={"target": "."},
        success_criteria=["Output is schema-valid and evidence-backed."],
        output_contract={"evidence_types": [capability]},
        estimated_tool_calls=1,
        risk_hint=risk,
        max_attempts=attempts,
    )


def test_security_intent_classification_is_digest_deterministic_and_offline() -> None:
    first = _intent()
    second = _intent()

    assert first.analysis_id == second.analysis_id
    assert first.content_digest == second.content_digest
    assert first.intent_type == "code_audit"
    assert first.recommended_strategy == StrategyLevel.DEEP
    assert "network_access_prohibited" in first.risk_flags
    assert first.rationale_summary.startswith("Deterministic intent classification")


def test_classifier_never_invents_missing_scope_or_deliverables() -> None:
    intent = _classifier().classify(
        run_id="run-ambiguous",
        task_spec_digest=_DIGEST,
        objective="审计代码",
        explicit_scope=[],
    )

    assert intent.explicit_scope == []
    assert "Authorized target scope is not explicit." in intent.ambiguities
    assert "Expected deliverables are not explicit." in intent.ambiguities


def test_quick_plan_defers_candidate_limit_until_language_and_affinity_routing() -> None:
    intent = _intent(objective="quick code audit")
    outcome = PlanCouncil(_validator()).deliberate(intent)
    sast = next(item for item in outcome.accepted_proposal.proposed_steps if item.capability == "sast")

    assert intent.recommended_strategy == StrategyLevel.QUICK
    assert sast.tool_candidates == ["sast-a", "sast-b"]
    assert sast.context_requirements["tool_candidate_limit"] == 1


@pytest.mark.parametrize(
    ("steps", "expected_code"),
    [
        (
            [
                _step("first", dependencies=["second"]),
                _step("second", dependencies=["first"]),
            ],
            "dag_cycle",
        ),
        ([_step("first", dependencies=["absent"])], "missing_dependency"),
        ([_step("same"), _step("same")], "duplicate_step_id"),
    ],
)
def test_validator_rejects_invalid_dag(steps: list[PlanStep], expected_code: str) -> None:
    intent = _intent(objective="审计代码仓库")
    council = PlanCouncil(_validator())
    proposal = council.proposal_from_steps(intent, steps, author_profile="model-proposer")

    result = council.validator.validate(proposal, intent)

    assert expected_code in {item.code for item in result.issues}
    assert not result.valid


def test_validator_topologically_orders_reverse_input_without_rewriting_it() -> None:
    intent = _intent(objective="审计代码仓库")
    validator = _validator()
    council = PlanCouncil(validator)
    proposal = council.proposal_from_steps(
        intent,
        [
            _step("scan", dependencies=["inventory"]),
            _step("inventory", capability="inventory", role="scout"),
        ],
        author_profile="model-proposer",
    )

    result = validator.validate(proposal, intent)

    assert result.valid
    assert result.topological_order == ("inventory", "scan")
    assert [item.step_id for item in proposal.proposed_steps] == ["scan", "inventory"]


def test_validator_checks_role_capability_budget_and_tool_catalog() -> None:
    intent = _intent(objective="审计代码仓库")
    validator = _validator(budget=PlanningBudget(max_steps=2, max_tool_calls=1))
    council = PlanCouncil(validator)
    invalid = _step(
        "scan",
        role="scout",
        tools=["unknown-tool"],
        attempts=2,
    )
    proposal = council.proposal_from_steps(intent, [invalid], author_profile="untrusted-model")

    result = validator.validate(proposal, intent)
    codes = {item.code for item in result.issues}

    assert {"role_capability_mismatch", "tool_capability_mismatch", "tool_budget_exceeded"} <= codes


def test_validator_fails_closed_for_r3_ceiling_or_missing_tool_risk() -> None:
    with pytest.raises(ValueError, match="R3"):
        _validator(ceiling=RiskLevel.R3)

    with pytest.raises(ValueError, match="platform risk"):
        PlanValidator(
            role_capabilities={"specialist": ["sast"]},
            capability_tools={"sast": ["unclassified-tool"]},
            tool_risks={},
        )


def test_council_elevates_platform_risk_then_requires_both_reviewers() -> None:
    intent = _intent(objective="审计代码仓库")
    validator = _validator(risks={"inventory-tool": RiskLevel.R0, "sast-a": RiskLevel.R2, "sast-b": RiskLevel.R2})
    council = PlanCouncil(validator)
    proposed = council.proposal_from_steps(
        intent,
        [_step("scan", risk=RiskLevel.R0)],
        author_profile="untrusted-model",
        prompt_ref="prompt-registry:plan-author@1",
    )

    outcome = council.deliberate(intent, initial_proposal=proposed)

    assert outcome.rounds == 2
    assert len(outcome.proposals) == 2
    assert len(outcome.gap_reviews) == len(outcome.independent_reviews) == 2
    assert outcome.gap_reviews[0].verdict == ReviewVerdict.REVISE
    assert outcome.independent_reviews[-1].verdict == ReviewVerdict.APPROVE
    assert outcome.accepted_proposal.proposed_steps[0].risk_hint == RiskLevel.R2

    contract = PlanContractCompiler(validator).compile(outcome)
    assert contract.approval_requirements == ["scan:risk-r2"]


def test_offline_council_is_deterministic_and_compiler_is_stable() -> None:
    intent = _intent(objective="审计代码仓库")
    validator = _validator()
    council = PlanCouncil(validator)

    first = council.deliberate(intent)
    second = council.deliberate(intent)
    first_contract = PlanContractCompiler(validator).compile(first)
    second_contract = PlanContractCompiler(validator).compile(second)

    assert first.rounds == 1
    assert all(item.verdict == ReviewVerdict.APPROVE for item in first.reviews)
    assert first.accepted_proposal.proposal_id == second.accepted_proposal.proposal_id
    assert first.accepted_proposal.content_digest == second.accepted_proposal.content_digest
    assert first_contract.contract_id == second_contract.contract_id
    assert first_contract.content_digest == second_contract.content_digest
    assert first_contract.allowed_tool_sets == {
        "inventory": ["inventory-tool"],
        "sast": ["sast-a", "sast-b"],
    }
    assert first_contract.budget_envelope["worst_case_tool_calls"] == 4


def test_parallel_tool_expansion_executes_each_healthy_scanner_as_its_own_step() -> None:
    intent = _intent(objective="审计代码仓库")
    council = PlanCouncil(_validator())
    original = council.deliberate(intent).accepted_proposal.proposed_steps

    expanded = expand_parallel_tool_steps(original)
    sast = [item for item in expanded if item.capability == "sast"]

    assert [item.tool_candidates for item in sast] == [["sast-a"], ["sast-b"]]
    assert len({item.step_id for item in sast}) == 2
    assert all(item.dependencies == ["inventory-project"] for item in sast)
    assert all(item.max_attempts == 1 for item in sast)

    proposal = council.proposal_from_steps(intent, expanded, author_profile="coverage-expander")
    outcome = council.deliberate(intent, initial_proposal=proposal)
    contract = PlanContractCompiler(council.validator).compile(outcome)
    assert contract.allowed_tool_sets["sast"] == ["sast-a", "sast-b"]


def test_model_proposal_cannot_authorize_r3_or_bypass_compiler() -> None:
    intent = _intent(objective="审计代码仓库")
    validator = _validator(
        risks={"inventory-tool": RiskLevel.R0, "sast-a": RiskLevel.R3, "sast-b": RiskLevel.R3},
        ceiling=RiskLevel.R2,
    )
    council = PlanCouncil(validator)
    untrusted = council.proposal_from_steps(
        intent,
        [_step("scan", risk=RiskLevel.R0)],
        author_profile="live-model-proposal-only",
    )

    with pytest.raises(PlanCouncilRejected) as rejected:
        council.deliberate(intent, initial_proposal=untrusted)

    assert len(rejected.value.proposals) == 1
    assert any("risk_ceiling_exceeded" in gap for item in rejected.value.reviews for gap in item.risk_gaps)

    fake_outcome = type(
        "FakeOutcome",
        (),
        {
            "accepted_proposal": untrusted,
            "intent": intent,
            "gap_reviews": (),
            "independent_reviews": (),
            "rounds": 0,
        },
    )()
    with pytest.raises(PlanValidationError):
        PlanContractCompiler(validator).compile(fake_outcome)
