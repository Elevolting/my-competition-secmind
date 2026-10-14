from security_agent.guardrail import Guardrail, GuardrailAction
from security_agent.schemas import RiskLevel, Scenario, ToolManifest


def manifest(risk: RiskLevel) -> ToolManifest:
    return ToolManifest(
        name=f"risk_{risk}",
        version="1",
        description="test",
        scenarios=[Scenario.CODE_AUDIT],
        input_schema={},
        output_schema={},
        risk_level=risk,
    )


def test_graded_risk_policy() -> None:
    guardrail = Guardrail()
    assert guardrail.evaluate(manifest(RiskLevel.R1), {}, "graded").action == GuardrailAction.ALLOW
    assert guardrail.evaluate(manifest(RiskLevel.R2), {}, "graded").action == GuardrailAction.REQUIRE_APPROVAL
    assert guardrail.evaluate(manifest(RiskLevel.R3), {}, "graded").action == GuardrailAction.REQUIRE_APPROVAL


def test_automatic_policy_allows_bounded_r2_without_approval() -> None:
    decision = Guardrail().evaluate(manifest(RiskLevel.R2), {}, "automatic")
    assert decision.action == GuardrailAction.ALLOW
    assert decision.policy_ids == ("POL-R2-AUTO",)


def test_automatic_r3_policy_skips_both_risk_approvals() -> None:
    for risk in (RiskLevel.R2, RiskLevel.R3):
        assert Guardrail().evaluate(manifest(risk), {}, "automatic_r3").action == GuardrailAction.ALLOW
    assert (Guardrail().evaluate(manifest(RiskLevel.R0), {"action": "credential_theft"},
                                 "automatic_r3").action == GuardrailAction.ALLOW)
    assert Guardrail().evaluate(manifest(RiskLevel.R3), {}, "automatic").action == GuardrailAction.REQUIRE_APPROVAL


def test_approval_all_keeps_human_review_for_r2() -> None:
    decision = Guardrail().evaluate(manifest(RiskLevel.R2), {}, "approval_all")
    assert decision.action == GuardrailAction.REQUIRE_APPROVAL


def test_high_risk_intent_requires_review_even_with_low_risk_manifest() -> None:
    decision = Guardrail().evaluate(manifest(RiskLevel.R0), {"action": "credential_theft"}, "automatic")
    assert decision.action == GuardrailAction.REQUIRE_APPROVAL
    assert decision.risk_level == RiskLevel.R3
