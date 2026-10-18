from __future__ import annotations

import pytest

from secmind.outcomes import (
    GradeContext,
    GraderRegistry,
    GradeStatus,
    OutcomeContractCompiler,
    OutcomeContractError,
    stable_digest,
)
from secmind.schemas import Claim, OutcomeContract, PlanStep


def step(criteria: list[str] | None = None) -> PlanStep:
    return PlanStep(
        step_id="scan-python",
        objective="Audit Python source",
        agent_role="sast_specialist",
        capability="sast",
        tool_candidates=["bandit_python_audit"],
        success_criteria=criteria or ["All indexed Python files are represented in scanner coverage"],
    )


def test_contract_compilation_is_stable_and_order_independent() -> None:
    compiler = OutcomeContractCompiler()
    first = compiler.compile(
        step(),
        expected_claim_types=["vulnerability", "misconfiguration", "vulnerability"],
        required_evidence_types=["rule", "location", "rule"],
        required_tool_versions={"semgrep": "1", "bandit": "2"},
        required_coverage={"languages": ["python"], "ratio": 1.0},
    )
    second = compiler.compile(
        step(),
        expected_claim_types=["misconfiguration", "vulnerability"],
        required_evidence_types=["location", "rule"],
        required_tool_versions={"bandit": "2", "semgrep": "1"},
        required_coverage={"ratio": 1.0, "languages": ["python"]},
    )
    assert first.contract_digest == second.contract_digest
    assert first.contract_id == second.contract_id


def test_contract_rejects_vague_success_and_tampering() -> None:
    compiler = OutcomeContractCompiler()
    with pytest.raises(OutcomeContractError, match="result quality"):
        compiler.compile(step(["Tool execution succeeded"]))

    contract = compiler.compile(step())
    assert contract.expected_claim_types == ["sast.coverage", "sast.finding"]
    tampered = contract.model_copy(update={"confidence_threshold": 0.1})
    with pytest.raises(OutcomeContractError, match="digest"):
        compiler.registry.validate_contract(tampered)


def test_registry_grades_evidence_tool_confidence_and_coverage() -> None:
    registry = GraderRegistry()
    contract = OutcomeContractCompiler(registry).compile(
        step(),
        expected_claim_types=["vulnerability"],
        required_evidence_types=["location", "rule"],
        required_tool_versions={"bandit": "2"},
        required_coverage={"ratio": 0.9, "languages": ["python"]},
        confidence_threshold=0.8,
    )
    context = GradeContext(
        contract=contract,
        claim=Claim(
            claim_type="vulnerability",
            statement="SQL injection is reachable",
            subject_ref="finding-1",
            producer="scan-python",
            confidence=0.95,
        ),
        evidence=(),
        evidence_types=frozenset({"location", "rule"}),
        tool_versions={"bandit": "2"},
        coverage={"ratio": 1.0, "languages": ["python", "typescript"]},
        integrity_valid=True,
    )
    assert all(result.status == GradeStatus.PASSED for result in registry.grade(context))

    failed = registry.grade(
        GradeContext(
            contract=contract,
            claim=context.claim.model_copy(update={"confidence": 0.2}),
            evidence=(),
            evidence_types=frozenset({"location"}),
            tool_versions={"bandit": "old"},
            coverage={"ratio": 0.5, "languages": []},
            integrity_valid=False,
        )
    )
    assert {item.grader_id for item in failed if not item.passed} == set(registry.grader_ids)


def test_unknown_grader_is_rejected_even_with_valid_digest() -> None:
    base = OutcomeContractCompiler().compile(step())
    payload = base.model_dump(mode="json")
    payload["grader_ids"] = ["repository-supplied-grader"]
    payload.pop("contract_digest")
    payload.pop("contract_id")
    contract = OutcomeContract(
        contract_id="unknown-grader",
        contract_digest=stable_digest(payload),
        **payload,
    )
    with pytest.raises(OutcomeContractError, match="unknown graders"):
        GraderRegistry().validate_contract(contract)
