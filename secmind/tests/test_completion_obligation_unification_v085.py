from __future__ import annotations

from typing import Any, cast

import pytest

from secmind.agents import ReporterAgent
from secmind.answer_revision_contracts import CompositeStatus
from secmind.completion_gate import CompletionGate, CompletionSnapshot
from secmind.evidence_graph import EvidenceGraph
from secmind.investigation.contracts import (
    ObligationStatus as InvestigationObligationStatus,
)
from secmind.investigation.contracts import (
    RequirementObligation,
    seal_contract,
)
from secmind.orchestration.obligation_runtime import (
    clamp_run_status,
    critical_investigation_requirements,
    current_obligation_set,
    merge_investigation_obligations,
    refresh_obligation_set,
)
from secmind.schemas import AgentReport, AgentState, OutcomeContract, RunStatus, Scenario, TaskRequest
from secmind.task_contract import (
    CompositeObligationStatus,
    ObligationKind,
    ObligationStatus,
    TaskObligation,
    compile_resolved_task_contract,
    evaluate_obligation_set,
)


def _contract(scoring_mode: str = "exact_answer_with_evidence"):
    return compile_resolved_task_contract(
        {
            "task_spec_id": "task-obligation-unification",
            "run_id": "run-obligation-unification",
            "revision": 1,
            "content_digest": "a" * 64,
            "objectives": ["answer from the supplied immutable evidence"],
            "primary_scenario": "unknown",
            "primary_domain": "complex_input_understanding",
            "secondary_scenarios": [],
            "secondary_capabilities": [],
            "scoring_mode": scoring_mode,
            "interaction_mode": "unattended",
            "authorized_scope": ["artifact:fixture"],
            "asset_ids": ["fixture"],
        },
        input_manifest_digest="b" * 64,
    )


def _state() -> AgentState:
    state = AgentState(
        run_id="run-obligation-unification",
        task=TaskRequest(objective="answer from the supplied immutable evidence"),
        scenario=Scenario.API_ASSESSMENT,
        status=RunStatus.COMPLETED,
    )
    state.resolved_task_contract = _contract()
    state.report = AgentReport(
        run_id=state.run_id,
        status=RunStatus.COMPLETED,
        executive_summary="bounded answer",
        answer_type="exact_answer",
        answer_payload={},
    )
    return state


@pytest.mark.parametrize(
    ("answer", "expected"),
    [
        (
            {
                "epistemic_status": "insufficient_evidence",
                "execution_status": "success",
                "values": {"provisional": 42},
                "source_offsets": [{"source_ref": "artifact:fixture", "offset": 0}],
                "limitations": ["the artifact omits the requested field"],
            },
            CompositeStatus.INSUFFICIENT,
        ),
        (
            {
                "epistemic_status": "conflicting_evidence",
                "execution_status": "success",
                "values": {"branch_a": 1, "branch_b": 2},
                "source_offsets": [{"source_ref": "artifact:fixture", "offset": 0}],
                "limitations": ["two immutable records disagree"],
            },
            CompositeStatus.CONFLICTED,
        ),
        (
            {
                "epistemic_status": "unknown",
                "execution_status": "policy_blocked",
                "values": {"untrusted": "must-not-complete"},
                "source_offsets": [{"source_ref": "artifact:fixture", "offset": 0}],
                "limitations": ["scope was not authorized"],
            },
            CompositeStatus.BLOCKED,
        ),
    ],
)
def test_typed_epistemic_states_cannot_be_promoted_to_completed(
    answer: dict[str, Any],
    expected: CompositeStatus,
) -> None:
    contract = _contract()
    result = evaluate_obligation_set(
        contract.obligations,
        answer,
        scoring_mode=contract.scoring_mode,
    )

    assert result.composite_status == expected
    assert clamp_run_status(result, RunStatus.COMPLETED) == RunStatus.PARTIAL
    gate = CompletionGate().evaluate(
        CompletionSnapshot(
            graph=EvidenceGraph(),
            findings=(),
            contracts=(),
            requested_status=RunStatus.COMPLETED,
            obligations=result.task_obligations,
            obligation_set=result,
        )
    )
    assert gate.status == RunStatus.PARTIAL
    assert expected.value in " ".join(gate.reasons)


def test_optional_enhancement_is_not_a_second_completion_gate() -> None:
    templates = [
        TaskObligation(
            obligation_id="obl-core-required",
            kind=ObligationKind.CORE_ANSWER,
            target_fields=["values"],
            acceptance_rule="any_nonempty",
            critical=True,
        ),
        TaskObligation(
            obligation_id="obl-optional-enhancement",
            kind=ObligationKind.OPTIONAL_ENHANCEMENT,
            target_fields=["optional_enrichment"],
            acceptance_rule="any_nonempty",
            critical=False,
        ),
    ]
    result = evaluate_obligation_set(
        templates,
        {"values": {"answer": 42}, "execution_status": "success", "epistemic_status": "conclusive"},
        scoring_mode="exact_answer_with_evidence",
    )

    assert result.composite_status == CompositeStatus.COMPLETED
    optional = next(item for item in result.obligations if item.stage.value == "enhancement")
    assert optional.status == CompositeObligationStatus.UNVERIFIED
    assert result.stage_statuses[optional.stage] == CompositeStatus.COMPLETED


def test_investigation_requirement_is_folded_into_the_same_aggregate() -> None:
    state = _state()
    answer_set = refresh_obligation_set(
        state,
        {
            "values": {"answer": 42},
            "source_offsets": [{"source_ref": "artifact:fixture", "offset": 0}],
            "execution_status": "success",
            "epistemic_status": "conclusive",
        },
    )
    requirement = seal_contract(
        RequirementObligation,
        obligation_id="scenario-requirement-unverified",
        run_id=state.run_id,
        source_type="outcome_contract",
        source_ref="contract-scenario-parser",
        requirement_summary="the critical scenario parser must bind verified evidence",
        immutable_scope=["artifact:fixture"],
        satisfaction_rule_id="scenario-parser-v1",
        required_evidence_types=["scenario_fact"],
        status=InvestigationObligationStatus.UNVERIFIED,
    )

    merged = merge_investigation_obligations(state, answer_set, [requirement])

    assert merged.composite_status == CompositeStatus.PARTIAL
    assert current_obligation_set(state) == merged
    assert any(item.stage.value == "scenario" for item in merged.obligations)


def test_allow_partial_and_high_risk_requirements_are_assurance_not_completion() -> None:
    state = _state()
    state.outcome_contracts = [
        OutcomeContract(
            contract_id="contract-optional-scan",
            step_id="optional-scan",
            allow_partial=True,
            contract_digest="c" * 64,
        )
    ]
    answer_set = refresh_obligation_set(
        state,
        {
            "values": {"answer": 42},
            "source_offsets": [{"source_ref": "artifact:fixture", "offset": 0}],
            "execution_status": "success",
            "epistemic_status": "conclusive",
        },
    )
    requirements = [
        seal_contract(
            RequirementObligation,
            obligation_id="optional-outcome-unverified",
            run_id=state.run_id,
            source_type="outcome_contract",
            source_ref="contract-optional-scan",
            requirement_summary="optional scanner did not produce a verified delta",
            immutable_scope=["artifact:fixture"],
            satisfaction_rule_id="optional-scan-v1",
            required_evidence_types=["scanner_result"],
            status=InvestigationObligationStatus.UNVERIFIED,
        ),
        seal_contract(
            RequirementObligation,
            obligation_id="high-risk-assurance-unverified",
            run_id=state.run_id,
            source_type="high_risk_finding",
            source_ref="finding-high",
            requirement_summary="a second independent lineage is unavailable",
            immutable_scope=["artifact:fixture"],
            satisfaction_rule_id="high-risk-independent-validation-v1",
            required_evidence_types=["supporting_evidence"],
            status=InvestigationObligationStatus.UNVERIFIED,
        ),
    ]

    merged = merge_investigation_obligations(state, answer_set, requirements)

    assert merged.composite_status == CompositeStatus.COMPLETED
    added = merged.obligations[-2:]
    assert all(not item.critical for item in added)
    assert all(item.kind == ObligationKind.OPTIONAL_ENHANCEMENT for item in added)
    assert critical_investigation_requirements(state, requirements) == ()


def test_complete_evidence_gap_answer_preserves_insufficient_epistemic_status() -> None:
    contract = _contract("evidence_gap")
    result = evaluate_obligation_set(
        contract.obligations,
        {
            "execution_status": "success",
            "epistemic_status": "insufficient_evidence",
            "observations": [{"fact": "only a Git LFS pointer is present"}],
            "unknown_fields": ["underlying object"],
            "next_evidence": ["retrieve the object by OID"],
            "limitations": ["the object bytes are absent"],
        },
        scoring_mode=contract.scoring_mode,
    )

    assert result.composite_status == CompositeStatus.COMPLETED
    assert {item.status for item in result.obligations} == {CompositeObligationStatus.SATISFIED}


@pytest.mark.asyncio
async def test_state_investigation_projection_and_reporter_share_one_sealed_set() -> None:
    state = _state()
    result = refresh_obligation_set(
        state,
        {
            "execution_status": "success",
            "epistemic_status": "insufficient_evidence",
            "limitations": ["the requested fact is absent"],
        },
    )

    assert current_obligation_set(state) == result
    assert {item.status for item in state.obligation_status} == {ObligationStatus.INSUFFICIENT}
    reporter = ReporterAgent(cast(Any, object()))
    await reporter.run(state)
    assert state.status == RunStatus.PARTIAL
    assert state.report is not None and state.report.status == RunStatus.PARTIAL

    # A stale compatibility projection cannot become a second source of truth.
    state.obligation_status[0] = state.obligation_status[0].model_copy(update={"status": ObligationStatus.SATISFIED})
    assert current_obligation_set(state) is None
