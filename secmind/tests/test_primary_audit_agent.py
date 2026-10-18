from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from secmind.audit_kernel.primary_agent import PrimaryAuditAgent, PrimaryAuditWorkItem
from secmind.investigation.contracts import AgentWorkContract, seal_contract
from secmind.live_source_review import SourceUnit


class _Kernel:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    async def run(self, **kwargs):
        self.calls.append(kwargs)
        return "bounded-result"


def _contract(**updates: object) -> AgentWorkContract:
    values: dict[str, object] = {
        "run_id": "run-primary-agent",
        "step_id": "model-source-review",
        "profile_id": "sast-investigator",
        "task": "Audit immutable Java source.",
        "goal": "Produce bounded unit verdicts.",
        "stop_conditions": ["all units decided"],
        "required_evidence_types": ["audit_unit_decision"],
        "capability": "sast",
        "immutable_scope": ["."],
        "allowed_action_kinds": ["review_immutable_source", "propose_security_claim"],
        "allowed_tool_sets": [],
        "success_criteria": ["one decision per unit"],
        "failure_policy": "continue",
        "budget_reservation_id": "model-budget-1",
        "outcome_contract_id": "outcome-1",
        "run_fence": 1,
        "step_fence": 1,
        "transition_id": "transition-primary-1",
    }
    values.update(updates)
    return seal_contract(AgentWorkContract, **values)


@pytest.mark.asyncio
async def test_primary_agent_receives_only_contract_and_immutable_sources() -> None:
    kernel = _Kernel()
    agent = PrimaryAuditAgent(kernel)  # type: ignore[arg-type]
    source = SourceUnit(case_id="case-1", path="src/A.java", content="class A {}")
    result = await agent.run(
        PrimaryAuditWorkItem(
            contract=_contract(),
            case_files=(source,),
            support_files=(),
            deadline_at=datetime.now(UTC) + timedelta(seconds=30),
            max_model_calls=1,
            mode="baseline",
            authorized_scope=(".",),
        )
    )

    assert result == "bounded-result"
    assert kernel.calls[0]["run_id"] == "run-primary-agent"
    assert "state" not in kernel.calls[0]


@pytest.mark.asyncio
async def test_primary_agent_rejects_direct_tool_authority() -> None:
    kernel = _Kernel()
    agent = PrimaryAuditAgent(kernel)  # type: ignore[arg-type]
    source = SourceUnit(case_id="case-1", path="src/A.java", content="class A {}")
    with pytest.raises(ValueError, match="cannot invoke tools"):
        await agent.run(
            PrimaryAuditWorkItem(
                contract=_contract(allowed_tool_sets=["semgrep"]),
                case_files=(source,),
                support_files=(),
                deadline_at=datetime.now(UTC) + timedelta(seconds=30),
                max_model_calls=1,
                mode="baseline",
                authorized_scope=(".",),
            )
        )
    assert kernel.calls == []
