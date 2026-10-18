from __future__ import annotations

from conftest import seal_execution_contract
from sqlalchemy.orm import Session

from secmind.guardrail import Guardrail
from secmind.investigation.store import InvestigationObjectRow, InvestigationStore
from secmind.ledger import LedgerStore
from secmind.llm import QwenGateway
from secmind.orchestrator import SecMindOrchestrator
from secmind.schemas import AgentState, LeaseSummary, ModelUsage, PlanStep, TaskRequest
from secmind.tools import ToolBroker, default_registry


def _runtime(settings):
    settings.prepare_directories()
    ledger = LedgerStore(settings.database_url)
    store = InvestigationStore(engine=ledger.engine)
    broker = ToolBroker(default_registry(), Guardrail())
    orchestrator = SecMindOrchestrator(
        settings,
        ledger,
        QwenGateway(settings),
        broker,
        investigation_store=store,
    )
    return orchestrator, ledger, broker, store


def _model_step() -> PlanStep:
    return PlanStep(
        step_id="model-source-review",
        objective="Produce one content-bound verdict for every Java audit unit.",
        agent_role="sast_specialist",
        capability="sast",
        outcome_contract_id="outcome-model-source-review",
        success_criteria=["Every Java unit has an explicit bounded verdict."],
        estimated_tool_calls=0,
        estimated_model_calls=1,
    )


def test_recovered_primary_work_contract_is_versioned_by_fence(settings) -> None:
    orchestrator, ledger, broker, store = _runtime(settings)
    try:
        step = _model_step()
        state = seal_execution_contract(
            AgentState(
                run_id="run-fenced-primary",
                task=TaskRequest(objective="Audit Java source"),
                plan_contract_id="accepted-plan",
                plan=[step],
                lease=LeaseSummary(owner_id="worker", fence=1),
            )
        )
        first = orchestrator._primary_agent_work_contract(state, step)  # noqa: SLF001
        state.lease.fence = 2
        second = orchestrator._primary_agent_work_contract(state, step)  # noqa: SLF001

        assert first.transition_id == second.transition_id
        assert first.contract_id != second.contract_id
        assert first.delegation_id != second.delegation_id
        assert first.budget_reservation_id == second.budget_reservation_id
        assert (first.run_fence, second.run_fence) == (1, 2)
        with Session(store.engine) as session:
            rows = (
                session.query(InvestigationObjectRow)
                .filter_by(run_id=state.run_id, object_type="agent_work_contract")
                .order_by(InvestigationObjectRow.version)
                .all()
            )
        assert [(row.version, row.object_id) for row in rows] == [
            (1, first.contract_id),
            (2, second.contract_id),
        ]
        assert (
            orchestrator._settle_primary_usage(  # noqa: SLF001
                run_id=state.run_id,
                reservation_id=second.budget_reservation_id,
                usage=ModelUsage(),
            )
            is None
        )
        assert store.unsettled_reservation_ids(state.run_id) == []
    finally:
        broker.close()
        ledger.close()


def test_primary_usage_settlement_uses_receipt_digest_contract(settings) -> None:
    orchestrator, ledger, broker, store = _runtime(settings)
    try:
        step = _model_step()
        state = seal_execution_contract(
            AgentState(
                run_id="run-primary-settlement",
                task=TaskRequest(objective="Audit Java source"),
                plan_contract_id="accepted-plan",
                plan=[step],
                lease=LeaseSummary(owner_id="worker", fence=1),
            )
        )
        contract = orchestrator._primary_agent_work_contract(state, step)  # noqa: SLF001

        error = orchestrator._settle_primary_usage(  # noqa: SLF001
            run_id=state.run_id,
            reservation_id=contract.budget_reservation_id,
            usage=ModelUsage(provider_requests=1, input_tokens=100, output_tokens=20, cost_units=0.5),
        )

        assert error is None
        assert store.unsettled_reservation_ids(state.run_id) == []
    finally:
        broker.close()
        ledger.close()
