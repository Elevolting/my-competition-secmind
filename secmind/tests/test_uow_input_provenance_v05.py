from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import event, func, select
from sqlalchemy.orm import Session

from secmind.coordinator import CoordinatorStore
from secmind.execution import ToolInvocationRow
from secmind.guardrail import Guardrail
from secmind.schemas import (
    AgentState,
    InputMutation,
    PlanRevision,
    ReplanTrigger,
    RiskLevel,
    RouteRecord,
    Scenario,
    StrategyMode,
    TaskRequest,
    ToolContext,
    ToolInputEnvelope,
    ToolManifest,
    ToolResult,
    ToolStatus,
)
from secmind.tools import BaseTool, ToolBroker, ToolRegistry
from secmind.unit_of_work import (
    ControlPlaneUnitOfWork,
    InputEnvelopeRow,
    InputMutationRow,
    PlanRevisionRow,
    ProjectionHeadRow,
    ScenarioRouteRow,
    UnitOfWorkConflict,
)


class EnvelopeRecordingTool(BaseTool):
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.manifest = ToolManifest(
            name="envelope_test_tool",
            version="1.0.0",
            description="Records calls after the governed input boundary.",
            scenarios=[Scenario.CODE_AUDIT],
            input_schema={
                "type": "object",
                "properties": {"target": {"type": "string"}},
                "required": ["target"],
                "additionalProperties": False,
            },
            output_schema={
                "type": "object",
                "properties": {"target": {"type": "string"}},
                "required": ["target"],
                "additionalProperties": False,
            },
            risk_level=RiskLevel.R1,
            idempotent=True,
        )

    async def invoke(self, args: dict[str, Any], context: ToolContext) -> ToolResult:
        self.calls.append(dict(args))
        return ToolResult(status=ToolStatus.SUCCESS, data={"target": str(args["target"])})


def _state(run_id: str, workspace: Path) -> AgentState:
    return AgentState(
        run_id=run_id,
        workspace=str(workspace),
        task=TaskRequest(objective="audit repository", target_scope=[str(workspace)]),
    )


def _route(run_id: str) -> RouteRecord:
    return RouteRecord(
        route_id="00000000-0000-4000-8000-000000000501",
        run_id=run_id,
        task_spec_digest="a" * 64,
        scenario=Scenario.CODE_AUDIT,
        candidate_ids=["code-audit"],
        candidate_scores={"code-audit": 1.0},
        selected_candidate_id="code-audit",
        selected_strategy=StrategyMode.BALANCED,
        rationale_summary="The repository input deterministically selects code audit.",
        policy_ids=["route/code-audit"],
        route_digest="b" * 64,
    )


def _revision(run_id: str, *, revision_id: str = "00000000-0000-4000-8000-000000000502") -> PlanRevision:
    return PlanRevision(
        revision_id=revision_id,
        run_id=run_id,
        revision=1,
        parent_plan_digest="c" * 64,
        plan_digest="d" * 64,
        trigger=ReplanTrigger.TOOL_UNAVAILABLE,
        changed_fields=["steps"],
        rationale_summary="Use an available deterministic scanner.",
    )


def _mutation(*, mutation_id: str = "00000000-0000-4000-8000-000000000503") -> InputMutation:
    return InputMutation(
        mutation_id=mutation_id,
        stage="trusted_hook_patch",
        field_path="profile",
        previous_digest="1" * 64,
        new_digest="2" * 64,
        actor="hook:profile",
        reason="A signed hook selected the bounded profile.",
        policy_ids=["hook/profile"],
    )


def _envelope(run_id: str, *, execution_digest: str = "5" * 64) -> ToolInputEnvelope:
    return ToolInputEnvelope(
        invocation_id="00000000-0000-4000-8000-000000000504",
        run_id=run_id,
        step_id="scan",
        raw_input_ref="3" * 64,
        observable_input={"target": ".", "profile": "balanced"},
        execution_input_ref=execution_digest,
        raw_digest="3" * 64,
        observable_digest="4" * 64,
        execution_digest=execution_digest,
        mutation_chain=[_mutation()],
        scope_binding=["/workspace"],
        approval_binding=None,
    )


def _broker(
    tmp_path: Path,
    *,
    run_id: str,
) -> tuple[ToolBroker, EnvelopeRecordingTool, ControlPlaneUnitOfWork, ToolContext]:
    database_url = f"sqlite:///{tmp_path / 'control.db'}"
    coordinator = CoordinatorStore(database_url)
    uow = ControlPlaneUnitOfWork(coordinator.engine)
    assert uow.submit_run(_state(run_id, tmp_path))
    lease = coordinator.claim_jobs("worker-envelope", lease_seconds=60)[0]
    tool = EnvelopeRecordingTool()
    registry = ToolRegistry()
    registry.register(tool)
    context = ToolContext(
        run_id=run_id,
        step_id="scan",
        workspace=str(tmp_path),
        allowed_paths=[str(tmp_path)],
        invocation_id="00000000-0000-4000-8000-000000000505",
        idempotency_key="logical-envelope-v05",
        lease_owner_id=lease.owner_id,
        lease_fence=lease.fence,
    )
    broker = ToolBroker(
        registry,
        Guardrail(),
        coordinator=coordinator,
        unit_of_work=uow,
    )
    return broker, tool, uow, context


def test_cognitive_projection_persists_route_and_plan_revision_idempotently(tmp_path: Path) -> None:
    coordinator = CoordinatorStore(f"sqlite:///{tmp_path / 'projection.db'}")
    uow = ControlPlaneUnitOfWork(coordinator.engine)
    state = _state("run-projection-v05", tmp_path)
    state.active_route = _route(state.run_id)
    state.plan_revisions = [_revision(state.run_id)]

    uow.persist_cognitive_projection(state)
    uow.persist_cognitive_projection(state)

    with Session(uow.engine) as session:
        route = session.scalar(select(ScenarioRouteRow))
        revision = session.scalar(select(PlanRevisionRow))
        assert route is not None
        assert route.run_id == state.run_id
        assert route.scenario == Scenario.CODE_AUDIT.value
        assert route.strategy == StrategyMode.BALANCED.value
        assert revision is not None
        assert revision.trigger == ReplanTrigger.TOOL_UNAVAILABLE.value
        assert session.scalar(select(func.count()).select_from(ScenarioRouteRow)) == 1
        assert session.scalar(select(func.count()).select_from(PlanRevisionRow)) == 1


def test_unchanged_cognitive_projection_performs_no_database_work(tmp_path: Path) -> None:
    coordinator = CoordinatorStore(f"sqlite:///{tmp_path / 'projection-cache.db'}")
    uow = ControlPlaneUnitOfWork(coordinator.engine)
    state = _state("run-projection-cache-v05", tmp_path)
    state.active_route = _route(state.run_id)
    statements: list[str] = []

    def record_statement(*args: Any) -> None:
        statements.append(str(args[2]))

    event.listen(coordinator.engine, "before_cursor_execute", record_statement)
    try:
        uow.persist_cognitive_projection(state)
        first_count = len(statements)
        uow.persist_cognitive_projection(state)
        assert len(statements) == first_count

        state.active_route = state.active_route.model_copy(update={"rationale_summary": "changed"})
        with pytest.raises(UnitOfWorkConflict, match="scenario route identity"):
            uow.persist_cognitive_projection(state)
        assert len(statements) > first_count
    finally:
        event.remove(coordinator.engine, "before_cursor_execute", record_statement)


def test_cognitive_projection_rejects_route_and_revision_identity_conflicts(tmp_path: Path) -> None:
    coordinator = CoordinatorStore(f"sqlite:///{tmp_path / 'projection-conflict.db'}")
    uow = ControlPlaneUnitOfWork(coordinator.engine)
    state = _state("run-projection-conflict-v05", tmp_path)
    original_route = _route(state.run_id)
    state.active_route = original_route
    state.plan_revisions = [_revision(state.run_id)]
    uow.persist_cognitive_projection(state)

    state.active_route = state.active_route.model_copy(update={"rationale_summary": "conflicting route"})
    with pytest.raises(UnitOfWorkConflict, match="scenario route identity"):
        uow.persist_cognitive_projection(state)

    state.active_route = original_route
    state.plan_revisions = [_revision(state.run_id, revision_id="00000000-0000-4000-8000-000000000599")]
    with pytest.raises(UnitOfWorkConflict, match="plan revision"):
        uow.persist_cognitive_projection(state)


def test_cognitive_projection_head_rejects_delayed_lower_state_and_fence(tmp_path: Path) -> None:
    coordinator = CoordinatorStore(f"sqlite:///{tmp_path / 'projection-head.db'}")
    uow = ControlPlaneUnitOfWork(coordinator.engine)
    run_id = "run-projection-head-v084"
    old = _state(run_id, tmp_path)
    old.state_version = 1
    old.lease.fence = 1
    uow.persist_cognitive_projection(old)

    newer = old.model_copy(deep=True)
    newer.state_version = 2
    newer.transition_counter = 1
    newer.lease.fence = 2
    uow.persist_cognitive_projection(newer)

    delayed = old.model_copy(deep=True)
    delayed.active_route = _route(run_id)
    uow.persist_cognitive_projection(delayed)

    with Session(uow.engine) as session:
        head = session.get(ProjectionHeadRow, run_id)
        assert head is not None
        assert head.source_state_version == 2
        assert head.source_fence == 2
        assert session.query(ScenarioRouteRow).count() == 0


def test_input_envelope_and_mutations_are_durable_and_semantically_idempotent(tmp_path: Path) -> None:
    coordinator = CoordinatorStore(f"sqlite:///{tmp_path / 'envelope.db'}")
    uow = ControlPlaneUnitOfWork(coordinator.engine)
    run_id = "run-envelope-v05"
    assert uow.submit_run(_state(run_id, tmp_path))
    envelope = _envelope(run_id)

    assert uow.record_tool_input_envelope(envelope)
    replay_mutation = _mutation(mutation_id="00000000-0000-4000-8000-000000000598")
    replay_mutation = replay_mutation.model_copy(
        update={"created_at": replay_mutation.created_at + timedelta(seconds=5)}
    )
    replay = envelope.model_copy(
        update={
            "mutation_chain": [replay_mutation],
            "created_at": envelope.created_at + timedelta(seconds=5),
        }
    )
    assert not uow.record_tool_input_envelope(replay)

    with Session(uow.engine) as session:
        row = session.get(InputEnvelopeRow, envelope.invocation_id)
        mutation = session.scalar(select(InputMutationRow))
        assert row is not None
        assert row.execution_digest == envelope.execution_digest
        assert mutation is not None
        assert mutation.parent_digest == envelope.mutation_chain[0].previous_digest
        assert session.scalar(select(func.count()).select_from(InputMutationRow)) == 1


def test_input_envelope_conflict_is_rejected_without_overwrite(tmp_path: Path) -> None:
    coordinator = CoordinatorStore(f"sqlite:///{tmp_path / 'envelope-conflict.db'}")
    uow = ControlPlaneUnitOfWork(coordinator.engine)
    run_id = "run-envelope-conflict-v05"
    assert uow.submit_run(_state(run_id, tmp_path))
    envelope = _envelope(run_id)
    assert uow.record_tool_input_envelope(envelope)

    with pytest.raises(UnitOfWorkConflict, match="binding conflict"):
        uow.record_tool_input_envelope(_envelope(run_id, execution_digest="9" * 64))

    with Session(uow.engine) as session:
        row = session.get(InputEnvelopeRow, envelope.invocation_id)
        assert row is not None
        assert row.execution_digest == "5" * 64


@pytest.mark.asyncio
async def test_broker_persists_input_envelope_before_tool_execution(tmp_path: Path) -> None:
    broker, tool, uow, context = _broker(tmp_path, run_id="run-broker-envelope-v05")

    result = await broker.execute("envelope_test_tool", {"target": "."}, context)

    assert result.status == ToolStatus.SUCCESS
    assert tool.calls == [{"target": "."}]
    with Session(uow.engine) as session:
        envelope = session.get(InputEnvelopeRow, context.invocation_id)
        assert envelope is not None
        assert envelope.run_id == context.run_id
        assert envelope.step_id == context.step_id


@pytest.mark.asyncio
async def test_broker_input_binding_conflict_fails_closed_before_tool_claim(tmp_path: Path) -> None:
    broker, tool, uow, context = _broker(tmp_path, run_id="run-broker-conflict-v05")
    conflicting = ToolInputEnvelope(
        invocation_id=context.invocation_id,
        run_id=context.run_id,
        step_id=context.step_id,
        raw_input_ref="f" * 64,
        observable_input={"target": "different"},
        execution_input_ref="f" * 64,
        raw_digest="f" * 64,
        observable_digest="f" * 64,
        execution_digest="f" * 64,
        scope_binding=list(context.allowed_paths),
    )
    assert uow.record_tool_input_envelope(conflicting)

    result = await broker.execute("envelope_test_tool", {"target": "."}, context)

    assert result.status == ToolStatus.DENIED
    assert result.error_code == "INPUT_BINDING_CONFLICT"
    assert tool.calls == []
    with Session(uow.engine) as session:
        assert session.scalar(select(func.count()).select_from(ToolInvocationRow)) == 0
