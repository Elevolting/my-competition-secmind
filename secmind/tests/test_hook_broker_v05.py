from __future__ import annotations

import json
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from secmind.coordinator import CoordinatorConflict, CoordinatorStore, RunJobRow
from secmind.execution import parameters_hash
from secmind.guardrail import Guardrail
from secmind.hook_bus import HookBus, HookRegistration
from secmind.ledger import LedgerStore
from secmind.policy import PolicyDecisionPoint
from secmind.schemas import (
    AgentState,
    HookDecision,
    HookEvent,
    HookResult,
    RiskLevel,
    Scenario,
    TaskRequest,
    ToolContext,
    ToolManifest,
    ToolResult,
    ToolStatus,
)
from secmind.tools import BaseTool, ToolBroker, ToolRegistry
from secmind.unit_of_work import ControlPlaneUnitOfWork, HookExecutionRow


class RecordingTool(BaseTool):
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.manifest = ToolManifest(
            name="hook_test_tool",
            version="5.0-alpha",
            description="Deterministic hook boundary test tool",
            scenarios=[Scenario.CODE_AUDIT],
            input_schema={
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "profile": {"type": "string"},
                },
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


class RecordingPDP(PolicyDecisionPoint):
    def __init__(self) -> None:
        super().__init__()
        self.inputs = []

    def evaluate(self, value, manifest):  # type: ignore[no-untyped-def]
        self.inputs.append(value)
        return super().evaluate(value, manifest)


def _hook_result(
    event: HookEvent,
    hook_id: str,
    decision: HookDecision,
    *,
    patch: dict[str, Any] | None = None,
) -> HookResult:
    return HookResult(
        hook_id=hook_id,
        event_id=event.event_id,
        decision=decision,
        patch=patch or {},
        input_hash="0" * 64,
        output_hash="0" * 64,
    )


def _register(
    bus: HookBus,
    *,
    hook_id: str,
    event: str,
    decision: HookDecision,
    patch: dict[str, Any] | None = None,
) -> None:
    bus.register(
        HookRegistration(
            hook_id=hook_id,
            version="1",
            events=frozenset({event}),
            handler=lambda value: _hook_result(value, hook_id, decision, patch=patch),
            signature_verified=True,
            security_critical=True,
        )
    )


def _context(
    workspace: Path,
    *,
    invocation_id: str = "invocation-hook-v05",
    idempotency_key: str = "logical-hook-v05",
    owner_id: str = "local-worker",
    fence: int = 0,
) -> ToolContext:
    return ToolContext(
        run_id="run-hook-v05",
        step_id="scan",
        workspace=str(workspace),
        allowed_paths=[str(workspace)],
        invocation_id=invocation_id,
        idempotency_key=idempotency_key,
        lease_owner_id=owner_id,
        lease_fence=fence,
    )


def _registry(tool: BaseTool) -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(tool)
    return registry


@pytest.mark.asyncio
async def test_before_policy_patch_is_revalidated_and_bound_to_input_envelope(tmp_path: Path) -> None:
    tool = RecordingTool()
    bus = HookBus()
    _register(
        bus,
        hook_id="select-profile",
        event="before_policy",
        decision=HookDecision.PATCH,
        patch={"profile": "balanced"},
    )
    ledger = LedgerStore(f"sqlite:///{tmp_path / 'ledger.db'}")
    broker = ToolBroker(_registry(tool), Guardrail(), ledger=ledger, hook_bus=bus)

    result = await broker.execute("hook_test_tool", {"target": "."}, _context(tmp_path))

    assert result.status == ToolStatus.SUCCESS
    assert tool.calls == [{"target": ".", "profile": "balanced"}]
    events = ledger.events("run-hook-v05")
    bound = next(event for event in events if event.event_type == "tool.input_bound")
    assert bound.payload["mutation_count"] == 1
    assert bound.payload["raw_digest"] != bound.payload["execution_digest"]
    assert [event.event_type for event in events] == [
        "hook.executed",
        "tool.input_bound",
        "tool.started",
        "tool.completed",
    ]


@pytest.mark.asyncio
async def test_before_policy_patch_is_schema_validated_again(tmp_path: Path) -> None:
    tool = RecordingTool()
    bus = HookBus()
    _register(
        bus,
        hook_id="invalid-target",
        event="before_policy",
        decision=HookDecision.PATCH,
        patch={"target": 42},
    )
    broker = ToolBroker(_registry(tool), Guardrail(), hook_bus=bus)

    result = await broker.execute("hook_test_tool", {"target": "."}, _context(tmp_path))

    assert result.status == ToolStatus.DENIED
    assert result.error_code == "HOOK_PATCH_INVALID"
    assert tool.calls == []


@pytest.mark.asyncio
async def test_before_policy_patch_is_evaluated_by_pdp_after_mutation(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    outside = tmp_path / "outside"
    allowed.mkdir()
    outside.mkdir()
    database_url = f"sqlite:///{tmp_path / 'pdp.db'}"
    coordinator = CoordinatorStore(database_url)
    uow = ControlPlaneUnitOfWork(coordinator.engine)
    state = AgentState(
        run_id="run-hook-v05",
        task=TaskRequest(objective="audit repository", target_scope=[str(allowed)]),
    )
    assert uow.submit_run(state)
    lease = coordinator.claim_jobs("worker-pdp", lease_seconds=60)[0]
    tool = RecordingTool()
    bus = HookBus()
    patched = str(outside.resolve())
    _register(
        bus,
        hook_id="redirect-outside-scope",
        event="before_policy",
        decision=HookDecision.PATCH,
        patch={"target": patched},
    )
    pdp = RecordingPDP()
    broker = ToolBroker(
        _registry(tool),
        Guardrail(),
        coordinator=coordinator,
        unit_of_work=uow,
        policy_decision_point=pdp,
        hook_bus=bus,
    )
    context = _context(allowed, owner_id=lease.owner_id, fence=lease.fence)

    result = await broker.execute("hook_test_tool", {"target": "."}, context)

    assert result.status == ToolStatus.DENIED
    assert result.error_code == "POLICY_DENIED"
    assert tool.calls == []
    assert len(pdp.inputs) == 1
    assert pdp.inputs[0].parameters_hash == parameters_hash({"target": patched})
    assert pdp.inputs[0].resource == outside.resolve().as_posix()


@pytest.mark.asyncio
async def test_stale_broker_fence_is_rejected_before_hooks_or_outbox(tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'stale-hook.db'}"
    coordinator = CoordinatorStore(database_url)
    uow = ControlPlaneUnitOfWork(coordinator.engine)
    state = AgentState(run_id="run-hook-v05", task=TaskRequest(objective="audit repository"))
    assert uow.submit_run(state)
    stale = coordinator.claim_jobs("worker-stale", lease_seconds=60)[0]
    with Session(coordinator.engine) as session:
        session.execute(
            update(RunJobRow)
            .where(RunJobRow.run_id == state.run_id)
            .values(lease_until=datetime.now(UTC) - timedelta(seconds=1))
        )
        session.commit()
    coordinator.claim_jobs("worker-current", lease_seconds=60)
    tool = RecordingTool()
    bus = HookBus()
    _register(bus, hook_id="must-not-run", event="before_policy", decision=HookDecision.CONTINUE)
    broker = ToolBroker(
        _registry(tool),
        Guardrail(),
        coordinator=coordinator,
        unit_of_work=uow,
        hook_bus=bus,
    )

    with pytest.raises(CoordinatorConflict, match="fenced"):
        await broker.execute(
            "hook_test_tool",
            {"target": "."},
            _context(tmp_path, owner_id=stale.owner_id, fence=stale.fence),
        )

    assert tool.calls == []
    with Session(coordinator.engine) as session:
        assert session.query(HookExecutionRow).count() == 0


@pytest.mark.asyncio
async def test_deny_hook_fails_closed_before_tool_execution(tmp_path: Path) -> None:
    tool = RecordingTool()
    bus = HookBus()
    _register(
        bus,
        hook_id="deny-invocation",
        event="before_policy",
        decision=HookDecision.DENY,
    )
    broker = ToolBroker(_registry(tool), Guardrail(), hook_bus=bus)

    result = await broker.execute("hook_test_tool", {"target": "."}, _context(tmp_path))

    assert result.status == ToolStatus.DENIED
    assert result.error_code == "HOOK_DENIED"
    assert tool.calls == []


@pytest.mark.asyncio
async def test_before_runner_patch_is_rejected_as_late_authorization_change(tmp_path: Path) -> None:
    tool = RecordingTool()
    bus = HookBus()
    _register(
        bus,
        hook_id="late-patch",
        event="before_runner",
        decision=HookDecision.PATCH,
        patch={"profile": "deep"},
    )
    broker = ToolBroker(_registry(tool), Guardrail(), hook_bus=bus)

    result = await broker.execute("hook_test_tool", {"target": "."}, _context(tmp_path))

    assert result.status == ToolStatus.DENIED
    assert result.error_code == "HOOK_DENIED"
    assert "late hook patch" in (result.error_message or "").lower()
    assert tool.calls == []


@pytest.mark.asyncio
async def test_hook_execution_is_persisted_idempotently_on_cached_replay(tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'uow.db'}"
    coordinator = CoordinatorStore(database_url)
    uow = ControlPlaneUnitOfWork(coordinator.engine)
    state = AgentState(run_id="run-hook-v05", task=TaskRequest(objective="audit repository"))
    assert uow.submit_run(state)
    lease = coordinator.claim_jobs("worker-hooks", lease_seconds=60)[0]
    tool = RecordingTool()
    bus = HookBus()
    hook_calls = 0

    def continue_hook(event: HookEvent) -> HookResult:
        nonlocal hook_calls
        hook_calls += 1
        return _hook_result(event, "persisted-hook", HookDecision.CONTINUE)

    bus.register(
        HookRegistration(
            hook_id="persisted-hook",
            version="1",
            events=frozenset({"before_policy"}),
            handler=continue_hook,
            signature_verified=True,
            security_critical=True,
        )
    )
    broker = ToolBroker(
        _registry(tool),
        Guardrail(),
        coordinator=coordinator,
        unit_of_work=uow,
        hook_bus=bus,
    )
    context = _context(tmp_path, owner_id=lease.owner_id, fence=lease.fence)

    first = await broker.execute("hook_test_tool", {"target": "."}, context)
    second = await broker.execute("hook_test_tool", {"target": "."}, context)

    assert first.status == second.status == ToolStatus.SUCCESS
    assert first.invocation_id == second.invocation_id
    assert len(tool.calls) == 1
    assert hook_calls == 1
    with Session(coordinator.engine) as session:
        rows = list(session.scalars(select(HookExecutionRow)).all())
    assert len(rows) == 1
    assert rows[0].hook_id == "persisted-hook"
    assert rows[0].status == HookDecision.CONTINUE.value
    assert json.loads(rows[0].result_json or "{}")["event_id"] == rows[0].event_id


@pytest.mark.asyncio
async def test_cached_result_cannot_bypass_new_policy_hook(tmp_path: Path) -> None:
    tool = RecordingTool()
    bus = HookBus()
    broker = ToolBroker(_registry(tool), Guardrail(), hook_bus=bus)
    context = _context(tmp_path)
    first = await broker.execute("hook_test_tool", {"target": "."}, context)
    assert first.status == ToolStatus.SUCCESS
    assert len(tool.calls) == 1
    _register(
        bus,
        hook_id="new-deny-policy",
        event="before_policy",
        decision=HookDecision.DENY,
    )

    replay = await broker.execute("hook_test_tool", {"target": "."}, context)

    assert replay.status == ToolStatus.DENIED
    assert replay.error_code == "HOOK_DENIED"
    assert len(tool.calls) == 1


@pytest.mark.asyncio
async def test_hook_replay_is_stable_across_process_cache_and_runtime_duration(tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'hook-replay.db'}"
    coordinator = CoordinatorStore(database_url)
    uow = ControlPlaneUnitOfWork(coordinator.engine)
    event_id = "stable-hook-event"

    def registration(delay: float) -> HookRegistration:
        def handler(event: HookEvent) -> HookResult:
            time.sleep(delay)
            return _hook_result(event, "durable-hook", HookDecision.CONTINUE)

        return HookRegistration(
            hook_id="durable-hook",
            version="1",
            events=frozenset({"before_policy"}),
            handler=handler,
            signature_verified=True,
            security_critical=True,
        )

    first_bus = HookBus()
    first_bus.register(registration(0.001))
    first_event = HookEvent(
        event_id=event_id,
        run_id="hook-replay-run",
        event_type="before_policy",
        payload={"observable_input": {"target": "."}},
    )
    first = await first_bus.dispatch(first_event)
    uow.record_hook_executions(first_event, first)

    second_bus = HookBus()
    # Windows timer quantization and coverage tracing can make 1 ms and 20 ms
    # handlers report the same integer duration. Keep the assertion meaningful
    # with a gap that remains observable under instrumentation.
    second_bus.register(registration(0.1))
    second_event = HookEvent(
        event_id=event_id,
        run_id="hook-replay-run",
        event_type="before_policy",
        payload={"observable_input": {"target": "."}},
    )
    second = await second_bus.dispatch(second_event)
    uow.record_hook_executions(second_event, second)

    assert first[0].event_id == second[0].event_id
    assert first[0].input_hash == second[0].input_hash
    assert first[0].duration_ms != second[0].duration_ms
    with Session(coordinator.engine) as session:
        rows = list(session.scalars(select(HookExecutionRow)).all())
    assert len(rows) == 1
    coordinator.close()


@pytest.mark.asyncio
async def test_hook_cache_identity_includes_observable_input(tmp_path: Path) -> None:
    calls = 0

    def handler(event: HookEvent) -> HookResult:
        nonlocal calls
        calls += 1
        return _hook_result(event, "input-bound-hook", HookDecision.CONTINUE)

    bus = HookBus()
    bus.register(
        HookRegistration(
            hook_id="input-bound-hook",
            version="1",
            events=frozenset({"before_policy"}),
            handler=handler,
            signature_verified=True,
            security_critical=True,
        )
    )
    broker = ToolBroker(_registry(RecordingTool()), Guardrail(), hook_bus=bus)
    context = _context(tmp_path, idempotency_key="same-logical-key")

    await broker.execute("hook_test_tool", {"target": "."}, context)
    await broker.execute("hook_test_tool", {"target": "different"}, context)

    assert calls == 2
