from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from secmind.coordinator import CoordinatorConflict, CoordinatorStore, RunJobRow
from secmind.execution import ExecutionStore
from secmind.guardrail import Guardrail
from secmind.investigation.contracts import AgentWorkContract, SkillBinding, UsageReservation, seal_contract
from secmind.investigation.store import InvestigationStore
from secmind.ledger import LedgerStore
from secmind.outbox_projector import OutboxProjector
from secmind.schemas import AgentState, AttachmentRef, RiskLevel, TaskRequest, ToolStatus
from secmind.skill_registry import SkillPackageError, SkillRegistry
from secmind.skill_usage import SkillLoadScope, query_skill_usage, skill_load_scope, skill_usage_event, tool_usage
from secmind.unit_of_work import ControlPlaneUnitOfWork
from sqlalchemy import update
from sqlalchemy.orm import Session
from test_execution_broker import CountingTool, broker_for, context
from test_orchestrator_v05 import _orchestrator
from test_primary_audit_agent import _contract

from secmind.tools import ToolBroker, ToolRegistry


def load_scope(ledger, operation, *, run="run-1", role="planner"):
    return skill_load_scope(
        SkillLoadScope(
            operation,
            "context",
            None,
            role,
            1,
            lambda kind, payload, key: ledger.append(run, kind, payload, actor="skill-registry", dedupe_key=key),
        )
    )


def test_real_load_success_failure_replay_and_new_operation(tmp_path):
    ledger = LedgerStore(f"sqlite:///{tmp_path / 'usage.db'}")
    registry = SkillRegistry.builtin()
    registry.discover()
    for operation in ("load-1", "load-1", "load-2"):
        with load_scope(ledger, operation):
            registry.load("project-inventory")
    with load_scope(ledger, "missing"):
        with pytest.raises(KeyError):
            registry.load("absent-skill")
    usage = query_skill_usage(ledger)
    assert usage["totals"] == {"loads": 2, "load_failures": 1, "calls": 0}
    assert usage["total_events"] == 3
    # Administrative reads outside task context do not become task usage.
    registry.load("project-inventory")
    assert query_skill_usage(ledger)["totals"] == usage["totals"]
    event = skill_usage_event(ledger, usage["events"][0]["event_id"])
    assert event["payload"]["error_type"] == "KeyError"
    recovered = LedgerStore(f"sqlite:///{tmp_path / 'usage.db'}")
    assert query_skill_usage(recovered) == usage
    assert recovered.verify("run-1")


def test_tampered_package_records_failed_load_without_body(tmp_path, monkeypatch):
    ledger = LedgerStore(f"sqlite:///{tmp_path / 'usage.db'}")
    registry = SkillRegistry.builtin()
    registry.discover()
    monkeypatch.setattr("secmind.skill_registry._package_digest", lambda *args, **kwargs: "0" * 64)
    with load_scope(ledger, "tampered"):
        with pytest.raises(SkillPackageError):
            registry.load("project-inventory")
    usage = query_skill_usage(ledger)
    assert usage["totals"] == {"loads": 0, "load_failures": 1, "calls": 0}
    assert usage["events"][0]["payload"]["error_type"] == "SkillPackageError"
    assert "instructions" not in str(usage)


@pytest.mark.asyncio
async def test_actual_boundary_cached_replay_and_denial(tmp_path):
    broker, _, ledger = broker_for(CountingTool(), tmp_path)
    for _ in range(2):
        assert (await broker.execute("counter", {"target": "."}, context())).status == ToolStatus.SUCCESS
    assert (await broker.execute("counter", {"wrong": True}, context(key="invalid"))).status == ToolStatus.DENIED
    usage = query_skill_usage(ledger)
    assert usage["totals"]["calls"] == 1
    assert usage["skills"][0]["skill_id"] == "unknown"
    assert usage["skills"][0]["succeeded"] == 1
    assert usage["total_events"] == 2
    (tmp_path / "denied").mkdir()
    denied, _, denied_ledger = broker_for(CountingTool(RiskLevel.R2), tmp_path / "denied")
    assert (await denied.execute("counter", {"target": "."}, context())).status == ToolStatus.DENIED
    assert query_skill_usage(denied_ledger)["totals"]["calls"] == 0


@pytest.mark.asyncio
async def test_real_retry_has_separate_attempt_and_result(tmp_path):
    class FlakyTool(CountingTool):
        async def invoke(self, args, ctx):
            if self.calls == 0:
                self.calls += 1
                raise RuntimeError("synthetic failure")
            return await super().invoke(args, ctx)

    tool = FlakyTool()
    broker, _, ledger = broker_for(tool, tmp_path)
    assert (await broker.execute("counter", {"target": "."}, context())).status == ToolStatus.ERROR
    assert (await broker.execute("counter", {"target": "."}, context())).status == ToolStatus.SUCCESS
    assert (await broker.execute("counter", {"target": "."}, context())).status == ToolStatus.SUCCESS
    usage = query_skill_usage(ledger)
    assert usage["totals"]["calls"] == 2
    assert usage["skills"][0]["failed"] == usage["skills"][0]["succeeded"] == 1
    assert {event["payload"]["skill_usage"]["invocation_attempt"] for event in usage["events"]} == {1, 2}


def test_multiple_candidates_total_once_pending_and_filters(tmp_path):
    ledger = LedgerStore(f"sqlite:///{tmp_path / 'usage.db'}")
    contract = SimpleNamespace(
        contract_id="contract-1",
        profile_id="investigator",
        skill_bindings=[
            SimpleNamespace(skill_id=skill, version="1.0", digest="1" * 64) for skill in ("skill-a", "skill-b")
        ],
    )
    usage = tool_usage(context(), 2, contract)
    for _ in range(2):
        ledger.append("run-1", "tool.invoked", {"tool": "counter", "skill_usage": usage}, dedupe_key="invoked-1")
    all_usage = query_skill_usage(ledger)
    assert all_usage["totals"]["calls"] == 1
    assert sum(item["calls"] for item in all_usage["skills"]) == 2
    assert all(item["pending"] == 1 for item in all_usage["skills"])
    assert query_skill_usage(ledger, skill_id="skill-a", role="investigator")["totals"]["calls"] == 1
    assert query_skill_usage(ledger, role="other")["totals"]["calls"] == 0
    assert query_skill_usage(ledger, run_id="other-run")["total_events"] == 0
    filtered = query_skill_usage(ledger, event_type="tool.completed")
    assert filtered["total_events"] == 0 and filtered["totals"]["calls"] == 1
    # Old reservation starts and a completion without an observed invoke never become actual calls.
    ledger.append("run-1", "tool.started", {"tool": "counter"})
    ledger.append("run-1", "tool.completed", {"status": "success", "skill_usage": tool_usage(context(key="unseen"), 1)})
    assert query_skill_usage(ledger)["totals"]["calls"] == 1


@pytest.mark.asyncio
async def test_durable_retry_projection_recovery_and_stale_fence(tmp_path):
    url = f"sqlite:///{tmp_path / 'durable.db'}"
    coordinator = CoordinatorStore(url)
    ledger = LedgerStore(engine=coordinator.engine)
    uow = ControlPlaneUnitOfWork(coordinator.engine)
    uow.submit_run(AgentState(run_id="run-1", task=TaskRequest(objective="test")))
    lease = coordinator.claim_jobs("worker", lease_seconds=60)[0]

    class FlakyTool(CountingTool):
        async def invoke(self, args, ctx):
            if self.calls == 0:
                self.calls += 1
                raise RuntimeError("first attempt failed")
            return await super().invoke(args, ctx)

    tool = FlakyTool()
    registry = ToolRegistry()
    registry.register(tool)
    broker = ToolBroker(
        registry,
        Guardrail(),
        execution_store=ExecutionStore(engine=coordinator.engine),
        ledger=ledger,
        coordinator=coordinator,
        unit_of_work=uow,
    )
    ctx = context().model_copy(update={"lease_owner_id": lease.owner_id, "lease_fence": lease.fence})
    assert (await broker.execute("counter", {"target": "."}, ctx)).status == ToolStatus.ERROR
    assert (await broker.execute("counter", {"target": "."}, ctx)).status == ToolStatus.SUCCESS
    assert (await broker.execute("counter", {"target": "."}, ctx)).status == ToolStatus.SUCCESS
    assert tool.calls == 2
    # Facts first survive in the durable outbox, then reach the query ledger.
    assert query_skill_usage(ledger)["totals"]["calls"] == 0
    projector = OutboxProjector(coordinator.engine, owner_id="projector")
    while ids := projector.claim_batch():
        for event_id in ids:
            projector.project_claimed(event_id)
            projector.project_claimed(event_id)
    result = query_skill_usage(ledger)
    assert result["totals"]["calls"] == 2
    assert result["skills"][0]["succeeded"] == result["skills"][0]["failed"] == 1
    assert query_skill_usage(LedgerStore(url)) == result
    assert ledger.verify("run-1")
    with Session(coordinator.engine) as session:
        session.execute(
            update(RunJobRow)
            .where(RunJobRow.run_id == "run-1")
            .values(lease_until=datetime.now(UTC) - timedelta(seconds=1))
        )
        session.commit()
    coordinator.claim_jobs("next-worker", lease_seconds=60)
    with pytest.raises(CoordinatorConflict):
        await broker.execute("counter", {"target": "."}, ctx.model_copy(update={"idempotency_key": "late"}))
    assert tool.calls == 2 and query_skill_usage(ledger) == result


@pytest.mark.asyncio
async def test_real_orchestrator_loads_context_and_execution_verification(settings):
    orchestrator = _orchestrator(settings)
    (settings.input_root / "app.py").write_text("print('ok')", encoding="utf-8")
    state = await orchestrator.start(
        TaskRequest(objective="audit the attached code", attachments=[AttachmentRef(ref="app.py")]), "usage-e2e"
    )
    events = query_skill_usage(orchestrator.ledger, run_id=state.run_id)["events"]
    purposes = {event["payload"].get("purpose") for event in events}
    assert {"context", "plan_validation"}.issubset(purposes)
    assert all(event["payload"].get("usage_id") for event in events if event["event_type"].startswith("skill."))
    assert orchestrator.ledger.verify(state.run_id)


def test_orchestrator_load_outbox_initialization_replay_and_fencing(settings):
    orchestrator = _orchestrator(settings)
    coordinator = CoordinatorStore(engine=orchestrator.ledger.engine)
    orchestrator.coordinator = coordinator
    state = AgentState(run_id="scope-run", task=TaskRequest(objective="test"))
    # Admission/context preparation may occur before an execution lease exists.
    for _ in range(2):
        with orchestrator._skill_scope(state, "context", "initial"):
            orchestrator.skill_registry.load("project-inventory")
    assert len(coordinator.pending_outbox()) == 1
    ControlPlaneUnitOfWork(coordinator.engine).submit_run(state)
    lease = coordinator.claim_jobs("worker", lease_seconds=60)[0]
    state.lease.owner_id, state.lease.fence = lease.owner_id, lease.fence
    with orchestrator._skill_scope(state, "work_contract", "step-1"):
        orchestrator.skill_runtime.compile_binding("project-inventory")
    count = len(coordinator.pending_outbox())
    with Session(coordinator.engine) as session:
        session.execute(update(RunJobRow).where(RunJobRow.run_id == state.run_id).values(fence=lease.fence + 1))
        session.commit()
    with pytest.raises(CoordinatorConflict):
        with orchestrator._skill_scope(state, "work_contract", "step-late"):
            orchestrator.skill_runtime.compile_binding("project-inventory")
    assert len(coordinator.pending_outbox()) == count


@pytest.mark.asyncio
@pytest.mark.parametrize("authorized", [True, False])
async def test_verified_work_contract_candidates_and_rejection(tmp_path, authorized):
    coordinator = CoordinatorStore(f"sqlite:///{tmp_path / 'contract.db'}")
    ledger = LedgerStore(engine=coordinator.engine)
    uow = ControlPlaneUnitOfWork(coordinator.engine)
    store = InvestigationStore(engine=coordinator.engine)
    uow.submit_run(AgentState(run_id="run-1", task=TaskRequest(objective="test")))
    lease = coordinator.claim_jobs("worker", lease_seconds=60)[0]
    for reservation_id, parent in (("root", None), ("step-budget", "root")):
        store.reserve_usage(
            seal_contract(
                UsageReservation,
                reservation_id=reservation_id,
                run_id="run-1",
                parent_reservation_id=parent,
                transition_id=f"reserve:{reservation_id}",
                kind="step" if parent else "run",
                tool_calls=1,
            )
        )
    step = coordinator.claim_step(
        run_id="run-1",
        step_id="step-1",
        owner_id=lease.owner_id,
        run_fence=lease.fence,
        transition_id="claim:step-1",
        reservation_id="step-budget",
        lease_seconds=60,
    )
    bindings = [
        SkillBinding(
            skill_id=skill,
            version="1.0",
            digest="1" * 64,
            compatible_profiles=["sast-investigator"],
            prompt_template_ref="prompt",
            input_schema_ref="input",
            output_schema_ref="output",
        )
        for skill in ("skill-a", "skill-b")
    ]
    contract = _contract(
        run_id="run-1",
        step_id="step-1",
        run_fence=lease.fence,
        step_fence=step.fence,
        skill_bindings=bindings,
        allowed_tool_sets=["counter" if authorized else "other-tool"],
        budget_reservation_id="step-budget",
    )
    assert isinstance(contract, AgentWorkContract)
    store.put_object_fenced(
        contract,
        authority=store.issue_authority("run-1", owner_id=lease.owner_id, run_fence=lease.fence),
        run_id="run-1",
        object_type="agent_work_contract",
        object_id=contract.contract_id,
        logical_key="step-1",
        content_digest=contract.content_digest,
    )
    tool = CountingTool()
    registry = ToolRegistry()
    registry.register(tool)
    broker = ToolBroker(
        registry,
        Guardrail(),
        execution_store=ExecutionStore(engine=coordinator.engine),
        ledger=ledger,
        coordinator=coordinator,
        unit_of_work=uow,
        investigation_store=store,
    )
    ctx = context().model_copy(
        update={
            "lease_owner_id": lease.owner_id,
            "lease_fence": lease.fence,
            "run_fence": lease.fence,
            "step_run_id": step.step_run_id,
            "step_fence": step.fence,
            "work_contract_id": contract.contract_id,
            "work_contract_digest": contract.content_digest,
        }
    )
    result = await broker.execute("counter", {"target": "."}, ctx)
    assert result.status == (ToolStatus.SUCCESS if authorized else ToolStatus.ERROR)
    if authorized:
        assert (await broker.execute("counter", {"target": "."}, ctx)).status == ToolStatus.SUCCESS
        assert store.execution_identity(ctx.invocation_id, run_id="run-1") is not None
    projector = OutboxProjector(coordinator.engine, owner_id="projector")
    while ids := projector.claim_batch():
        for event_id in ids:
            projector.project_claimed(event_id)
    usage = query_skill_usage(ledger)
    assert usage["totals"]["calls"] == tool.calls == int(authorized)
    if authorized:
        assert {item["skill_id"] for item in usage["skills"]} == {"skill-a", "skill-b"}
        assert all(item["calls"] == item["succeeded"] == 1 for item in usage["skills"])
        assert all(
            event["payload"]["skill_usage"]["attribution"] == "verified_work_contract" for event in usage["events"]
        )
        assert query_skill_usage(ledger, role="sast-investigator")["totals"]["calls"] == 1
    else:
        assert usage["total_events"] == 0
