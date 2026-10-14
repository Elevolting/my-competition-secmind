from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest
from conftest import seal_execution_contract
from sqlalchemy import update
from sqlalchemy.orm import Session

from secmind.coordinator import CoordinatorConflict, CoordinatorStore, RunJobRow
from secmind.execution import ApprovalRow, ExecutionConflict, ExecutionStore
from secmind.investigation.contracts import UsageReservation, seal_contract
from secmind.investigation.store import InvestigationStore
from secmind.ledger import LedgerStore
from secmind.schemas import (
    AgentState,
    ApprovalDecision,
    ApprovalRequest,
    ApprovalResponse,
    InvocationStatus,
    RiskLevel,
    RunStatus,
    StepStatus,
    TaskRequest,
    ToolResult,
    ToolStatus,
)
from secmind.unit_of_work import CapabilityGrantRow, ControlPlaneUnitOfWork


def _database_url(tmp_path: object) -> str:
    return f"sqlite:///{tmp_path}/v04-uow.db"


def test_submit_is_one_transaction_and_idempotent(tmp_path) -> None:
    url = _database_url(tmp_path)
    coordinator = CoordinatorStore(url)
    uow = ControlPlaneUnitOfWork(coordinator.engine)
    ledger = LedgerStore(url)
    state = AgentState(run_id="run-uow", task=TaskRequest(objective="audit this repository"))

    assert uow.submit_run(state) is True
    assert uow.submit_run(state) is False
    stored = ledger.load_state(state.run_id)
    assert stored is not None and stored.status == RunStatus.PENDING
    assert coordinator.job_status(state.run_id)[0] == "queued"
    pending = coordinator.pending_outbox()
    assert [(item.event_type, item.transition_id) for item in pending] == [("run.queued", "run:run-uow:submitted")]


def test_submit_does_not_publish_job_when_root_budget_write_fails(tmp_path, monkeypatch) -> None:
    url = _database_url(tmp_path)
    coordinator = CoordinatorStore(url)
    ledger = LedgerStore(engine=coordinator.engine)
    investigation = InvestigationStore(engine=coordinator.engine)
    uow = ControlPlaneUnitOfWork(coordinator.engine)
    state = AgentState(run_id="run-budget-atomic", task=TaskRequest(objective="audit this repository"))
    reservation = seal_contract(
        UsageReservation, run_id=state.run_id,
        transition_id=f"run:{state.run_id}:budget-root", kind="run",
        tool_calls=2,
    )
    stage = ControlPlaneUnitOfWork._stage_root_reservation

    def fail_after_staging(session, value, now):
        stage(session, value, now)
        raise RuntimeError("injected budget transaction failure")

    monkeypatch.setattr(ControlPlaneUnitOfWork, "_stage_root_reservation", staticmethod(fail_after_staging))
    with pytest.raises(RuntimeError, match="injected budget transaction failure"):
        uow.submit_run(state, root_reservation=reservation)
    assert ledger.load_state(state.run_id) is None
    assert coordinator.pending_outbox() == []
    assert investigation.unsettled_reservation_ids(state.run_id, include_run_envelope=True) == []
    with pytest.raises(KeyError):
        coordinator.job_status(state.run_id)

    monkeypatch.setattr(ControlPlaneUnitOfWork, "_stage_root_reservation", staticmethod(stage))
    assert uow.submit_run(state, root_reservation=reservation)
    assert coordinator.job_status(state.run_id)[0] == "queued"
    assert investigation.unsettled_reservation_ids(state.run_id, include_run_envelope=True) == [
        reservation.reservation_id,
    ]


def test_approval_resolution_grant_consume_and_wake_are_atomic(tmp_path) -> None:
    url = _database_url(tmp_path)
    coordinator = CoordinatorStore(url)
    uow = ControlPlaneUnitOfWork(coordinator.engine)
    execution = ExecutionStore(url)
    ledger = LedgerStore(url)
    request = ApprovalRequest(
        request_id="approval-uow",
        run_id="run-approval",
        step_id="step-network",
        tool_name="approved-tool",
        parameters={"target": "scope-a"},
        target="scope-a",
        risk_level=RiskLevel.R2,
        reason="network access",
        expected_impact="read metadata",
    )
    state = AgentState(
        run_id=request.run_id,
        task=TaskRequest(objective="audit this repository", target_scope=["scope-a"]),
        status=RunStatus.WAITING_APPROVAL,
        pending_approval=request,
    )
    seal_execution_contract(state)
    assert uow.submit_run(state)
    execution.register_approval(request)
    with Session(coordinator.engine) as session:
        session.execute(update(RunJobRow).where(RunJobRow.run_id == state.run_id).values(status="waiting"))
        session.commit()
    response = ApprovalResponse(decision=ApprovalDecision.APPROVE, resolution_id="resolution-uow")

    def resolve() -> tuple[str, bool]:
        return uow.resolve_approval_and_wake(
            run_id=state.run_id,
            request_id=request.request_id,
            response=response,
            actor="operator:test",
            fence=0,
        )

    with ThreadPoolExecutor(max_workers=10) as pool:
        results = list(pool.map(lambda _: resolve(), range(50)))
    assert sum(changed for _, changed in results) == 1
    assert {resolution for resolution, _ in results} == {"resolution-uow"}
    assert coordinator.job_status(state.run_id)[0] == "queued"
    with Session(coordinator.engine) as session:
        approval = session.get(ApprovalRow, request.request_id)
        grants = session.query(CapabilityGrantRow).filter_by(run_id=state.run_id).all()
        assert approval is not None and approval.status == "consumed"
        assert len(grants) == 1
        assert grants[0].max_uses == 1
    assert ledger.load_state(state.run_id) is not None


def test_denied_approval_is_consumed_and_wakes_without_grant(tmp_path) -> None:
    url = _database_url(tmp_path)
    coordinator = CoordinatorStore(url)
    uow = ControlPlaneUnitOfWork(coordinator.engine)
    execution = ExecutionStore(url)
    request = ApprovalRequest(
        request_id="approval-deny",
        run_id="run-deny",
        step_id="step",
        tool_name="tool",
        parameters={},
        target="scope",
        risk_level=RiskLevel.R2,
        reason="approval",
        expected_impact="none",
    )
    state = AgentState(
        run_id=request.run_id,
        task=TaskRequest(objective="audit the repository"),
        status=RunStatus.WAITING_APPROVAL,
        pending_approval=request,
    )
    seal_execution_contract(state)
    uow.submit_run(state)
    execution.register_approval(request)
    _, changed = uow.resolve_approval_and_wake(
        run_id=state.run_id,
        request_id=request.request_id,
        response=ApprovalResponse(decision=ApprovalDecision.DENY),
        actor="operator:test",
        fence=0,
    )
    assert changed is True
    with Session(coordinator.engine) as session:
        assert session.query(CapabilityGrantRow).count() == 0
        assert session.get(ApprovalRow, request.request_id).status == "consumed"  # type: ignore[union-attr]


def test_expired_step_lease_is_fenced_before_reclaim(tmp_path) -> None:
    url = _database_url(tmp_path)
    coordinator = CoordinatorStore(url)
    uow = ControlPlaneUnitOfWork(coordinator.engine)
    state = AgentState(run_id="run-step", task=TaskRequest(objective="audit the repository"))
    uow.submit_run(state)
    run_lease = coordinator.claim_jobs("worker-a", lease_seconds=120)[0]
    claimed_at = datetime.now(UTC)
    old = coordinator.claim_step(
        run_id=state.run_id,
        step_id="scan",
        owner_id=run_lease.owner_id,
        run_fence=run_lease.fence,
        transition_id="step:scan",
        lease_seconds=1,
        now=claimed_at,
    )
    new = coordinator.claim_step(
        run_id=state.run_id,
        step_id="scan",
        owner_id=run_lease.owner_id,
        run_fence=run_lease.fence,
        transition_id="step:scan:retry",
        lease_seconds=30,
        now=claimed_at + timedelta(seconds=2),
    )
    assert new.fence > old.fence and new.attempt == old.attempt + 1
    with pytest.raises(CoordinatorConflict):
        coordinator.complete_step(
            old,
            status=StepStatus.SUCCEEDED,
            result={"late": True},
            dependency_outputs={},
        )
    coordinator.complete_step(
        new,
        status=StepStatus.SUCCEEDED,
        result={"ok": True},
        dependency_outputs={"report": "artifact-sha"},
    )


def test_capability_grant_is_consumed_with_one_logical_invocation(tmp_path) -> None:
    url = _database_url(tmp_path)
    coordinator = CoordinatorStore(url)
    uow = ControlPlaneUnitOfWork(coordinator.engine)
    execution = ExecutionStore(url)
    request = ApprovalRequest(
        request_id="approval-tool",
        run_id="run-tool",
        step_id="step",
        tool_name="r2-tool",
        parameters={"target": "."},
        target=".",
        risk_level=RiskLevel.R2,
        reason="R2",
        expected_impact="bounded",
    )
    state = AgentState(
        run_id=request.run_id,
        task=TaskRequest(objective="audit the repository"),
        status=RunStatus.WAITING_APPROVAL,
        pending_approval=request,
    )
    seal_execution_contract(state)
    uow.submit_run(state)
    execution.register_approval(request)
    uow.resolve_approval_and_wake(
        run_id=state.run_id,
        request_id=request.request_id,
        response=ApprovalResponse(decision=ApprovalDecision.APPROVE),
        actor="operator:test",
        fence=0,
    )
    grant = uow.grants_for_run(state.run_id)[0]
    lease = coordinator.claim_jobs("worker", lease_seconds=60)[0]
    status, _, attempt = uow.claim_tool_invocation(
        invocation_id="invocation-1",
        run_id=state.run_id,
        step_id="step",
        tool_name="r2-tool",
        tool_version="1",
        idempotency_key="logical-1",
        parameters=request.parameters,
        idempotent=True,
        lease_seconds=30,
        owner_id=lease.owner_id,
        fence=lease.fence,
        grant_id=grant.grant_id,
        grant_required=True,
    )
    assert status.value == "running" and attempt == 1
    coordinator.complete_tool_invocation(
        run_id=state.run_id,
        idempotency_key="logical-1",
        invocation_id="invocation-1",
        attempt=1,
        owner_id=lease.owner_id,
        fence=lease.fence,
        result=ToolResult(status=ToolStatus.SUCCESS, summary="done"),
        transition_id="tool:logical-1:completed",
        event_type="tool.completed",
        payload={"status": "success"},
    )
    cached = uow.cached_tool_result(
        run_id=state.run_id,
        idempotency_key="logical-1",
        tool_name="r2-tool",
        tool_version="1",
        parameters=request.parameters,
    )
    assert cached is not None and cached.status == ToolStatus.SUCCESS
    with pytest.raises(ExecutionConflict):
        uow.claim_tool_invocation(
            invocation_id="invocation-2",
            run_id=state.run_id,
            step_id="step",
            tool_name="r2-tool",
            tool_version="1",
            idempotency_key="logical-2",
            parameters=request.parameters,
            idempotent=True,
            lease_seconds=30,
            owner_id=lease.owner_id,
            fence=lease.fence,
            grant_id=grant.grant_id,
            grant_required=True,
        )


def test_approval_grant_scope_cannot_be_widened_by_raw_task_mutation(tmp_path) -> None:
    url = _database_url(tmp_path)
    coordinator = CoordinatorStore(url)
    uow = ControlPlaneUnitOfWork(coordinator.engine)
    execution = ExecutionStore(url)
    request = ApprovalRequest(
        request_id="approval-contract-scope",
        run_id="run-contract-scope",
        step_id="step",
        tool_name="r2-tool",
        parameters={"target": "scope-a"},
        target="scope-a",
        risk_level=RiskLevel.R2,
        reason="R2",
        expected_impact="bounded",
    )
    state = AgentState(
        run_id=request.run_id,
        task=TaskRequest(objective="audit the repository", target_scope=["scope-a"]),
        status=RunStatus.WAITING_APPROVAL,
        pending_approval=request,
    )
    seal_execution_contract(state)
    # Simulate an untrusted raw request mutation after contract compilation.
    state.task.target_scope = ["../../host", "secrets"]
    uow.submit_run(state)
    execution.register_approval(request)

    uow.resolve_approval_and_wake(
        run_id=state.run_id,
        request_id=request.request_id,
        response=ApprovalResponse(decision=ApprovalDecision.APPROVE),
        actor="operator:test",
        fence=0,
    )

    grant = uow.grants_for_run(state.run_id)[0]
    assert grant.target_scope == ["scope-a"]


@pytest.mark.parametrize(
    ("idempotent", "expected_status", "expected_attempt"),
    [
        (True, InvocationStatus.RUNNING, 2),
        (False, InvocationStatus.RECOVERY_REQUIRED, 1),
    ],
)
def test_stale_fence_invocation_is_reclaimed_only_when_idempotent(
    tmp_path,
    idempotent: bool,
    expected_status: InvocationStatus,
    expected_attempt: int,
) -> None:
    url = f"sqlite:///{tmp_path}/stale-invocation-{idempotent}.db"
    coordinator = CoordinatorStore(url)
    uow = ControlPlaneUnitOfWork(coordinator.engine)
    run_id = f"run-stale-invocation-{idempotent}"
    uow.submit_run(AgentState(run_id=run_id, task=TaskRequest(objective="audit the repository")))
    old = coordinator.claim_jobs("worker-old", lease_seconds=60)[0]
    status, _, attempt = uow.claim_tool_invocation(
        invocation_id="invocation-old",
        run_id=run_id,
        step_id="scan",
        tool_name="scanner",
        tool_version="1",
        idempotency_key="logical-scan",
        parameters={"target": "."},
        idempotent=idempotent,
        lease_seconds=300,
        owner_id=old.owner_id,
        fence=old.fence,
        grant_id=None,
        grant_required=False,
    )
    assert status == InvocationStatus.RUNNING and attempt == 1
    with Session(coordinator.engine) as session:
        session.execute(
            update(RunJobRow)
            .where(RunJobRow.run_id == run_id)
            .values(lease_until=datetime.now(UTC) - timedelta(seconds=1))
        )
        session.commit()
    replacement = coordinator.claim_jobs("worker-new", lease_seconds=60)[0]

    status, _, attempt = uow.claim_tool_invocation(
        invocation_id="invocation-new",
        run_id=run_id,
        step_id="scan",
        tool_name="scanner",
        tool_version="1",
        idempotency_key="logical-scan",
        parameters={"target": "."},
        idempotent=idempotent,
        lease_seconds=300,
        owner_id=replacement.owner_id,
        fence=replacement.fence,
        grant_id=None,
        grant_required=False,
    )
    assert status == expected_status
    assert attempt == expected_attempt
