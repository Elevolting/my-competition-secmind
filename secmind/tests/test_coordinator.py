from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from secmind.coordinator import CoordinatorConflict, CoordinatorStore, OutboxEventRow
from secmind.execution import (
    ApprovalRow,
    ExecutionConflict,
    ExecutionStore,
    StaleFenceError,
    ToolInvocationRow,
)
from secmind.ledger import LedgerStore
from secmind.schemas import (
    AgentState,
    ApprovalDecision,
    ApprovalRequest,
    ApprovalResponse,
    InvocationStatus,
    RiskLevel,
    TaskRequest,
    ToolResult,
    ToolStatus,
)


def state(run_id: str) -> AgentState:
    return AgentState(run_id=run_id, task=TaskRequest(objective="Audit this Python project"))


def test_run_queue_uses_lease_heartbeat_and_monotonic_fence(tmp_path) -> None:
    store = CoordinatorStore(f"sqlite:///{(tmp_path / 'queue.db').as_posix()}")
    start = datetime.now(UTC)
    store.enqueue_run("run-1", next_attempt_at=start)

    first = store.claim_jobs("worker-a", lease_seconds=10, now=start)
    assert [(item.run_id, item.fence) for item in first] == [("run-1", 1)]
    assert store.claim_jobs("worker-b", now=start + timedelta(seconds=5)) == []

    renewed = store.heartbeat("run-1", owner_id="worker-a", fence=1, lease_seconds=10, now=start + timedelta(seconds=5))
    assert renewed.lease_until == start + timedelta(seconds=15)
    second = store.claim_jobs("worker-b", now=start + timedelta(seconds=16))
    assert [(item.owner_id, item.fence, item.attempts) for item in second] == [("worker-b", 2, 2)]

    with pytest.raises(CoordinatorConflict, match="fenced"):
        store.finish_job("run-1", owner_id="worker-a", fence=1)
    store.finish_job("run-1", owner_id="worker-b", fence=2)
    store.close()


def test_step_heartbeat_extends_only_under_the_current_run_fence(tmp_path) -> None:
    store = CoordinatorStore(f"sqlite:///{(tmp_path / 'step-heartbeat.db').as_posix()}")
    start = datetime.now(UTC)
    store.enqueue_run("run-step-heartbeat", next_attempt_at=start)
    run_lease = store.claim_jobs("worker-a", lease_seconds=10, now=start)[0]
    step_lease = store.claim_step(
        run_id=run_lease.run_id,
        step_id="scan",
        owner_id=run_lease.owner_id,
        run_fence=run_lease.fence,
        transition_id="scan:attempt:1",
        lease_seconds=8,
        now=start,
    )

    renewed = store.heartbeat_step(step_lease, lease_seconds=30, now=start + timedelta(seconds=5))
    renewed_until = (
        renewed.lease_until if renewed.lease_until.tzinfo is not None else renewed.lease_until.replace(tzinfo=UTC)
    )
    assert renewed_until == start + timedelta(seconds=35)

    replacement = store.claim_jobs("worker-b", lease_seconds=30, now=start + timedelta(seconds=11))[0]
    assert replacement.fence > run_lease.fence
    with pytest.raises(CoordinatorConflict, match="fenced"):
        store.heartbeat_step(renewed, lease_seconds=30, now=start + timedelta(seconds=12))
    store.close()


def test_stale_step_lease_is_reclaimed_only_for_idempotent_work(tmp_path) -> None:
    store = CoordinatorStore(f"sqlite:///{(tmp_path / 'step-reclaim.db').as_posix()}")
    start = datetime.now(UTC)
    store.enqueue_run("run-step-reclaim", next_attempt_at=start)
    first = store.claim_jobs("worker-a", lease_seconds=10, now=start)[0]
    store.claim_step(
        run_id=first.run_id,
        step_id="scan",
        owner_id=first.owner_id,
        run_fence=first.fence,
        transition_id="scan:first",
        lease_seconds=180,
        now=start,
    )

    replacement = store.claim_jobs("worker-b", lease_seconds=60, now=start + timedelta(seconds=11))[0]
    assert store.active_step_lease_ids(first.run_id) == []
    with pytest.raises(CoordinatorConflict, match="non-idempotent"):
        store.claim_step(
            run_id=replacement.run_id,
            step_id="scan",
            owner_id=replacement.owner_id,
            run_fence=replacement.fence,
            transition_id="scan:replacement",
            idempotent=False,
            now=start + timedelta(seconds=12),
        )

    reclaimed = store.claim_step(
        run_id=replacement.run_id,
        step_id="scan",
        owner_id=replacement.owner_id,
        run_fence=replacement.fence,
        transition_id="scan:replacement",
        idempotent=True,
        now=start + timedelta(seconds=12),
    )
    assert reclaimed.attempt == 2
    assert reclaimed.run_fence == replacement.fence
    store.close()


def test_ensure_job_awake_heals_waiting_without_revoking_live_lease(tmp_path) -> None:
    store = CoordinatorStore(f"sqlite:///{(tmp_path / 'wake.db').as_posix()}")
    store.enqueue_run("run-wake")
    first = store.claim_jobs("worker-a", lease_seconds=60)[0]
    assert store.ensure_job_awake("run-wake") is False
    store.park_job("run-wake", owner_id=first.owner_id, fence=first.fence)
    assert store.job_status("run-wake")[0] == "queued"
    assert store.ensure_job_awake("run-wake") is False
    second = store.claim_jobs("worker-b", lease_seconds=60)[0]
    assert second.fence > first.fence
    assert second.attempts == 1
    assert store.ensure_job_awake("run-wake") is False

    store.enqueue_run("run-parked")
    parked = store.claim_jobs("worker-c", lease_seconds=60)[0]
    store.park_job("run-parked", owner_id=parked.owner_id, fence=parked.fence)
    assert store.ensure_job_awake("run-parked") is True
    assert store.job_status("run-parked")[0] == "queued"
    store.close()


def test_retry_budget_counts_only_consecutive_failures(tmp_path) -> None:
    store = CoordinatorStore(f"sqlite:///{(tmp_path / 'retry-sequence.db').as_posix()}")
    store.enqueue_run("run-retry-sequence")
    first = store.claim_jobs("worker-a", lease_seconds=60)[0]
    store.park_job(first.run_id, owner_id=first.owner_id, fence=first.fence)
    store.wake_job(first.run_id)

    resumed = store.claim_jobs("worker-b", lease_seconds=60)[0]
    assert resumed.attempts == 1
    store.retry_job(
        resumed.run_id,
        owner_id=resumed.owner_id,
        fence=resumed.fence,
        delay_seconds=0,
        error="retryable",
    )
    retried = store.claim_jobs("worker-c", lease_seconds=60)[0]
    assert retried.attempts == 2
    store.close()


def test_transition_cas_and_outbox_are_atomic_and_replayable(tmp_path) -> None:
    url = f"sqlite:///{(tmp_path / 'transition.db').as_posix()}"
    coordinator = CoordinatorStore(url)
    ledger = LedgerStore(url)
    current = state("run-cas")
    ledger.save_state(current)
    assert current.state_version == 1
    coordinator.enqueue_run(current.run_id)
    lease = coordinator.claim_jobs("worker-1")[0]

    version = coordinator.commit_transition(
        current,
        expected_version=1,
        owner_id=lease.owner_id,
        fence=lease.fence,
        transition_id="plan:1",
        event_type="plan.created",
        payload={"steps": 3},
    )
    assert version == 2
    assert len(coordinator.pending_outbox()) == 1

    assert (
        coordinator.commit_transition(
            current,
            expected_version=1,
            owner_id=lease.owner_id,
            fence=lease.fence,
            transition_id="plan:1",
            event_type="plan.created",
            payload={"steps": 3},
        )
        == 2
    )
    with pytest.raises(CoordinatorConflict, match="different event"):
        coordinator.commit_transition(
            current,
            expected_version=2,
            owner_id=lease.owner_id,
            fence=lease.fence,
            transition_id="plan:1",
            event_type="plan.created",
            payload={"steps": 4},
        )
    with pytest.raises(CoordinatorConflict, match="compare-and-swap"):
        coordinator.commit_transition(
            current,
            expected_version=1,
            owner_id=lease.owner_id,
            fence=lease.fence,
            transition_id="plan:2",
            event_type="plan.revised",
            payload={},
        )

    event = coordinator.pending_outbox()[0]
    coordinator.mark_outbox_projected(event.outbox_id)
    coordinator.mark_outbox_projected(event.outbox_id)
    assert coordinator.pending_outbox() == []
    ledger.close()
    coordinator.close()


@pytest.mark.parametrize("status", ["pending", "projecting", "failed"])
def test_quiet_gate_treats_every_unprojected_outbox_status_as_blocking(tmp_path, status: str) -> None:
    store = CoordinatorStore(f"sqlite:///{(tmp_path / f'outbox-{status}.db').as_posix()}")
    run_id = f"run-{status}"
    store.enqueue_run(run_id)
    with Session(store.engine) as session:
        session.add(
            OutboxEventRow(
                outbox_id=f"outbox-{status}",
                run_id=run_id,
                transition_id=f"transition-{status}",
                transition_ordinal=17,
                event_type="test.event",
                actor="test",
                payload_json="{}",
                status=status,
                created_at=datetime.now(UTC),
            )
        )
        session.commit()

    assert store.pending_outbox_ordinals(run_id) == [17]
    with Session(store.engine) as session:
        row = session.query(OutboxEventRow).one()
        row.status = "projected"
        session.commit()
    assert store.pending_outbox_ordinals(run_id) == []
    store.close()


def test_operator_retry_outbox_is_digest_bound_and_audited(tmp_path) -> None:
    store = CoordinatorStore(f"sqlite:///{(tmp_path / 'outbox-retry.db').as_posix()}")
    outbox_id = store.enqueue_outbox(
        "run-outbox-retry",
        transition_id="transition-outbox-retry",
        event_type="run.updated",
        payload={"status": "running"},
    )
    with Session(store.engine) as session:
        row = session.get(OutboxEventRow, outbox_id)
        assert row is not None
        payload_digest = row.payload_digest
        row.status = "dead_letter"
        session.commit()

    assert payload_digest is not None
    assert store.retry_outbox(
        outbox_id,
        actor="operator-1",
        reason="external database outage was repaired",
        expected_payload_digest=payload_digest,
    )
    with Session(store.engine) as session:
        original = session.get(OutboxEventRow, outbox_id)
        receipts = session.scalars(
            select(OutboxEventRow).where(OutboxEventRow.event_type == "outbox.retry_authorized")
        ).all()
        assert original is not None and original.status == "retry_wait" and original.attempts == 0
        assert len(receipts) == 1
    with pytest.raises(CoordinatorConflict, match="payload digest"):
        store.retry_outbox(
            outbox_id,
            actor="operator-1",
            reason="wrong digest",
            expected_payload_digest="0" * 64,
        )
    store.close()


def test_approval_is_run_bound_and_resolution_is_consumed_once(tmp_path) -> None:
    store = ExecutionStore(f"sqlite:///{(tmp_path / 'approval.db').as_posix()}")
    request = ApprovalRequest(
        request_id="approval-1",
        run_id="run-a",
        step_id="network-step",
        tool_name="advisory_updater",
        parameters={"channel": "stable"},
        target="offline-db",
        risk_level=RiskLevel.R2,
        reason="network access",
        expected_impact="updates vulnerability metadata",
    )
    store.register_approval(request)
    response = ApprovalResponse(decision=ApprovalDecision.APPROVE)
    with pytest.raises(ExecutionConflict, match="different run"):
        store.resolve_approval(request.request_id, response, run_id="run-b", fence=1)

    resolution_id = store.resolve_approval(request.request_id, response, run_id="run-a", fence=1)
    assert resolution_id == store.resolve_approval(request.request_id, response, run_id="run-a", fence=1)
    assert (
        store.consume_approval(
            request.request_id,
            run_id="run-a",
            step_id=request.step_id,
            tool_name=request.tool_name,
            parameters=request.parameters,
            fence=1,
            resolution_id=resolution_id,
        )
        == resolution_id
    )
    with pytest.raises(ExecutionConflict, match="already consumed"):
        store.consume_approval(
            request.request_id,
            run_id="run-a",
            step_id=request.step_id,
            tool_name=request.tool_name,
            parameters=request.parameters,
            fence=1,
        )
    with Session(store.engine) as session:
        assert session.get(ApprovalRow, request.request_id).status == "consumed"
    store.close()


def test_stale_invocation_fence_cannot_commit_after_reclaim(tmp_path) -> None:
    store = ExecutionStore(f"sqlite:///{(tmp_path / 'invocation.db').as_posix()}")
    args = dict(
        run_id="run-1",
        step_id="scan",
        tool_name="scanner",
        tool_version="1",
        idempotency_key="run-1:scan",
        parameters={"path": "src"},
        idempotent=True,
        lease_seconds=60,
    )
    status, _ = store.claim_invocation(invocation_id="invocation-1", owner_id="worker-a", fence=1, **args)
    assert status == InvocationStatus.RUNNING
    with Session(store.engine) as session:
        row = session.get(ToolInvocationRow, "invocation-1")
        assert row is not None
        row.lease_until = datetime.now(UTC) - timedelta(seconds=1)
        session.commit()

    status, _ = store.claim_invocation(invocation_id="invocation-2", owner_id="worker-b", fence=2, **args)
    assert status == InvocationStatus.RUNNING
    result = ToolResult(invocation_id="invocation-2", status=ToolStatus.SUCCESS)
    with pytest.raises(StaleFenceError, match="id is stale"):
        store.complete_invocation("run-1", "run-1:scan", result, invocation_id="invocation-1", attempt=1, fence=1)
    store.complete_invocation("run-1", "run-1:scan", result, invocation_id="invocation-2", attempt=2, fence=2)
    store.close()


def test_tool_completion_and_outbox_commit_together(tmp_path) -> None:
    url = f"sqlite:///{(tmp_path / 'tool-outbox.db').as_posix()}"
    coordinator = CoordinatorStore(url)
    execution = ExecutionStore(url)
    coordinator.enqueue_run("run-atomic")
    lease = coordinator.claim_jobs("worker", lease_seconds=60)[0]
    status, _ = execution.claim_invocation(
        invocation_id="invocation-atomic",
        run_id="run-atomic",
        step_id="scan",
        tool_name="scanner",
        tool_version="1",
        idempotency_key="run-atomic:scan:1",
        parameters={"target": "."},
        idempotent=True,
        lease_seconds=60,
        owner_id=lease.owner_id,
        fence=lease.fence,
    )
    assert status == InvocationStatus.RUNNING
    result = ToolResult(invocation_id="invocation-atomic", status=ToolStatus.SUCCESS)
    coordinator.complete_tool_invocation(
        run_id="run-atomic",
        idempotency_key="run-atomic:scan:1",
        invocation_id="invocation-atomic",
        attempt=1,
        owner_id=lease.owner_id,
        fence=lease.fence,
        result=result,
        transition_id="tool:run-atomic:scan:1:completed",
        event_type="tool.completed",
        payload={"tool": "scanner", "status": "success"},
    )
    assert coordinator.pending_outbox()[0].event_type == "tool.completed"
    with Session(execution.engine) as session:
        row = session.get(ToolInvocationRow, "invocation-atomic")
        assert row is not None and row.status == InvocationStatus.COMPLETED.value
    execution.close()
    coordinator.close()
