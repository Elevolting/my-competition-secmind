from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from secmind.coordinator import (
    CoordinatorConflict,
    CoordinatorStore,
    ModelInvocationRow,
    OutboxEventRow,
)
from secmind.execution import (
    ApprovalRow,
    ExecutionConflict,
    ExecutionStore,
    StaleFenceError,
    ToolInvocationRow,
)
from secmind.guardrail import Guardrail
from secmind.ledger import LedgerStore
from secmind.llm import QwenGateway
from secmind.orchestrator import SecMindOrchestrator
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
from secmind.tools import ToolBroker, default_registry


def _state(run_id: str) -> AgentState:
    return AgentState(run_id=run_id, task=TaskRequest(objective="audit"))


@pytest.mark.parametrize("worker_count", [2, 4])
def test_multiple_workers_claim_each_of_100_runs_once(tmp_path, worker_count: int) -> None:
    url = f"sqlite:///{(tmp_path / f'claims-{worker_count}.db').as_posix()}"
    seed = CoordinatorStore(url)
    for index in range(100):
        seed.enqueue_run(f"run-{index:03d}")
    seed.close()

    def claim(owner: str) -> list[tuple[str, int]]:
        store = CoordinatorStore(url)
        claimed: list[tuple[str, int]] = []
        try:
            while True:
                leases = store.claim_jobs(owner, limit=7, lease_seconds=300)
                if not leases:
                    return claimed
                for lease in leases:
                    claimed.append((lease.run_id, lease.fence))
                    store.finish_job(lease.run_id, owner_id=owner, fence=lease.fence)
        finally:
            store.close()

    with ThreadPoolExecutor(max_workers=worker_count) as pool:
        batches = list(pool.map(claim, [f"worker-{index}" for index in range(worker_count)]))

    all_claims = [claim for batch in batches for claim in batch]
    assert len(all_claims) == 100
    assert len({run_id for run_id, _ in all_claims}) == 100
    assert {fence for _, fence in all_claims} == {1}


def test_expired_owner_cannot_cas_state_or_create_outbox(tmp_path) -> None:
    url = f"sqlite:///{(tmp_path / 'stale-cas.db').as_posix()}"
    coordinator = CoordinatorStore(url)
    ledger = LedgerStore(url)
    current = _state("run-fenced")
    ledger.save_state(current)
    coordinator.enqueue_run(current.run_id)
    start = datetime.now(UTC)
    old = coordinator.claim_jobs("old", lease_seconds=1, now=start)[0]
    new = coordinator.claim_jobs("new", lease_seconds=60, now=start + timedelta(seconds=2))[0]

    with pytest.raises(CoordinatorConflict, match="fenced"):
        coordinator.commit_transition(
            current,
            expected_version=1,
            owner_id=old.owner_id,
            fence=old.fence,
            transition_id="stale-transition",
            event_type="state.changed",
            payload={"owner": "old"},
        )
    assert coordinator.pending_outbox() == []

    assert (
        coordinator.commit_transition(
            current,
            expected_version=1,
            owner_id=new.owner_id,
            fence=new.fence,
            transition_id="fresh-transition",
            event_type="state.changed",
            payload={"owner": "new"},
        )
        == 2
    )
    assert [event.transition_id for event in coordinator.pending_outbox()] == ["fresh-transition"]
    ledger.close()
    coordinator.close()


def test_queue_retry_park_wake_cancel_and_validation_paths(tmp_path) -> None:
    store = CoordinatorStore(f"sqlite:///{(tmp_path / 'lifecycle.db').as_posix()}")
    with pytest.raises(ValueError):
        store.claim_jobs("")
    with pytest.raises(ValueError):
        store.finish_job("missing", owner_id="worker", fence=1, status="invalid")
    with pytest.raises(ValueError):
        store.park_job("missing", owner_id="worker", fence=1, status="invalid")
    with pytest.raises(KeyError):
        store.wake_job("missing")
    with pytest.raises(KeyError):
        store.cancel_job("missing")
    with pytest.raises(KeyError):
        store.job_status("missing")

    start = datetime.now(UTC)
    store.enqueue_run("retry", next_attempt_at=start)
    lease = store.claim_jobs("worker", now=start)[0]
    status, active = store.job_status("retry")
    assert status == "leased" and active == lease
    store.assert_lease("retry", owner_id="worker", fence=lease.fence, now=start)
    store.retry_job("retry", owner_id="worker", fence=lease.fence, delay_seconds=2, error="boom")
    assert store.claim_jobs("other", now=start + timedelta(seconds=1)) == []
    retried = store.claim_jobs("other", now=start + timedelta(seconds=3))[0]
    store.park_job("retry", owner_id="other", fence=retried.fence, status="recovery_required")
    assert store.job_status("retry") == ("recovery_required", None)
    store.wake_job("retry")
    final = store.claim_jobs("final", lease_seconds=60)[0]
    store.finish_job("retry", owner_id="final", fence=final.fence)
    with pytest.raises(CoordinatorConflict, match="terminal"):
        store.wake_job("retry")
    with pytest.raises(CoordinatorConflict, match="terminal"):
        store.enqueue_run("retry")

    store.enqueue_run("cancel")
    store.cancel_job("cancel")
    assert store.job_status("cancel") == ("cancelled", None)
    missing = store.enqueue_outbox("run", transition_id="project", event_type="created", payload={})
    store.mark_outbox_projected(missing)
    store.mark_outbox_projected(missing)
    for event in store.pending_outbox():
        store.mark_outbox_projected(event.outbox_id)
    assert store.pending_outbox() == []
    with pytest.raises(KeyError):
        store.mark_outbox_projected("missing")
    store.close()


def test_fifty_identical_approval_resolutions_are_consumed_once(tmp_path) -> None:
    url = f"sqlite:///{(tmp_path / 'approval-race.db').as_posix()}"
    seed = ExecutionStore(url)
    request = ApprovalRequest(
        request_id="approval-race",
        run_id="run-a",
        step_id="update",
        tool_name="advisory_updater",
        parameters={"channel": "stable"},
        target="offline-db",
        risk_level=RiskLevel.R2,
        reason="network access",
        expected_impact="update database",
    )
    seed.register_approval(request)
    seed.close()
    response = ApprovalResponse(decision=ApprovalDecision.APPROVE)

    def resolve_and_consume(_: int) -> tuple[str, bool]:
        store = ExecutionStore(url)
        try:
            resolution_id = store.resolve_approval(request.request_id, response, run_id=request.run_id, fence=7)
            try:
                store.consume_approval(
                    request.request_id,
                    run_id=request.run_id,
                    step_id=request.step_id,
                    tool_name=request.tool_name,
                    parameters=request.parameters,
                    fence=7,
                    resolution_id=resolution_id,
                )
                consumed = True
            except ExecutionConflict as exc:
                assert "already consumed" in str(exc)
                consumed = False
            return resolution_id, consumed
        finally:
            store.close()

    with ThreadPoolExecutor(max_workers=10) as pool:
        outcomes = list(pool.map(resolve_and_consume, range(50)))

    assert len({resolution_id for resolution_id, _ in outcomes}) == 1
    assert sum(consumed for _, consumed in outcomes) == 1
    check = ExecutionStore(url)
    with Session(check.engine) as session:
        row = session.get(ApprovalRow, request.request_id)
        assert row is not None
        assert row.status == "consumed"
        assert row.fence == 7
        assert row.consumed_at is not None
    with pytest.raises(ExecutionConflict, match="different run"):
        check.resolve_approval(request.request_id, response, run_id="run-b", fence=8)
    check.close()


def test_approval_and_invocation_conflicts_fail_closed(tmp_path) -> None:
    store = ExecutionStore(f"sqlite:///{(tmp_path / 'execution-conflicts.db').as_posix()}")
    request = ApprovalRequest(
        request_id="approval",
        run_id="run",
        step_id="step",
        tool_name="tool",
        parameters={"value": 1},
        target="target",
        risk_level=RiskLevel.R2,
        reason="risk",
        expected_impact="impact",
    )
    store.register_approval(request)
    store.register_approval(request)
    conflicting = request.model_copy(update={"parameters": {"value": 2}})
    with pytest.raises(ExecutionConflict, match="different request"):
        store.register_approval(conflicting)
    with pytest.raises(KeyError):
        store.resolve_approval("missing", ApprovalResponse(decision=ApprovalDecision.APPROVE))
    with pytest.raises(KeyError):
        store.approval_response("missing", run_id="run")
    with pytest.raises(ExecutionConflict, match="not been resolved"):
        store.approval_response(request.request_id, run_id="run")
    with pytest.raises(ExecutionConflict, match="parameters changed after resolution"):
        store.consume_approval(
            request.request_id,
            run_id="run",
            step_id="step",
            tool_name="tool",
            parameters=request.parameters,
            fence=1,
        )

    resolution = store.resolve_approval(
        request.request_id, ApprovalResponse(decision=ApprovalDecision.APPROVE), run_id="run", fence=5
    )
    assert store.approval_response(request.request_id, run_id="run").decision == ApprovalDecision.APPROVE
    assert store.approval_authorizes(
        request.request_id,
        run_id="run",
        step_id="step",
        tool_name="tool",
        parameters=request.parameters,
    )
    with pytest.raises(ExecutionConflict, match="parameters changed"):
        store.consume_approval(
            request.request_id,
            run_id="run",
            step_id="step",
            tool_name="tool",
            parameters={"value": 99},
            fence=5,
        )
    with pytest.raises(ExecutionConflict, match="resolution does not match"):
        store.consume_approval(
            request.request_id,
            run_id="run",
            step_id="step",
            tool_name="tool",
            parameters=request.parameters,
            fence=5,
            resolution_id="wrong",
        )
    with pytest.raises(StaleFenceError, match="approval fence"):
        store.consume_approval(
            request.request_id,
            run_id="run",
            step_id="step",
            tool_name="tool",
            parameters=request.parameters,
            fence=4,
            resolution_id=resolution,
        )

    invocation = {
        "run_id": "run",
        "step_id": "step",
        "tool_name": "tool",
        "tool_version": "1",
        "idempotency_key": "key",
        "parameters": {"value": 1},
        "idempotent": True,
        "lease_seconds": 60,
        "owner_id": "owner",
        "fence": 5,
    }
    status, _ = store.claim_invocation(invocation_id="inv", **invocation)  # type: ignore[arg-type]
    assert status == InvocationStatus.RUNNING
    status, _ = store.claim_invocation(invocation_id="second", **invocation)  # type: ignore[arg-type]
    assert status == InvocationStatus.PENDING
    with pytest.raises(ExecutionConflict, match="different tool input"):
        store.claim_invocation(
            invocation_id="mismatch",
            run_id="run",
            step_id="step",
            tool_name="tool",
            tool_version="1",
            idempotency_key="key",
            parameters={"value": 2},
            idempotent=True,
            lease_seconds=60,
        )
    assert store.invocation_attempt("run", "key", invocation_id="inv", fence=5) == 1
    with pytest.raises(StaleFenceError, match="owner"):
        store.heartbeat_invocation(
            "run",
            "key",
            owner_id="wrong",
            invocation_id="inv",
            attempt=1,
            fence=5,
            lease_seconds=60,
        )
    store.heartbeat_invocation(
        "run",
        "key",
        owner_id="owner",
        invocation_id="inv",
        attempt=1,
        fence=5,
        lease_seconds=60,
    )
    store.fail_invocation("run", "key", "failed", invocation_id="inv", attempt=1, fence=5)
    with pytest.raises(StaleFenceError, match="no longer running"):
        store.complete_invocation(
            "run",
            "key",
            ToolResult(invocation_id="inv", status=ToolStatus.SUCCESS),
            invocation_id="inv",
            attempt=1,
            fence=5,
        )

    status, _ = store.claim_invocation(
        invocation_id="non-idempotent",
        run_id="run",
        step_id="mutate",
        tool_name="mutator",
        tool_version="1",
        idempotency_key="mutation",
        parameters={},
        idempotent=False,
        lease_seconds=60,
    )
    assert status == InvocationStatus.RUNNING
    with Session(store.engine) as session:
        row = session.get(ToolInvocationRow, "non-idempotent")
        assert row is not None
        row.lease_until = datetime.now(UTC) - timedelta(seconds=1)
        session.commit()
    status, _ = store.claim_invocation(
        invocation_id="non-idempotent-retry",
        run_id="run",
        step_id="mutate",
        tool_name="mutator",
        tool_version="1",
        idempotency_key="mutation",
        parameters={},
        idempotent=False,
        lease_seconds=60,
    )
    assert status == InvocationStatus.RECOVERY_REQUIRED
    store.close()


def test_outbox_dedupe_is_strict_under_replay_and_conflict(tmp_path) -> None:
    store = CoordinatorStore(f"sqlite:///{(tmp_path / 'outbox.db').as_posix()}")
    first = store.enqueue_outbox(
        "run",
        transition_id="transition-1",
        event_type="step.completed",
        payload={"finding_ids": ["a", "b"]},
        actor="worker",
    )
    assert (
        store.enqueue_outbox(
            "run",
            transition_id="transition-1",
            event_type="step.completed",
            payload={"finding_ids": ["a", "b"]},
            actor="worker",
        )
        == first
    )
    with pytest.raises(CoordinatorConflict, match="different event"):
        store.enqueue_outbox(
            "run",
            transition_id="transition-1",
            event_type="step.completed",
            payload={"finding_ids": ["tampered"]},
            actor="worker",
        )
    with Session(store.engine) as session:
        assert session.scalar(select(func.count()).select_from(OutboxEventRow)) == 1
    store.close()


def test_expired_run_lease_rejects_late_tool_completion(tmp_path) -> None:
    """A reclaimed run must fence a tool result even if its invocation row is unchanged."""
    url = f"sqlite:///{(tmp_path / 'late-tool.db').as_posix()}"
    coordinator = CoordinatorStore(url)
    execution = ExecutionStore(url)
    coordinator.enqueue_run("run-late")
    start = datetime.now(UTC)
    old = coordinator.claim_jobs("old", lease_seconds=1, now=start)[0]
    claimed, _ = execution.claim_invocation(
        invocation_id="inv-old",
        run_id="run-late",
        step_id="scan",
        tool_name="scanner",
        tool_version="1",
        idempotency_key="scan-1",
        parameters={"target": "."},
        idempotent=True,
        lease_seconds=300,
        owner_id=old.owner_id,
        fence=old.fence,
    )
    assert claimed == InvocationStatus.RUNNING
    new = coordinator.claim_jobs("new", lease_seconds=60, now=start + timedelta(seconds=2))[0]
    assert new.fence > old.fence

    with pytest.raises(CoordinatorConflict, match="fenced"):
        coordinator.complete_tool_invocation(
            run_id="run-late",
            idempotency_key="scan-1",
            invocation_id="inv-old",
            attempt=1,
            owner_id=old.owner_id,
            fence=old.fence,
            result=ToolResult(invocation_id="inv-old", status=ToolStatus.SUCCESS),
            transition_id="tool:scan-1:completed",
            event_type="tool.completed",
            payload={"status": "success"},
        )
    execution.close()
    coordinator.close()


def test_cancelled_run_rejects_late_tool_completion(tmp_path) -> None:
    url = f"sqlite:///{(tmp_path / 'cancel-tool.db').as_posix()}"
    coordinator = CoordinatorStore(url)
    execution = ExecutionStore(url)
    coordinator.enqueue_run("run-cancel")
    lease = coordinator.claim_jobs("worker", lease_seconds=300)[0]
    status, _ = execution.claim_invocation(
        invocation_id="inv-cancel",
        run_id="run-cancel",
        step_id="scan",
        tool_name="scanner",
        tool_version="1",
        idempotency_key="scan-cancel",
        parameters={},
        idempotent=True,
        lease_seconds=300,
        owner_id=lease.owner_id,
        fence=lease.fence,
    )
    assert status == InvocationStatus.RUNNING
    coordinator.cancel_job("run-cancel")

    with pytest.raises(CoordinatorConflict, match="cancelled|fenced"):
        coordinator.complete_tool_invocation(
            run_id="run-cancel",
            idempotency_key="scan-cancel",
            invocation_id="inv-cancel",
            attempt=1,
            owner_id=lease.owner_id,
            fence=lease.fence,
            result=ToolResult(invocation_id="inv-cancel", status=ToolStatus.SUCCESS),
            transition_id="tool:scan-cancel:completed",
            event_type="tool.completed",
            payload={"status": "success"},
        )
    execution.close()
    coordinator.close()


def test_kill_after_tool_commit_recovers_cached_result_without_duplicate_outbox(tmp_path) -> None:
    """Simulate process loss after DB commit but before graph checkpoint acknowledgement."""
    url = f"sqlite:///{(tmp_path / 'tool-kill-window.db').as_posix()}"
    coordinator = CoordinatorStore(url)
    execution = ExecutionStore(url)
    coordinator.enqueue_run("run-kill")
    lease = coordinator.claim_jobs("worker", lease_seconds=60)[0]
    status, _ = execution.claim_invocation(
        invocation_id="inv-first",
        run_id="run-kill",
        step_id="scan",
        tool_name="scanner",
        tool_version="1",
        idempotency_key="scan-kill",
        parameters={"target": "."},
        idempotent=True,
        lease_seconds=60,
        owner_id=lease.owner_id,
        fence=lease.fence,
    )
    assert status == InvocationStatus.RUNNING
    result = ToolResult(invocation_id="inv-first", status=ToolStatus.SUCCESS, summary="done")
    coordinator.complete_tool_invocation(
        run_id="run-kill",
        idempotency_key="scan-kill",
        invocation_id="inv-first",
        attempt=1,
        owner_id=lease.owner_id,
        fence=lease.fence,
        result=result,
        transition_id="tool:scan-kill:completed",
        event_type="tool.completed",
        payload={"status": "success"},
    )
    execution.close()
    coordinator.close()  # Simulated process death.

    recovered_execution = ExecutionStore(url)
    recovered_coordinator = CoordinatorStore(url)
    replay_status, cached = recovered_execution.claim_invocation(
        invocation_id="inv-replayed",
        run_id="run-kill",
        step_id="scan",
        tool_name="scanner",
        tool_version="1",
        idempotency_key="scan-kill",
        parameters={"target": "."},
        idempotent=True,
        lease_seconds=60,
        owner_id=lease.owner_id,
        fence=lease.fence,
    )
    assert replay_status == InvocationStatus.COMPLETED
    assert cached is not None and cached.summary == "done"
    assert len(recovered_coordinator.pending_outbox()) == 1
    with Session(recovered_execution.engine) as session:
        assert session.scalar(select(func.count()).select_from(ToolInvocationRow)) == 1
    recovered_execution.close()
    recovered_coordinator.close()


@pytest.mark.asyncio
async def test_provider_attempt_ids_remain_unique_across_drain_and_persistence(settings) -> None:
    settings.demo_mode = False
    settings.model_mode = "mock"
    calls = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": json.dumps({"answer": str(calls)})}}],
                "usage": {
                    "prompt_tokens": 2,
                    "completion_tokens": 1,
                    "total_tokens": 3,
                    "prompt_cache_hit_tokens": 1,
                    "prompt_cache_miss_tokens": 1,
                },
            },
        )

    class Output(BaseModel):
        answer: str

    coordinator = CoordinatorStore(settings.database_url)
    for _ in range(2):
        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        gateway = QwenGateway(settings, client)
        await gateway.structured(
            role="planner",
            system_prompt="system",
            user_prompt="user",
            output_model=Output,
            prompt_version="v1",
            run_id="run-model",
        )
        attempts = list(gateway.drain_provider_attempts())
        assert len(attempts) == 1
        coordinator.record_model_attempts("run-model", attempts)
        await client.aclose()

    with Session(coordinator.engine) as session:
        rows = list(session.scalars(select(ModelInvocationRow).where(ModelInvocationRow.run_id == "run-model")).all())
    assert len(rows) == 2
    assert len({row.provider_request_id for row in rows}) == 2
    assert sum(row.input_tokens + row.output_tokens for row in rows) == 6
    assert sum(row.cache_hit_input_tokens for row in rows) == 2
    assert sum(row.cache_miss_input_tokens for row in rows) == 2
    coordinator.close()


@pytest.mark.asyncio
async def test_orchestrator_checkpoint_persists_and_releases_provider_attempts(settings) -> None:
    settings.demo_mode = False
    settings.model_mode = "mock"

    class Output(BaseModel):
        answer: str

    client = httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(
                200,
                json={
                    "choices": [{"message": {"content": json.dumps({"answer": "ok"})}}],
                    "usage": {"prompt_tokens": 2, "completion_tokens": 1},
                },
            )
        )
    )
    gateway = QwenGateway(settings, client)
    run_id = "run-model-checkpoint"
    await gateway.structured(
        role="planner",
        system_prompt="system",
        user_prompt="user",
        output_model=Output,
        prompt_version="v1",
        run_id=run_id,
    )
    coordinator = CoordinatorStore(settings.database_url)
    ledger = LedgerStore(settings.database_url)
    broker = ToolBroker(default_registry(), Guardrail())
    orchestrator = SecMindOrchestrator(
        settings,
        ledger,
        gateway,
        broker,
        coordinator=coordinator,
    )

    await orchestrator._checkpoint(_state(run_id), "model.checked", {})

    assert gateway.provider_attempts_for(run_id) == ()
    with Session(coordinator.engine) as session:
        rows = list(session.scalars(select(ModelInvocationRow).where(ModelInvocationRow.run_id == run_id)))
    assert len(rows) == 1
    assert rows[0].input_tokens == 2
    assert rows[0].output_tokens == 1
    await client.aclose()
    broker.close()
    ledger.close()
    coordinator.close()
