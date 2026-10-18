from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from sqlalchemy.orm import Session

from secmind.config import Settings
from secmind.coordinator import CoordinatorConflict, CoordinatorStore, ModelInvocationRow, OutboxEventRow
from secmind.execution import ExecutionStore
from secmind.guardrail import Guardrail
from secmind.ledger import LedgerStore
from secmind.llm import ProviderAttempt, QwenGateway
from secmind.model_router import MODEL_ROUTER_VERSION
from secmind.orchestrator import SecMindOrchestrator
from secmind.outbox_projector import OutboxProjector
from secmind.schemas import (
    AgentState,
    ApprovalDecision,
    ApprovalResponse,
    AttachmentRef,
    ModelUsage,
    RiskLevel,
    RunStatus,
    Scenario,
    TaskRequest,
    ToolContext,
    ToolManifest,
    ToolResult,
    ToolStatus,
)
from secmind.tools import BaseTool, ToolBroker, ToolRegistry


class PostgresApprovalTool(BaseTool):
    manifest = ToolManifest(
        name="bandit_python_audit",
        version="postgres-test",
        description="Read-only integration test tool",
        scenarios=[Scenario.CODE_AUDIT],
        input_schema={"type": "object", "properties": {"target": {"type": "string"}}},
        output_schema={"type": "object", "properties": {"findings": {"type": "array"}}},
        risk_level=RiskLevel.R2,
        idempotent=True,
    )

    async def invoke(self, args: dict, context: ToolContext) -> ToolResult:
        return ToolResult(
            invocation_id=context.invocation_id,
            status=ToolStatus.SUCCESS,
            data={"findings": []},
            summary="approved integration call",
        )


def build_orchestrator(settings: Settings, checkpointer) -> SecMindOrchestrator:
    ledger = LedgerStore(settings.database_url)
    registry = ToolRegistry()
    registry.register(PostgresApprovalTool())
    broker = ToolBroker(
        registry,
        Guardrail(),
        execution_store=ExecutionStore(settings.database_url),
        ledger=ledger,
    )
    return SecMindOrchestrator(
        settings,
        ledger,
        QwenGateway(settings),
        broker,
        checkpointer=checkpointer,
    )


@pytest.mark.integration
@pytest.mark.asyncio
async def test_postgres_checkpoint_resumes_approval_in_new_runtime(tmp_path: Path) -> None:
    checkpoint_url = os.getenv("SECMIND_TEST_CHECKPOINT_URL")
    business_url = os.getenv("SECMIND_TEST_DATABASE_URL")
    if not checkpoint_url or not business_url:
        pytest.fail("PostgreSQL integration requires SECMIND_TEST_DATABASE_URL and SECMIND_TEST_CHECKPOINT_URL")
    settings = Settings(
        demo_mode=True,
        database_url=business_url,
        checkpoint_database_url=checkpoint_url,
        input_root=tmp_path / "inputs",
        upload_root=tmp_path / "uploads",
        run_root=tmp_path / "runs",
        artifact_root=tmp_path / "artifacts",
    )
    settings.prepare_directories()
    (settings.input_root / "app.py").write_text("print('ok')", encoding="utf-8")
    run_id = str(uuid4())

    async with AsyncPostgresSaver.from_conn_string(checkpoint_url) as first_checkpointer:
        await first_checkpointer.setup()
        first = build_orchestrator(settings, first_checkpointer)
        waiting = await first.start(
            TaskRequest(
                objective="audit code",
                attachments=[AttachmentRef(ref="app.py")],
            ),
            run_id,
        )
        assert waiting.pending_approval is not None
        assert waiting.context_items
        assert waiting.context_packs

    (settings.input_root / "app.py").unlink()

    async with AsyncPostgresSaver.from_conn_string(checkpoint_url) as second_checkpointer:
        second = build_orchestrator(settings, second_checkpointer)
        completed = await second.resume(
            run_id,
            ApprovalResponse(decision=ApprovalDecision.APPROVE, reason="integration test"),
        )
        assert completed.status in {RunStatus.COMPLETED, RunStatus.PARTIAL}
        assert completed.report is not None
        assert completed.budget.steps_used == 1
        assert completed.observations[0].summary == "approved integration call"


@pytest.mark.integration
def test_postgres_persists_complete_provider_prompt_lineage() -> None:
    business_url = os.getenv("SECMIND_TEST_DATABASE_URL")
    if not business_url:
        pytest.fail("PostgreSQL integration requires SECMIND_TEST_DATABASE_URL")
    coordinator = CoordinatorStore(business_url, initialize_schema=False)
    run_id = str(uuid4())
    try:
        attempt = ProviderAttempt(
            provider_request_id=f"postgres-lineage-provider-{uuid4().hex}",
            sequence=1,
            model_id="qwen-plus",
            endpoint="chat/completions",
            duration_ms=4,
            status_code=200,
            succeeded=True,
            retryable=False,
            error_type=None,
            usage=ModelUsage(provider_requests=1, input_tokens=11, output_tokens=7, cost_units=0.0001),
            provider_request_sha256="a" * 64,
            task_kind="planning",
            lane="reasoning",
            router_version=MODEL_ROUTER_VERSION,
            prompt_version="postgres-lineage-v1",
            prompt_artifact_id="b" * 64,
            prompt_selection_digest="c" * 64,
            prompt_optimizer_attempt_id="prompt-opt-postgres",
            prompt_lineage_reason="optimizer_completed",
            parent_logical_call_id="parent-postgres-call",
            logical_call_id="logical-postgres-call",
            ordinal=2,
            lineage_stage="fallback_repair",
            response_sha256="d" * 64,
            run_id=run_id,
        )
        coordinator.record_model_attempts(run_id, [attempt])
        with Session(coordinator.engine) as session:
            row = session.query(ModelInvocationRow).filter_by(run_id=run_id).one()
            event = session.query(OutboxEventRow).filter_by(run_id=run_id).one()
            assert (
                row.prompt_artifact_id,
                row.prompt_selection_digest,
                row.prompt_optimizer_attempt_id,
                row.parent_logical_call_id,
                row.logical_call_id,
                row.attempt_ordinal,
                row.lineage_stage,
            ) == (
                "b" * 64,
                "c" * 64,
                "prompt-opt-postgres",
                "parent-postgres-call",
                "logical-postgres-call",
                2,
                "fallback_repair",
            )
            payload = json.loads(event.payload_json)
            assert payload["prompt_lineage_reason"] == "optimizer_completed"
            assert payload["lineage_stage"] == "fallback_repair"
    finally:
        coordinator.close()


@pytest.mark.integration
def test_postgres_run_lease_cas_outbox_and_restart_are_durable() -> None:
    """Exercise the business control plane against a real PostgreSQL server.

    SQLite unit tests cover transition shapes, but they cannot prove
    PostgreSQL advisory locks, row-level lease fencing, transactional CAS and
    projector restart behavior.  Missing service configuration is a failure,
    never a passing skip.
    """

    business_url = os.getenv("SECMIND_TEST_DATABASE_URL")
    if not business_url:
        pytest.fail("PostgreSQL integration requires SECMIND_TEST_DATABASE_URL")
    run_id = str(uuid4())
    coordinator = CoordinatorStore(business_url, initialize_schema=False)
    ledger = LedgerStore(business_url, initialize_schema=False)
    try:
        state = AgentState(run_id=run_id, task=TaskRequest(objective="durable PostgreSQL control-plane probe"))
        ledger.save_state(state)
        # Keep this probe ahead of unrelated historical jobs in a shared
        # integration database.  ``claim_jobs(limit=1)`` is intentionally
        # bounded, so a random enqueue time can otherwise starve this run
        # without changing the lease semantics under test.
        coordinator.enqueue_run(run_id, next_attempt_at=datetime(1970, 1, 1, tzinfo=UTC))
        owner_id = f"postgres-integration-worker-{uuid4().hex[:12]}"
        lease = None
        for _ in range(16):
            claimed = coordinator.claim_jobs(owner_id, lease_seconds=30, limit=1)
            candidate = next((item for item in claimed if item.run_id == run_id), None)
            if candidate is not None:
                lease = candidate
                break
        assert lease is not None
        renewed = coordinator.heartbeat(run_id, owner_id=lease.owner_id, fence=lease.fence, lease_seconds=30)
        assert renewed.fence == lease.fence

        current = ledger.load_state(run_id)
        assert current is not None
        current.status = RunStatus.RUNNING
        committed_version = coordinator.commit_transition(
            current,
            expected_version=current.state_version,
            owner_id=lease.owner_id,
            fence=lease.fence,
            transition_id="postgres-cas-transition",
            event_type="run.running",
            payload={"probe": "run-lease-cas"},
        )
        assert committed_version == current.state_version
        with pytest.raises(CoordinatorConflict, match="compare-and-swap"):
            coordinator.commit_transition(
                current,
                expected_version=committed_version - 1,
                owner_id=lease.owner_id,
                fence=lease.fence,
                transition_id="postgres-cas-stale",
                event_type="run.running.stale",
                payload={"probe": "stale-cas"},
            )

        projector = OutboxProjector(coordinator.engine, owner_id="postgres-integration-projector")
        claimed = projector.claim_batch(run_id=run_id)
        assert claimed, "the CAS transition must enqueue a durable outbox row"
        projected = projector.project_claimed(claimed[0])
        assert projected.run_id == run_id
        assert ledger.verify(run_id)

        # Closing and reopening both stores is the restart boundary.  The
        # lease/CAS/outbox result must remain readable from PostgreSQL.
        coordinator.close()
        ledger.close()
        coordinator = CoordinatorStore(business_url, initialize_schema=False)
        ledger = LedgerStore(business_url, initialize_schema=False)
        status, durable_lease, _ = coordinator.job_snapshot(run_id)
        assert status == "leased"
        assert durable_lease is not None and durable_lease.fence == lease.fence
        restarted = ledger.load_state(run_id)
        assert restarted is not None and restarted.state_version == committed_version
        assert not [item for item in coordinator.pending_outbox() if item.run_id == run_id]
    finally:
        coordinator.close()
        ledger.close()
