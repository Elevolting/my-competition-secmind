from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from secmind.coordinator import CoordinatorStore, OutboxEventRow, RunJobRow, StepRunRow
from secmind.execution import ToolInvocationRow
from secmind.ledger import RunRow
from secmind.resume_reconciler import (
    CheckpointView,
    InvocationView,
    ReconciliationAction,
    ReconciliationSnapshot,
    ResumeReconciler,
    RunJobView,
)
from secmind.runtime import build_runtime
from secmind.schemas import (
    AgentState,
    DataView,
    Evidence,
    InvocationStatus,
    PlanStep,
    ResumeAction,
    ResumeAssessment,
    RunStatus,
    TaskRequest,
)
from secmind.service import _checkpoint_view
from secmind.unit_of_work import (
    ControlPlaneUnitOfWork,
    DataAccessEventRow,
    ResumeAssessmentRow,
    UnitOfWorkConflict,
)


def _state(run_id: str) -> AgentState:
    return AgentState(run_id=run_id, task=TaskRequest(objective="exercise safe recovery"))


def _assessment(
    run_id: str,
    *,
    action: ResumeAction = ResumeAction.REQUEUE_SAFE_STEP,
    digest: str = "a" * 64,
    control_digest: str = "b" * 64,
    runner_resources_collected: bool = False,
) -> ResumeAssessment:
    return ResumeAssessment(
        assessment_id=f"00000000-0000-4000-8000-{digest[:12]}",
        run_id=run_id,
        action=action,
        reason_codes=["TEST_RECOVERY_ACTION"],
        rationale_summary="A deterministic test assessment.",
        state_version=1,
        fence=0,
        checkpoint_present=False,
        checkpoint_state_version=None,
        checkpoint_id=None,
        control_digest=control_digest,
        runner_resources_collected=runner_resources_collected,
        assessment_digest=digest,
    )


def _snapshot(**changes) -> ReconciliationSnapshot:  # type: ignore[no-untyped-def]
    snapshot = ReconciliationSnapshot(
        run_id="run-reconcile-safe-v05",
        state_version=3,
        state_status=RunStatus.RUNNING,
        checkpoint=CheckpointView(True, 3, "checkpoint-3"),
        run_job=RunJobView("queued", 4),
    )
    return replace(snapshot, **changes)


def test_assessment_digest_binds_fence_checkpoint_and_control_summary() -> None:
    reconciler = ResumeReconciler()
    base = reconciler.assess(_snapshot())
    changed_fence = reconciler.assess(_snapshot(run_job=RunJobView("queued", 5)))
    changed_checkpoint = reconciler.assess(_snapshot(checkpoint=CheckpointView(True, 3, "different-checkpoint")))
    changed_control = reconciler.assess(_snapshot(report_committed=True))

    assert base.fence == 4
    assert base.checkpoint_state_version == 3
    assert base.checkpoint_id == "checkpoint-3"
    assert len(base.control_digest) == 64
    assert (
        len(
            {
                base.assessment_digest,
                changed_fence.assessment_digest,
                changed_checkpoint.assessment_digest,
                changed_control.assessment_digest,
            }
        )
        == 4
    )
    assert base.control_digest != changed_control.control_digest


def test_unavailable_runner_inventory_fails_closed_for_active_or_unknown_invocation() -> None:
    running = InvocationView(
        "run-reconcile-safe-v05",
        "invocation-running",
        "scan",
        InvocationStatus.RUNNING,
        4,
        1,
        True,
    )

    active = ResumeReconciler().assess(_snapshot(invocations=(running,), runner_resources_collected=False))
    unknown = ResumeReconciler().assess(
        _snapshot(unknown_invocation_ids=("invocation-unknown",), runner_resources_collected=False)
    )

    assert active.action == ReconciliationAction.REQUIRE_OPERATOR_RECOVERY
    assert "RUNNER_RESOURCE_STATE_UNAVAILABLE" in active.reason_codes
    assert unknown.action == ReconciliationAction.REQUIRE_OPERATOR_RECOVERY
    assert "UNKNOWN_INVOCATION_STATUS" in unknown.reason_codes
    assert "RUNNER_RESOURCE_STATE_UNAVAILABLE" in unknown.reason_codes


def test_checkpoint_view_uses_payload_state_version_and_fails_closed_when_absent() -> None:
    durable = SimpleNamespace(
        checkpoint={
            "id": "checkpoint-7",
            "channel_values": {"agent": {"run_id": "run", "state_version": 7}},
        }
    )
    missing = SimpleNamespace(checkpoint={"id": "checkpoint-unknown", "channel_values": {"agent": {"run_id": "run"}}})

    assert _checkpoint_view(durable) == CheckpointView(True, 7, "checkpoint-7")
    unavailable = ResumeReconciler().assess(_snapshot(checkpoint=_checkpoint_view(missing)))
    assert unavailable.action == ReconciliationAction.REQUIRE_OPERATOR_RECOVERY
    assert unavailable.reason_codes == ("CHECKPOINT_STATE_VERSION_UNAVAILABLE",)


def test_resume_assessment_consumption_is_atomic_cas_and_single_use(tmp_path: Path) -> None:
    coordinator = CoordinatorStore(f"sqlite:///{tmp_path / 'consume.db'}")
    uow = ControlPlaneUnitOfWork(coordinator.engine)
    run_id = "run-consume-safe-v05"
    assert uow.submit_run(_state(run_id))
    assessment = _assessment(run_id)
    assert uow.record_resume_assessment(assessment)

    consumption_id = uow.consume_resume_assessment(assessment, actor="operator")
    assert uow.consume_resume_assessment(assessment, actor="operator") == consumption_id

    with Session(uow.engine) as session:
        run = session.get(RunRow, run_id)
        job = session.get(RunJobRow, run_id)
        row = session.get(ResumeAssessmentRow, assessment.assessment_id)
        assert run is not None and run.state_version == 1 and run.status == RunStatus.PENDING.value
        assert job is not None and job.status == "queued" and job.fence == 0
        assert row is not None and row.consumption_id == consumption_id and row.consumed_at is not None
        consumed_events = session.scalar(
            select(func.count()).select_from(OutboxEventRow).where(OutboxEventRow.event_type == "recovery.consumed")
        )
        assert consumed_events == 1


def test_finalize_outbox_releases_dead_letter_with_receipt(tmp_path: Path) -> None:
    coordinator = CoordinatorStore(f"sqlite:///{tmp_path / 'finalize-outbox.db'}")
    uow = ControlPlaneUnitOfWork(coordinator.engine)
    run_id = "run-finalize-outbox-v084"
    assert uow.submit_run(_state(run_id))
    outbox_id = coordinator.enqueue_outbox(
        run_id,
        transition_id="transition-dead-letter",
        event_type="tool.completed",
        payload={"status": "success"},
    )
    with Session(coordinator.engine) as session:
        row = session.get(OutboxEventRow, outbox_id)
        assert row is not None
        row.status = "dead_letter"
        session.commit()

    assessment = _assessment(run_id, action=ResumeAction.FINALIZE_OUTBOX, digest="d" * 64)
    assert uow.record_resume_assessment(assessment)
    consumption_id = uow.consume_resume_assessment(assessment, actor="operator")
    assert consumption_id
    with Session(coordinator.engine) as session:
        row = session.get(OutboxEventRow, outbox_id)
        receipts = session.scalars(
            select(OutboxEventRow).where(OutboxEventRow.event_type == "outbox.retry_authorized")
        ).all()
        assert row is not None and row.status == "retry_wait" and row.attempts == 0
        assert len(receipts) == 1


def test_stale_or_operator_only_assessment_cannot_change_state(tmp_path: Path) -> None:
    coordinator = CoordinatorStore(f"sqlite:///{tmp_path / 'stale.db'}")
    uow = ControlPlaneUnitOfWork(coordinator.engine)
    stale_run = "run-stale-assessment-v05"
    assert uow.submit_run(_state(stale_run))
    stale = _assessment(stale_run, digest="c" * 64)
    assert uow.record_resume_assessment(stale)
    with Session(uow.engine) as session:
        job = session.get(RunJobRow, stale_run)
        assert job is not None
        job.fence = 1
        session.commit()
    with pytest.raises(UnitOfWorkConflict, match="fence changed"):
        uow.consume_resume_assessment(stale, actor="operator")

    operator_run = "run-operator-only-v05"
    assert uow.submit_run(_state(operator_run))
    operator_only = _assessment(
        operator_run,
        action=ResumeAction.REQUIRE_OPERATOR_RECOVERY,
        digest="d" * 64,
    )
    assert uow.record_resume_assessment(operator_only)
    with pytest.raises(UnitOfWorkConflict, match="cannot resume"):
        uow.consume_resume_assessment(operator_only, actor="operator")
    with Session(uow.engine) as session:
        run = session.get(RunRow, operator_run)
        assert run is not None and run.state_version == 1 and run.status == RunStatus.PENDING.value


def test_cancel_and_reap_requires_positive_runner_confirmation(tmp_path: Path) -> None:
    coordinator = CoordinatorStore(f"sqlite:///{tmp_path / 'reap.db'}")
    uow = ControlPlaneUnitOfWork(coordinator.engine)
    run_id = "run-cancel-reap-v05"
    assert uow.submit_run(_state(run_id))
    assessment = _assessment(
        run_id,
        action=ResumeAction.CANCEL_AND_REAP,
        digest="e" * 64,
        runner_resources_collected=True,
    )
    assert uow.record_resume_assessment(assessment)

    with pytest.raises(UnitOfWorkConflict, match="confirmed"):
        uow.consume_resume_assessment(assessment, actor="operator", reaper_confirmed=False)
    with Session(uow.engine) as session:
        run = session.get(RunRow, run_id)
        assert run is not None and run.state_version == 1 and run.status == RunStatus.PENDING.value

    uow.consume_resume_assessment(assessment, actor="operator", reaper_confirmed=True)
    with Session(uow.engine) as session:
        run = session.get(RunRow, run_id)
        job = session.get(RunJobRow, run_id)
        assert run is not None and run.status == RunStatus.CANCELLED.value
        assert job is not None and job.status == "cancelled" and job.fence == 1


@pytest.mark.asyncio
async def test_service_revalidates_bound_assessment_before_recovery(settings, monkeypatch) -> None:
    service, gateway = build_runtime(settings)
    run_id = service.submit(TaskRequest(objective="recover a queued safe run"))
    assessment = await service.recovery_assessment(run_id)
    assert assessment.action == ResumeAction.REQUEUE_SAFE_STEP
    monkeypatch.setattr(service.worker, "notify", lambda: None)
    monkeypatch.setattr(service.orchestrator, "project_outbox", AsyncMock())

    consumption_id = await service.recover(
        run_id,
        assessment_id=assessment.assessment_id,
        assessment_digest=assessment.assessment_digest,
    )
    duplicate = await service.recover(
        run_id,
        assessment_id=assessment.assessment_id,
        assessment_digest=assessment.assessment_digest,
    )

    assert duplicate == consumption_id
    assert service.state(run_id).status == RunStatus.PENDING
    await gateway.close()


@pytest.mark.asyncio
async def test_service_rejects_assessment_after_control_state_changes(settings) -> None:
    service, gateway = build_runtime(settings)
    run_id = service.submit(TaskRequest(objective="reject a stale recovery assessment"))
    assessment = await service.recovery_assessment(run_id)
    changed = service.state(run_id)
    changed.last_error = "control state changed after assessment"
    service.ledger.save_state(changed)

    with pytest.raises(RuntimeError, match="stale"):
        await service.recover(
            run_id,
            assessment_id=assessment.assessment_id,
            assessment_digest=assessment.assessment_digest,
        )

    assert service.state(run_id).last_error == "control state changed after assessment"
    await gateway.close()


@pytest.mark.asyncio
async def test_service_governance_methods_fail_closed_without_transactional_uow(settings) -> None:
    service, gateway = build_runtime(settings)
    run_id = service.submit(TaskRequest(objective="exercise unavailable governance stores"))
    service.unit_of_work = None

    with pytest.raises(RuntimeError, match="transactional control plane"):
        await service.recover(
            run_id,
            assessment_id="missing-assessment",
            assessment_digest="a" * 64,
        )
    with pytest.raises(KeyError, match="missing-envelope"):
        service.input_envelope(run_id, "missing-envelope")
    with pytest.raises(RuntimeError, match="retention governance"):
        service.create_retention_hold(
            run_id,
            reason="retain for review",
            expires_at=datetime.now(UTC) + timedelta(days=1),
        )
    assert service.retention_holds(run_id) == []
    with pytest.raises(RuntimeError, match="assessment store"):
        service.latest_recovery_assessment(run_id)
    await gateway.close()


@pytest.mark.asyncio
async def test_service_recovery_rejects_digest_and_operator_only_action(settings, monkeypatch) -> None:
    service, gateway = build_runtime(settings)
    run_id = service.submit(TaskRequest(objective="reject invalid recovery actions"))
    assert service.unit_of_work is not None
    requested = _assessment(
        run_id,
        action=ResumeAction.REQUIRE_OPERATOR_RECOVERY,
        digest="7" * 64,
    )
    monkeypatch.setattr(service.unit_of_work, "load_resume_assessment", lambda *_args: requested)
    monkeypatch.setattr(service.unit_of_work, "resume_assessment_consumption", lambda *_args: None)

    with pytest.raises(RuntimeError, match="digest does not match"):
        await service.recover(
            run_id,
            assessment_id=requested.assessment_id,
            assessment_digest="8" * 64,
        )

    monkeypatch.setattr(service, "recovery_assessment", AsyncMock(return_value=requested))
    with pytest.raises(RuntimeError, match="operator investigation"):
        await service.recover(
            run_id,
            assessment_id=requested.assessment_id,
            assessment_digest=requested.assessment_digest,
        )
    await gateway.close()


@pytest.mark.asyncio
async def test_service_cancel_recovery_skips_worker_notification(settings, monkeypatch) -> None:
    service, gateway = build_runtime(settings)
    run_id = service.submit(TaskRequest(objective="consume a confirmed cancel assessment"))
    assert service.unit_of_work is not None
    assessment = _assessment(
        run_id,
        action=ResumeAction.CANCEL_AND_REAP,
        digest="9" * 64,
        runner_resources_collected=True,
    )
    monkeypatch.setattr(service.unit_of_work, "load_resume_assessment", lambda *_args: assessment)
    monkeypatch.setattr(service.unit_of_work, "resume_assessment_consumption", lambda *_args: None)
    consume = MagicMock(return_value="consumption-cancel")
    monkeypatch.setattr(service.unit_of_work, "consume_resume_assessment", consume)
    monkeypatch.setattr(service, "recovery_assessment", AsyncMock(return_value=assessment))
    notify = MagicMock()
    monkeypatch.setattr(service.worker, "notify", notify)
    project = AsyncMock()
    monkeypatch.setattr(service.orchestrator, "project_outbox", project)

    result = await service.recover(
        run_id,
        assessment_id=assessment.assessment_id,
        assessment_digest=assessment.assessment_digest,
        reaper_confirmed=True,
    )

    assert result == "consumption-cancel"
    notify.assert_not_called()
    project.assert_awaited_once()
    consume.assert_called_once()
    await gateway.close()


@pytest.mark.asyncio
async def test_service_retention_client_id_projects_and_latest_missing_fails(settings, monkeypatch) -> None:
    service, gateway = build_runtime(settings)
    run_id = service.submit(TaskRequest(objective="create deterministic retention hold"))
    projector = MagicMock()
    projector.claim_batch.return_value = ["outbox-retention"]
    monkeypatch.setattr(service.orchestrator, "outbox_projector", projector)

    hold = service.create_retention_hold(
        run_id,
        reason="preserve evidence for adjudication",
        expires_at=datetime.now(UTC) + timedelta(days=2),
        client_request_id="retention-request-0001",
    )

    assert hold.hold_id
    projector.project_claimed.assert_called_once_with("outbox-retention")
    with pytest.raises(RuntimeError, match="no recovery assessment"):
        service.latest_recovery_assessment(run_id)
    assert [item.hold_id for item in service.retention_holds(run_id)] == [hold.hold_id]
    await gateway.close()


@pytest.mark.asyncio
async def test_recovery_assessment_rejects_missing_job_projection(settings) -> None:
    service, gateway = build_runtime(settings)
    run_id = service.submit(TaskRequest(objective="detect missing run job projection"))
    with Session(service.coordinator.engine) as session:
        job = session.get(RunJobRow, run_id)
        assert job is not None
        session.delete(job)
        session.commit()

    with pytest.raises(KeyError, match=run_id):
        await service.recovery_assessment(run_id)
    await gateway.close()


@pytest.mark.asyncio
async def test_recovery_assessment_covers_steps_unknown_invocation_and_missing_artifact(settings) -> None:
    service, gateway = build_runtime(settings)
    run_id = service.submit(TaskRequest(objective="collect corrupted recovery projections"))
    state = service.state(run_id)
    state.plan = [
        PlanStep(
            step_id="known-step",
            objective="use an unavailable candidate",
            agent_role="specialist",
            tool_candidates=["tool-not-registered"],
        )
    ]
    state.evidence = [
        Evidence(
            source="missing-artifact-test",
            summary="evidence points to a missing immutable object",
            artifact_ref="f" * 64,
        )
    ]
    service.ledger.save_state(state)
    now = datetime.now(UTC)
    with Session(service.coordinator.engine) as session:
        for index, step_id in enumerate(("known-step", "orphan-step"), start=1):
            session.add(
                StepRunRow(
                    step_run_id=f"00000000-0000-4000-8000-{index:012d}",
                    run_id=run_id,
                    step_id=step_id,
                    attempt=1,
                    status="ready",
                    transition_id=f"transition-{index}",
                    fence=0,
                    created_at=now,
                    updated_at=now,
                )
            )
        session.add(
            ToolInvocationRow(
                invocation_id="00000000-0000-4000-8000-000000000099",
                run_id=run_id,
                step_id="known-step",
                tool_name="tool-not-registered",
                tool_version="1",
                idempotency_key="unknown-status-invocation",
                parameters_hash="1" * 64,
                attempt=1,
                status="alien-status",
                fence=0,
                created_at=now,
                updated_at=now,
            )
        )
        session.commit()

    assessment = await service.recovery_assessment(run_id)

    assert assessment.action == ResumeAction.REQUIRE_OPERATOR_RECOVERY
    assert "UNKNOWN_INVOCATION_STATUS" in assessment.reason_codes
    assert "ARTIFACT_INTEGRITY_FAILURE" in assessment.reason_codes
    await gateway.close()


@pytest.mark.parametrize(
    ("values", "message"),
    [
        ({"decision": "maybe"}, "decision"),
        ({"actor": ""}, "actor or resource type"),
        ({"actor": "actor\n"}, "actor or resource type"),
        ({"resource_type": ""}, "actor or resource type"),
        ({"resource_type": "x" * 51}, "actor or resource type"),
        ({"resource_id": ""}, "resource or reason"),
        ({"resource_id": "resource\x00"}, "resource or reason"),
        ({"reason_code": ""}, "resource or reason"),
        ({"reason_code": "x" * 101}, "resource or reason"),
    ],
)
def test_data_access_rejects_malformed_audit_dimensions(tmp_path: Path, values, message: str) -> None:  # type: ignore[no-untyped-def]
    coordinator = CoordinatorStore(f"sqlite:///{tmp_path / 'data-invalid.db'}")
    uow = ControlPlaneUnitOfWork(coordinator.engine)
    arguments = {
        "run_id": "missing-run",
        "actor": "operator",
        "view": DataView.OBSERVABLE,
        "resource_type": "artifact",
        "resource_id": "artifact-1",
        "purpose": "review",
        "decision": "allowed",
        "reason_code": "POLICY_ALLOWED",
        **values,
    }

    with pytest.raises(ValueError, match=message):
        uow.record_data_access_event(**arguments)


def test_data_access_requires_run_and_scrubs_persisted_purpose(tmp_path: Path) -> None:
    coordinator = CoordinatorStore(f"sqlite:///{tmp_path / 'data-access.db'}")
    uow = ControlPlaneUnitOfWork(coordinator.engine)
    arguments = {
        "run_id": "run-data-access-v05",
        "actor": "operator",
        "view": DataView.OBSERVABLE,
        "resource_type": "artifact",
        "resource_id": "artifact-1",
        "purpose": "inspect token=secret-value\nfor adjudication",
        "decision": "denied",
        "reason_code": "SCOPE_DENIED",
    }
    with pytest.raises(KeyError, match="run-data-access-v05"):
        uow.record_data_access_event(**arguments)
    assert uow.submit_run(_state("run-data-access-v05"))

    access_id = uow.record_data_access_event(**arguments)

    with Session(uow.engine) as session:
        row = session.get(DataAccessEventRow, access_id)
        assert row is not None
        assert "secret-value" not in row.purpose
        assert "decision=denied" in row.purpose
        event = session.scalar(select(OutboxEventRow).where(OutboxEventRow.event_type == "data.access_decision"))
        assert event is not None and "secret-value" not in event.payload_json


def test_resume_assessment_repositories_reject_missing_and_unknown_run(tmp_path: Path) -> None:
    coordinator = CoordinatorStore(f"sqlite:///{tmp_path / 'assessment-missing.db'}")
    uow = ControlPlaneUnitOfWork(coordinator.engine)
    missing = _assessment("missing-run")

    with pytest.raises(KeyError, match="missing-run"):
        uow.record_resume_assessment(missing)
    with pytest.raises(KeyError, match=missing.assessment_id):
        uow.load_resume_assessment("missing-run", missing.assessment_id)
    with pytest.raises(KeyError, match="missing-run"):
        uow.latest_resume_assessment("missing-run")
    with pytest.raises(KeyError, match=missing.assessment_id):
        uow.resume_assessment_consumption("missing-run", missing.assessment_id, missing.assessment_digest)
    with pytest.raises(KeyError, match=missing.assessment_id):
        uow.consume_resume_assessment(missing, actor="operator")


def test_resume_assessment_repositories_reject_corrupt_json(tmp_path: Path) -> None:
    coordinator = CoordinatorStore(f"sqlite:///{tmp_path / 'assessment-json.db'}")
    uow = ControlPlaneUnitOfWork(coordinator.engine)
    run_id = "run-assessment-json-v05"
    assert uow.submit_run(_state(run_id))
    assessment = _assessment(run_id, digest="2" * 64)
    assert uow.record_resume_assessment(assessment)
    with Session(uow.engine) as session:
        row = session.get(ResumeAssessmentRow, assessment.assessment_id)
        assert row is not None
        row.assessment_json = "not-json"
        session.commit()

    operations = (
        lambda: uow.record_resume_assessment(assessment),
        lambda: uow.load_resume_assessment(run_id, assessment.assessment_id),
        lambda: uow.latest_resume_assessment(run_id),
        lambda: uow.resume_assessment_consumption(run_id, assessment.assessment_id, assessment.assessment_digest),
        lambda: uow.consume_resume_assessment(assessment, actor="operator"),
    )
    for operation in operations:
        with pytest.raises(UnitOfWorkConflict, match="invalid"):
            operation()


def test_resume_assessment_repositories_detect_projection_tampering(tmp_path: Path) -> None:
    coordinator = CoordinatorStore(f"sqlite:///{tmp_path / 'assessment-projection.db'}")
    uow = ControlPlaneUnitOfWork(coordinator.engine)
    run_id = "run-assessment-projection-v05"
    assert uow.submit_run(_state(run_id))
    assessment = _assessment(run_id, digest="3" * 64)
    assert uow.record_resume_assessment(assessment)
    with Session(uow.engine) as session:
        row = session.get(ResumeAssessmentRow, assessment.assessment_id)
        assert row is not None
        row.action = ResumeAction.WAIT_FOR_APPROVAL.value
        session.commit()

    operations = (
        lambda: uow.record_resume_assessment(assessment),
        lambda: uow.load_resume_assessment(run_id, assessment.assessment_id),
        lambda: uow.latest_resume_assessment(run_id),
        lambda: uow.resume_assessment_consumption(run_id, assessment.assessment_id, assessment.assessment_digest),
        lambda: uow.consume_resume_assessment(assessment, actor="operator"),
    )
    for operation in operations:
        with pytest.raises(UnitOfWorkConflict, match="projection is inconsistent"):
            operation()


def test_resume_assessment_consumption_validates_digest_and_record_shape(tmp_path: Path) -> None:
    coordinator = CoordinatorStore(f"sqlite:///{tmp_path / 'assessment-consumption.db'}")
    uow = ControlPlaneUnitOfWork(coordinator.engine)
    run_id = "run-assessment-consumption-v05"
    assert uow.submit_run(_state(run_id))
    assessment = _assessment(run_id, digest="4" * 64)
    assert uow.record_resume_assessment(assessment)

    with pytest.raises(UnitOfWorkConflict, match="digest does not match"):
        uow.resume_assessment_consumption(run_id, assessment.assessment_id, "5" * 64)
    with Session(uow.engine) as session:
        row = session.get(ResumeAssessmentRow, assessment.assessment_id)
        assert row is not None
        row.consumption_id = "incomplete-consumption"
        session.commit()
    with pytest.raises(UnitOfWorkConflict, match="incomplete"):
        uow.resume_assessment_consumption(run_id, assessment.assessment_id, assessment.assessment_digest)
    with pytest.raises(UnitOfWorkConflict, match="incomplete"):
        uow.consume_resume_assessment(assessment, actor="operator")


@pytest.mark.parametrize(
    ("action", "control_digest", "message"),
    [
        (ResumeAction.WAIT_FOR_APPROVAL, "6" * 64, "not executable"),
        (ResumeAction.RESUME_FROM_CHECKPOINT, "6" * 64, "no bound checkpoint"),
        (ResumeAction.REQUEUE_SAFE_STEP, "0" * 64, "no bound control summary"),
    ],
)
def test_consume_resume_assessment_rejects_non_executable_bindings(
    tmp_path: Path,
    action: ResumeAction,
    control_digest: str,
    message: str,
) -> None:
    coordinator = CoordinatorStore(f"sqlite:///{tmp_path / f'action-{action.value}.db'}")
    uow = ControlPlaneUnitOfWork(coordinator.engine)
    run_id = f"run-action-{action.value}"
    assert uow.submit_run(_state(run_id))
    assessment = _assessment(
        run_id,
        action=action,
        digest={
            ResumeAction.WAIT_FOR_APPROVAL: "6",
            ResumeAction.FINALIZE_OUTBOX: "7",
            ResumeAction.RESUME_FROM_CHECKPOINT: "8",
            ResumeAction.REQUEUE_SAFE_STEP: "9",
        }[action]
        * 64,
        control_digest=control_digest,
    )
    assert uow.record_resume_assessment(assessment)

    with pytest.raises(UnitOfWorkConflict, match=message):
        uow.consume_resume_assessment(assessment, actor="operator")


def test_consume_resume_assessment_rejects_empty_actor_and_payload_drift(tmp_path: Path) -> None:
    coordinator = CoordinatorStore(f"sqlite:///{tmp_path / 'assessment-input.db'}")
    uow = ControlPlaneUnitOfWork(coordinator.engine)
    run_id = "run-assessment-input-v05"
    assert uow.submit_run(_state(run_id))
    assessment = _assessment(run_id, digest="a" * 64, control_digest="c" * 64)
    assert uow.record_resume_assessment(assessment)

    with pytest.raises(ValueError, match="actor"):
        uow.consume_resume_assessment(assessment, actor="")
    changed = assessment.model_copy(update={"rationale_summary": "changed after persistence"})
    with pytest.raises(UnitOfWorkConflict, match="stale"):
        uow.consume_resume_assessment(changed, actor="operator")


@pytest.mark.parametrize(
    ("case", "message"),
    [
        ("missing_job", "incomplete run"),
        ("state_version", "run state changed"),
        ("leased", "leased run"),
        ("snapshot_version", "snapshot version"),
        ("terminal_job", "terminal run job"),
    ],
)
def test_consume_resume_assessment_rejects_control_plane_races(
    tmp_path: Path,
    case: str,
    message: str,
) -> None:
    coordinator = CoordinatorStore(f"sqlite:///{tmp_path / f'assessment-race-{case}.db'}")
    uow = ControlPlaneUnitOfWork(coordinator.engine)
    run_id = f"run-assessment-race-{case}"
    assert uow.submit_run(_state(run_id))
    digest = {
        "missing_job": "b",
        "state_version": "c",
        "leased": "d",
        "snapshot_version": "e",
        "terminal_job": "f",
    }[case]
    assessment = _assessment(run_id, digest=digest * 64, control_digest="d" * 64)
    assert uow.record_resume_assessment(assessment)
    with Session(uow.engine) as session:
        run = session.get(RunRow, run_id)
        job = session.get(RunJobRow, run_id)
        assert run is not None and job is not None
        if case == "missing_job":
            session.delete(job)
        elif case == "state_version":
            run.state_version = 2
        elif case == "leased":
            job.status = "leased"
        elif case == "snapshot_version":
            state = AgentState.model_validate_json(run.state_json)
            state.state_version = 2
            run.state_json = state.model_dump_json()
        elif case == "terminal_job":
            job.status = "completed"
        session.commit()

    with pytest.raises(UnitOfWorkConflict, match=message):
        uow.consume_resume_assessment(assessment, actor="operator")
