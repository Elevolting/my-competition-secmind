from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from secmind.resume_reconciler import (
    ApprovalView,
    ArtifactView,
    CheckpointView,
    ClarificationView,
    InvocationView,
    OutboxView,
    ReconciliationAction,
    ReconciliationSnapshot,
    ResumeReconciler,
    RunJobView,
    RunnerResourceView,
    StepView,
)
from secmind.schemas import InvocationStatus, RunStatus, StepStatus

NOW = datetime(2026, 7, 14, tzinfo=UTC)


def _snapshot(**changes) -> ReconciliationSnapshot:  # type: ignore[no-untyped-def]
    value = ReconciliationSnapshot(
        run_id="run-1",
        state_version=3,
        state_status=RunStatus.RUNNING,
        checkpoint=CheckpointView(True, 3),
        run_job=RunJobView("queued", 2),
    )
    return replace(value, **changes)


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"ledger_valid": False}, "LEDGER_OR_OUTBOX_HEAD_INVALID"),
        ({"budget_consistent": False}, "BUDGET_ACCOUNTING_MISMATCH"),
        (
            {"artifacts": (ArtifactView("run-1", "a" * 64, exists=True, digest_valid=False),)},
            "ARTIFACT_INTEGRITY_FAILURE",
        ),
        ({"checkpoint": CheckpointView(True, 4)}, "CHECKPOINT_AHEAD_OF_BUSINESS_STATE"),
    ],
)
def test_integrity_drift_requires_operator_recovery(change, reason: str) -> None:  # type: ignore[no-untyped-def]
    assessment = ResumeReconciler().assess(_snapshot(**change), now=NOW)

    assert assessment.action == ReconciliationAction.REQUIRE_OPERATOR_RECOVERY
    assert reason in assessment.reason_codes
    assert assessment.requires_operator


def test_cross_run_or_duplicate_projection_is_never_reconciled_automatically() -> None:
    cross_run = _snapshot(
        invocations=(
            InvocationView(
                "other-run",
                "inv-1",
                "scan",
                InvocationStatus.COMPLETED,
                1,
                1,
                True,
                result_committed=True,
            ),
        )
    )
    duplicate = _snapshot(
        steps=(
            StepView("run-1", "scan", StepStatus.READY, 1, True),
            StepView("run-1", "scan", StepStatus.PENDING, 2, True),
        )
    )

    cross_result = ResumeReconciler().assess(cross_run, now=NOW)
    duplicate_result = ResumeReconciler().assess(duplicate, now=NOW)

    assert cross_result.action == ReconciliationAction.REQUIRE_OPERATOR_RECOVERY
    assert "CROSS_RUN_PROJECTION" in cross_result.reason_codes
    assert duplicate_result.action == ReconciliationAction.REQUIRE_OPERATOR_RECOVERY
    assert "DUPLICATE_STEP_PROJECTION" in duplicate_result.reason_codes


def test_pending_and_resolved_interrupts_get_distinct_single_actions() -> None:
    pending_approval = ResumeReconciler().assess(
        _snapshot(
            state_status=RunStatus.WAITING_APPROVAL,
            approvals=(ApprovalView("run-1", "approval", "pending"),),
        ),
        now=NOW,
    )
    pending_clarification = ResumeReconciler().assess(
        _snapshot(
            state_status=RunStatus.WAITING_CLARIFICATION,
            clarifications=(ClarificationView("run-1", "clarification", "pending"),),
        ),
        now=NOW,
    )
    resolved = ResumeReconciler().assess(
        _snapshot(
            state_status=RunStatus.WAITING_APPROVAL,
            approvals=(ApprovalView("run-1", "approval", "resolved_unconsumed"),),
        ),
        now=NOW,
    )

    assert pending_approval.action == ReconciliationAction.WAIT_FOR_APPROVAL
    assert pending_clarification.action == ReconciliationAction.WAIT_FOR_CLARIFICATION
    assert resolved.action == ReconciliationAction.RESUME_FROM_CHECKPOINT


def test_resolved_interrupt_without_checkpoint_requires_operator() -> None:
    assessment = ResumeReconciler().assess(
        _snapshot(
            state_status=RunStatus.WAITING_APPROVAL,
            checkpoint=CheckpointView(False),
            approvals=(ApprovalView("run-1", "approval", "resolved_unconsumed"),),
        ),
        now=NOW,
    )

    assert assessment.action == ReconciliationAction.REQUIRE_OPERATOR_RECOVERY
    assert assessment.reason_codes == ("RESOLVED_INTERRUPT_HAS_NO_CHECKPOINT",)


def test_committed_result_not_applied_to_state_returns_cache_without_reexecution() -> None:
    assessment = ResumeReconciler().assess(
        _snapshot(
            invocations=(
                InvocationView(
                    "run-1",
                    "inv-cached",
                    "scan",
                    InvocationStatus.COMPLETED,
                    2,
                    1,
                    True,
                    result_committed=True,
                    applied_to_state=False,
                ),
            )
        ),
        now=NOW,
    )

    assert assessment.action == ReconciliationAction.RETURN_CACHED_RESULT
    assert assessment.invocation_ids == ("inv-cached",)
    assert assessment.stale_invocation_ids == ()


def test_old_fence_completed_result_is_stale_and_never_applied_to_current_state() -> None:
    assessment = ResumeReconciler().assess(
        _snapshot(
            invocations=(
                InvocationView(
                    "run-1",
                    "inv-stale",
                    "scan",
                    InvocationStatus.COMPLETED,
                    1,
                    1,
                    True,
                    result_committed=True,
                    applied_to_state=False,
                ),
            )
        ),
        now=NOW,
    )

    assert assessment.action == ReconciliationAction.REQUIRE_OPERATOR_RECOVERY
    assert assessment.reason_codes == ("STALE_RESULT_MUST_NOT_ENTER_CURRENT_STATE",)
    assert assessment.stale_invocation_ids == ("inv-stale",)


def test_expired_idempotent_invocation_requeues_but_non_idempotent_unknown_does_not() -> None:
    safe = InvocationView(
        "run-1",
        "inv-safe",
        "scan",
        InvocationStatus.RUNNING,
        2,
        1,
        True,
        lease_until=NOW - timedelta(seconds=1),
    )
    unsafe = InvocationView(
        "run-1",
        "inv-unsafe",
        "modify",
        InvocationStatus.RUNNING,
        2,
        1,
        False,
        outcome_uncertain=True,
        lease_until=NOW - timedelta(seconds=1),
    )

    safe_result = ResumeReconciler().assess(_snapshot(invocations=(safe,)), now=NOW)
    unsafe_result = ResumeReconciler().assess(_snapshot(invocations=(unsafe,)), now=NOW)

    assert safe_result.action == ReconciliationAction.REQUEUE_SAFE_STEP
    assert safe_result.step_ids == ("scan",)
    assert unsafe_result.action == ReconciliationAction.REQUIRE_OPERATOR_RECOVERY
    assert unsafe_result.reason_codes == ("NON_IDEMPOTENT_OUTCOME_UNCERTAIN",)


def test_old_fence_runner_is_reaped_and_cannot_be_resumed() -> None:
    stale = RunnerResourceView("run-1", "container-old", "inv-old", fence=1)
    assessment = ResumeReconciler().assess(
        _snapshot(runner_resources=(stale,)),
        now=NOW,
    )

    assert assessment.action == ReconciliationAction.CANCEL_AND_REAP
    assert assessment.reason_codes == ("STALE_RUNNER_RESOURCE",)
    assert assessment.runner_resource_ids == ("container-old",)


def test_current_fence_orphan_runner_is_reaped_before_checkpoint_resume() -> None:
    orphan = RunnerResourceView("run-1", "container-orphan", "missing-invocation", fence=2)

    assessment = ResumeReconciler().assess(_snapshot(runner_resources=(orphan,)), now=NOW)

    assert assessment.action == ReconciliationAction.CANCEL_AND_REAP
    assert assessment.reason_codes == ("ORPHAN_RUNNER_RESOURCE",)
    assert assessment.runner_resource_ids == ("container-orphan",)


def test_terminal_commit_with_pending_projection_finalizes_outbox_only() -> None:
    assessment = ResumeReconciler().assess(
        _snapshot(
            state_status=RunStatus.COMPLETED,
            outbox=OutboxView(pending_count=1),
            report_committed=True,
        ),
        now=NOW,
    )

    assert assessment.action == ReconciliationAction.FINALIZE_OUTBOX
    assert assessment.reason_codes == ("TERMINAL_STATE_REQUIRES_IDEMPOTENT_PROJECTION",)


def test_failed_outbox_projection_is_finalized_before_graph_resume() -> None:
    assessment = ResumeReconciler().assess(
        _snapshot(outbox=OutboxView(failed_count=1)),
        now=NOW,
    )

    assert assessment.action == ReconciliationAction.FINALIZE_OUTBOX
    assert assessment.reason_codes == ("FAILED_OUTBOX_PROJECTION_REQUIRES_RETRY",)


def test_pending_run_without_checkpoint_or_side_effect_can_be_requeued() -> None:
    assessment = ResumeReconciler().assess(
        _snapshot(state_status=RunStatus.PENDING, checkpoint=CheckpointView(False)),
        now=NOW,
    )

    assert assessment.action == ReconciliationAction.REQUEUE_SAFE_STEP
    assert assessment.reason_codes == ("NO_CHECKPOINT_AND_NO_UNCERTAIN_SIDE_EFFECT",)


def test_assessment_is_order_independent_and_digest_is_stable() -> None:
    first = _snapshot(
        invocations=(
            InvocationView("run-1", "b", "b-step", InvocationStatus.FAILED, 2, 1, True),
            InvocationView("run-1", "a", "a-step", InvocationStatus.FAILED, 2, 1, True),
        )
    )
    second = replace(first, invocations=tuple(reversed(first.invocations)))

    first_result = ResumeReconciler().assess(first, now=NOW)
    second_result = ResumeReconciler().assess(second, now=NOW)

    assert first_result == second_result
    assert len(first_result.assessment_digest) == 64


@pytest.mark.parametrize(
    "snapshot",
    [
        _snapshot(run_job=RunJobView("unknown", 2)),
        _snapshot(run_job=RunJobView("leased", 2)),
        _snapshot(run_job=RunJobView("queued", 2, owner_id="unexpected")),
        _snapshot(approvals=(ApprovalView("run-1", "approval", "unknown"),)),
        _snapshot(clarifications=(ClarificationView("run-1", "clarification", "unknown"),)),
        _snapshot(steps=(StepView("run-1", "future", StepStatus.READY, 3, True, run_fence=3),)),
        _snapshot(invocations=(InvocationView("run-1", "complete", "scan", InvocationStatus.COMPLETED, 2, 1, True),)),
    ],
)
def test_invalid_control_plane_projection_requires_operator(snapshot: ReconciliationSnapshot) -> None:
    assessment = ResumeReconciler().assess(snapshot, now=NOW)

    assert assessment.action == ReconciliationAction.REQUIRE_OPERATOR_RECOVERY


def test_multiple_interrupt_types_and_missing_wait_records_require_operator() -> None:
    both = ResumeReconciler().assess(
        _snapshot(
            approvals=(ApprovalView("run-1", "approval", "pending"),),
            clarifications=(ClarificationView("run-1", "clarification", "pending"),),
        ),
        now=NOW,
    )
    missing = ResumeReconciler().assess(
        _snapshot(state_status=RunStatus.WAITING_APPROVAL),
        now=NOW,
    )

    assert both.reason_codes == ("MULTIPLE_INTERRUPT_TYPES_ACTIVE",)
    assert missing.reason_codes == ("WAITING_APPROVAL_WITHOUT_ACTIVE_REQUEST",)


def test_future_fence_and_terminal_invocation_resources_do_not_resume() -> None:
    future = ResumeReconciler().assess(
        _snapshot(runner_resources=(RunnerResourceView("run-1", "future", "inv", fence=3),)),
        now=NOW,
    )
    terminal = ResumeReconciler().assess(
        _snapshot(
            invocations=(
                InvocationView(
                    "run-1",
                    "inv-terminal",
                    "scan",
                    InvocationStatus.COMPLETED,
                    2,
                    1,
                    True,
                    result_committed=True,
                    applied_to_state=True,
                ),
            ),
            runner_resources=(RunnerResourceView("run-1", "leftover", "inv-terminal", fence=2),),
        ),
        now=NOW,
    )

    assert future.reason_codes == ("RUNNER_FENCE_AHEAD_OF_CONTROL_PLANE",)
    assert terminal.action == ReconciliationAction.CANCEL_AND_REAP
    assert terminal.reason_codes == ("RUNNER_REMAINED_AFTER_INVOCATION_TERMINAL",)


def test_durable_cancellation_and_recovery_required_are_safety_decisions() -> None:
    cancelled = ResumeReconciler().assess(_snapshot(cancel_requested=True), now=NOW)
    recovery = ResumeReconciler().assess(_snapshot(state_status=RunStatus.RECOVERY_REQUIRED), now=NOW)

    assert cancelled.action == ReconciliationAction.CANCEL_AND_REAP
    assert recovery.action == ReconciliationAction.REQUIRE_OPERATOR_RECOVERY


def test_abandoned_non_idempotent_running_invocation_requires_operator() -> None:
    invocation = InvocationView(
        "run-1",
        "inv-unsafe",
        "modify",
        InvocationStatus.RUNNING,
        2,
        1,
        False,
        lease_until=NOW - timedelta(seconds=1),
    )

    assessment = ResumeReconciler().assess(_snapshot(invocations=(invocation,)), now=NOW)

    assert assessment.reason_codes == ("NON_IDEMPOTENT_RUNNING_OUTCOME_UNKNOWN",)


def test_report_checkpoint_safe_step_and_partial_paths_are_distinct() -> None:
    report = ResumeReconciler().assess(_snapshot(report_committed=True), now=NOW)
    checkpoint = ResumeReconciler().assess(_snapshot(), now=NOW)
    safe_step = ResumeReconciler().assess(
        _snapshot(
            checkpoint=CheckpointView(False),
            steps=(StepView("run-1", "scan", StepStatus.READY, 2, True),),
        ),
        now=NOW,
    )
    partial = ResumeReconciler().assess(
        _snapshot(
            checkpoint=CheckpointView(False),
            steps=(StepView("run-1", "scan", StepStatus.SUCCEEDED, 2, False),),
        ),
        now=NOW,
    )

    assert report.action == ReconciliationAction.FINALIZE_OUTBOX
    assert checkpoint.action == ReconciliationAction.RESUME_FROM_CHECKPOINT
    assert safe_step.action == ReconciliationAction.REQUEUE_SAFE_STEP
    assert partial.action == ReconciliationAction.MARK_PARTIAL


def test_active_runner_without_checkpoint_is_reaped_only_when_idempotent() -> None:
    safe = InvocationView("run-1", "safe", "scan", InvocationStatus.RUNNING, 2, 1, True)
    unsafe = InvocationView("run-1", "unsafe", "modify", InvocationStatus.RUNNING, 2, 1, False)

    safe_result = ResumeReconciler().assess(
        _snapshot(
            checkpoint=CheckpointView(False),
            invocations=(safe,),
            runner_resources=(RunnerResourceView("run-1", "safe-container", "safe", 2),),
        ),
        now=NOW,
    )
    unsafe_result = ResumeReconciler().assess(
        _snapshot(
            checkpoint=CheckpointView(False),
            invocations=(unsafe,),
            runner_resources=(RunnerResourceView("run-1", "unsafe-container", "unsafe", 2),),
        ),
        now=NOW,
    )

    assert safe_result.reason_codes == ("IDEMPOTENT_RUNNER_HAS_NO_CHECKPOINT",)
    assert unsafe_result.reason_codes == ("NON_IDEMPOTENT_RUNNER_HAS_NO_CHECKPOINT",)


def test_invalid_projection_constructor_values_are_rejected() -> None:
    unavailable = ResumeReconciler().assess(
        _snapshot(checkpoint=CheckpointView(True)),
        now=NOW,
    )
    assert unavailable.reason_codes == ("CHECKPOINT_STATE_VERSION_UNAVAILABLE",)
    with pytest.raises(ValueError):
        RunJobView("queued", -1)
    with pytest.raises(ValueError):
        StepView("", "step", StepStatus.READY, 1, True)
    with pytest.raises(ValueError):
        InvocationView("run", "inv", "step", InvocationStatus.RUNNING, 1, 0, True)
    with pytest.raises(ValueError):
        RunnerResourceView("run", "", "inv", 1)
    with pytest.raises(ValueError):
        ResumeReconciler().assess(_snapshot(), now=datetime(2026, 7, 14))
