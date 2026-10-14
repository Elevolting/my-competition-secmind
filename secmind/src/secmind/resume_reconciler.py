"""Deterministic recovery assessment across durable control-plane views.

``ResumeReconciler`` compares checkpoints, leases, steps, invocations,
approvals, artifacts, and outbox state. It only recommends an immutable resume
action; it never repairs rows or resumes a graph by itself.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Hashable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import TypeVar

from secmind.ledger import canonical_json
from secmind.schemas import InvocationStatus, ResumeAction, RunStatus, StepStatus

ReconciliationAction = ResumeAction


@dataclass(frozen=True)
class CheckpointView:
    exists: bool
    state_version: int | None = None
    checkpoint_id: str | None = None

    def __post_init__(self) -> None:
        if not self.exists and (self.state_version is not None or self.checkpoint_id is not None):
            raise ValueError("absent checkpoint cannot have identity or state version")
        if self.state_version is not None and self.state_version < 1:
            raise ValueError("checkpoint state version must be positive")


@dataclass(frozen=True)
class RunJobView:
    status: str
    fence: int
    owner_id: str | None = None
    lease_until: datetime | None = None

    def __post_init__(self) -> None:
        if self.fence < 0:
            raise ValueError("run job fence cannot be negative")


@dataclass(frozen=True)
class StepView:
    run_id: str
    step_id: str
    status: StepStatus
    fence: int
    idempotent: bool
    lease_until: datetime | None = None
    attempt: int = 1
    run_fence: int = 0

    def __post_init__(self) -> None:
        if not self.run_id or not self.step_id or self.fence < 0 or self.attempt < 1 or self.run_fence < 0:
            raise ValueError("valid step identity and fence are required")


@dataclass(frozen=True)
class InvocationView:
    run_id: str
    invocation_id: str
    step_id: str
    status: InvocationStatus
    fence: int
    attempt: int
    idempotent: bool
    result_committed: bool = False
    applied_to_state: bool = False
    outcome_uncertain: bool = False
    lease_until: datetime | None = None

    def __post_init__(self) -> None:
        if not self.run_id or not self.invocation_id or not self.step_id:
            raise ValueError("valid invocation identity is required")
        if self.fence < 0 or self.attempt < 1:
            raise ValueError("invocation fence and attempt are invalid")


@dataclass(frozen=True)
class ApprovalView:
    run_id: str
    request_id: str
    status: str


@dataclass(frozen=True)
class ClarificationView:
    run_id: str
    request_id: str
    status: str


@dataclass(frozen=True)
class ArtifactView:
    run_id: str
    artifact_id: str
    exists: bool
    digest_valid: bool


@dataclass(frozen=True)
class RunnerResourceView:
    run_id: str
    resource_id: str
    invocation_id: str
    fence: int
    active: bool = True

    def __post_init__(self) -> None:
        if not self.run_id or not self.resource_id or not self.invocation_id or self.fence < 0:
            raise ValueError("valid runner resource identity and fence are required")


@dataclass(frozen=True)
class OutboxView:
    pending_count: int = 0
    failed_count: int = 0
    ledger_head_matches: bool = True


@dataclass(frozen=True)
class ReconciliationSnapshot:
    run_id: str
    state_version: int
    state_status: RunStatus
    checkpoint: CheckpointView
    run_job: RunJobView
    steps: tuple[StepView, ...] = ()
    invocations: tuple[InvocationView, ...] = ()
    approvals: tuple[ApprovalView, ...] = ()
    clarifications: tuple[ClarificationView, ...] = ()
    artifacts: tuple[ArtifactView, ...] = ()
    runner_resources: tuple[RunnerResourceView, ...] = ()
    runner_resources_collected: bool = True
    unknown_invocation_ids: tuple[str, ...] = ()
    outbox: OutboxView = OutboxView()
    ledger_valid: bool = True
    budget_consistent: bool = True
    report_committed: bool = False
    cancel_requested: bool = False

    def __post_init__(self) -> None:
        if not self.run_id or self.state_version < 1 or self.run_job.fence < 0:
            raise ValueError("valid run identity, state version and fence are required")
        if self.outbox.pending_count < 0 or self.outbox.failed_count < 0:
            raise ValueError("outbox counts cannot be negative")
        if any(not item for item in self.unknown_invocation_ids):
            raise ValueError("unknown invocation identities cannot be empty")


@dataclass(frozen=True)
class ReconciliationAssessment:
    run_id: str
    action: ReconciliationAction
    reason_codes: tuple[str, ...]
    step_ids: tuple[str, ...]
    invocation_ids: tuple[str, ...]
    runner_resource_ids: tuple[str, ...]
    stale_invocation_ids: tuple[str, ...]
    fence: int
    checkpoint_state_version: int | None
    checkpoint_id: str | None
    control_digest: str
    runner_resources_collected: bool
    assessment_digest: str

    @property
    def requires_operator(self) -> bool:
        return self.action == ReconciliationAction.REQUIRE_OPERATOR_RECOVERY


class ResumeReconciler:
    """Pure, deterministic cross-plane recovery decision.

    The reconciler never mutates state or retries a side effect. Its one output is
    an allowlisted action that a fenced coordinator may execute and ledger.
    """

    TERMINAL_STEPS = {
        StepStatus.SUCCEEDED,
        StepStatus.FAILED,
        StepStatus.SKIPPED,
        StepStatus.CANCELLED,
    }
    TERMINAL_RUNS = {
        RunStatus.COMPLETED,
        RunStatus.PARTIAL,
        RunStatus.DENIED,
        RunStatus.FAILED,
        RunStatus.CANCELLED,
    }

    def assess(
        self,
        snapshot: ReconciliationSnapshot,
        *,
        now: datetime | None = None,
    ) -> ReconciliationAssessment:
        checked_at = now or datetime.now(UTC)
        if checked_at.tzinfo is None:
            raise ValueError("reconciliation time must be timezone-aware")
        integrity_reasons = self._integrity_reasons(snapshot)
        if integrity_reasons:
            return self._assessment(
                snapshot,
                ReconciliationAction.REQUIRE_OPERATOR_RECOVERY,
                integrity_reasons,
            )
        if snapshot.run_job.status == "leased" and _lease_active(snapshot.run_job.lease_until, checked_at):
            return self._assessment(
                snapshot,
                ReconciliationAction.REQUIRE_OPERATOR_RECOVERY,
                ("RUN_LEASE_STILL_ACTIVE",),
            )
        if snapshot.run_job.status == "leased":
            return self._assessment(
                snapshot,
                ReconciliationAction.REQUIRE_OPERATOR_RECOVERY,
                ("EXPIRED_RUN_LEASE_REQUIRES_COORDINATOR_RECLAIM",),
            )

        active_resources = tuple(sorted((item for item in snapshot.runner_resources if item.active), key=_resource_key))
        stale_resources = tuple(item for item in active_resources if item.fence < snapshot.run_job.fence)
        future_resources = tuple(item for item in active_resources if item.fence > snapshot.run_job.fence)
        if future_resources:
            return self._assessment(
                snapshot,
                ReconciliationAction.REQUIRE_OPERATOR_RECOVERY,
                ("RUNNER_FENCE_AHEAD_OF_CONTROL_PLANE",),
                resources=future_resources,
            )
        if snapshot.cancel_requested or snapshot.state_status == RunStatus.CANCELLED:
            return self._assessment(
                snapshot,
                ReconciliationAction.CANCEL_AND_REAP,
                ("CANCELLATION_IS_DURABLE",),
                resources=active_resources,
            )
        if stale_resources:
            return self._assessment(
                snapshot,
                ReconciliationAction.CANCEL_AND_REAP,
                ("STALE_RUNNER_RESOURCE",),
                resources=stale_resources,
            )
        invocation_ids = {item.invocation_id for item in snapshot.invocations}
        orphan_resources = tuple(item for item in active_resources if item.invocation_id not in invocation_ids)
        if orphan_resources:
            return self._assessment(
                snapshot,
                ReconciliationAction.CANCEL_AND_REAP,
                ("ORPHAN_RUNNER_RESOURCE",),
                resources=orphan_resources,
            )
        terminal_invocation_ids = {
            item.invocation_id
            for item in snapshot.invocations
            if item.status
            in {
                InvocationStatus.COMPLETED,
                InvocationStatus.FAILED,
                InvocationStatus.RECOVERY_REQUIRED,
                InvocationStatus.CANCELLED,
            }
        }
        terminal_resources = tuple(item for item in active_resources if item.invocation_id in terminal_invocation_ids)
        if terminal_resources:
            return self._assessment(
                snapshot,
                ReconciliationAction.CANCEL_AND_REAP,
                ("RUNNER_REMAINED_AFTER_INVOCATION_TERMINAL",),
                resources=terminal_resources,
            )
        if snapshot.state_status == RunStatus.RECOVERY_REQUIRED:
            return self._assessment(
                snapshot,
                ReconciliationAction.REQUIRE_OPERATOR_RECOVERY,
                ("RUN_ALREADY_REQUIRES_OPERATOR_RECOVERY",),
            )

        pending_approvals = tuple(
            sorted((item for item in snapshot.approvals if item.status == "pending"), key=_request_key)
        )
        ready_approvals = tuple(
            sorted((item for item in snapshot.approvals if item.status == "resolved_unconsumed"), key=_request_key)
        )
        pending_clarifications = tuple(
            sorted((item for item in snapshot.clarifications if item.status == "pending"), key=_request_key)
        )
        ready_clarifications = tuple(
            sorted(
                (item for item in snapshot.clarifications if item.status == "resolved_unconsumed"),
                key=_request_key,
            )
        )
        if (pending_approvals or ready_approvals) and (pending_clarifications or ready_clarifications):
            return self._assessment(
                snapshot,
                ReconciliationAction.REQUIRE_OPERATOR_RECOVERY,
                ("MULTIPLE_INTERRUPT_TYPES_ACTIVE",),
            )
        if pending_approvals:
            return self._assessment(
                snapshot,
                ReconciliationAction.WAIT_FOR_APPROVAL,
                ("APPROVAL_PENDING",),
            )
        if pending_clarifications:
            return self._assessment(
                snapshot,
                ReconciliationAction.WAIT_FOR_CLARIFICATION,
                ("CLARIFICATION_PENDING",),
            )
        if snapshot.state_status == RunStatus.WAITING_APPROVAL and not ready_approvals:
            return self._assessment(
                snapshot,
                ReconciliationAction.REQUIRE_OPERATOR_RECOVERY,
                ("WAITING_APPROVAL_WITHOUT_ACTIVE_REQUEST",),
            )
        if snapshot.state_status == RunStatus.WAITING_CLARIFICATION and not ready_clarifications:
            return self._assessment(
                snapshot,
                ReconciliationAction.REQUIRE_OPERATOR_RECOVERY,
                ("WAITING_CLARIFICATION_WITHOUT_ACTIVE_REQUEST",),
            )
        if ready_approvals or ready_clarifications:
            if not snapshot.checkpoint.exists:
                return self._assessment(
                    snapshot,
                    ReconciliationAction.REQUIRE_OPERATOR_RECOVERY,
                    ("RESOLVED_INTERRUPT_HAS_NO_CHECKPOINT",),
                )
            return self._assessment(
                snapshot,
                ReconciliationAction.RESUME_FROM_CHECKPOINT,
                ("RESOLVED_INTERRUPT_READY_FOR_SINGLE_CONSUME",),
            )

        uncertain = tuple(
            sorted(
                (
                    item
                    for item in snapshot.invocations
                    if item.status == InvocationStatus.RECOVERY_REQUIRED
                    or (item.outcome_uncertain and not item.idempotent)
                ),
                key=_invocation_key,
            )
        )
        if uncertain:
            return self._assessment(
                snapshot,
                ReconciliationAction.REQUIRE_OPERATOR_RECOVERY,
                ("NON_IDEMPOTENT_OUTCOME_UNCERTAIN",),
                invocations=uncertain,
            )

        stale_completed = tuple(
            sorted(
                (
                    item
                    for item in snapshot.invocations
                    if item.status == InvocationStatus.COMPLETED
                    and item.result_committed
                    and not item.applied_to_state
                    and item.fence < snapshot.run_job.fence
                ),
                key=_invocation_key,
            )
        )
        if stale_completed:
            return self._assessment(
                snapshot,
                ReconciliationAction.REQUIRE_OPERATOR_RECOVERY,
                ("STALE_RESULT_MUST_NOT_ENTER_CURRENT_STATE",),
                invocations=stale_completed,
            )

        cached = tuple(
            sorted(
                (
                    item
                    for item in snapshot.invocations
                    if item.status == InvocationStatus.COMPLETED
                    and item.result_committed
                    and not item.applied_to_state
                    and item.fence == snapshot.run_job.fence
                ),
                key=_invocation_key,
            )
        )
        if cached:
            return self._assessment(
                snapshot,
                ReconciliationAction.RETURN_CACHED_RESULT,
                ("DURABLE_RESULT_NOT_APPLIED_TO_STATE",),
                invocations=cached,
            )

        running = tuple(item for item in snapshot.invocations if item.status == InvocationStatus.RUNNING)
        active_invocation_ids = {item.invocation_id for item in active_resources}
        abandoned_non_idempotent = tuple(
            sorted(
                (
                    item
                    for item in running
                    if not item.idempotent
                    and item.invocation_id not in active_invocation_ids
                    and not _lease_active(item.lease_until, checked_at)
                ),
                key=_invocation_key,
            )
        )
        if abandoned_non_idempotent:
            return self._assessment(
                snapshot,
                ReconciliationAction.REQUIRE_OPERATOR_RECOVERY,
                ("NON_IDEMPOTENT_RUNNING_OUTCOME_UNKNOWN",),
                invocations=abandoned_non_idempotent,
            )
        active_without_checkpoint = tuple(
            item for item in running if item.invocation_id in active_invocation_ids and not snapshot.checkpoint.exists
        )
        if active_without_checkpoint:
            if all(item.idempotent for item in active_without_checkpoint):
                checkpointless_ids = {item.invocation_id for item in active_without_checkpoint}
                resources = tuple(item for item in active_resources if item.invocation_id in checkpointless_ids)
                return self._assessment(
                    snapshot,
                    ReconciliationAction.CANCEL_AND_REAP,
                    ("IDEMPOTENT_RUNNER_HAS_NO_CHECKPOINT",),
                    invocations=active_without_checkpoint,
                    resources=resources,
                )
            return self._assessment(
                snapshot,
                ReconciliationAction.REQUIRE_OPERATOR_RECOVERY,
                ("NON_IDEMPOTENT_RUNNER_HAS_NO_CHECKPOINT",),
                invocations=active_without_checkpoint,
            )

        safe_invocations = tuple(
            sorted(
                (
                    item
                    for item in snapshot.invocations
                    if item.idempotent
                    and (
                        item.status in {InvocationStatus.PENDING, InvocationStatus.FAILED}
                        or (
                            item.status == InvocationStatus.RUNNING
                            and item.invocation_id not in active_invocation_ids
                            and not _lease_active(item.lease_until, checked_at)
                        )
                    )
                ),
                key=_invocation_key,
            )
        )
        if safe_invocations:
            return self._assessment(
                snapshot,
                ReconciliationAction.REQUEUE_SAFE_STEP,
                ("IDEMPOTENT_INVOCATION_SAFE_TO_REQUEUE",),
                steps=tuple(sorted({item.step_id for item in safe_invocations})),
                invocations=safe_invocations,
            )

        if snapshot.outbox.failed_count:
            return self._assessment(
                snapshot,
                ReconciliationAction.FINALIZE_OUTBOX,
                ("FAILED_OUTBOX_PROJECTION_REQUIRES_RETRY",),
            )

        if snapshot.state_status in self.TERMINAL_RUNS:
            return self._assessment(
                snapshot,
                ReconciliationAction.FINALIZE_OUTBOX,
                ("TERMINAL_STATE_REQUIRES_IDEMPOTENT_PROJECTION",),
            )
        if snapshot.report_committed:
            return self._assessment(
                snapshot,
                ReconciliationAction.FINALIZE_OUTBOX,
                ("REPORT_COMMITTED_BEFORE_RUN_FINALIZATION",),
            )
        if snapshot.checkpoint.exists:
            return self._assessment(
                snapshot,
                ReconciliationAction.RESUME_FROM_CHECKPOINT,
                ("CHECKPOINT_AND_CONTROL_STATE_RECONCILED",),
            )

        safe_steps = tuple(
            sorted(
                item.step_id
                for item in snapshot.steps
                if item.idempotent and item.status in {StepStatus.PENDING, StepStatus.READY, StepStatus.FAILED}
            )
        )
        if safe_steps or (snapshot.state_status == RunStatus.PENDING and not snapshot.invocations):
            return self._assessment(
                snapshot,
                ReconciliationAction.REQUEUE_SAFE_STEP,
                ("NO_CHECKPOINT_AND_NO_UNCERTAIN_SIDE_EFFECT",),
                steps=safe_steps,
            )
        if snapshot.steps and all(item.status in self.TERMINAL_STEPS for item in snapshot.steps):
            return self._assessment(
                snapshot,
                ReconciliationAction.MARK_PARTIAL,
                ("ALL_STEPS_TERMINAL_BUT_RUN_NOT_FINALIZED",),
            )
        return self._assessment(
            snapshot,
            ReconciliationAction.REQUIRE_OPERATOR_RECOVERY,
            ("NO_SAFE_AUTOMATIC_RECOVERY_PATH",),
        )

    @staticmethod
    def _integrity_reasons(snapshot: ReconciliationSnapshot) -> tuple[str, ...]:
        reasons: list[str] = []
        if any(
            any(item.run_id != snapshot.run_id for item in projection)
            for projection in (
                snapshot.steps,
                snapshot.invocations,
                snapshot.approvals,
                snapshot.clarifications,
                snapshot.artifacts,
                snapshot.runner_resources,
            )
        ):
            reasons.append("CROSS_RUN_PROJECTION")
        if not snapshot.ledger_valid or not snapshot.outbox.ledger_head_matches:
            reasons.append("LEDGER_OR_OUTBOX_HEAD_INVALID")
        if not snapshot.budget_consistent:
            reasons.append("BUDGET_ACCOUNTING_MISMATCH")
        if any(not item.exists or not item.digest_valid for item in snapshot.artifacts):
            reasons.append("ARTIFACT_INTEGRITY_FAILURE")
        if snapshot.checkpoint.exists and snapshot.checkpoint.state_version is None:
            reasons.append("CHECKPOINT_STATE_VERSION_UNAVAILABLE")
        elif snapshot.checkpoint.state_version is not None:
            if snapshot.checkpoint.state_version > snapshot.state_version:
                reasons.append("CHECKPOINT_AHEAD_OF_BUSINESS_STATE")
            elif snapshot.checkpoint.state_version < snapshot.state_version:
                reasons.append("CHECKPOINT_BEHIND_BUSINESS_STATE")
        if _has_duplicate(snapshot.steps, lambda item: (item.step_id, item.attempt)):
            reasons.append("DUPLICATE_STEP_PROJECTION")
        if _has_duplicate(snapshot.invocations, lambda item: item.invocation_id):
            reasons.append("DUPLICATE_INVOCATION_PROJECTION")
        if _has_duplicate(snapshot.approvals, lambda item: item.request_id):
            reasons.append("DUPLICATE_APPROVAL_PROJECTION")
        if _has_duplicate(snapshot.clarifications, lambda item: item.request_id):
            reasons.append("DUPLICATE_CLARIFICATION_PROJECTION")
        if _has_duplicate(snapshot.runner_resources, lambda item: item.resource_id):
            reasons.append("DUPLICATE_RUNNER_RESOURCE_PROJECTION")
        if snapshot.unknown_invocation_ids:
            reasons.append("UNKNOWN_INVOCATION_STATUS")
        runner_state_required = snapshot.unknown_invocation_ids or any(
            item.status in {InvocationStatus.RUNNING, InvocationStatus.RECOVERY_REQUIRED}
            for item in snapshot.invocations
        )
        if not snapshot.runner_resources_collected and runner_state_required:
            reasons.append("RUNNER_RESOURCE_STATE_UNAVAILABLE")
        valid_approval_statuses = {"pending", "resolved_unconsumed", "consumed"}
        valid_clarification_statuses = {"pending", "resolved_unconsumed", "consumed"}
        if any(item.status not in valid_approval_statuses for item in snapshot.approvals):
            reasons.append("UNKNOWN_APPROVAL_STATUS")
        if any(item.status not in valid_clarification_statuses for item in snapshot.clarifications):
            reasons.append("UNKNOWN_CLARIFICATION_STATUS")
        valid_job_statuses = {
            "queued",
            "leased",
            "waiting",
            "retry",
            "recovery_required",
            "completed",
            "cancelled",
        }
        if snapshot.run_job.status not in valid_job_statuses:
            reasons.append("UNKNOWN_RUN_JOB_STATUS")
        if snapshot.run_job.status == "leased" and (
            snapshot.run_job.owner_id is None or snapshot.run_job.lease_until is None
        ):
            reasons.append("LEASED_JOB_HAS_NO_OWNER_OR_EXPIRY")
        if snapshot.run_job.status != "leased" and snapshot.run_job.owner_id is not None:
            reasons.append("UNLEASED_JOB_HAS_OWNER")
        if any(item.run_fence > snapshot.run_job.fence for item in snapshot.steps) or any(
            item.fence > snapshot.run_job.fence for item in snapshot.invocations
        ):
            reasons.append("DURABLE_FENCE_AHEAD_OF_RUN_JOB")
        if any(
            item.status == InvocationStatus.COMPLETED and not item.result_committed for item in snapshot.invocations
        ):
            reasons.append("COMPLETED_INVOCATION_WITHOUT_RESULT")
        return tuple(sorted(set(reasons)))

    @staticmethod
    def _assessment(
        snapshot: ReconciliationSnapshot,
        action: ReconciliationAction,
        reasons: tuple[str, ...],
        *,
        steps: tuple[str, ...] = (),
        invocations: tuple[InvocationView, ...] = (),
        resources: tuple[RunnerResourceView, ...] = (),
    ) -> ReconciliationAssessment:
        invocation_ids = tuple(sorted(item.invocation_id for item in invocations))
        resource_ids = tuple(sorted(item.resource_id for item in resources))
        stale_invocation_ids = tuple(
            sorted(item.invocation_id for item in snapshot.invocations if item.fence < snapshot.run_job.fence)
        )
        reason_codes = tuple(sorted(set(reasons)))
        step_ids = tuple(sorted(set(steps)))
        control_digest = _control_digest(snapshot)
        material = {
            "action": action.value,
            "checkpoint_id": snapshot.checkpoint.checkpoint_id,
            "checkpoint_state_version": snapshot.checkpoint.state_version,
            "control_digest": control_digest,
            "fence": snapshot.run_job.fence,
            "invocation_ids": invocation_ids,
            "reason_codes": reason_codes,
            "run_id": snapshot.run_id,
            "runner_resources_collected": snapshot.runner_resources_collected,
            "runner_resource_ids": resource_ids,
            "stale_invocation_ids": stale_invocation_ids,
            "state_version": snapshot.state_version,
            "step_ids": step_ids,
        }
        return ReconciliationAssessment(
            run_id=snapshot.run_id,
            action=action,
            reason_codes=reason_codes,
            step_ids=step_ids,
            invocation_ids=invocation_ids,
            runner_resource_ids=resource_ids,
            stale_invocation_ids=stale_invocation_ids,
            fence=snapshot.run_job.fence,
            checkpoint_state_version=snapshot.checkpoint.state_version,
            checkpoint_id=snapshot.checkpoint.checkpoint_id,
            control_digest=control_digest,
            runner_resources_collected=snapshot.runner_resources_collected,
            assessment_digest=hashlib.sha256(canonical_json(material).encode()).hexdigest(),
        )


def _control_digest(snapshot: ReconciliationSnapshot) -> str:
    """Bind an assessment to a deterministic summary of every control plane."""

    material = {
        "approvals": [asdict(item) for item in sorted(snapshot.approvals, key=_request_key)],
        "artifacts": [asdict(item) for item in sorted(snapshot.artifacts, key=lambda item: item.artifact_id)],
        "budget_consistent": snapshot.budget_consistent,
        "cancel_requested": snapshot.cancel_requested,
        "checkpoint": asdict(snapshot.checkpoint),
        "clarifications": [asdict(item) for item in sorted(snapshot.clarifications, key=_request_key)],
        "invocations": [asdict(item) for item in sorted(snapshot.invocations, key=_invocation_key)],
        "ledger_valid": snapshot.ledger_valid,
        "outbox": asdict(snapshot.outbox),
        "report_committed": snapshot.report_committed,
        "run_id": snapshot.run_id,
        "run_job": asdict(snapshot.run_job),
        "runner_resources": [asdict(item) for item in sorted(snapshot.runner_resources, key=_resource_key)],
        "runner_resources_collected": snapshot.runner_resources_collected,
        "state_status": snapshot.state_status.value,
        "state_version": snapshot.state_version,
        "steps": [asdict(item) for item in sorted(snapshot.steps, key=lambda item: item.step_id)],
        "unknown_invocation_ids": sorted(snapshot.unknown_invocation_ids),
    }
    return hashlib.sha256(canonical_json(material).encode()).hexdigest()


def _lease_active(value: datetime | None, now: datetime) -> bool:
    if value is None:
        return False
    effective = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    return effective > now


_T = TypeVar("_T")


def _has_duplicate(items: tuple[_T, ...], key: Callable[[_T], Hashable]) -> bool:
    values = [key(item) for item in items]
    return len(values) != len(set(values))


def _invocation_key(value: InvocationView) -> tuple[str, int]:
    return value.invocation_id, value.attempt


def _resource_key(value: RunnerResourceView) -> str:
    return value.resource_id


def _request_key(value: ApprovalView | ClarificationView) -> str:
    return value.request_id


__all__ = [
    "ApprovalView",
    "ArtifactView",
    "CheckpointView",
    "ClarificationView",
    "InvocationView",
    "OutboxView",
    "ReconciliationAction",
    "ReconciliationAssessment",
    "ReconciliationSnapshot",
    "ResumeReconciler",
    "RunJobView",
    "RunnerResourceView",
    "StepView",
]
