from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine, update
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from secmind.coordinator import CoordinatorBase, CoordinatorStore, OutboxEventRow, RunJobRow
from secmind.execution import ExecutionBase, ToolInvocationRow
from secmind.investigation.contracts import (
    ArtifactDataClass,
    ArtifactSecurityLabel,
    ArtifactView,
    CollaborationMessage,
    CompletionOutcome,
    CompletionReceipt,
    CompletionSnapshotV2,
    DispatchPermit,
    MessageKind,
    MessageReceipt,
    ObligationStatus,
    RecoveryAction,
    RecoveryCommand,
    RequirementObligation,
    SecureStateProjection,
    UsageReservation,
    UsageSettlement,
    canonical_content_digest,
    seal_contract,
)
from secmind.investigation.store import (
    DispatchPermitRow,
    InvestigationAccessDenied,
    InvestigationBase,
    InvestigationConflict,
    InvestigationMessageRow,
    InvestigationStore,
    MessageReceiptRow,
    RecoveryCommandRow,
)
from secmind.ledger import Base, RunRow
from secmind.schemas import AgentState, InvocationStatus, TaskRequest
from secmind.task_specs import CognitiveBase

SHA_A = "a" * 64
SHA_B = "b" * 64


@dataclass(frozen=True)
class StoreFixture:
    store: InvestigationStore
    engine: Engine
    run_id: str
    owner_id: str
    fence: int
    state: AgentState

    def authority(self):
        return self.store.issue_authority(
            self.run_id,
            owner_id=self.owner_id,
            run_fence=self.fence,
        )


@pytest.fixture
def store_fixture() -> Iterator[StoreFixture]:
    engine = create_engine(
        "sqlite://",
        future=True,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    CoordinatorBase.metadata.create_all(engine)
    ExecutionBase.metadata.create_all(engine)
    CognitiveBase.metadata.create_all(engine)
    InvestigationBase.metadata.create_all(engine)
    now = datetime.now(UTC)
    run_id = "run-v06-store"
    owner_id = "worker-1"
    fence = 7
    state = AgentState(
        run_id=run_id,
        task=TaskRequest(objective="Audit the repository for security defects"),
    )
    with Session(engine) as session:
        session.add(
            RunRow(
                run_id=run_id,
                status=state.status.value,
                state_version=state.state_version,
                state_json=state.model_dump_json(),
                created_at=now,
                updated_at=now,
            )
        )
        session.add(
            RunJobRow(
                run_id=run_id,
                status="leased",
                owner_id=owner_id,
                lease_until=now + timedelta(minutes=5),
                fence=fence,
                heartbeat_at=now,
                wake_requested=False,
                next_attempt_at=now,
                attempts=1,
                created_at=now,
                updated_at=now,
            )
        )
        session.commit()
    fixture = StoreFixture(
        store=InvestigationStore(engine=engine, initialize_schema=False),
        engine=engine,
        run_id=run_id,
        owner_id=owner_id,
        fence=fence,
        state=state,
    )
    yield fixture
    fixture.store.close()
    engine.dispose()


def reservation(
    fixture: StoreFixture,
    reservation_id: str,
    *,
    parent_id: str | None = None,
    tool_calls: int = 0,
    input_tokens: int = 0,
    cost_units: float = 0,
) -> UsageReservation:
    return seal_contract(
        UsageReservation,
        reservation_id=reservation_id,
        run_id=fixture.run_id,
        parent_reservation_id=parent_id,
        transition_id=f"transition:{reservation_id}",
        kind="run" if parent_id is None else "step",
        tool_calls=tool_calls,
        input_tokens=input_tokens,
        cost_units=cost_units,
    )


def settlement(
    fixture: StoreFixture,
    reservation_id: str,
    *,
    settlement_id: str = "settlement-1",
    actual_tool_calls: int = 0,
    input_tokens: int = 0,
    cost_units: float = 0,
) -> UsageSettlement:
    return seal_contract(
        UsageSettlement,
        digest_field="receipt_digest",
        settlement_id=settlement_id,
        reservation_id=reservation_id,
        run_id=fixture.run_id,
        actual_tool_calls=actual_tool_calls,
        input_tokens=input_tokens,
        cost_units=cost_units,
    )


def snapshot(
    fixture: StoreFixture,
    *,
    quiet_epoch: int,
    obligation_id: str,
    active_invocations: list[str] | None = None,
    ledger_integrity: bool = True,
) -> CompletionSnapshotV2:
    return seal_contract(
        CompletionSnapshotV2,
        digest_field="snapshot_digest",
        run_id=fixture.run_id,
        run_state_version=fixture.state.state_version,
        run_fence=fixture.fence,
        quiet_epoch=quiet_epoch,
        active_invocations=active_invocations or [],
        input_integrity=True,
        artifact_integrity=True,
        evidence_integrity=True,
        ledger_integrity=ledger_integrity,
        requirement_obligations=[obligation_id],
    )


def completion_receipt(
    fixture: StoreFixture,
    value: CompletionSnapshotV2,
    *,
    obligation_id: str,
    verifier_receipt_id: str,
) -> CompletionReceipt:
    return seal_contract(
        CompletionReceipt,
        digest_field="receipt_digest",
        run_id=fixture.run_id,
        snapshot_id=value.snapshot_id,
        decision=CompletionOutcome.COMPLETE,
        satisfied_obligation_ids=[obligation_id],
        verification_receipt_ids=[verifier_receipt_id],
        gate_rule_version="v0.6-test",
    )


def satisfied_requirement(
    fixture: StoreFixture,
    *,
    obligation_id: str = "requirement-1",
    verifier_receipt_id: str = "verification-1",
) -> RequirementObligation:
    requirement = seal_contract(
        RequirementObligation,
        obligation_id=obligation_id,
        run_id=fixture.run_id,
        source_type="task",
        source_ref=f"task:{obligation_id}",
        requirement_summary="Every reported conclusion is bound to verified evidence.",
        immutable_scope=["."],
        satisfaction_rule_id="evidence-obligation-v1",
        required_evidence_types=["tool_observation"],
        status=ObligationStatus.SATISFIED,
        satisfied_by_evidence_ids=[f"evidence:{obligation_id}"],
        verifier_receipt_id=verifier_receipt_id,
    )
    fixture.store.put_object(
        requirement,
        run_id=fixture.run_id,
        object_type="requirement_obligation",
        object_id=requirement.obligation_id,
        logical_key=requirement.obligation_id,
        content_digest=requirement.content_digest,
    )
    return requirement


def collaboration_message(
    fixture: StoreFixture,
    *,
    message_id: str,
    dedupe_key: str,
    payload: dict[str, object],
) -> CollaborationMessage:
    return CollaborationMessage(
        message_id=message_id,
        run_id=fixture.run_id,
        sender_profile_id="specialist",
        sender_delegation_id="delegation-1",
        sender_thread_id="thread-1",
        sender_attempt=1,
        recipient_role="coordinator",
        kind=MessageKind.EVIDENCE_SUPPLIED,
        correlation_id="correlation-1",
        contract_digest=SHA_A,
        transition_id=f"message:{message_id}",
        run_fence=fixture.fence,
        payload_schema="evidence.supplied@1",
        payload=payload,
        payload_digest=canonical_content_digest(payload),
        dedupe_key=dedupe_key,
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )


def recovery_command(
    fixture: StoreFixture,
    *,
    command_id: str,
    issued_fence: int | None = None,
) -> RecoveryCommand:
    return seal_contract(
        RecoveryCommand,
        digest_field="command_digest",
        command_id=command_id,
        run_id=fixture.run_id,
        assessment_id=f"assessment:{command_id}",
        assessment_digest=SHA_A,
        action=RecoveryAction.RESUME_CHECKPOINT,
        checkpoint_id="checkpoint-1",
        checkpoint_state_version=1,
        expected_run_state_version=fixture.state.state_version,
        issued_fence=issued_fence if issued_fence is not None else fixture.fence,
        postconditions=["checkpoint state is reconciled with durable business state"],
    )


def test_run_authority_requires_the_current_database_owner_fence_and_lease(store_fixture: StoreFixture) -> None:
    authority = store_fixture.authority()
    assert authority.owner_id == store_fixture.owner_id
    assert authority.run_fence == store_fixture.fence
    assert authority.claimed_state_version == store_fixture.state.state_version

    with pytest.raises(InvestigationConflict, match="current durable lease"):
        store_fixture.store.issue_authority(
            store_fixture.run_id,
            owner_id=store_fixture.owner_id,
            run_fence=store_fixture.fence - 1,
        )
    with pytest.raises(InvestigationConflict, match="current durable lease"):
        store_fixture.store.issue_authority(
            store_fixture.run_id,
            owner_id="stale-worker",
            run_fence=store_fixture.fence,
        )

    with Session(store_fixture.engine) as session:
        job = session.get(RunJobRow, store_fixture.run_id)
        assert job is not None
        job.lease_until = datetime.now(UTC) - timedelta(seconds=1)
        session.commit()
    with pytest.raises(InvestigationConflict, match="current durable lease"):
        store_fixture.store.issue_authority(
            store_fixture.run_id,
            owner_id=store_fixture.owner_id,
            run_fence=store_fixture.fence,
        )


def test_transition_replay_returns_the_durable_post_state_and_rejects_conflicting_payload(
    store_fixture: StoreFixture,
) -> None:
    authority = store_fixture.authority()
    first = store_fixture.store.commit_transition(
        store_fixture.state,
        authority=authority,
        transition_id="transition:ingest:1",
        graph_node_id="ingest",
        event_type="investigation.ingested",
        event_payload={"artifact_ids": ["artifact-1"]},
    )
    assert not first.replayed
    assert first.state.state_version == store_fixture.state.state_version + 1

    replay = store_fixture.store.commit_transition(
        store_fixture.state.model_copy(update={"last_error": "must not replace durable post-state"}),
        authority=authority,
        transition_id="transition:ingest:1",
        graph_node_id="ingest",
        event_type="investigation.ingested",
        event_payload={"artifact_ids": ["artifact-1"]},
    )
    assert replay.replayed
    assert replay.state == first.state
    assert replay.receipt == first.receipt

    with pytest.raises(InvestigationConflict, match="replay content"):
        store_fixture.store.commit_transition(
            store_fixture.state,
            authority=authority,
            transition_id="transition:ingest:1",
            graph_node_id="ingest",
            event_type="investigation.ingested",
            event_payload={"artifact_ids": ["different-artifact"]},
        )


def test_usage_reservations_cannot_oversell_parent_and_settle_or_release_once(
    store_fixture: StoreFixture,
) -> None:
    parent = reservation(
        store_fixture,
        "reservation-parent",
        tool_calls=4,
        input_tokens=1_000,
        cost_units=4,
    )
    first = reservation(
        store_fixture,
        "reservation-child-1",
        parent_id=parent.reservation_id,
        tool_calls=3,
        input_tokens=700,
        cost_units=3,
    )
    oversold = reservation(
        store_fixture,
        "reservation-child-2",
        parent_id=parent.reservation_id,
        tool_calls=2,
        input_tokens=400,
        cost_units=2,
    )
    store_fixture.store.reserve_usage(parent)
    store_fixture.store.reserve_usage(first)
    with pytest.raises(InvestigationConflict, match="oversell parent"):
        store_fixture.store.reserve_usage(oversold)

    store_fixture.store.release_usage(first.reservation_id, run_id=store_fixture.run_id)
    store_fixture.store.reserve_usage(oversold)
    settled = settlement(
        store_fixture,
        oversold.reservation_id,
        actual_tool_calls=2,
        input_tokens=350,
        cost_units=1.5,
    )
    assert store_fixture.store.settle_usage(settled) == settled
    assert store_fixture.store.settle_usage(settled) == settled
    with pytest.raises(InvestigationConflict, match="settled usage cannot be released"):
        store_fixture.store.release_usage(oversold.reservation_id, run_id=store_fixture.run_id)

    excessive = settlement(
        store_fixture,
        first.reservation_id,
        settlement_id="settlement-excessive",
        actual_tool_calls=4,
    )
    assert store_fixture.store.settle_usage(excessive) == excessive


def test_dispatch_permit_is_single_use_and_rejects_wrong_hash_or_expiry(store_fixture: StoreFixture) -> None:
    authority = store_fixture.authority()
    missing_step = DispatchPermit(
        permit_id="permit-without-step",
        invocation_id="invocation-without-step",
        run_id=store_fixture.run_id,
        step_run_id="missing-step-run",
        run_fence=store_fixture.fence,
        step_fence=1,
        input_digest=SHA_A,
        policy_decision_id="policy-1",
        expires_at=datetime.now(UTC) + timedelta(minutes=1),
        nonce="nonce-without-step",
    )
    with pytest.raises(InvestigationConflict, match="no current fenced step lease"):
        store_fixture.store.issue_dispatch_permit(missing_step, authority)

    parent = reservation(store_fixture, "permit-budget-root", tool_calls=1)
    step_budget = reservation(
        store_fixture,
        "permit-budget-step",
        parent_id=parent.reservation_id,
        tool_calls=1,
    )
    store_fixture.store.reserve_usage(parent)
    store_fixture.store.reserve_usage(step_budget)
    step_lease = CoordinatorStore(engine=store_fixture.engine, initialize_schema=False).claim_step(
        run_id=store_fixture.run_id,
        step_id="scan-step",
        owner_id=store_fixture.owner_id,
        run_fence=store_fixture.fence,
        transition_id="transition:scan-step:1",
        reservation_id=step_budget.reservation_id,
        lease_seconds=60,
    )
    permit = DispatchPermit(
        permit_id="permit-1",
        invocation_id="invocation-1",
        run_id=store_fixture.run_id,
        step_run_id=step_lease.step_run_id,
        run_fence=store_fixture.fence,
        step_fence=step_lease.fence,
        input_digest=SHA_A,
        policy_decision_id="policy-1",
        expires_at=datetime.now(UTC) + timedelta(minutes=1),
        nonce="nonce-1",
    )
    store_fixture.store.issue_dispatch_permit(permit, authority)
    with pytest.raises(InvestigationConflict, match="binding mismatch"):
        store_fixture.store.consume_dispatch_permit(
            permit.permit_id,
            invocation_id=permit.invocation_id,
            input_digest=SHA_B,
            run_fence=permit.run_fence,
            step_fence=permit.step_fence,
        )
    consumed = store_fixture.store.consume_dispatch_permit(
        permit.permit_id,
        invocation_id=permit.invocation_id,
        input_digest=permit.input_digest,
        run_fence=permit.run_fence,
        step_fence=permit.step_fence,
    )
    assert consumed.status.value == "consumed"
    with pytest.raises(InvestigationConflict, match="not consumable"):
        store_fixture.store.consume_dispatch_permit(
            permit.permit_id,
            invocation_id=permit.invocation_id,
            input_digest=permit.input_digest,
            run_fence=permit.run_fence,
            step_fence=permit.step_fence,
        )

    expiring = permit.model_copy(
        update={
            "permit_id": "permit-expired",
            "invocation_id": "invocation-expired",
            "nonce": "nonce-expired",
        }
    )
    store_fixture.store.issue_dispatch_permit(expiring, authority)
    with Session(store_fixture.engine) as session:
        session.execute(
            update(DispatchPermitRow)
            .where(DispatchPermitRow.permit_id == expiring.permit_id)
            .values(expires_at=datetime.now(UTC) - timedelta(seconds=1))
        )
        session.commit()
    with pytest.raises(InvestigationConflict, match="expired"):
        store_fixture.store.consume_dispatch_permit(
            expiring.permit_id,
            invocation_id=expiring.invocation_id,
            input_digest=expiring.input_digest,
            run_fence=expiring.run_fence,
            step_fence=expiring.step_fence,
        )


def test_artifact_authorization_denies_missing_cross_run_wrong_purpose_and_quarantine(
    store_fixture: StoreFixture,
) -> None:
    with pytest.raises(InvestigationAccessDenied, match="no current run-bound"):
        store_fixture.store.authorize_artifact(SHA_A, run_id=store_fixture.run_id, purpose="report")

    label = ArtifactSecurityLabel(
        artifact_id=SHA_A,
        owner_run_id=store_fixture.run_id,
        view=ArtifactView.OBSERVABLE,
        data_class=ArtifactDataClass.TOOL_OUTPUT,
        retention_policy_id="competition-run",
        allowed_purposes=["report"],
        created_by="tool-broker",
        content_sha256=SHA_A,
        size=42,
        media_type="application/json",
    )
    store_fixture.store.label_artifact(label)
    assert store_fixture.store.authorize_artifact(SHA_A, run_id=store_fixture.run_id, purpose="report") == label
    with pytest.raises(InvestigationAccessDenied, match="no current run-bound"):
        store_fixture.store.authorize_artifact(SHA_A, run_id="other-run", purpose="report")
    with pytest.raises(InvestigationAccessDenied, match="not authorized"):
        store_fixture.store.authorize_artifact(SHA_A, run_id=store_fixture.run_id, purpose="model_context")

    quarantined = label.model_copy(
        update={
            "artifact_id": SHA_B,
            "content_sha256": SHA_B,
            "view": ArtifactView.QUARANTINED,
        }
    )
    store_fixture.store.label_artifact(quarantined)
    with pytest.raises(InvestigationAccessDenied, match="not authorized"):
        store_fixture.store.authorize_artifact(SHA_B, run_id=store_fixture.run_id, purpose="report")


def test_artifact_classification_version_is_idempotent_conflict_safe_and_quarantine_wins(
    store_fixture: StoreFixture,
) -> None:
    observable = ArtifactSecurityLabel(
        artifact_id=SHA_A,
        owner_run_id=store_fixture.run_id,
        owner_step_id="step-1",
        owner_invocation_id="invocation-1",
        view=ArtifactView.OBSERVABLE,
        data_class=ArtifactDataClass.TOOL_OUTPUT,
        retention_policy_id="competition-run",
        allowed_purposes=["report"],
        created_by="tool-broker",
        classification_version=1,
        content_sha256=SHA_A,
        size=42,
        media_type="application/json",
    )
    assert store_fixture.store.label_artifact(observable) == observable
    assert store_fixture.store.label_artifact(observable) == observable
    with pytest.raises(InvestigationConflict, match="classification version conflicts"):
        store_fixture.store.label_artifact(
            observable.model_copy(update={"allowed_purposes": ["report", "model_context"]})
        )

    quarantined = observable.model_copy(
        update={
            "classification_version": 2,
            "view": ArtifactView.QUARANTINED,
            "allowed_purposes": ["security_review"],
        }
    )
    store_fixture.store.label_artifact(quarantined)
    with pytest.raises(InvestigationAccessDenied, match="not authorized"):
        store_fixture.store.authorize_artifact(
            observable.artifact_id,
            run_id=store_fixture.run_id,
            purpose="report",
        )


def test_secure_artifact_projection_is_idempotent_and_rejects_source_reuse(
    store_fixture: StoreFixture,
) -> None:
    projection = SecureStateProjection(
        projection_id="projection-1",
        source_ref="artifact:restricted-source",
        run_id=store_fixture.run_id,
        scrub_policy_version="secret-scrubber-v1",
        observable_ref="artifact:observable-projection",
        removed_field_paths=["$.credentials.token"],
        secret_fingerprints=[SHA_A],
        source_digest=SHA_A,
        observable_digest=SHA_B,
        scrub_receipt_digest="c" * 64,
    )
    assert store_fixture.store.record_secure_projection(projection) == projection
    assert store_fixture.store.record_secure_projection(projection) == projection
    with pytest.raises(InvestigationConflict, match="source was reused with different content"):
        store_fixture.store.record_secure_projection(
            projection.model_copy(
                update={
                    "projection_id": "projection-conflict",
                    "observable_ref": "artifact:different-projection",
                    "observable_digest": "d" * 64,
                }
            )
        )


def test_complete_receipt_requires_a_quiet_integrity_verified_snapshot(store_fixture: StoreFixture) -> None:
    authority = store_fixture.authority()
    obligation_id = "requirement-1"
    verifier_receipt_id = "verification-1"
    requirement = seal_contract(
        RequirementObligation,
        obligation_id=obligation_id,
        run_id=store_fixture.run_id,
        source_type="task",
        source_ref="task:security-audit",
        requirement_summary="Every reported conclusion is bound to verified evidence.",
        immutable_scope=["."],
        satisfaction_rule_id="evidence-obligation-v1",
        required_evidence_types=["tool_observation"],
        status=ObligationStatus.SATISFIED,
        satisfied_by_evidence_ids=["evidence-1"],
        verifier_receipt_id=verifier_receipt_id,
    )
    store_fixture.store.put_object(
        requirement,
        run_id=store_fixture.run_id,
        object_type="requirement_obligation",
        object_id=requirement.obligation_id,
        logical_key=requirement.obligation_id,
        content_digest=requirement.content_digest,
    )

    quiet = snapshot(store_fixture, quiet_epoch=1, obligation_id=obligation_id)
    store_fixture.store.record_completion_snapshot(quiet, authority)
    receipt = completion_receipt(
        store_fixture,
        quiet,
        obligation_id=obligation_id,
        verifier_receipt_id=verifier_receipt_id,
    )
    assert store_fixture.store.record_completion_receipt(receipt, authority) == receipt
    assert store_fixture.store.record_completion_receipt(receipt, authority) == receipt

    active = snapshot(
        store_fixture,
        quiet_epoch=2,
        obligation_id=obligation_id,
        active_invocations=["invocation-1"],
    )
    with pytest.raises(InvestigationConflict, match="durable control-plane quiescence"):
        store_fixture.store.record_completion_snapshot(active, authority)

    corrupt = snapshot(
        store_fixture,
        quiet_epoch=3,
        obligation_id=obligation_id,
        ledger_integrity=False,
    )
    store_fixture.store.record_completion_snapshot(corrupt, authority)
    with pytest.raises(InvestigationConflict, match="quiet, integrity-verified"):
        store_fixture.store.record_completion_receipt(
            completion_receipt(
                store_fixture,
                corrupt,
                obligation_id=obligation_id,
                verifier_receipt_id=verifier_receipt_id,
            ),
            authority,
        )


def test_completion_snapshot_and_receipt_replays_reject_conflicting_content(
    store_fixture: StoreFixture,
) -> None:
    authority = store_fixture.authority()
    requirement = satisfied_requirement(store_fixture)
    quiet = snapshot(
        store_fixture,
        quiet_epoch=1,
        obligation_id=requirement.obligation_id,
    )
    assert store_fixture.store.record_completion_snapshot(quiet, authority) == quiet
    assert store_fixture.store.record_completion_snapshot(quiet, authority) == quiet

    conflicting_snapshot = seal_contract(
        CompletionSnapshotV2,
        digest_field="snapshot_digest",
        **{
            **quiet.model_dump(mode="python", exclude={"snapshot_digest"}),
            "limitations": ["late limitation must not replace an immutable epoch"],
        },
    )
    with pytest.raises(InvestigationConflict, match="snapshot epoch conflicts"):
        store_fixture.store.record_completion_snapshot(conflicting_snapshot, authority)
    with pytest.raises(InvestigationConflict, match="snapshot digest is invalid"):
        store_fixture.store.record_completion_snapshot(
            quiet.model_copy(update={"quiet_epoch": 2, "snapshot_digest": SHA_B}),
            authority,
        )

    receipt = completion_receipt(
        store_fixture,
        quiet,
        obligation_id=requirement.obligation_id,
        verifier_receipt_id=requirement.verifier_receipt_id or "",
    )
    assert store_fixture.store.record_completion_receipt(receipt, authority) == receipt
    conflicting_receipt = seal_contract(
        CompletionReceipt,
        digest_field="receipt_digest",
        receipt_id="completion-conflict",
        run_id=store_fixture.run_id,
        snapshot_id=quiet.snapshot_id,
        decision=CompletionOutcome.COMPLETE,
        satisfied_obligation_ids=[requirement.obligation_id],
        verification_receipt_ids=[requirement.verifier_receipt_id],
        gate_rule_version="different-gate-rule",
    )
    with pytest.raises(InvestigationConflict, match="conflicting decision"):
        store_fixture.store.record_completion_receipt(conflicting_receipt, authority)


@pytest.mark.parametrize("status", ["pending", "projecting", "failed"])
def test_completion_snapshot_rechecks_all_unprojected_outbox_rows_in_its_transaction(
    store_fixture: StoreFixture,
    status: str,
) -> None:
    authority = store_fixture.authority()
    with Session(store_fixture.engine) as session:
        session.add(
            OutboxEventRow(
                outbox_id=f"outbox-{status}",
                run_id=store_fixture.run_id,
                transition_id=f"transition-{status}",
                transition_ordinal=23,
                event_type="test.event",
                actor="test",
                payload_json="{}",
                status=status,
                created_at=datetime.now(UTC),
            )
        )
        session.commit()

    stale_quiet = snapshot(
        store_fixture,
        quiet_epoch={"pending": 10, "projecting": 11, "failed": 12}[status],
        obligation_id="requirement-1",
    )
    with pytest.raises(InvestigationConflict, match="durable outbox quiescence"):
        store_fixture.store.record_completion_snapshot(stale_quiet, authority)

    accurate_nonquiet = seal_contract(
        CompletionSnapshotV2,
        digest_field="snapshot_digest",
        **{
            **stale_quiet.model_dump(mode="python", exclude={"snapshot_digest"}),
            "unprojected_outbox_ordinals": [23],
        },
    )
    assert store_fixture.store.record_completion_snapshot(accurate_nonquiet, authority) == accurate_nonquiet


def test_completion_snapshot_rechecks_active_control_plane_in_its_transaction(
    store_fixture: StoreFixture,
) -> None:
    authority = store_fixture.authority()
    now = datetime.now(UTC)
    with Session(store_fixture.engine) as session:
        session.add(
            ToolInvocationRow(
                invocation_id="invocation-active",
                run_id=store_fixture.run_id,
                step_id="scan",
                tool_name="bandit",
                tool_version="1",
                idempotency_key="active-invocation",
                parameters_hash=SHA_A,
                attempt=1,
                status=InvocationStatus.RUNNING.value,
                lease_until=now + timedelta(minutes=1),
                owner_id=store_fixture.owner_id,
                fence=store_fixture.fence,
                created_at=now,
                updated_at=now,
            )
        )
        session.commit()

    stale_quiet = snapshot(store_fixture, quiet_epoch=30, obligation_id="requirement-1")
    with pytest.raises(InvestigationConflict, match="control-plane quiescence"):
        store_fixture.store.record_completion_snapshot(stale_quiet, authority)

    accurate_active = seal_contract(
        CompletionSnapshotV2,
        digest_field="snapshot_digest",
        **{
            **stale_quiet.model_dump(mode="python", exclude={"snapshot_digest"}),
            "active_invocations": ["invocation-active"],
        },
    )
    assert store_fixture.store.record_completion_snapshot(accurate_active, authority) == accurate_active


def test_completion_receipt_rejects_missing_snapshot_bad_digest_and_inexact_evidence_binding(
    store_fixture: StoreFixture,
) -> None:
    authority = store_fixture.authority()
    requirement = satisfied_requirement(store_fixture)
    quiet = snapshot(
        store_fixture,
        quiet_epoch=1,
        obligation_id=requirement.obligation_id,
    )
    valid = completion_receipt(
        store_fixture,
        quiet,
        obligation_id=requirement.obligation_id,
        verifier_receipt_id=requirement.verifier_receipt_id or "",
    )
    with pytest.raises(InvestigationConflict, match="no matching snapshot"):
        store_fixture.store.record_completion_receipt(valid, authority)

    store_fixture.store.record_completion_snapshot(quiet, authority)
    with pytest.raises(InvestigationConflict, match="receipt digest is invalid"):
        store_fixture.store.record_completion_receipt(
            valid.model_copy(update={"receipt_digest": SHA_B}),
            authority,
        )
    incomplete = seal_contract(
        CompletionReceipt,
        digest_field="receipt_digest",
        run_id=store_fixture.run_id,
        snapshot_id=quiet.snapshot_id,
        decision=CompletionOutcome.PARTIAL,
        gate_rule_version="v0.6-test",
    )
    with pytest.raises(InvestigationConflict, match="exactly cover snapshot obligations"):
        store_fixture.store.record_completion_receipt(incomplete, authority)
    wrong_verifier = seal_contract(
        CompletionReceipt,
        digest_field="receipt_digest",
        run_id=store_fixture.run_id,
        snapshot_id=quiet.snapshot_id,
        decision=CompletionOutcome.COMPLETE,
        satisfied_obligation_ids=[requirement.obligation_id],
        verification_receipt_ids=["verification-other"],
        gate_rule_version="v0.6-test",
    )
    with pytest.raises(InvestigationConflict, match="exact verifier receipt set"):
        store_fixture.store.record_completion_receipt(wrong_verifier, authority)

    unknown = snapshot(
        store_fixture,
        quiet_epoch=2,
        obligation_id="requirement-unknown",
    )
    store_fixture.store.record_completion_snapshot(unknown, authority)
    with pytest.raises(InvestigationConflict, match="unknown requirement obligation"):
        store_fixture.store.record_completion_receipt(
            completion_receipt(
                store_fixture,
                unknown,
                obligation_id="requirement-unknown",
                verifier_receipt_id="verification-unknown",
            ),
            authority,
        )


def test_completion_snapshot_and_receipt_reject_stale_authority_after_fence_takeover(
    store_fixture: StoreFixture,
) -> None:
    authority = store_fixture.authority()
    requirement = satisfied_requirement(store_fixture)
    valid = snapshot(
        store_fixture,
        quiet_epoch=1,
        obligation_id=requirement.obligation_id,
    )
    stale_snapshot = seal_contract(
        CompletionSnapshotV2,
        digest_field="snapshot_digest",
        **{
            **valid.model_dump(mode="python", exclude={"snapshot_digest"}),
            "run_fence": store_fixture.fence - 1,
        },
    )
    with pytest.raises(InvestigationConflict, match="outside current run authority"):
        store_fixture.store.record_completion_snapshot(stale_snapshot, authority)

    store_fixture.store.record_completion_snapshot(valid, authority)
    with Session(store_fixture.engine) as session:
        job = session.get(RunJobRow, store_fixture.run_id)
        assert job is not None
        job.fence += 1
        session.commit()
    replacement_authority = store_fixture.store.issue_authority(
        store_fixture.run_id,
        owner_id=store_fixture.owner_id,
        run_fence=store_fixture.fence + 1,
    )
    with pytest.raises(InvestigationConflict, match="fence does not match current authority"):
        store_fixture.store.record_completion_receipt(
            completion_receipt(
                store_fixture,
                valid,
                obligation_id=requirement.obligation_id,
                verifier_receipt_id=requirement.verifier_receipt_id or "",
            ),
            replacement_authority,
        )


def test_message_dedupe_and_reclaim_reject_the_old_delivery_fence(store_fixture: StoreFixture) -> None:
    authority = store_fixture.authority()
    message = collaboration_message(
        store_fixture,
        message_id="message-1",
        dedupe_key="evidence:claim-1",
        payload={
            "schema_version": "1.5",
            "request_id": "request-1",
            "evidence_ids": ["evidence-1"],
        },
    )
    assert store_fixture.store.publish_message(message, authority) == message
    assert store_fixture.store.publish_message(message, authority) == message
    conflicting = collaboration_message(
        store_fixture,
        message_id="message-2",
        dedupe_key=message.dedupe_key,
        payload={
            "schema_version": "1.5",
            "request_id": "request-1",
            "evidence_ids": ["evidence-2"],
        },
    )
    with pytest.raises(InvestigationConflict, match="dedupe key"):
        store_fixture.store.publish_message(conflicting, authority)

    first = store_fixture.store.reserve_messages(
        store_fixture.run_id,
        recipient_role="coordinator",
        owner_id=store_fixture.owner_id,
        authority=authority,
    )[0]
    with Session(store_fixture.engine) as session:
        session.execute(
            update(MessageReceiptRow)
            .where(MessageReceiptRow.message_id == first.message_id)
            .values(lease_until=datetime.now(UTC) - timedelta(seconds=1))
        )
        session.commit()
    reclaimed = store_fixture.store.reserve_messages(
        store_fixture.run_id,
        recipient_role="coordinator",
        owner_id=store_fixture.owner_id,
        authority=authority,
    )[0]
    assert reclaimed.delivery_attempt == first.delivery_attempt + 1
    assert reclaimed.delivery_fence == first.delivery_fence + 1
    with pytest.raises(InvestigationConflict, match="lost its delivery fence"):
        store_fixture.store.acknowledge_message(
            first,
            transition_id="transition:stale-consumer",
            recipient_role="coordinator",
            authority=authority,
        )
    completed = store_fixture.store.acknowledge_message(
        reclaimed,
        transition_id="transition:consumer-2",
        recipient_role="coordinator",
        authority=authority,
    )
    assert completed.processing_status == "processed"
    assert (
        store_fixture.store.acknowledge_message(
            reclaimed,
            transition_id="transition:consumer-2",
            recipient_role="coordinator",
            authority=authority,
        )
        == completed
    )
    assert not store_fixture.store.reserve_messages(
        store_fixture.run_id,
        recipient_role="coordinator",
        owner_id=store_fixture.owner_id,
        authority=authority,
    )


def test_durable_mailbox_rejects_stale_authority_invalid_routes_and_payloads(
    store_fixture: StoreFixture,
) -> None:
    authority = store_fixture.authority()
    valid = collaboration_message(
        store_fixture,
        message_id="message-valid",
        dedupe_key="evidence:valid",
        payload={
            "schema_version": "1.5",
            "request_id": "request-valid",
            "evidence_ids": ["evidence-valid"],
        },
    )
    with pytest.raises(InvestigationAccessDenied, match="outside current run authority"):
        store_fixture.store.publish_message(
            valid.model_copy(update={"run_fence": store_fixture.fence - 1}),
            authority,
        )
    with pytest.raises(InvestigationAccessDenied, match="outside current run authority"):
        store_fixture.store.publish_message(
            valid.model_copy(update={"run_id": "another-run"}),
            authority,
        )
    with pytest.raises(InvestigationAccessDenied, match="only routes through the coordinator"):
        store_fixture.store.publish_message(
            valid.model_copy(update={"recipient_role": "specialist"}),
            authority,
        )
    with pytest.raises(InvestigationAccessDenied, match="another mailbox owner"):
        store_fixture.store.publish_message(
            valid.model_copy(update={"resolved_recipient_id": "other-worker"}),
            authority,
        )
    with pytest.raises(InvestigationConflict, match="routing identity is incomplete"):
        store_fixture.store.publish_message(
            valid.model_copy(update={"sender_thread_id": ""}),
            authority,
        )
    with pytest.raises(InvestigationConflict, match="payload schema"):
        store_fixture.store.publish_message(
            valid.model_copy(update={"payload_schema": "evidence.supplied@2"}),
            authority,
        )
    with pytest.raises(InvestigationConflict, match="payload digest mismatch"):
        store_fixture.store.publish_message(
            valid.model_copy(update={"payload_digest": SHA_B}),
            authority,
        )
    policy_payload = {
        "schema_version": "1.5",
        "request_id": "request-policy",
        "evidence_ids": ["evidence-policy"],
        "policy": {"allowed_tools": ["shell"]},
    }
    with pytest.raises(InvestigationConflict, match="message contract is invalid"):
        store_fixture.store.publish_message(
            valid.model_copy(
                update={
                    "message_id": "message-policy",
                    "dedupe_key": "evidence:policy",
                    "payload": policy_payload,
                    "payload_digest": canonical_content_digest(policy_payload),
                }
            ),
            authority,
        )
    store_fixture.store.publish_message(valid, authority)
    with Session(store_fixture.engine) as session:
        session.execute(
            update(InvestigationMessageRow)
            .where(InvestigationMessageRow.message_id == valid.message_id)
            .values(payload_digest=SHA_B)
        )
        session.commit()
    with pytest.raises(InvestigationConflict, match="indexed routing fields"):
        store_fixture.store.reserve_messages(
            store_fixture.run_id,
            recipient_role="coordinator",
            owner_id=store_fixture.owner_id,
            authority=authority,
        )


def test_durable_mailbox_rejects_corrupt_persisted_payload(store_fixture: StoreFixture) -> None:
    authority = store_fixture.authority()
    message = collaboration_message(
        store_fixture,
        message_id="message-corrupt-payload",
        dedupe_key="evidence:corrupt-payload",
        payload={
            "schema_version": "1.5",
            "request_id": "request-corrupt-payload",
            "evidence_ids": ["evidence-corrupt-payload"],
        },
    )
    store_fixture.store.publish_message(message, authority)
    with Session(store_fixture.engine) as session:
        session.execute(
            update(InvestigationMessageRow)
            .where(InvestigationMessageRow.message_id == message.message_id)
            .values(payload_json="{not-json")
        )
        session.commit()
    with pytest.raises(InvestigationConflict, match="stored mailbox message is invalid"):
        store_fixture.store.reserve_messages(
            store_fixture.run_id,
            recipient_role="coordinator",
            owner_id=store_fixture.owner_id,
            authority=authority,
        )


def test_durable_mailbox_reserve_and_ack_require_current_owner_and_recipient(
    store_fixture: StoreFixture,
) -> None:
    authority = store_fixture.authority()
    message = collaboration_message(
        store_fixture,
        message_id="message-owned",
        dedupe_key="evidence:owned",
        payload={
            "schema_version": "1.5",
            "request_id": "request-owned",
            "evidence_ids": ["evidence-owned"],
        },
    )
    store_fixture.store.publish_message(message, authority)
    with pytest.raises(InvestigationAccessDenied, match="only the coordinator"):
        store_fixture.store.reserve_messages(
            store_fixture.run_id,
            recipient_role="specialist",
            owner_id=store_fixture.owner_id,
            authority=authority,
        )
    with pytest.raises(InvestigationAccessDenied, match="not the current run owner"):
        store_fixture.store.reserve_messages(
            store_fixture.run_id,
            recipient_role="coordinator",
            owner_id="other-worker",
            authority=authority,
        )
    receipt = store_fixture.store.reserve_messages(
        store_fixture.run_id,
        recipient_role="coordinator",
        owner_id=store_fixture.owner_id,
        authority=authority,
    )[0]
    with pytest.raises(InvestigationAccessDenied, match="another reservation owner"):
        store_fixture.store.acknowledge_message(
            receipt.model_copy(update={"reservation_owner": "other-worker"}),
            transition_id="transition:foreign-owner",
            recipient_role="coordinator",
            authority=authority,
        )
    with pytest.raises(InvestigationAccessDenied, match="only the coordinator"):
        store_fixture.store.acknowledge_message(
            receipt,
            transition_id="transition:wrong-recipient",
            recipient_role="specialist",
            authority=authority,
        )


def test_durable_mailbox_rejects_expired_and_duplicate_envelopes(store_fixture: StoreFixture) -> None:
    authority = store_fixture.authority()
    payload = {
        "schema_version": "1.5",
        "request_id": "request-duplicate",
        "evidence_ids": ["evidence-duplicate"],
    }
    message = collaboration_message(
        store_fixture,
        message_id="message-duplicate",
        dedupe_key="evidence:duplicate",
        payload=payload,
    )
    with pytest.raises(InvestigationConflict, match="expiry is invalid"):
        store_fixture.store.publish_message(
            message.model_copy(update={"expires_at": datetime.now(UTC) - timedelta(seconds=1)}),
            authority,
        )

    store_fixture.store.publish_message(message, authority)
    with pytest.raises(InvestigationConflict, match="message id was reused"):
        store_fixture.store.publish_message(
            message.model_copy(update={"dedupe_key": "evidence:different-key"}),
            authority,
        )
    with pytest.raises(InvestigationConflict, match="dedupe key"):
        store_fixture.store.publish_message(
            message.model_copy(
                update={
                    "message_id": "message-same-payload-new-envelope",
                    "correlation_id": "different-correlation",
                }
            ),
            authority,
        )
    with pytest.raises(InvestigationAccessDenied, match="cross-run mailbox reservation"):
        store_fixture.store.reserve_messages(
            "another-run",
            recipient_role="coordinator",
            owner_id=store_fixture.owner_id,
            authority=authority,
        )
    with pytest.raises(ValueError, match="lease must be positive"):
        store_fixture.store.reserve_messages(
            store_fixture.run_id,
            recipient_role="coordinator",
            owner_id=store_fixture.owner_id,
            authority=authority,
            lease_seconds=0,
        )


def test_durable_mailbox_ack_rejects_missing_expired_tampered_and_conflicting_replay(
    store_fixture: StoreFixture,
) -> None:
    authority = store_fixture.authority()
    missing = MessageReceipt(
        message_id="message-missing",
        reservation_owner=store_fixture.owner_id,
        delivery_fence=1,
        lease_until=datetime.now(UTC) + timedelta(minutes=1),
        transport_status="reserved",
        processing_status="processing",
    )
    with pytest.raises(ValueError, match="transition id is required"):
        store_fixture.store.acknowledge_message(
            missing,
            transition_id="",
            recipient_role="coordinator",
            authority=authority,
        )
    with pytest.raises(InvestigationConflict, match="no durable message"):
        store_fixture.store.acknowledge_message(
            missing,
            transition_id="transition:missing",
            recipient_role="coordinator",
            authority=authority,
        )

    for index in (1, 2):
        store_fixture.store.publish_message(
            collaboration_message(
                store_fixture,
                message_id=f"message-ack-{index}",
                dedupe_key=f"evidence:ack:{index}",
                payload={
                    "schema_version": "1.5",
                    "request_id": f"request-ack-{index}",
                    "evidence_ids": [f"evidence-ack-{index}"],
                },
            ),
            authority,
        )
    first = store_fixture.store.reserve_messages(
        store_fixture.run_id,
        recipient_role="coordinator",
        owner_id=store_fixture.owner_id,
        authority=authority,
        limit=1,
    )[0]
    with pytest.raises(InvestigationConflict, match="does not match durable delivery"):
        store_fixture.store.acknowledge_message(
            first.model_copy(update={"receipt_version": first.receipt_version + 1}),
            transition_id="transition:tampered-receipt",
            recipient_role="coordinator",
            authority=authority,
        )
    completed = store_fixture.store.acknowledge_message(
        first,
        transition_id="transition:first-ack",
        recipient_role="coordinator",
        authority=authority,
    )
    assert completed.receipt_version == first.receipt_version + 1
    with pytest.raises(InvestigationConflict, match="different owner or transition"):
        store_fixture.store.acknowledge_message(
            first,
            transition_id="transition:conflicting-replay",
            recipient_role="coordinator",
            authority=authority,
        )

    second = store_fixture.store.reserve_messages(
        store_fixture.run_id,
        recipient_role="coordinator",
        owner_id=store_fixture.owner_id,
        authority=authority,
        limit=1,
    )[0]
    with Session(store_fixture.engine) as session:
        session.execute(
            update(MessageReceiptRow)
            .where(MessageReceiptRow.message_id == second.message_id)
            .values(lease_until=datetime.now(UTC) - timedelta(seconds=1))
        )
        session.commit()
    with pytest.raises(InvestigationConflict, match="lost its delivery fence"):
        store_fixture.store.acknowledge_message(
            second,
            transition_id="transition:expired-receipt",
            recipient_role="coordinator",
            authority=authority,
        )


def test_recovery_command_can_be_claimed_and_completed_only_once(store_fixture: StoreFixture) -> None:
    authority = store_fixture.authority()
    command = seal_contract(
        RecoveryCommand,
        digest_field="command_digest",
        command_id="recovery-command-1",
        run_id=store_fixture.run_id,
        assessment_id="assessment-1",
        assessment_digest=SHA_A,
        action=RecoveryAction.RESUME_CHECKPOINT,
        checkpoint_id="checkpoint-1",
        checkpoint_state_version=1,
        expected_run_state_version=store_fixture.state.state_version,
        issued_fence=store_fixture.fence,
        postconditions=["checkpoint state is reconciled with durable business state"],
    )
    assert store_fixture.store.create_recovery_command(command) == command
    claimed = store_fixture.store.claim_recovery_command(command.command_id, authority)
    assert claimed.status.value == "claimed"
    with pytest.raises(InvestigationConflict, match="already consumed"):
        store_fixture.store.claim_recovery_command(command.command_id, authority)

    store_fixture.store.complete_recovery_command(
        command.command_id,
        authority,
        result_receipt_id="recovery-result-1",
        applied=True,
    )
    with pytest.raises(InvestigationConflict, match="lost authority"):
        store_fixture.store.complete_recovery_command(
            command.command_id,
            authority,
            result_receipt_id="recovery-result-2",
            applied=True,
        )


def test_run_authority_and_recovery_fail_closed_for_missing_stale_and_failed_commands(
    store_fixture: StoreFixture,
) -> None:
    authority = store_fixture.authority()
    now = datetime.now(UTC)
    with Session(store_fixture.engine) as session:
        session.add(
            RunJobRow(
                run_id="run-without-state",
                status="leased",
                owner_id="worker-ghost",
                lease_until=now + timedelta(minutes=1),
                fence=1,
                heartbeat_at=now,
                wake_requested=False,
                next_attempt_at=now,
                attempts=1,
                created_at=now,
                updated_at=now,
            )
        )
        session.commit()
    with pytest.raises(InvestigationConflict, match="current durable lease"):
        store_fixture.store.issue_authority("run-without-state", owner_id="worker-ghost", run_fence=1)

    command = recovery_command(store_fixture, command_id="recovery-failed")
    assert store_fixture.store.create_recovery_command(command) == command
    assert store_fixture.store.create_recovery_command(command) == command
    with pytest.raises(InvestigationConflict, match="missing, stale, or already consumed"):
        store_fixture.store.claim_recovery_command("missing-command", authority)

    stale = recovery_command(
        store_fixture,
        command_id="recovery-stale",
        issued_fence=store_fixture.fence - 1,
    )
    store_fixture.store.create_recovery_command(stale)
    with pytest.raises(InvestigationConflict, match="missing, stale, or already consumed"):
        store_fixture.store.claim_recovery_command(stale.command_id, authority)

    store_fixture.store.claim_recovery_command(command.command_id, authority)
    store_fixture.store.complete_recovery_command(
        command.command_id,
        authority,
        result_receipt_id="recovery-failure-receipt",
        applied=False,
    )
    with Session(store_fixture.engine) as session:
        row = session.get(RecoveryCommandRow, command.command_id)
        assert row is not None
        assert row.status == "recovery_required"

    fresh = recovery_command(store_fixture, command_id="recovery-lost-authority")
    store_fixture.store.create_recovery_command(fresh)
    with Session(store_fixture.engine) as session:
        job = session.get(RunJobRow, store_fixture.run_id)
        assert job is not None
        job.fence += 1
        session.commit()
    with pytest.raises(InvestigationConflict, match="current database lease"):
        store_fixture.store.claim_recovery_command(fresh.command_id, authority)
