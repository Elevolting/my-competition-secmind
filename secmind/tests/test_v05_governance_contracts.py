from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError
from sqlalchemy.orm import Session

from secmind.coordinator import CoordinatorStore
from secmind.schemas import (
    AgentState,
    ApprovalBatch,
    ApprovalBatchRequest,
    ApprovalDecision,
    ApprovalResolutionItem,
    ApprovalResponse,
    BudgetState,
    ContextBudget,
    DataView,
    LogLayer,
    LogQuery,
    LogStream,
    OperatorSession,
    ResumeAction,
    ResumeAssessment,
    RetentionHold,
    RetentionHoldRequest,
    RetentionProfile,
    RunStatus,
    TaskRequest,
)
from secmind.unit_of_work import (
    ControlPlaneUnitOfWork,
    ResumeAssessmentRow,
    UnitOfWorkConflict,
)


def _state(run_id: str) -> AgentState:
    return AgentState(
        run_id=run_id,
        task=TaskRequest(objective="exercise governance contracts"),
        status=RunStatus.PENDING,
        budget=BudgetState(),
    )


def _assessment(run_id: str) -> ResumeAssessment:
    return ResumeAssessment(
        assessment_id="00000000-0000-4000-8000-000000000801",
        run_id=run_id,
        action=ResumeAction.REQUEUE_SAFE_STEP,
        reason_codes=["NO_CHECKPOINT_AND_NO_UNCERTAIN_SIDE_EFFECT"],
        rationale_summary="safe deterministic requeue",
        state_version=1,
        fence=0,
        checkpoint_present=False,
        assessment_digest="a" * 64,
    )


def test_retention_hold_and_resume_assessment_are_durable_and_idempotent(tmp_path) -> None:
    coordinator = CoordinatorStore(f"sqlite:///{tmp_path / 'governance.db'}")
    uow = ControlPlaneUnitOfWork(coordinator.engine)
    run_id = "00000000-0000-4000-8000-000000000800"
    assert uow.submit_run(_state(run_id))

    hold = RetentionHold(
        hold_id="00000000-0000-4000-8000-000000000802",
        run_id=run_id,
        reason="preserve evidence for appeal",
        expires_at=datetime.now(UTC) + timedelta(days=3),
    )
    assert uow.create_retention_hold(hold)
    assert not uow.create_retention_hold(hold)
    stored_holds = uow.list_retention_holds(run_id)
    assert [item.hold_id for item in stored_holds] == [hold.hold_id]
    with pytest.raises(UnitOfWorkConflict, match="identity"):
        uow.create_retention_hold(hold.model_copy(update={"reason": "different purpose"}))
    with pytest.raises(UnitOfWorkConflict, match="future"):
        uow.create_retention_hold(hold.model_copy(update={"expires_at": datetime.now(UTC)}))

    assessment = _assessment(run_id)
    assert uow.record_resume_assessment(assessment)
    replay = assessment.model_copy(update={"created_at": assessment.created_at + timedelta(seconds=5)})
    assert not uow.record_resume_assessment(replay)
    with pytest.raises(UnitOfWorkConflict, match="identity"):
        uow.record_resume_assessment(assessment.model_copy(update={"reason_codes": ["DIFFERENT"]}))


def test_governance_repositories_reject_unknown_or_corrupt_records(tmp_path) -> None:
    coordinator = CoordinatorStore(f"sqlite:///{tmp_path / 'corrupt.db'}")
    uow = ControlPlaneUnitOfWork(coordinator.engine)
    with pytest.raises(KeyError):
        uow.list_retention_holds("missing-run")
    with pytest.raises(KeyError):
        uow.create_retention_hold(
            RetentionHold(
                run_id="missing-run",
                reason="missing owner run",
                expires_at=datetime.now(UTC) + timedelta(days=1),
            )
        )
    run_id = "00000000-0000-4000-8000-000000000803"
    assert uow.submit_run(_state(run_id))
    assessment = _assessment(run_id)
    assert uow.record_resume_assessment(assessment)
    with Session(uow.engine) as session:
        row = session.get(ResumeAssessmentRow, assessment.assessment_id)
        assert row is not None
        row.assessment_json = "not-json"
        session.commit()
    with pytest.raises(UnitOfWorkConflict, match="invalid"):
        uow.record_resume_assessment(assessment)


@pytest.mark.parametrize(
    "factory",
    [
        lambda: RetentionHoldRequest(reason="review", expires_at=datetime.now(UTC) - timedelta(seconds=1)),
        lambda: RetentionHoldRequest(reason="review", expires_at=datetime.now()),
        lambda: RetentionProfile(name="bad", layer_ttl_days={LogLayer.RUNTIME: 30}),
        lambda: LogStream(run_id="run", source="x" * 501, format="jsonl", view=DataView.RAW_RESTRICTED),
        lambda: LogQuery(event_types={str(index) for index in range(101)}),
        lambda: OperatorSession(
            actor="operator",
            role="operator",
            created_at=datetime.now(UTC),
            expires_at=datetime.now(UTC) - timedelta(seconds=1),
        ),
        lambda: ApprovalBatch(
            run_id="run",
            ready_wave="wave-1",
            risk_level=1,
            parameter_summary_digest="b" * 64,
            request_ids=["same", "same"],
            actor="operator",
        ),
    ],
)
def test_public_governance_contracts_fail_closed(factory) -> None:
    with pytest.raises((ValidationError, ValueError)):
        factory()


def test_public_governance_validators_cover_valid_and_boundary_paths() -> None:
    profile = RetentionProfile(name="default")
    assert profile.layer_ttl_days[LogLayer.DECISION_AUDIT] == 180
    invalid_ttl = dict(profile.layer_ttl_days)
    invalid_ttl[LogLayer.RUNTIME] = 0
    with pytest.raises(ValidationError, match="TTL"):
        RetentionProfile(name="bad-ttl", layer_ttl_days=invalid_ttl)

    now = datetime.now(UTC)
    session = OperatorSession(actor="operator", role="operator", created_at=now, expires_at=now + timedelta(hours=1))
    assert session.actor == "operator"
    batch = ApprovalBatch(
        run_id="run",
        ready_wave="wave",
        risk_level=1,
        parameter_summary_digest="c" * 64,
        request_ids=["request-1"],
        actor="operator",
    )
    assert batch.request_ids == ["request-1"]
    with pytest.raises(ValidationError, match="request id"):
        batch.model_copy(update={"request_ids": []}).__class__(**{**batch.model_dump(), "request_ids": ["x" * 101]})

    with pytest.raises(ValidationError, match="edited_parameters"):
        ApprovalResponse(decision=ApprovalDecision.EDIT)
    response = ApprovalResponse(decision=ApprovalDecision.APPROVE)
    with pytest.raises(ValidationError, match="duplicate"):
        ApprovalBatchRequest(
            items=[
                ApprovalResolutionItem(request_id="same", response=response),
                ApprovalResolutionItem(request_id="same", response=response),
            ]
        )

    assert ContextBudget().used_tokens == 0
    with pytest.raises(ValidationError, match="partitions"):
        ContextBudget(
            total_tokens=256,
            policy_tokens=257,
            task_tokens=0,
            skill_tool_tokens=0,
            repository_tokens=0,
            evidence_tokens=0,
            working_output_tokens=0,
        )
    with pytest.raises(ValidationError, match="used_tokens"):
        ContextBudget(
            total_tokens=256,
            policy_tokens=0,
            task_tokens=0,
            skill_tool_tokens=0,
            repository_tokens=0,
            evidence_tokens=0,
            working_output_tokens=0,
            used_tokens=257,
        )
