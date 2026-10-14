from __future__ import annotations

from pathlib import Path

import pytest
from conftest import seal_execution_contract
from fastapi.testclient import TestClient

from secmind.api import create_app
from secmind.config import Settings
from secmind.schemas import (
    AgentState,
    ApprovalRequest,
    ClaimStatus,
    Evidence,
    EvidenceLink,
    Finding,
    PlanStep,
    QueueStatus,
    RunStatus,
    RunSummary,
    Scenario,
    StepRuntime,
    StepStatus,
    TaskRequest,
    ToolResult,
    ToolStatus,
    VerificationResult,
)
from secmind.session_projection import build_run_session_snapshot


def _summary(state: AgentState, *, queue_status: QueueStatus = QueueStatus.WAITING) -> RunSummary:
    return RunSummary(
        run_id=state.run_id,
        status=state.status,
        scenario=state.scenario,
        current_step=state.current_step_index,
        total_steps=len(state.plan),
        plan=state.plan,
        current_step_id=state.plan[0].step_id if state.plan else None,
        started_at=state.started_at,
        updated_at=state.started_at,
        queue_status=queue_status,
        active_step_ids=[],
    )


def test_session_snapshot_projects_multi_step_evidence_lifecycle() -> None:
    evidence = Evidence(evidence_id="ev-1", source="semgrep_sast", summary="tainted data reaches eval")
    state = seal_execution_contract(
        AgentState(
            run_id="run-1",
            task=TaskRequest(objective="Audit the uploaded JavaScript app", interaction_mode="interactive"),
            scenario=Scenario.CODE_AUDIT,
            status=RunStatus.WAITING_APPROVAL,
            workspace="workspace/run-1",
            plan=[
                PlanStep(
                    step_id="scan-js",
                    objective="Scan JavaScript sinks.",
                    agent_role="sast_specialist",
                    capability="sast",
                    tool_candidates=["semgrep_sast"],
                    skill_ids=["injection-dataflow-review"],
                ),
                PlanStep(
                    step_id="scan-secrets",
                    objective="Scan for exposed secrets.",
                    agent_role="secret_specialist",
                    capability="secret_scan",
                    dependencies=["scan-js"],
                    tool_candidates=["gitleaks"],
                ),
            ],
            step_runtime={
                "scan-js": StepRuntime(
                    step_id="scan-js",
                    status=StepStatus.SUCCEEDED,
                    actual_tool_calls=1,
                    tool_invocation_ids=["inv-1"],
                    observation_indexes=[0],
                ),
                "scan-secrets": StepRuntime(
                    step_id="scan-secrets",
                    status=StepStatus.FAILED,
                    actual_tool_calls=1,
                    tool_invocation_ids=["inv-2"],
                    observation_indexes=[1],
                ),
            },
            observations=[
                ToolResult(
                    invocation_id="inv-1",
                    status=ToolStatus.SUCCESS,
                    summary="1 finding",
                    evidence=[evidence],
                ),
                ToolResult(
                    invocation_id="inv-2",
                    status=ToolStatus.ERROR,
                    summary="scanner unavailable",
                    error_code="unavailable",
                ),
            ],
            evidence=[evidence],
            evidence_links=[EvidenceLink(claim_id="claim-1", evidence_id="ev-1", verifier_status=ClaimStatus.VERIFIED)],
            verification_results=[
                VerificationResult(
                    claim_id="claim-1",
                    status=ClaimStatus.VERIFIED,
                    reason_summary="Source and sink were independently confirmed.",
                    verified_evidence_ids=["ev-1"],
                )
            ],
            findings=[
                Finding(
                    finding_id="finding-1",
                    rule_id="js-eval",
                    path="app.js",
                    line=12,
                    title="eval on tainted input",
                    description="User input reaches eval.",
                    evidence_ids=["ev-1"],
                )
            ],
            selected_skill_ids=["injection-dataflow-review"],
            pending_approval=ApprovalRequest(
                request_id="approval-1",
                run_id="run-1",
                step_id="scan-js",
                tool_name="semgrep_sast",
                parameters={"target": "."},
                target=".",
                risk_level=1,
                reason="Need approved SAST execution.",
                expected_impact="Read-only static analysis over the submitted workspace.",
            ),
        )
    )

    snapshot = build_run_session_snapshot(state, _summary(state))

    assert snapshot.session_id == "run-1"
    assert snapshot.resume.recommended_action == "resolve_approval"
    assert snapshot.resume.requires_operator_input is True
    assert snapshot.resume.action_url == "/api/v1/runs/run-1/approvals/approval-1"
    assert snapshot.prompt_tool_skill.selected_skill_ids == ["injection-dataflow-review"]
    assert snapshot.prompt_tool_skill.tool_invocation_count == 2
    assert snapshot.multi_task.task_count == 2
    assert snapshot.multi_task.status_counts["succeeded"] == 1
    assert snapshot.multi_task.status_counts["failed"] == 1
    successful, failed = snapshot.tasks
    assert successful.tool_result_observed is True
    assert successful.tool_result_succeeded is True
    assert successful.evidence_ids == ["ev-1"]
    assert successful.integrated_evidence_ids == ["ev-1"]
    assert successful.verified_evidence_ids == ["ev-1"]
    assert successful.finding_ids == ["finding-1"]
    assert failed.tool_result_observed is True
    assert failed.tool_result_succeeded is False
    assert failed.integrated_evidence_ids == []
    assert failed.finding_ids == []


def test_recovery_required_takes_priority_over_waiting_queue() -> None:
    state = seal_execution_contract(
        AgentState(
            run_id="recovery-run",
            task=TaskRequest(objective="Recover an interrupted audit"),
            status=RunStatus.RECOVERY_REQUIRED,
        )
    )

    snapshot = build_run_session_snapshot(state, _summary(state, queue_status=QueueStatus.WAITING))

    assert snapshot.resume.can_resume is False
    assert snapshot.resume.automatic_recovery_possible is False
    assert snapshot.resume.requires_operator_input is True
    assert snapshot.resume.recommended_action == "operator_recovery_required"
    assert snapshot.resume.action_url == "/api/v1/runs/recovery-run/recover"


def test_parked_status_without_durable_request_requires_reconciliation() -> None:
    state = seal_execution_contract(
        AgentState(
            run_id="drifted-run",
            task=TaskRequest(objective="Inspect inconsistent parked state"),
            status=RunStatus.WAITING_APPROVAL,
        )
    )

    snapshot = build_run_session_snapshot(state, _summary(state, queue_status=QueueStatus.WAITING))

    assert snapshot.resume.can_resume is False
    assert snapshot.resume.automatic_recovery_possible is False
    assert snapshot.resume.recommended_action == "operator_recovery_required"
    assert snapshot.resume.action_url == "/api/v1/runs/drifted-run/recover"


def test_session_endpoint_reads_persisted_state_after_restart(tmp_path: Path) -> None:
    settings = Settings(
        database_url=f"sqlite:///{(tmp_path / 'session.db').as_posix()}",
        input_root=tmp_path / "inputs",
        upload_root=tmp_path / "uploads",
        run_root=tmp_path / "runs",
        artifact_root=tmp_path / "artifacts",
        unsafe_development_tools=True,
    )
    first_app = create_app(settings)
    with TestClient(first_app, base_url="http://127.0.0.1"):
        first_app.state.runtime.service.ledger.save_state(
            seal_execution_contract(
                AgentState(
                    run_id="persisted-session",
                    task=TaskRequest(objective="Inspect a persisted run"),
                    status=RunStatus.FAILED,
                )
            )
        )

    second_app = create_app(settings)
    with TestClient(second_app, base_url="http://127.0.0.1") as client:
        response = client.get("/api/v1/runs/persisted-session/session")

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["etag"].startswith('W/"session-')
    payload = response.json()
    assert payload["run_id"] == "persisted-session"
    assert payload["status"] == "failed"
    assert payload["consistency"]["stable"] is True
    assert payload["consistency"]["read_attempts"] == 2
    assert payload["resume"]["recommended_action"] == "inspect_report_or_replay"


def test_session_snapshot_rejects_cross_run_composition() -> None:
    state = seal_execution_contract(AgentState(run_id="run-a", task=TaskRequest(objective="Inspect run A")))
    summary = _summary(state).model_copy(update={"run_id": "run-b"})

    with pytest.raises(ValueError, match="state and summary must belong to the same run"):
        build_run_session_snapshot(state, summary)


def test_session_snapshot_marks_continuously_changing_run_unstable(tmp_path: Path, monkeypatch) -> None:
    settings = Settings(
        database_url=f"sqlite:///{(tmp_path / 'unstable.db').as_posix()}",
        input_root=tmp_path / "inputs",
        upload_root=tmp_path / "uploads",
        run_root=tmp_path / "runs",
        artifact_root=tmp_path / "artifacts",
        unsafe_development_tools=True,
    )
    app = create_app(settings)
    with TestClient(app, base_url="http://127.0.0.1"):
        service = app.state.runtime.service
        states = [
            seal_execution_contract(
                AgentState(
                    run_id="moving-run",
                    task=TaskRequest(objective="Observe a changing run"),
                    state_version=version,
                )
            )
            for version in (1, 2, 3)
        ]
        monkeypatch.setattr(service, "state", lambda _run_id: states.pop(0))
        monkeypatch.setattr(
            service,
            "_summary_from_state",
            lambda state: _summary(state, queue_status=QueueStatus.QUEUED).model_copy(
                update={"latest_event_sequence": state.state_version}
            ),
        )

        snapshot = service.session_snapshot("moving-run")

    assert snapshot.state_version == 3
    assert snapshot.consistency.stable is False
    assert snapshot.consistency.read_attempts == 3
