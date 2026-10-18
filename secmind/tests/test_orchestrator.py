from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from secmind.guardrail import Guardrail
from secmind.investigation.contracts import RunAuthority, seal_contract
from secmind.investigation.store import InvestigationStore
from secmind.knowledge import OfflineKnowledgeStore
from secmind.ledger import LedgerStore
from secmind.llm import QwenGateway
from secmind.orchestration.obligation_runtime import refresh_obligation_set
from secmind.orchestrator import SecMindOrchestrator
from secmind.schemas import (
    ApprovalDecision,
    ApprovalResponse,
    AttachmentRef,
    BudgetState,
    Evidence,
    Finding,
    InputArtifact,
    LeaseSummary,
    PlanStep,
    RiskLevel,
    RunStatus,
    Scenario,
    StepPatch,
    StepRuntime,
    StepStatus,
    TaskRequest,
    ToolContext,
    ToolManifest,
    ToolResult,
    ToolStatus,
    WorkItem,
)
from secmind.task_contract import compile_resolved_task_contract
from secmind.tools import BaseTool, ToolBroker, ToolRegistry, default_registry


class ControlledAuditTool(BaseTool):
    def __init__(self, risk: RiskLevel, fail_once: bool = False) -> None:
        self.manifest = ToolManifest(
            name="bandit_python_audit",
            version="test",
            description="controlled test tool",
            scenarios=[Scenario.CODE_AUDIT],
            input_schema={},
            output_schema={},
            risk_level=risk,
        )
        self.fail_once = fail_once
        self.calls = 0

    async def invoke(self, args: dict, context: ToolContext) -> ToolResult:
        self.calls += 1
        if self.fail_once and self.calls == 1:
            return ToolResult(
                status=ToolStatus.ERROR,
                error_code="TRANSIENT",
                error_message="temporary failure",
            )
        return ToolResult(status=ToolStatus.SUCCESS, data={"findings": []}, summary="ok")


class IndependentHighRiskTool(BaseTool):
    def __init__(self, name: str) -> None:
        self.manifest = ToolManifest(
            name=name,
            version="1.0.0",
            description=f"independent {name} SAST fixture",
            scenarios=[Scenario.CODE_AUDIT],
            input_schema={"type": "object"},
            output_schema={"type": "object"},
            risk_level=RiskLevel.R1,
            platform_risk=RiskLevel.R1,
            capability_tags=["sast"],
            evidence_types=["sast_finding"],
            concurrency_key=name,
        )
        self.calls = 0

    async def invoke(self, args: dict, context: ToolContext) -> ToolResult:
        del args
        self.calls += 1
        evidence_id = f"{self.manifest.name}-command-injection"
        evidence = Evidence(
            evidence_id=evidence_id,
            source=f"{self.manifest.name}:{self.manifest.version}",
            summary="Untrusted input reaches a shell command sink.",
            metadata={
                "evidence_type": "sast_finding",
                "evidence_types": ["sast_finding"],
                "tool_name": self.manifest.name,
                "tool_version": self.manifest.version,
                "path": "app.py",
            },
        )
        finding = Finding(
            finding_id="finding-command-injection",
            rule_id="command-injection",
            severity="HIGH",
            confidence="HIGH",
            path="app.py",
            line=1,
            title="Command injection",
            description="Untrusted input can reach a shell command sink.",
            remediation="Use an argument vector and an allowlist.",
            evidence_ids=[evidence_id],
            raw={
                "attack_path": "HTTP parameter -> command builder -> shell sink",
                "preconditions": ["An attacker can control the HTTP parameter."],
                "impact": "Arbitrary command execution in the service account context.",
            },
        )
        return ToolResult(
            invocation_id=context.invocation_id,
            status=ToolStatus.SUCCESS,
            data={"findings": [finding.model_dump(mode="json")]},
            summary=f"{self.manifest.name} found one high-risk issue",
            evidence=[evidence],
        )


class EmbeddedInvestigationStore(InvestigationStore):
    """Permit a direct-orchestrator test without weakening production authority checks."""

    def issue_authority(self, run_id: str, *, owner_id: str, run_fence: int) -> RunAuthority:
        return seal_contract(
            RunAuthority,
            digest_field="authority_digest",
            run_id=run_id,
            owner_id=owner_id,
            run_fence=run_fence,
            lease_until=datetime.now(UTC) + timedelta(minutes=5),
            claimed_state_version=1,
            claim_transition_id=f"test:{run_id}:{run_fence}",
        )

    def record_completion_snapshot(self, snapshot, authority) -> str:
        del authority
        return self.put_object(
            snapshot,
            run_id=snapshot.run_id,
            object_type="completion_snapshot",
            object_id=snapshot.snapshot_id,
            logical_key=snapshot.snapshot_id,
            content_digest=snapshot.snapshot_digest,
        )

    def record_completion_receipt(self, receipt, authority) -> str:
        del authority
        return self.put_object(
            receipt,
            run_id=receipt.run_id,
            object_type="completion_receipt",
            object_id=receipt.receipt_id,
            logical_key=receipt.snapshot_id,
            content_digest=receipt.receipt_digest,
        )


def controlled_orchestrator(settings, risk: RiskLevel, fail_once: bool = False):
    settings.prepare_directories()
    (settings.input_root / "app.py").write_text("print('ok')", encoding="utf-8")
    ledger = LedgerStore(settings.database_url)
    registry = ToolRegistry()
    tool = ControlledAuditTool(risk, fail_once)
    registry.register(tool)
    orchestrator = SecMindOrchestrator(
        settings,
        ledger,
        QwenGateway(settings),
        ToolBroker(registry, Guardrail()),
    )
    return orchestrator, ledger, tool


@pytest.mark.asyncio
async def test_code_audit_end_to_end(settings, tmp_path: Path) -> None:
    settings.prepare_directories()
    (settings.input_root / "bad.py").write_text(
        "import subprocess\nsubprocess.Popen('echo unsafe', shell=True)\n", encoding="utf-8"
    )
    ledger = LedgerStore(settings.database_url)
    orchestrator = SecMindOrchestrator(
        settings,
        ledger,
        QwenGateway(settings),
        ToolBroker(default_registry(), Guardrail()),
    )
    state = await orchestrator.start(
        TaskRequest(
            objective="审计 Python 代码并给出漏洞报告",
            attachments=[AttachmentRef(ref="bad.py")],
        ),
        "e2e-run",
    )
    assert state.status == RunStatus.COMPLETED
    assert state.last_error is None
    assert state.report is not None, {
        "status": state.status,
        "scenario": state.scenario,
        "error": state.last_error,
        "clarifications": state.active_clarification_ids,
        "decisions": [item.decision for item in state.decisions],
    }
    assert state.report.findings
    assert state.report.evidence
    routing = state.report.coverage["tool_routing"]
    assert routing["planned"] == [
        "bandit_python_audit",
        "project_inventory",
        "python_taint_audit",
    ]
    assert routing["executed"] == routing["planned"]
    assert routing["actual_tool_calls"] == 3
    # The redacted secret scanner is no longer suppressed by shallow lexical
    # pre-signals.  This compact default plan does not retain the optional
    # step, but the affinity router itself must not claim a low-signal veto.
    assert routing["skipped"]["secret_pattern_scan"] == "plan_step_removed"  # noqa: S105
    skill_by_tool = {step.tool_candidates[0]: step.skill_ids for step in state.plan if len(step.tool_candidates) == 1}
    assert skill_by_tool["bandit_python_audit"] == ["python-security-audit"]
    assert skill_by_tool["python_taint_audit"] == ["injection-dataflow-review"]
    assert state.report.coverage["augmentation_status"] == "completed"
    assert ledger.verify("e2e-run")
    event_types = [event.event_type for event in ledger.events("e2e-run")]
    assert "guardrail.evaluated" in event_types
    assert "report.generated" in event_types


@pytest.mark.asyncio
async def test_max_steps_one_full_orchestrator_converges_without_recursion(settings) -> None:
    """The graph schedule remains bounded when the semantic step budget is one."""

    settings.max_steps = 1
    orchestrator, _, _ = controlled_orchestrator(settings, RiskLevel.R1)
    state = await orchestrator.start(
        TaskRequest(
            objective="audit code",
            attachments=[AttachmentRef(ref="app.py")],
        ),
        "max-steps-one-run",
    )

    # This deliberately sparse fixture has no finding/evidence pair, so the
    # strict completion contract reports PARTIAL.  It must nevertheless leave
    # the full graph at a terminal state rather than exhausting recursion.
    assert state.status == RunStatus.PARTIAL
    assert state.last_error == "Step budget exhausted"
    assert state.report is not None
    assert state.budget.steps_used <= settings.max_steps


@pytest.mark.asyncio
async def test_config_only_audit_keeps_inventory_and_records_bandit_skip(settings) -> None:
    settings.prepare_directories()
    (settings.input_root / "settings.yaml").write_text("debug: true\n", encoding="utf-8")
    ledger = LedgerStore(settings.database_url)
    broker = ToolBroker(default_registry(), Guardrail())
    orchestrator = SecMindOrchestrator(settings, ledger, QwenGateway(settings), broker)

    state = await orchestrator.start(
        TaskRequest(
            objective="code audit repository configuration",
            attachments=[AttachmentRef(ref="settings.yaml")],
        ),
        "config-tool-routing-run",
    )

    assert state.report is not None
    routing = state.report.coverage["tool_routing"]
    assert routing["planned"] == ["project_inventory"]
    assert routing["executed"] == routing["planned"]
    assert routing["skipped"]["bandit_python_audit"] == "input_language_not_supported"
    assert routing["skipped"]["secret_pattern_scan"] == "plan_step_removed"  # noqa: S105
    assert routing["actual_tool_calls"] == 1
    assert state.report.coverage["augmentation_status"] == "completed"
    broker.close()
    ledger.close()


@pytest.mark.asyncio
async def test_deep_audit_runs_independent_scanners_proactively(settings) -> None:
    settings.prepare_directories()
    (settings.input_root / "app.py").write_text("print(input())\n", encoding="utf-8")
    ledger = LedgerStore(settings.database_url)
    investigation_store = EmbeddedInvestigationStore(engine=ledger.engine)
    registry = ToolRegistry()
    primary = IndependentHighRiskTool("a_primary_sast")
    independent = IndependentHighRiskTool("b_independent_sast")
    registry.register(primary)
    registry.register(independent)
    broker = ToolBroker(registry, Guardrail(), investigation_store=investigation_store)
    orchestrator = SecMindOrchestrator(
        settings,
        ledger,
        QwenGateway(settings),
        broker,
        investigation_store=investigation_store,
    )

    state = await orchestrator.start(
        TaskRequest(
            objective="Deep code audit with evidence-backed high-risk findings.",
            attachments=[AttachmentRef(ref="app.py")],
        ),
        "independent-gap-run",
    )

    assert state.status == RunStatus.COMPLETED, {
        "rounds": state.verification_rounds,
        "replans": state.replan_count,
        "calls": (primary.calls, independent.calls),
        "reasons": state.completion_reasons,
        "error": state.last_error,
        "active_requests": state.active_evidence_request_ids,
        "grades": state.contract_grades,
        "claims": [(item.subject_ref, item.status.value) for item in state.claims],
    }
    # Healthy independent scanners are now planned as parallel work instead
    # of hiding the second scanner behind an evidence-gap retry.
    assert state.verification_rounds == 0
    assert state.replan_count == 0
    assert primary.calls == 1
    assert independent.calls == 1
    assert state.active_evidence_request_ids == []
    assert investigation_store.unsettled_reservation_ids(state.run_id) == []
    assert {item.subject_ref for item in state.claims if item.claim_type == "sast.coverage"} == {
        "coverage:scan-sast-a-primary-sast",
        "coverage:scan-sast-b-independent-sast",
    }
    assert investigation_store.list_objects(state.run_id, "plan_revision") == []
    assert investigation_store.list_objects(state.run_id, "evidence_request") == []
    receipts = investigation_store.list_objects(state.run_id, "completion_receipt")
    assert receipts[-1]["decision"] == "complete"
    assert state.report is not None
    assert [item.finding_id for item in state.report.findings] == ["finding-command-injection"]


@pytest.mark.asyncio
async def test_r2_tool_interrupts_and_resumes(settings) -> None:
    orchestrator, ledger, tool = controlled_orchestrator(settings, RiskLevel.R2)
    waiting = await orchestrator.start(
        TaskRequest(
            objective="audit code",
            attachments=[AttachmentRef(ref="app.py")],
            autonomy_policy="graded",
        ),
        "approval-run",
    )
    assert waiting.status == RunStatus.WAITING_APPROVAL
    assert waiting.pending_approval is not None
    completed = await orchestrator.resume(
        "approval-run", ApprovalResponse(decision=ApprovalDecision.APPROVE, reason="authorized")
    )
    # The controlled fixture emits no finding and no evidence-backed negative
    # coverage.  Approval is consumed and the tool runs once, but the strict
    # answer obligation correctly reports a partial terminal result.
    assert completed.status == RunStatus.PARTIAL
    assert tool.calls == 1
    assert ledger.verify("approval-run")


@pytest.mark.asyncio
@pytest.mark.parametrize("decision", [ApprovalDecision.EDIT, ApprovalDecision.DENY])
async def test_r2_approval_edit_and_deny_resume_once(settings, decision: ApprovalDecision) -> None:
    orchestrator, _, tool = controlled_orchestrator(settings, RiskLevel.R2)
    run_id = f"approval-{decision.value}"
    waiting = await orchestrator.start(
        TaskRequest(objective="audit code", attachments=[AttachmentRef(ref="app.py")]),
        run_id,
    )
    assert waiting.status == RunStatus.WAITING_APPROVAL
    response = ApprovalResponse(
        decision=decision,
        reason="operator decision",
        edited_parameters={"target": "."} if decision == ApprovalDecision.EDIT else None,
    )
    resolved = await orchestrator.resume(run_id, response)
    if decision == ApprovalDecision.DENY:
        assert resolved.status == RunStatus.DENIED
        assert tool.calls == 0
    else:
        assert resolved.status == RunStatus.PARTIAL
        assert tool.calls == 1
        assert resolved.approvals[-1]["decision"] == ApprovalDecision.EDIT.value


@pytest.mark.asyncio
async def test_r3_tool_is_denied_without_execution(settings) -> None:
    orchestrator, ledger, tool = controlled_orchestrator(settings, RiskLevel.R3)
    state = await orchestrator.start(
        TaskRequest(objective="audit code", attachments=[AttachmentRef(ref="app.py")]),
        "denied-run",
    )
    assert state.status == RunStatus.DENIED
    assert state.completion_receipt_id is not None
    gated = [item for item in ledger.events("denied-run") if item.event_type == "completion.gated"]
    assert len(gated) == 1
    assert gated[0].payload["completion_outcome"] == "denied"
    assert tool.calls == 0


@pytest.mark.asyncio
async def test_idempotent_tool_failure_is_retried(settings) -> None:
    orchestrator, _, tool = controlled_orchestrator(settings, RiskLevel.R1, fail_once=True)
    state = await orchestrator.start(
        TaskRequest(objective="audit code", attachments=[AttachmentRef(ref="app.py")]),
        "retry-run",
    )
    assert state.status == RunStatus.PARTIAL
    assert state.retry_counts["scan-sast"] == 1
    assert tool.calls == 2
    assert state.plan[0].skill_ids
    step_pack = next(pack for pack in state.context_packs if pack.step_id == "scan-sast")
    assert step_pack.selected_skill_refs
    assert any(item.decision == "skill_tool_invoked" for item in state.decisions)


@pytest.mark.asyncio
async def test_unsupported_scenario_produces_partial_report(settings) -> None:
    orchestrator, _, _ = controlled_orchestrator(settings, RiskLevel.R1)
    state = await orchestrator.start(TaskRequest(objective="分析网络日志异常"), "log-run")
    assert state.status == RunStatus.PARTIAL
    assert state.report is not None
    assert state.report.limitations


def node_state(run_id: str = "node-run"):
    plan = [
        PlanStep(
            step_id="audit-python-bandit",
            objective="scan",
            agent_role="sast_specialist",
            capability="sast",
            tool_candidates=["bandit_python_audit"],
            inputs={"target": "."},
            success_criteria=["done"],
            risk_hint=RiskLevel.R1,
        )
    ]
    from secmind.schemas import AgentState

    state = AgentState(
        run_id=run_id,
        task=TaskRequest(objective="audit code"),
        scenario=Scenario.CODE_AUDIT,
        plan=plan,
        workspace=".",
        resolved_task_contract=compile_resolved_task_contract(
            {
                "task_spec_id": f"task-spec-{run_id}",
                "run_id": run_id,
                "revision": 1,
                "content_digest": hashlib.sha256(f"task-spec:{run_id}".encode()).hexdigest(),
                "objectives": ["audit code"],
                "primary_scenario": Scenario.CODE_AUDIT.value,
                "primary_domain": "code_audit_and_patch",
                "secondary_scenarios": [],
                "secondary_capabilities": [],
                "scoring_mode": "security_finding",
                "interaction_mode": "unattended",
                "autonomy_policy": "automatic",
                "authorized_scope": ["."],
                "constraints": [],
                "prohibited_actions": [],
                "expected_outputs": ["security_report"],
                "success_criteria": [],
                "output_contract": {},
                "asset_ids": [],
            },
            input_manifest_digest=hashlib.sha256(b"empty-test-manifest").hexdigest(),
        ),
    )
    state.step_runtime = {plan[0].step_id: StepRuntime(step_id=plan[0].step_id)}
    return state


def test_input_integrity_rehashes_workspace_content_and_rejects_tampering(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    source = workspace / "app.py"
    original = b"print('trusted')\n"
    source.write_bytes(original)
    state = node_state("input-integrity")
    state.workspace = str(workspace)
    state.input_artifacts = [
        InputArtifact(
            artifact_id="input-app",
            original_name="app.py",
            relative_path="app.py",
            sha256=hashlib.sha256(original).hexdigest(),
            size_bytes=len(original),
            media_type="text/x-python",
        )
    ]

    assert SecMindOrchestrator._verify_input_artifacts(state) is True

    source.write_bytes(b"print('changed')\n")
    assert SecMindOrchestrator._verify_input_artifacts(state) is False

    source.unlink()
    assert SecMindOrchestrator._verify_input_artifacts(state) is False


@pytest.mark.asyncio
async def test_schedule_cancel_and_budget_terminal_paths(settings) -> None:
    orchestrator, _, _ = controlled_orchestrator(settings, RiskLevel.R1)
    cancelled = node_state("cancel-node")
    cancelled.cancel_requested = True
    result = await orchestrator._schedule({"agent": cancelled.model_dump(mode="json")})
    cancelled_result = orchestrator._state(result)
    assert cancelled_result.status == RunStatus.PARTIAL
    assert cancelled_result.step_runtime["audit-python-bandit"].status == StepStatus.CANCELLED

    exhausted = node_state("step-budget")
    exhausted.budget.steps_used = exhausted.budget.max_steps
    result = await orchestrator._schedule({"agent": exhausted.model_dump(mode="json")})
    assert orchestrator._state(result).last_error == "Step budget exhausted"

    timed_out = node_state("runtime-budget")
    timed_out.started_at = datetime.now(UTC) - timedelta(seconds=timed_out.budget.max_runtime_seconds + 1)
    result = await orchestrator._schedule({"agent": timed_out.model_dump(mode="json")})
    assert orchestrator._state(result).last_error == "Runtime budget exhausted"


@pytest.mark.asyncio
async def test_schedule_completed_and_stalled_paths(settings) -> None:
    orchestrator, _, _ = controlled_orchestrator(settings, RiskLevel.R1)
    completed = node_state("dag-complete")
    completed.step_runtime["audit-python-bandit"].status = StepStatus.SUCCEEDED
    result = await orchestrator._schedule({"agent": completed.model_dump(mode="json")})
    assert result["route"] == "report"

    stalled = node_state("dag-stalled")
    stalled.step_runtime["audit-python-bandit"].status = StepStatus.RUNNING
    result = await orchestrator._schedule({"agent": stalled.model_dump(mode="json")})
    assert orchestrator._state(result).last_error == "DAG has no runnable step"


@pytest.mark.asyncio
async def test_invalid_approval_node_and_record_denial_preserve_failure(settings) -> None:
    orchestrator, _, _ = controlled_orchestrator(settings, RiskLevel.R1)
    state = node_state("invalid-approval")
    result = await orchestrator._approval({"agent": state.model_dump(mode="json")})
    assert result["route"] == "deny"
    invalid = orchestrator._state(result)
    assert invalid.status == RunStatus.FAILED

    denied = await orchestrator._record_denial({"agent": invalid.model_dump(mode="json")})
    assert orchestrator._state(denied).status == RunStatus.FAILED


@pytest.mark.asyncio
async def test_worker_discards_invalid_finding_and_retry_reduction(settings) -> None:
    class InvalidFindingTool(ControlledAuditTool):
        async def invoke(self, args: dict, context: ToolContext) -> ToolResult:
            self.calls += 1
            return ToolResult(status=ToolStatus.SUCCESS, data={"findings": [{"not": "a finding"}]})

    settings.prepare_directories()
    ledger = LedgerStore(settings.database_url)
    registry = ToolRegistry()
    tool = InvalidFindingTool(RiskLevel.R1)
    registry.register(tool)
    orchestrator = SecMindOrchestrator(settings, ledger, QwenGateway(settings), ToolBroker(registry, Guardrail()))
    item = WorkItem(
        run_id="worker-invalid",
        step_id="audit-python-bandit",
        capability="sast",
        tool_name="bandit_python_audit",
        inputs={"target": "."},
        workspace_ref=".",
        transition_id="transition",
        budget_reservation=BudgetState(),
    )
    output = await orchestrator._worker({"work_item": item.model_dump(mode="json")})
    assert output["worker_patches"][0]["findings"] == []

    state = node_state("retry-reduce")
    state.plan[0].max_attempts = 2
    state.step_runtime["audit-python-bandit"] = StepRuntime(
        step_id="audit-python-bandit",
        status=StepStatus.RUNNING,
        attempt=1,
        transition_id="failed-transition",
    )
    patch = {
        "step_id": "audit-python-bandit",
        "transition_id": "failed-transition",
        "status": StepStatus.FAILED.value,
        "typed_error": "TRANSIENT",
    }
    reduced = await orchestrator._reduce_workers({"agent": state.model_dump(mode="json"), "worker_patches": [patch]})
    retrying = orchestrator._state(reduced)
    assert retrying.step_runtime["audit-python-bandit"].status == StepStatus.PENDING
    assert retrying.retry_counts["audit-python-bandit"] == 1


@pytest.mark.asyncio
async def test_stale_pending_send_is_fenced_without_reexecuting_tool(settings) -> None:
    orchestrator, _, tool = controlled_orchestrator(settings, RiskLevel.R1)
    item = WorkItem(
        run_id="stale-send",
        step_id="audit-python-bandit",
        capability="sast",
        tool_name="bandit_python_audit",
        inputs={"target": "."},
        workspace_ref=".",
        transition_id="stale-transition",
        run_fence=1,
        step_fence=1,
        lease_fence=1,
        attempt=1,
        budget_reservation=BudgetState(),
    )
    token = orchestrator._active_authority.set(SimpleNamespace(run_fence=2))
    try:
        output = await orchestrator._worker({"work_item": item.model_dump(mode="json")})
    finally:
        orchestrator._active_authority.reset(token)

    assert tool.calls == 0
    assert output["worker_patches"][0]["typed_error"] == "STALE_DISPATCH"

    state = node_state("stale-send")
    state.lease = LeaseSummary(owner_id="worker-2", fence=2)
    state.step_runtime["audit-python-bandit"] = StepRuntime(
        step_id="audit-python-bandit",
        status=StepStatus.RUNNING,
        attempt=1,
        transition_id="stale-transition",
        lease_fence=1,
    )
    reduced = await orchestrator._reduce_workers(
        {"agent": state.model_dump(mode="json"), "worker_patches": output["worker_patches"]}
    )
    recovered = orchestrator._state(reduced)
    assert recovered.step_runtime["audit-python-bandit"].status == StepStatus.PENDING
    assert recovered.step_runtime["audit-python-bandit"].transition_id is None
    assert recovered.budget.steps_used == 0


@pytest.mark.asyncio
async def test_reduce_workers_filters_prior_wave_before_durable_side_effects(settings, monkeypatch) -> None:
    """An operator.add patch channel must not re-settle an earlier DAG wave."""

    orchestrator, _, _ = controlled_orchestrator(settings, RiskLevel.R1)
    coordinator = SimpleNamespace(complete_step=MagicMock())
    investigation_store = SimpleNamespace(settle_usage=MagicMock())
    orchestrator.coordinator = coordinator
    orchestrator.investigation_store = investigation_store

    async def checkpoint(state, _event_type, _payload, _route=None):
        return {"agent": state.model_dump(mode="json")}

    monkeypatch.setattr(orchestrator, "_checkpoint", checkpoint)
    state = node_state("two-wave-reduce")
    first_step = state.plan[0]
    second_step = first_step.model_copy(
        update={
            "step_id": "audit-python-second-wave",
            "dependencies": [first_step.step_id],
        }
    )
    state.plan.append(second_step)
    state.lease = LeaseSummary(
        owner_id="worker-1",
        fence=7,
        lease_until=datetime.now(UTC) + timedelta(minutes=1),
    )
    state.step_runtime = {
        first_step.step_id: StepRuntime(
            step_id=first_step.step_id,
            status=StepStatus.SUCCEEDED,
            attempt=1,
            transition_id="transition-wave-1",
        ),
        second_step.step_id: StepRuntime(
            step_id=second_step.step_id,
            status=StepStatus.RUNNING,
            attempt=1,
            transition_id="transition-wave-2",
        ),
    }
    state.processed_transition_ids = {"transition-wave-1"}
    old_patch = StepPatch(
        step_id=first_step.step_id,
        transition_id="transition-wave-1",
        step_run_id="step-run-wave-1",
        run_fence=7,
        step_fence=1,
        usage_reservation_id="reservation-wave-1",
        status=StepStatus.SUCCEEDED,
        tool_invocation_ids=["invocation-wave-1-a", "invocation-wave-1-b", "invocation-wave-1-c"],
        actual_tool_calls=3,
        artifact_bytes=9000,
        observation=ToolResult(
            invocation_id="invocation-wave-1",
            status=ToolStatus.SUCCESS,
        ),
    )
    fresh_patch = StepPatch(
        step_id=second_step.step_id,
        transition_id="transition-wave-2",
        step_run_id="step-run-wave-2",
        run_fence=7,
        step_fence=1,
        usage_reservation_id="reservation-wave-2",
        status=StepStatus.SUCCEEDED,
        tool_invocation_ids=["invocation-wave-2-a", "invocation-wave-2-b"],
        actual_tool_calls=2,
        artifact_bytes=4096,
        observation=ToolResult(
            invocation_id="invocation-wave-2",
            status=ToolStatus.SUCCESS,
        ),
    )

    result = await orchestrator._reduce_workers(
        {
            "agent": state.model_dump(mode="json"),
            # LangGraph's operator.add channel retains the first wave here.
            "worker_patches": [
                old_patch.model_dump(mode="json"),
                fresh_patch.model_dump(mode="json"),
            ],
        }
    )

    assert coordinator.complete_step.call_count == 1
    completed_lease = coordinator.complete_step.call_args.args[0]
    assert completed_lease.step_id == second_step.step_id
    assert investigation_store.settle_usage.call_count == 1
    settlement = investigation_store.settle_usage.call_args.args[0]
    assert settlement.reservation_id == "reservation-wave-2"
    assert settlement.tool_invocation_ids == ["invocation-wave-2-a", "invocation-wave-2-b"]
    assert settlement.actual_tool_calls == 2
    assert settlement.artifact_bytes == 4096
    reduced = orchestrator._state(result)
    assert reduced.processed_transition_ids == {"transition-wave-1", "transition-wave-2"}
    assert reduced.budget.tool_calls_used == 2
    assert result["worker_patches"] == [{"_channel_control": "clear"}]


@pytest.mark.asyncio
async def test_verify_marks_failed_step_partial_and_memory_curates_terminal(settings, tmp_path: Path) -> None:
    knowledge = OfflineKnowledgeStore(f"sqlite:///{(tmp_path / 'curated.db').as_posix()}")
    orchestrator, ledger, _ = controlled_orchestrator(settings, RiskLevel.R1)
    orchestrator.knowledge_store = knowledge
    failed = node_state("verify-failed")
    failed.step_runtime["audit-python-bandit"].status = StepStatus.FAILED
    result = await orchestrator._verify_dag({"agent": failed.model_dump(mode="json")})
    assert orchestrator._state(result).status == RunStatus.PARTIAL

    completed = node_state("memory-complete")
    completed.status = RunStatus.COMPLETED
    completed.observations = [ToolResult(status=ToolStatus.SUCCESS)]
    refresh_obligation_set(
        completed,
        {
            "execution_status": "success",
            "epistemic_status": "conclusive",
            "negative_evidence": ["the controlled scanner found no findings"],
            "checked_paths": ["app.py"],
        },
    )
    completed = await orchestrator.reporter.run(completed)
    result = await orchestrator._memory_commit({"agent": completed.model_dump(mode="json")})
    assert orchestrator._state(result).status == RunStatus.COMPLETED
    assert knowledge.search("audit code", kind="episodic")
    assert ledger.verify("memory-complete")
    knowledge.close()


@pytest.mark.asyncio
async def test_start_resume_and_recover_reject_invalid_state(settings) -> None:
    orchestrator, ledger, _ = controlled_orchestrator(settings, RiskLevel.R1)
    with pytest.raises(KeyError):
        await orchestrator.resume("missing", ApprovalResponse(decision=ApprovalDecision.APPROVE))
    with pytest.raises(KeyError):
        await orchestrator.recover("missing")

    state = node_state("no-approval")
    ledger.save_state(state)
    with pytest.raises(RuntimeError, match="no active approval"):
        await orchestrator.resume("no-approval", ApprovalResponse(decision=ApprovalDecision.APPROVE))

    state.status = RunStatus.COMPLETED
    ledger.save_state(state)
    with pytest.raises(RuntimeError, match="cannot be started"):
        await orchestrator.start(state.task, state.run_id)
    with pytest.raises(RuntimeError, match="no durable"):
        await orchestrator.recover(state.run_id)


@pytest.mark.asyncio
async def test_direct_ingest_plan_validation_and_dispatch_edges(settings) -> None:
    orchestrator, _, _ = controlled_orchestrator(settings, RiskLevel.R1)
    from secmind.schemas import AgentState

    missing = AgentState(
        run_id="ingest-missing",
        task=TaskRequest(objective="audit code", attachments=[AttachmentRef(ref="missing.py")]),
    )
    ingested = await orchestrator._ingest({"agent": missing.model_dump(mode="json")})
    assert orchestrator._state(ingested).status == RunStatus.FAILED

    failed = node_state("plan-skipped")
    failed.status = RunStatus.FAILED
    failed.last_error = "ingestion failed"
    skipped = await orchestrator._validate_plan({"agent": failed.model_dump(mode="json")})
    assert skipped["route"] == "report"

    invalid = node_state("plan-invalid")
    invalid.plan[0].tool_candidates = ["missing-tool"]
    validated = await orchestrator._validate_plan({"agent": invalid.model_dump(mode="json")})
    assert orchestrator._state(validated).status == RunStatus.FAILED

    preplanned = node_state("preplanned")
    preplanned.plan[0].risk_hint = RiskLevel.R0
    preplanned.plan[0].tool_candidates.append("missing-tool")
    planned = await orchestrator._plan({"agent": preplanned.model_dump(mode="json")})
    assert orchestrator._state(planned).status == RunStatus.FAILED
    assert orchestrator._state(planned).last_error == "Planning requires an immutable TaskSpec"

    assert orchestrator._dispatch_scheduled({"route": "report"}) == "report"
    dispatched = orchestrator._dispatch_scheduled(
        {"route": "workers", "work_items": [{"step_id": "one"}, {"step_id": "two"}]}
    )
    assert isinstance(dispatched, list) and len(dispatched) == 2
    await orchestrator.project_outbox()
