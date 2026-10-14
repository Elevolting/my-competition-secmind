from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from pydantic import BaseModel, ValidationError

from secmind.admission import AdmissionService
from secmind.agents import ReporterAgent
from secmind.canonical_primary import (
    _build_manifest_only_context_legacy as build_manifest_only_context,
)
from secmind.canonical_primary import (
    canonical_system_prompt,
)
from secmind.guardrail import Guardrail
from secmind.ledger import LedgerStore
from secmind.llm import QwenGateway
from secmind.orchestrator import SecMindOrchestrator
from secmind.schemas import (
    AgentReport,
    AgentState,
    Evidence,
    Finding,
    InputArtifact,
    PlanStep,
    RiskLevel,
    RunStatus,
    Scenario,
    TaskRequest,
)
from secmind.service import RunWorker
from secmind.task_contract import EvidenceCompilerReceipt, EvidenceFact, compile_resolved_task_contract
from secmind.tools import ToolBroker, default_registry


def _primary_state() -> AgentState:
    evidence = Evidence(
        evidence_id="primary-evidence",
        source="secmind:canonical-primary:test",
        summary="Untrusted input reaches eval.",
        sha256="a" * 64,
    )
    finding = Finding(
        finding_id="primary-finding",
        rule_id="CWE-95",
        severity="HIGH",
        confidence="HIGH",
        path="app.py",
        line=1,
        title="Unsafe evaluation",
        description="Untrusted input reaches eval.",
        evidence_ids=[evidence.evidence_id],
        raw={"canonical_primary": True},
    )
    report = AgentReport(
        run_id="run-resilience",
        status=RunStatus.COMPLETED,
        executive_summary="Primary result",
        findings=[finding],
        evidence=[evidence],
    )
    return AgentState(
        run_id="run-resilience",
        task=TaskRequest(objective="Audit the code", autonomy_policy="automatic"),
        scenario=Scenario.CODE_AUDIT,
        status=RunStatus.RUNNING,
        findings=[finding],
        evidence=[evidence],
        audit_coverage={"canonical_primary_completed": True},
        report=report,
    )


def _bind_primary_evidence(state: AgentState, artifact_store) -> None:
    """Make the synthetic primary evidence readable by strict CAS admission."""

    stored = artifact_store.put(  # type: ignore[union-attr]
        b"primary evidence fixture",
        run_id=state.run_id,
        media_type="application/vnd.secmind.test-evidence",
    )
    for item in state.evidence:
        item.artifact_ref = stored.artifact_id
        item.sha256 = stored.sha256
    if state.report is not None:
        for item in state.report.evidence:
            item.artifact_ref = stored.artifact_id
            item.sha256 = stored.sha256


def _recovery_worker(artifact_store, capsule_store) -> RunWorker:
    service = SimpleNamespace(
        artifact_store=artifact_store,
        orchestrator=SimpleNamespace(capsule_store=capsule_store, settings=SimpleNamespace()),
    )
    return RunWorker(service)  # type: ignore[arg-type]


def test_skill_or_plan_failure_skips_augmentation_and_preserves_primary() -> None:
    state = _primary_state()

    SecMindOrchestrator._degrade_augmentation(  # noqa: SLF001
        state,
        reason="signed skill unavailable",
        decision="augmentation_planning_skipped",
        policy_ids=["BASELINE-PRESERVING-V1"],
    )

    assert state.status == RunStatus.PARTIAL
    assert state.audit_coverage["augmentation_status"] == "skipped"
    assert state.audit_coverage["primary_preserved"] is True
    assert [item.finding_id for item in state.report.findings] == ["primary-finding"]
    assert state.status != RunStatus.DENIED


@pytest.mark.asyncio
async def test_reporter_treats_primary_as_success_without_tool_observation() -> None:
    state = _primary_state()

    result = await ReporterAgent(None).run(state)  # type: ignore[arg-type]

    assert result.status == RunStatus.COMPLETED
    assert result.report is not None
    assert "Task-level Primary completed" in result.report.executive_summary
    assert [item.finding_id for item in result.report.findings] == ["primary-finding"]


def test_retry_exhaustion_materializes_recovery_report(admission_stores) -> None:
    state = _primary_state()
    artifact_store, capsule_store = admission_stores
    _bind_primary_evidence(state, artifact_store)
    state.status = RunStatus.RECOVERY_REQUIRED
    state.last_error = "Worker retry budget exhausted: TimeoutError"
    assert state.report is not None
    state.report.executive_summary = "MUTABLE-REPORT-MUST-NOT-LEAK"

    _recovery_worker(artifact_store, capsule_store)._materialize_recovery_report(state)  # noqa: SLF001

    assert state.report is not None
    assert state.report.status == RunStatus.RECOVERY_REQUIRED
    assert state.report.findings[0].finding_id == "primary-finding"
    assert state.audit_coverage["recovery_report_materialized"] is True
    assert state.last_error in state.report.limitations
    assert state.sealed_admission is not None
    assert AdmissionService.project(state.sealed_admission) == state.report
    assert "MUTABLE-REPORT-MUST-NOT-LEAK" not in state.report.executive_summary


def test_retry_exhaustion_restores_existing_sealed_report_instead_of_mutable_view(admission_stores) -> None:
    state = _primary_state()
    artifact_store, capsule_store = admission_stores
    _bind_primary_evidence(state, artifact_store)
    state.status = RunStatus.COMPLETED
    assert state.report is not None
    snapshot = AdmissionService.seal(
        state,
        state.report,
        artifact_store=artifact_store,
        capsule_store=capsule_store,
    )
    expected = AdmissionService.project(snapshot)
    state.status = RunStatus.RECOVERY_REQUIRED
    state.last_error = "Worker retry budget exhausted: TimeoutError"
    state.report = AgentReport(
        run_id=state.run_id,
        status=RunStatus.RECOVERY_REQUIRED,
        executive_summary="unsealed recovery replacement",
    )

    _recovery_worker(artifact_store, capsule_store)._materialize_recovery_report(state)  # noqa: SLF001

    assert state.report == expected
    assert state.audit_coverage["recovery_report_materialized"] is True
    assert "unsealed recovery replacement" not in state.report.executive_summary


def test_manifest_fallback_and_forensics_prompt_preserve_analyzable_text() -> None:
    payload = b"event_id=4624 account=alice timestamp=2026-01-01T00:00:00Z"
    artifact = InputArtifact(
        artifact_id="event-log",
        original_name="events.log",
        relative_path="events.log",
        sha256=hashlib.sha256(payload).hexdigest(),
        size_bytes=len(payload),
        media_type="text/plain",
    )
    contract, views = build_manifest_only_context(
        task_id="TASK-LOG",
        task=TaskRequest(objective="Analyze Windows forensic logs", autonomy_policy="automatic"),
        scenario=Scenario.LOG_ANALYSIS,
        artifacts=[artifact],
        reason="OSError",
    )

    prompt = canonical_system_prompt(contract.analysis_profile)
    assert views == []
    assert contract.omitted_paths == ["events.log"]
    assert "Analyze structured logs normally" in prompt
    assert "Use insufficient_evidence only" in prompt


def test_tool_routing_explains_planned_incompatible_and_unavailable_tools(settings, tmp_path: Path) -> None:
    ledger = LedgerStore(settings.database_url)
    broker = ToolBroker(default_registry(), Guardrail())
    orchestrator = SecMindOrchestrator(settings, ledger, QwenGateway(settings), broker)
    payload = b"openapi: 3.0.0\n"
    state = AgentState(
        run_id="run-tool-routing",
        task=TaskRequest(objective="Audit API configuration", autonomy_policy="automatic"),
        scenario=Scenario.CODE_AUDIT,
        workspace=str(tmp_path),
        input_artifacts=[
            InputArtifact(
                artifact_id="api-yaml",
                original_name="api.yaml",
                relative_path="api.yaml",
                sha256=hashlib.sha256(payload).hexdigest(),
                size_bytes=len(payload),
                media_type="application/yaml",
            )
        ],
    )
    steps = [
        PlanStep(
            step_id="inventory-project",
            objective="Inventory project",
            agent_role="scout",
            capability="inventory",
            tool_candidates=["project_inventory"],
            inputs={"target": "."},
            success_criteria=["Inventory is evidence-backed"],
            risk_hint=RiskLevel.R0,
        ),
        PlanStep(
            step_id="scan-redacted-secrets",
            objective="Scan redacted secrets",
            agent_role="secret_specialist",
            capability="secret_scan",
            tool_candidates=["secret_pattern_scan"],
            inputs={"target": "."},
            success_criteria=["Secret scan is evidence-backed"],
            risk_hint=RiskLevel.R1,
        ),
    ]
    try:
        orchestrator._record_tool_routing(state, steps)  # noqa: SLF001
    finally:
        broker.close()
        ledger.close()

    routing = state.audit_coverage["tool_routing"]
    assert routing["input_languages"] == ["yaml"]
    assert routing["planned"] == ["project_inventory", "secret_pattern_scan"]
    assert routing["skipped"]["bandit_python_audit"] == "input_language_not_supported"
    assert "semgrep_sast" in routing["unavailable"]


def test_report_finalizes_pending_augmentation_state() -> None:
    state = _primary_state()
    state.audit_coverage["augmentation_status"] = "pending"

    SecMindOrchestrator._finalize_augmentation_status(state)  # noqa: SLF001

    assert state.audit_coverage["augmentation_status"] == "not_applicable"


@pytest.mark.asyncio
async def test_failed_live_primary_records_attempt_and_returns_partial_report(settings, tmp_path: Path) -> None:
    settings.demo_mode = False
    settings.model_mode = "mock"
    source = tmp_path / "app.py"
    source.write_text("value = eval(user_input)\n", encoding="utf-8")
    payload = source.read_bytes()
    artifact = InputArtifact(
        artifact_id="source",
        original_name="app.py",
        relative_path="app.py",
        sha256=hashlib.sha256(payload).hexdigest(),
        size_bytes=len(payload),
        media_type="text/x-python",
    )

    def unavailable(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("provider unavailable", request=request)

    client = httpx.AsyncClient(transport=httpx.MockTransport(unavailable))
    gateway = QwenGateway(settings, client)
    ledger = LedgerStore(settings.database_url)
    broker = ToolBroker(default_registry(), Guardrail())
    orchestrator = SecMindOrchestrator(settings, ledger, gateway, broker)
    state = AgentState(
        run_id="run-provider-failure",
        task=TaskRequest(objective="Audit app.py", autonomy_policy="automatic"),
        scenario=Scenario.CODE_AUDIT,
        status=RunStatus.RUNNING,
        workspace=str(tmp_path),
        input_artifacts=[artifact],
        resolved_task_contract=compile_resolved_task_contract(
            {
                "task_spec_id": "task-spec-run-provider-failure",
                "run_id": "run-provider-failure",
                "revision": 1,
                "content_digest": hashlib.sha256(b"task-spec-run-provider-failure").hexdigest(),
                "objectives": ["Audit app.py"],
                "primary_scenario": Scenario.CODE_AUDIT.value,
                "primary_domain": "code_audit_and_patch",
                "secondary_scenarios": [],
                "secondary_capabilities": [],
                "scoring_mode": "security_finding",
                "interaction_mode": "unattended",
                "autonomy_policy": "automatic",
                "authorized_scope": ["app.py"],
                "constraints": [],
                "prohibited_actions": [],
                "expected_outputs": ["security_report"],
                "success_criteria": [],
                "output_contract": {},
                "asset_ids": [artifact.artifact_id],
            },
            input_manifest_digest=hashlib.sha256(payload).hexdigest(),
        ),
    )
    try:
        output = await orchestrator._canonical_primary(  # noqa: SLF001
            {"agent": state.model_dump(mode="json")}
        )
        result = AgentState.model_validate(output["agent"])
    finally:
        broker.close()
        ledger.close()
        await client.aclose()

    assert result.status == RunStatus.PARTIAL
    assert result.report is not None
    assert result.audit_coverage["canonical_primary_attempted"] is True
    assert result.audit_coverage["canonical_primary_provider_requests"] > 0
    assert result.budget.model_calls_used == 1
    assert result.budget.usage.provider_requests > 0


@pytest.mark.asyncio
async def test_primary_publication_validation_failure_preserves_deterministic_gap(
    settings,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A bad typed projection must not discard pre-Primary LFS evidence."""

    run_id = "run-primary-projection-validation"
    source = b"version https://git-lfs.github.com/spec/v1\noid sha256:" + b"a" * 64 + b"\nsize 1478202\n"
    source_sha256 = hashlib.sha256(source).hexdigest()
    resolved = compile_resolved_task_contract(
        {
            "task_spec_id": "task-spec-primary-projection-validation",
            "run_id": run_id,
            "revision": 1,
            "content_digest": hashlib.sha256(b"task-spec-primary-projection-validation").hexdigest(),
            "objectives": ["Determine whether the supplied telemetry supports attribution"],
            "primary_scenario": Scenario.UNKNOWN.value,
            "primary_domain": "orchestration_recovery_uncertainty",
            "secondary_scenarios": [],
            "secondary_capabilities": ["evidence_gap_handling"],
            "scoring_mode": "evidence_gap",
            "interaction_mode": "unattended",
            "autonomy_policy": "automatic",
            "authorized_scope": ["telemetry.log"],
            "constraints": [],
            "prohibited_actions": [],
            "expected_outputs": ["evidence_gap_assessment"],
            "success_criteria": [],
            "output_contract": {},
            "asset_ids": ["artifact-lfs"],
        },
        input_manifest_digest=source_sha256,
    )
    lfs_fact = EvidenceFact(
        fact_id="fact-lfs",
        fact_type="artifact.git_lfs_pointer",
        value={
            "relative_path": "telemetry.log",
            "pointer_oid": "a" * 64,
            "declared_size": 1_478_202,
            "underlying_object_present": False,
            "attribution_permitted": False,
        },
        source_ref="telemetry.log",
        source_sha256=source_sha256,
        locator="whole-file",
    )
    state = AgentState(
        run_id=run_id,
        task=TaskRequest(
            objective="Determine whether the supplied telemetry supports attribution",
            autonomy_policy="automatic",
        ),
        scenario=Scenario.UNKNOWN,
        status=RunStatus.RUNNING,
        resolved_task_contract=resolved,
        evidence_compiler_receipt=EvidenceCompilerReceipt(
            run_id=run_id,
            contract_digest=resolved.contract_digest,
            input_manifest_digest=resolved.input_manifest_digest,
            facts=[lfs_fact],
            raw_window_refs=[source_sha256],
            output_digest="d" * 64,
        ),
    )

    class RequiredProjection(BaseModel):
        required_field: str

    with pytest.raises(ValidationError) as captured:
        RequiredProjection.model_validate({})

    async def invalid_publication(_value):
        raise captured.value

    settings.model_mode = "offline"
    settings.demo_mode = True
    gateway = QwenGateway(settings)
    ledger = LedgerStore(settings.database_url)
    broker = ToolBroker(default_registry(), Guardrail())
    orchestrator = SecMindOrchestrator(settings, ledger, gateway, broker)
    monkeypatch.setattr(orchestrator, "_canonical_primary", invalid_publication)
    try:
        output = await orchestrator._canonical_primary_guarded(  # noqa: SLF001
            {"agent": state.model_dump(mode="json")}
        )
        result = AgentState.model_validate(output["agent"])
    finally:
        broker.close()
        ledger.close()

    assert result.status == RunStatus.PARTIAL
    assert result.report is not None
    assert result.report.answer_type == "evidence_gap"
    assert result.report.answer_payload["epistemic_status"] == "insufficient_evidence"
    assert "referenced Git LFS object bytes" in result.report.answer_payload["unknown_fields"]
    failure = result.audit_coverage["canonical_primary_projection_failure"]
    assert failure["partial_publication_discarded"] is True
    assert failure["issues"] == [{"location": ["required_field"], "type": "missing"}]


@pytest.mark.asyncio
async def test_primary_entry_state_validation_recovers_once_from_durable_checkpoint(
    settings,
) -> None:
    settings.model_mode = "offline"
    settings.demo_mode = True
    gateway = QwenGateway(settings)
    ledger = LedgerStore(settings.database_url)
    broker = ToolBroker(default_registry(), Guardrail())
    orchestrator = SecMindOrchestrator(settings, ledger, gateway, broker)
    state = AgentState(
        run_id="run-primary-entry-state-recovery",
        task=TaskRequest(objective="Recover the last valid state", autonomy_policy="automatic"),
        scenario=Scenario.UNKNOWN,
        status=RunStatus.RUNNING,
    )
    ledger.save_state(state)
    damaged = state.model_dump(mode="json")
    damaged["budget"]["max_steps"] = "not-an-integer"
    try:
        output = await orchestrator._canonical_primary_guarded({"agent": damaged})  # noqa: SLF001
        recovered = AgentState.model_validate(output["agent"])
    finally:
        broker.close()
        ledger.close()

    assert recovered.status == RunStatus.PARTIAL
    assert recovered.report is not None
    failure = recovered.audit_coverage["canonical_primary_projection_failure"]
    assert failure["failure_stage"] == "pre_primary_state"
    assert failure["provider_requests"] == 0
    assert failure["raw_response_preserved"] is False
    assert recovered.budget.model_calls_used == 0
