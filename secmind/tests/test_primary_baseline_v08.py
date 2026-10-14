from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest

from secmind.admission import AdmissionError, AdmissionService
from secmind.evidence_graph import EvidenceGraph, make_claim, make_link
from secmind.guardrail import Guardrail
from secmind.investigation.contracts import ObligationStatus
from secmind.ledger import LedgerStore
from secmind.llm import QwenGateway
from secmind.log_analysis import LogAnalysisError
from secmind.orchestrator import SecMindOrchestrator
from secmind.primary_baseline import (
    publish_primary_baseline,
    report_preserves_baseline,
    restore_published_baseline,
    validate_baseline_chain,
)
from secmind.schemas import (
    SCHEMA_VERSION,
    AgentReport,
    AgentState,
    ClaimStatus,
    DecisionRecord,
    Evidence,
    EvidenceGapTicket,
    EvidenceRelation,
    Finding,
    PlanStep,
    RepositoryIndexRef,
    RunStatus,
    Scenario,
    StepRuntime,
    StepStatus,
    TaskRequest,
    ToolResult,
    ToolStatus,
)
from secmind.task_contract import compile_resolved_task_contract
from secmind.tools import ToolBroker, default_registry

_PRIMARY_EVIDENCE_BYTES = b"primary baseline evidence fixture"
_PRIMARY_EVIDENCE_SHA = hashlib.sha256(_PRIMARY_EVIDENCE_BYTES).hexdigest()
_PRIMARY_RESPONSE_BYTES = b"primary baseline response fixture"
_PRIMARY_RESPONSE_SHA = hashlib.sha256(_PRIMARY_RESPONSE_BYTES).hexdigest()
_DELTA_EVIDENCE_BYTES = b"authoritative delta evidence fixture"
_DELTA_EVIDENCE_SHA = hashlib.sha256(_DELTA_EVIDENCE_BYTES).hexdigest()
_COVERAGE_EVIDENCE_BYTES = b"coverage evidence fixture"
_COVERAGE_EVIDENCE_SHA = hashlib.sha256(_COVERAGE_EVIDENCE_BYTES).hexdigest()


def _sealed_primary_state() -> AgentState:
    evidence = Evidence(
        evidence_id="primary-evidence",
        source="secmind:canonical-primary:test",
        summary="Untrusted input reaches eval.",
        artifact_ref=_PRIMARY_EVIDENCE_SHA,
        sha256=_PRIMARY_EVIDENCE_SHA,
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
    decision = DecisionRecord(
        decision="canonical_primary_completed",
        rationale_summary="Primary completed.",
        evidence_ids=[evidence.evidence_id],
    )
    state = AgentState(
        run_id="run-v08-baseline",
        task=TaskRequest(objective="Audit the supplied evidence", autonomy_policy="automatic"),
        scenario=Scenario.LOG_ANALYSIS,
        status=RunStatus.RUNNING,
        findings=[finding],
        evidence=[evidence],
        decisions=[decision],
        audit_kernel="canonical-primary-v1",
        audit_coverage={"canonical_primary_completed": True},
        resolved_task_contract=compile_resolved_task_contract(
            {
                "task_spec_id": "task-spec-run-v08-baseline",
                "run_id": "run-v08-baseline",
                "revision": 1,
                "content_digest": hashlib.sha256(b"task-spec-run-v08-baseline").hexdigest(),
                "objectives": ["Audit the supplied evidence"],
                "primary_scenario": Scenario.LOG_ANALYSIS.value,
                "primary_domain": "logs_ir_hunting",
                "secondary_scenarios": [],
                "secondary_capabilities": [],
                "scoring_mode": "forensic_attribution",
                "interaction_mode": "unattended",
                "autonomy_policy": "automatic",
                "authorized_scope": ["."],
                "constraints": [],
                "prohibited_actions": [],
                "expected_outputs": ["evidence_backed_assessment"],
                "success_criteria": [],
                "output_contract": {},
                "asset_ids": [],
            },
            input_manifest_digest=hashlib.sha256(b"empty-test-manifest").hexdigest(),
        ),
        report=AgentReport(
            run_id="run-v08-baseline",
            status=RunStatus.COMPLETED,
            executive_summary="Primary result",
            findings=[finding],
            evidence=[evidence],
            decisions=[decision],
        ),
    )
    publish_primary_baseline(
        state,
        model_id="deepseek-v4-flash",
        prompt_version="canonical-primary-v2",
        prompt_artifact_id=None,
        request_sha256="b" * 64,
        response_sha256=_PRIMARY_RESPONSE_SHA,
        response_schema_sha256="d" * 64,
        context_sha256="e" * 64,
        response_artifact_id=_PRIMARY_RESPONSE_SHA,
        provider_requests=1,
        input_tokens=100,
        output_tokens=50,
        cost_units=0.01,
        status=RunStatus.COMPLETED,
        executive_summary="Primary result",
        findings=[finding],
        evidence=[evidence],
        decisions=[decision],
        limitations=[],
        coverage=state.audit_coverage,
    )
    return state


def _gap_ticket(**values: Any) -> EvidenceGapTicket:
    digest = hashlib.sha256(
        json.dumps(values, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return EvidenceGapTicket(ticket_id=f"gap-ticket-{digest}", **values)


def _clean_coverage_state(
    *,
    claim_status: ClaimStatus = ClaimStatus.VERIFIED,
    link_status: ClaimStatus = ClaimStatus.VERIFIED,
    relation: EvidenceRelation = EvidenceRelation.SUPPORTS,
    include_link: bool = True,
    include_report_claim: bool = True,
    tamper_report_evidence: bool = False,
) -> AgentState:
    evidence = Evidence(
        evidence_id="coverage-evidence",
        source="bandit_python_audit:1",
        summary="The bounded scan covered its immutable input.",
        artifact_ref=_COVERAGE_EVIDENCE_SHA,
        sha256=_COVERAGE_EVIDENCE_SHA,
        metadata={"evidence_type": "execution_coverage"},
    )
    report_evidence = (
        evidence.model_copy(update={"summary": "Reporter-replaced evidence."})
        if tamper_report_evidence
        else evidence.model_copy(deep=True)
    )
    claim = make_claim(
        claim_type="sast.coverage",
        statement="The bounded scan covered its immutable input.",
        subject_ref="coverage:scan-sast",
        producer="scan-sast",
    ).model_copy(update={"status": claim_status})
    link = make_link(
        claim_id=claim.claim_id,
        evidence_id=evidence.evidence_id,
        relation=relation,
    ).model_copy(update={"verifier_status": link_status})
    report = AgentReport(
        run_id="run-clean-coverage",
        status=RunStatus.COMPLETED,
        executive_summary="No vulnerability was verified.",
        evidence=[report_evidence],
        claim_ids=[claim.claim_id] if include_report_claim else [],
    )
    return AgentState(
        run_id=report.run_id,
        task=TaskRequest(objective="Audit the supplied source", autonomy_policy="automatic"),
        scenario=Scenario.CODE_AUDIT,
        status=RunStatus.COMPLETED,
        evidence=[evidence],
        claims=[claim],
        evidence_links=[link] if include_link else [],
        report=report,
    )


def _state_with_authoritative_delta() -> tuple[AgentState, Finding]:
    state = _sealed_primary_state()
    assert state.published_baseline is not None
    snapshot_digest = "8" * 64
    state.repository_index = RepositoryIndexRef(
        index_id="repository-index",
        run_id=state.run_id,
        artifact_id="repository-index-artifact",
        digest=snapshot_digest,
        file_count=1,
        total_bytes=100,
        languages=["python"],
    )
    state.audit_coverage["repository_snapshot_digest"] = snapshot_digest
    delta_evidence = Evidence(
        evidence_id="delta-evidence",
        source="python_taint_audit:1",
        summary="A bounded source-to-sink flow confirms a risky call.",
        artifact_ref=_DELTA_EVIDENCE_SHA,
        sha256=_DELTA_EVIDENCE_SHA,
        metadata={"tool_name": "python_taint_audit"},
    )
    delta = Finding(
        finding_id="delta-good",
        rule_id="CWE-78",
        severity="HIGH",
        confidence="HIGH",
        path="worker.py",
        line=8,
        title="Command injection",
        description="Untrusted data reaches a shell.",
        evidence_ids=[delta_evidence.evidence_id],
    )
    ticket = _gap_ticket(
        run_id=state.run_id,
        snapshot_digest=snapshot_digest,
        primary_semantic_digest=state.published_baseline.semantic_digest,
        gap_code="empty_or_inconclusive_primary",
        target_finding_id=None,
        allowed_patch_class="add_finding",
        capability="sast",
        tool_name="python_taint_audit",
        step_id="delta-step",
        release_policy="authoritative",
        max_tool_calls=1,
        max_runtime_ms=120_000,
    )
    state.evidence_gap_tickets = [ticket]
    state.plan = [
        PlanStep(
            step_id="delta-step",
            objective="Collect the bounded missing flow.",
            agent_role="sast_specialist",
            capability="sast",
            tool_candidates=["python_taint_audit"],
            context_requirements={
                "evidence_gap_ticket_id": ticket.ticket_id,
                "allowed_patch_class": ticket.allowed_patch_class,
                "release_policy": ticket.release_policy,
                "primary_semantic_digest": ticket.primary_semantic_digest,
            },
            estimated_tool_calls=1,
        )
    ]
    state.observations = [
        ToolResult(
            invocation_id="delta-invocation",
            status=ToolStatus.SUCCESS,
            evidence=[delta_evidence],
            duration_ms=500,
        )
    ]
    state.step_runtime["delta-step"] = StepRuntime(
        step_id="delta-step",
        status=StepStatus.SUCCEEDED,
        attempt=1,
        actual_tool_calls=1,
        tool_invocation_ids=["delta-invocation"],
        actual_tool_name="python_taint_audit",
        observation_indexes=[0],
    )
    state.findings.append(delta)
    state.evidence.append(delta_evidence)
    state.claims.append(
        make_claim(
            claim_type="worker.delta_finding",
            statement="The bounded worker confirmed a command injection flow.",
            subject_ref=delta.finding_id,
            producer="delta-step",
        ).model_copy(update={"status": ClaimStatus.VERIFIED})
    )
    assert state.report is not None
    state.report = state.report.model_copy(
        update={
            "findings": [*state.report.findings, delta],
            "evidence": [*state.report.evidence, delta_evidence],
        }
    )
    return state, delta


def _seed_admission_stores(state: AgentState, admission_stores) -> None:
    artifact_store, _capsule_store = admission_stores
    payloads = {
        _PRIMARY_EVIDENCE_SHA: _PRIMARY_EVIDENCE_BYTES,
        _PRIMARY_RESPONSE_SHA: _PRIMARY_RESPONSE_BYTES,
        _DELTA_EVIDENCE_SHA: _DELTA_EVIDENCE_BYTES,
        _COVERAGE_EVIDENCE_SHA: _COVERAGE_EVIDENCE_BYTES,
    }
    evidence_items = [*state.evidence]
    if state.report is not None:
        evidence_items.extend(state.report.evidence)
    if state.published_baseline is not None:
        evidence_items.extend(state.published_baseline.evidence)
    for item in evidence_items:
        if item.artifact_ref in payloads:
            artifact_store.put(
                payloads[item.artifact_ref],
                expected_sha256=item.artifact_ref,
                run_id=state.run_id,
                media_type="application/vnd.secmind.test-evidence",
            )
    artifact_store.put(
        _PRIMARY_RESPONSE_BYTES,
        expected_sha256=_PRIMARY_RESPONSE_SHA,
        run_id=state.run_id,
        media_type="application/vnd.secmind.canonical-primary+json",
    )


def _seal(state: AgentState, admission_stores, report: AgentReport | None = None):
    _seed_admission_stores(state, admission_stores)
    artifact_store, capsule_store = admission_stores
    return AdmissionService.seal(
        state,
        report,
        artifact_store=artifact_store,
        capsule_store=capsule_store,
    )


def _orchestrator(settings) -> tuple[SecMindOrchestrator, LedgerStore, ToolBroker]:
    ledger = LedgerStore(settings.database_url)
    broker = ToolBroker(default_registry(), Guardrail())
    return SecMindOrchestrator(settings, ledger, QwenGateway(settings), broker), ledger, broker


def test_primary_projection_survives_state_round_trip_and_report_mutation() -> None:
    state = AgentState.model_validate(_sealed_primary_state().model_dump(mode="json"))
    assert state.published_baseline is not None
    assert state.raw_primary_receipt is not None
    assert state.baseline_admission is not None
    assert report_preserves_baseline(state)

    state.report = AgentReport(
        run_id=state.run_id,
        status=RunStatus.PARTIAL,
        executive_summary="A downstream adapter replaced the report.",
    )
    assert not report_preserves_baseline(state)

    assert restore_published_baseline(state)
    assert state.report is not None
    assert [item.finding_id for item in state.report.findings] == ["primary-finding"]
    assert state.audit_coverage["primary_preserved"] is True


def test_v071_json_state_is_upcast_as_one_public_schema_graph() -> None:
    payload = _sealed_primary_state().model_dump(mode="json")
    payload["schema_version"] = "1.6"
    payload["report"]["schema_version"] = "1.6"
    payload["raw_primary_receipt"]["schema_version"] = "1.6"
    payload["baseline_admission"]["schema_version"] = "1.6"
    payload["published_baseline"]["schema_version"] = "1.6"

    restored = AgentState.model_validate(payload)

    assert restored.schema_version == SCHEMA_VERSION
    assert restored.report is not None and restored.report.schema_version == SCHEMA_VERSION
    assert restored.raw_primary_receipt is not None
    assert restored.raw_primary_receipt.schema_version == SCHEMA_VERSION
    assert restored.baseline_admission is not None
    assert restored.baseline_admission.schema_version == SCHEMA_VERSION
    assert restored.published_baseline is not None
    assert restored.published_baseline.schema_version == SCHEMA_VERSION


def test_tampered_or_cross_run_baseline_fails_before_restore() -> None:
    state = _sealed_primary_state()
    assert state.published_baseline is not None
    state.report = AgentReport(
        run_id=state.run_id,
        status=RunStatus.PARTIAL,
        executive_summary="Empty downstream report",
    )
    state.published_baseline.findings[0].title = "tampered title"

    valid, reason = validate_baseline_chain(state)
    assert not valid
    assert reason is not None and "mismatch" in reason
    assert not restore_published_baseline(state)
    assert state.report.findings == []

    other_run = AgentState.model_validate(_sealed_primary_state().model_dump(mode="json"))
    other_run.run_id = "another-run"
    assert validate_baseline_chain(other_run) == (False, "baseline chain belongs to another run")
    assert not restore_published_baseline(other_run)


def test_single_admission_snapshot_preserves_baseline_and_filters_broken_delta(admission_stores) -> None:
    state, good_delta = _state_with_authoritative_delta()
    broken_delta = Finding(
        finding_id="delta-broken",
        rule_id="CWE-89",
        path="db.py",
        line=4,
        title="Unbound SQL claim",
        description="No evidence exists for this candidate.",
        evidence_ids=["missing-evidence"],
    )
    state.findings.append(broken_delta)
    assert state.report is not None
    state.report = state.report.model_copy(
        update={
            "findings": [*state.report.findings, broken_delta],
        }
    )

    snapshot = _seal(state, admission_stores, state.report)

    assert snapshot.admitted_finding_ids == ["primary-finding", "delta-good"]
    assert snapshot.rejected_finding_ids == ["delta-broken"]
    assert [item.finding_id for item in AdmissionService.project(snapshot).findings] == [
        "primary-finding",
        "delta-good",
    ]
    snapshot.report.findings[0].title = "tampered"
    try:
        AdmissionService.project(snapshot)
    except AdmissionError as exc:
        assert "mismatch" in str(exc)
    else:  # pragma: no cover - defensive assertion
        raise AssertionError("tampered admission snapshot was projected")


def test_admission_preserves_verified_coverage_evidence_without_a_finding(admission_stores) -> None:
    state = _clean_coverage_state()

    snapshot = _seal(state, admission_stores, state.report)

    assert snapshot.report.findings == []
    assert [item.evidence_id for item in snapshot.report.evidence] == ["coverage-evidence"]
    assert AdmissionService.validate_snapshot(snapshot) == (True, None)


@pytest.mark.parametrize(
    "values",
    [
        {"claim_status": ClaimStatus.CANDIDATE},
        {"link_status": ClaimStatus.REJECTED},
        {"relation": EvidenceRelation.CONTRADICTS},
        {"include_link": False},
        {"include_report_claim": False},
        {"tamper_report_evidence": True},
    ],
    ids=(
        "claim-not-verified",
        "support-link-not-verified",
        "verified-link-not-supporting",
        "evidence-unlinked",
        "claim-not-in-report",
        "report-evidence-content-drift",
    ),
)
def test_admission_rejects_non_authoritative_report_evidence(values: dict[str, Any], admission_stores) -> None:
    state = _clean_coverage_state(**values)

    snapshot = _seal(state, admission_stores, state.report)

    assert snapshot.report.evidence == []
    assert AdmissionService.validate_snapshot(snapshot) == (True, None)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("run_id", "another-run"),
        ("snapshot_digest", "9" * 64),
        ("primary_semantic_digest", "9" * 64),
        ("tool_name", "semgrep_sast"),
        ("step_id", "another-step"),
        ("capability", "secret_scan"),
        ("allowed_patch_class", "correct_cwe"),
        ("release_policy", "shadow"),
        ("target_finding_id", "primary-finding"),
    ],
)
def test_admission_rejects_delta_when_authoritative_ticket_binding_drifts(
    field: str,
    value: Any,
    admission_stores,
) -> None:
    state, delta = _state_with_authoritative_delta()
    current = state.evidence_gap_tickets[0]
    payload = current.model_dump(
        mode="python",
        exclude={"ticket_id", "schema_version", "created_at"},
    )
    payload[field] = value
    state.evidence_gap_tickets = [_gap_ticket(**payload)]

    snapshot = _seal(state, admission_stores, state.report)

    assert delta.finding_id not in snapshot.admitted_finding_ids
    assert delta.finding_id in snapshot.rejected_finding_ids


@pytest.mark.parametrize("budget_drift", ["attempt", "duration", "estimated_calls", "actual_calls"])
def test_admission_rejects_delta_that_exceeds_ticket_budget(budget_drift: str, admission_stores) -> None:
    state, delta = _state_with_authoritative_delta()
    if budget_drift == "attempt":
        state.step_runtime["delta-step"].attempt = 2
    elif budget_drift == "duration":
        state.observations[0].duration_ms = 120_001
    elif budget_drift == "actual_calls":
        state.step_runtime["delta-step"].actual_tool_calls = 2
        state.step_runtime["delta-step"].tool_invocation_ids.append("delta-invocation-2")
    else:
        state.plan[0].estimated_tool_calls = 2

    snapshot = _seal(state, admission_stores, state.report)

    assert delta.finding_id not in snapshot.admitted_finding_ids
    assert delta.finding_id in snapshot.rejected_finding_ids


def test_admission_rejects_forged_ticket_identity_and_quarantined_public_overlap(admission_stores) -> None:
    forged_state, delta = _state_with_authoritative_delta()
    forged_state.evidence_gap_tickets[0] = forged_state.evidence_gap_tickets[0].model_copy(
        update={"ticket_id": "gap-ticket-" + "0" * 64}
    )
    forged = _seal(forged_state, admission_stores, forged_state.report)
    assert delta.finding_id not in forged.admitted_finding_ids

    quarantined_state, delta = _state_with_authoritative_delta()
    quarantined_state.audit_coverage["tool_gain_gate"] = {"quarantined_finding_ids": [delta.finding_id]}
    quarantined = _seal(quarantined_state, admission_stores, quarantined_state.report)
    assert delta.finding_id not in quarantined.admitted_finding_ids
    assert delta.finding_id in quarantined.rejected_finding_ids
    assert not set(quarantined.admitted_finding_ids) & set(quarantined.rejected_finding_ids)
    assert delta.finding_id not in {item.finding_id for item in quarantined.report.findings}


def test_resealing_same_snapshot_restores_sealed_public_view(admission_stores) -> None:
    state = _sealed_primary_state()
    state.status = RunStatus.COMPLETED
    assert state.report is not None
    snapshot = _seal(state, admission_stores, state.report)
    expected = AdmissionService.project(snapshot)

    state.report = state.report.model_copy(
        update={
            "executive_summary": "mutable downstream replacement",
            "limitations": ["unsealed mutable limitation"],
        }
    )
    state.findings = []
    state.evidence = []
    state.decisions = []

    repeated = _seal(state, admission_stores, state.report)

    assert repeated is state.sealed_admission
    assert repeated.snapshot_id == snapshot.snapshot_id
    assert state.report == expected
    assert state.findings == expected.findings
    assert state.evidence == expected.evidence
    assert state.decisions == expected.decisions
    assert "mutable downstream replacement" not in state.report.executive_summary
    assert "unsealed mutable limitation" not in state.report.limitations


def test_unbound_primary_is_shadow_not_public_baseline() -> None:
    state = _sealed_primary_state()
    state.raw_primary_receipt = None
    state.baseline_admission = None
    state.published_baseline = None
    assert state.report is not None
    unbound = state.report.findings[0].model_copy(update={"evidence_ids": ["missing"]})
    projection = publish_primary_baseline(
        state,
        model_id="deepseek-v4-flash",
        prompt_version="canonical-primary-v2",
        prompt_artifact_id=None,
        request_sha256="2" * 64,
        response_sha256="3" * 64,
        response_schema_sha256="4" * 64,
        context_sha256="5" * 64,
        response_artifact_id="3" * 64,
        provider_requests=1,
        input_tokens=1,
        output_tokens=1,
        cost_units=0,
        status=RunStatus.PARTIAL,
        executive_summary="Unbound result",
        findings=[unbound],
        evidence=state.evidence,
        decisions=state.decisions,
        limitations=[],
        coverage={},
    )
    assert projection.findings
    assert state.baseline_admission is not None
    assert state.baseline_admission.admission_status == "shadow"
    assert not restore_published_baseline(state)


def test_product_admission_excludes_unbound_candidates_without_losing_receipt() -> None:
    state = _sealed_primary_state()
    state.raw_primary_receipt = None
    state.baseline_admission = None
    state.published_baseline = None
    assert state.report is not None
    projection = publish_primary_baseline(
        state,
        model_id="deepseek-v4-flash",
        prompt_version="canonical-primary-v2",
        prompt_artifact_id=None,
        request_sha256="2" * 64,
        response_sha256="3" * 64,
        response_schema_sha256="4" * 64,
        context_sha256="5" * 64,
        response_artifact_id="3" * 64,
        provider_requests=1,
        input_tokens=1,
        output_tokens=1,
        cost_units=0,
        status=RunStatus.COMPLETED,
        executive_summary="Mixed provenance result",
        findings=state.report.findings,
        evidence=state.report.evidence,
        decisions=state.report.decisions,
        limitations=[],
        coverage={},
        bound_finding_ids=set(),
    )

    assert projection.findings == []
    assert projection.status == RunStatus.PARTIAL
    assert state.raw_primary_receipt is not None
    assert state.baseline_admission is not None
    assert state.baseline_admission.admission_status == "baseline_admitted"
    assert validate_baseline_chain(state) == (True, None)


def test_product_admission_preserves_only_explicitly_bound_answer_evidence() -> None:
    state = _sealed_primary_state()
    state.raw_primary_receipt = None
    state.baseline_admission = None
    state.published_baseline = None
    bound = Evidence(
        evidence_id="answer-evidence",
        source="secmind:evidence-compiler:git-lfs@1.0",
        summary="Verified Git LFS pointer metadata",
        artifact_ref="7" * 64,
        sha256="7" * 64,
    )
    unrelated = Evidence(
        evidence_id="unrelated-evidence",
        source="mutable-worker-output",
        summary="Not bound to the typed answer",
        artifact_ref="8" * 64,
        sha256="8" * 64,
    )

    projection = publish_primary_baseline(
        state,
        model_id="gpt-5.6-terra",
        prompt_version="canonical-primary-v6",
        prompt_artifact_id=None,
        request_sha256="2" * 64,
        response_sha256="3" * 64,
        response_schema_sha256="4" * 64,
        context_sha256="5" * 64,
        response_artifact_id="3" * 64,
        provider_requests=1,
        input_tokens=1,
        output_tokens=1,
        cost_units=0,
        status=RunStatus.PARTIAL,
        executive_summary="Evidence is insufficient because the LFS object is absent.",
        answer_type="evidence_gap",
        answer_payload={"answer_kind": "evidence_gap", "unknown_fields": ["underlying object"]},
        findings=[],
        evidence=[bound, unrelated],
        decisions=[],
        limitations=["The underlying object is unavailable."],
        coverage={},
        bound_finding_ids=set(),
        bound_evidence_ids={bound.evidence_id},
    )

    assert [item.evidence_id for item in projection.evidence] == [bound.evidence_id]
    assert projection.coverage["unbound_primary_evidence_ids"] == [unrelated.evidence_id]
    assert state.baseline_admission is not None
    assert state.baseline_admission.evidence_ids == [bound.evidence_id]
    assert validate_baseline_chain(state) == (True, None)


def test_complete_primary_without_gap_uses_lean_completion_route(settings) -> None:
    orchestrator, ledger, broker = _orchestrator(settings)
    state = _sealed_primary_state()
    state.scenario = Scenario.CODE_AUDIT
    state.audit_coverage["evidence_gap_compiler"] = {"gap_codes": []}
    try:
        assert (
            orchestrator._scenario_route(  # noqa: SLF001
                {"agent": state.model_dump(mode="json")}
            )
            == "complete"
        )
        state.audit_coverage["direct_anchor_pipeline"] = True
        assert (
            orchestrator._scenario_route(  # noqa: SLF001
                {"agent": state.model_dump(mode="json")}
            )
            == "code"
        )
        state.audit_coverage["evidence_gap_compiler"] = {"gap_codes": ["source_sink_trace_missing"]}
        assert (
            orchestrator._scenario_route(  # noqa: SLF001
                {"agent": state.model_dump(mode="json")}
            )
            == "code"
        )
    finally:
        broker.close()
        ledger.close()


def test_model_only_high_primary_keeps_finding_but_cannot_claim_complete_assurance() -> None:
    state = _sealed_primary_state()
    graph = EvidenceGraph(claims=state.claims, evidence=state.evidence, links=state.evidence_links)
    evidence_graph = SecMindOrchestrator._investigation_evidence_graph(state, graph)  # noqa: SLF001

    obligations = SecMindOrchestrator._requirement_obligations(  # noqa: SLF001
        object.__new__(SecMindOrchestrator), state, evidence_graph
    )

    assert [item.finding_id for item in state.published_baseline.findings] == ["primary-finding"]
    assert SecMindOrchestrator._verified_direct_first_finding_ids(state) == set()  # noqa: SLF001
    high_risk = next(item for item in obligations if item.source_type == "high_risk_finding")
    assert high_risk.status == ObligationStatus.UNVERIFIED


async def test_scenario_exception_preserves_sealed_primary(settings) -> None:
    orchestrator, ledger, broker = _orchestrator(settings)
    state = _sealed_primary_state()

    class BrokenScenarioCompiler:
        def compile(self, _request):
            raise LogAnalysisError("EVTX parser is unavailable")

    orchestrator.scenario_compiler = BrokenScenarioCompiler()  # type: ignore[assignment]
    try:
        output = await orchestrator._execute_scenario(  # noqa: SLF001
            {"agent": state.model_dump(mode="json")}
        )
        result = AgentState.model_validate(output["agent"])
    finally:
        broker.close()
        ledger.close()

    assert result.status == RunStatus.COMPLETED
    assert result.report is not None
    assert [item.finding_id for item in result.report.findings] == ["primary-finding"]
    assert result.audit_coverage["primary_preserved"] is True
    assert any("LogAnalysisError" in item for item in result.report.limitations)
    assert result.audit_coverage["scenario_projection"]["status"] == "partial"


async def test_reporter_uses_sealed_primary_not_mutable_report(settings) -> None:
    orchestrator, ledger, broker = _orchestrator(settings)
    state = _sealed_primary_state()
    state.status = RunStatus.PARTIAL
    state.report = AgentReport(
        run_id=state.run_id,
        status=RunStatus.PARTIAL,
        executive_summary="Empty mutable report",
    )
    try:
        output = await orchestrator._report({"agent": state.model_dump(mode="json")})  # noqa: SLF001
        result = AgentState.model_validate(output["agent"])
    finally:
        broker.close()
        ledger.close()

    assert result.report is not None
    assert [item.finding_id for item in result.report.findings] == ["primary-finding"]
    assert result.audit_coverage["primary_preserved"] is True
