from __future__ import annotations

from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from secmind.admission import AdmissionService
from secmind.direct_anchor_pipeline import (
    AnchorReport,
    CandidateState,
    CandidateStore,
    DeltaAction,
    DeltaAdjudicator,
    DeltaDisposition,
    build_anchor_report,
)
from secmind.evidence_graph import make_claim
from secmind.orchestrator import SecMindOrchestrator
from secmind.schemas import AgentReport, AgentState, ClaimStatus, Evidence, Finding, RunStatus, Scenario, TaskRequest
from secmind.tool_assurance import build_tool_assurance
from secmind.tool_gain_gate import ToolGainGate

_ASSURANCE_SIGNING_KEY = Ed25519PrivateKey.generate()


@pytest.fixture(autouse=True)
def _tool_assurance_trust_root(tmp_path, monkeypatch):
    public_key_path = tmp_path / "tool-assurance-public.pem"
    public_key_path.write_bytes(
        _ASSURANCE_SIGNING_KEY.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    monkeypatch.setenv("SECMIND_TOOL_ASSURANCE_PUBLIC_KEY_FILE", str(public_key_path))


def _finding(
    finding_id: str,
    *,
    line: int,
    tool: str,
    assurance: str = "semantically_corroborated",
    complete: bool = True,
) -> Finding:
    digest = "a" * 64
    rule_digest = "b" * 64
    return Finding(
        finding_id=finding_id,
        rule_id="CWE-89",
        severity="HIGH",
        confidence="HIGH",
        path="src/app.py",
        line=line,
        title="unsafe query",
        description="user input reaches a query sink",
        evidence_ids=[f"ev-{finding_id}"],
        raw={
            "tool_name": tool,
            "assurance_level": assurance,
            "sink": "cursor.execute",
            "data_flow": "request.args -> cursor.execute",
            **({"file_sha256": digest, "rule_bundle_digest": rule_digest} if complete else {}),
        },
    )


def _evidence(finding_id: str, tool: str, *, complete: bool = True, signed: bool = False) -> Evidence:
    digest = "a" * 64
    metadata = {
        "tool_name": tool,
        "tool_version": "1",
        "assurance_level": "semantically_corroborated",
        "sink": "cursor.execute",
        "data_flow": "request.args -> cursor.execute",
        **({"file_sha256": digest, "rule_bundle_digest": "b" * 64} if complete else {}),
    }
    if signed:
        metadata["tool_assurance"] = build_tool_assurance(
            tool_name=tool,
            tool_version="1",
            input_manifest_digest="c" * 64,
            finding_fingerprint="d" * 64,
            rule_bundle_digest="b" * 64,
            signing_key=_ASSURANCE_SIGNING_KEY,
        ).model_dump(mode="json")
        metadata["record_fingerprint"] = "d" * 64
    return Evidence(
        evidence_id=f"ev-{finding_id}",
        source=tool,
        summary="semantic tool trace",
        sha256=digest if complete else None,
        metadata=metadata,
    )


def _bind_evidence(state: AgentState, evidence: list[Evidence], artifact_store) -> None:
    """Persist fixture evidence in the same CAS admission rehash will read."""

    for item in evidence:
        stored = artifact_store.put(
            f"{state.run_id}:{item.evidence_id}".encode(),
            run_id=state.run_id,
            media_type="application/vnd.secmind.test-evidence",
        )
        item.artifact_ref = stored.artifact_id
        item.sha256 = stored.sha256


def _state() -> AgentState:
    return AgentState(
        run_id="anchor-run",
        task=TaskRequest(objective="Audit source", autonomy_policy="automatic"),
        scenario=Scenario.CODE_AUDIT,
        status=RunStatus.RUNNING,
        audit_coverage={"direct_anchor_pipeline": True},
    )


def test_different_tools_same_sink_correlate_before_admission() -> None:
    state = _state()
    findings = [
        _finding("a", line=10, tool="tool-a"),
        _finding("b", line=13, tool="tool-b"),
    ]
    evidence = {item.evidence_ids[0]: _evidence(item.finding_id, item.raw["tool_name"]) for item in findings}
    store = CandidateStore(state.run_id)
    for finding in findings:
        store.register(finding, evidence)
    clusters = store.correlate()

    assert len(clusters) == 1
    assert set(clusters[0].producer_ids) == {"tool-a", "tool-b"}
    assert clusters[0].key.sink == "cursor.execute"
    assert clusters[0].key.line_window == (10, 13)

    deltas = DeltaAdjudicator().adjudicate(
        run_id=state.run_id,
        clusters=clusters,
        anchor_findings=(),
        evidence_by_id=evidence,
        primary_degraded=True,
        anchor_semantic_digest="c" * 64,
    )
    assert deltas[0].disposition == DeltaDisposition.ACCEPTED
    assert deltas[0].admission_ready is True


def test_independent_deterministic_cluster_rescues_degraded_primary_through_terminal_admission(
    admission_stores,
) -> None:
    state = _state()
    artifact_store, capsule_store = admission_stores
    state.audit_coverage.update(
        {
            "canonical_primary_attempted": True,
            "canonical_primary_completed": False,
            "canonical_primary_status": "degraded",
        }
    )
    findings = [
        _finding("det-a", line=10, tool="semgrep_sast", assurance="deterministic_candidate"),
        _finding("det-b", line=12, tool="python_taint_audit", assurance="deterministic_candidate"),
    ]
    evidence = [_evidence(item.finding_id, str(item.raw["tool_name"]), signed=True) for item in findings]
    for item in findings:
        item.raw.pop("sink")
        item.raw.pop("data_flow")
    for item in evidence:
        item.metadata["assurance_level"] = "deterministic_candidate"
        item.metadata.pop("sink")
        item.metadata["data_flow"] = ["source:request.POST.get", "sink:eval"]
    _bind_evidence(state, evidence, artifact_store)
    state.findings = findings
    state.evidence = evidence
    state.report = AgentReport(
        run_id=state.run_id,
        status=RunStatus.PARTIAL,
        executive_summary="Primary degraded; deterministic candidates retained.",
        findings=findings,
        evidence=evidence,
    )

    summary = ToolGainGate.apply(state)
    snapshot = AdmissionService.seal(
        state,
        state.report,
        artifact_store=artifact_store,
        capsule_store=capsule_store,
    )

    assert summary.accepted_new == 1
    assert state.audit_coverage["typed_deltas"][0]["reason_code"] == ("correlated_independent_degraded_rescue")
    assert len(snapshot.admitted_finding_ids) == 1
    assert snapshot.report.coverage["accepted_delta_count"] == 1


def test_cluster_prefers_semantic_tool_over_lexically_first_scout() -> None:
    state = _state()
    scout = _finding(
        "a-scout",
        line=10,
        tool="independent-primary-scout-v1",
        assurance="deterministic_candidate",
    )
    semantic = _finding("z-semantic", line=11, tool="python_taint_audit")
    evidence = {
        scout.evidence_ids[0]: _evidence("a-scout", "independent-primary-scout-v1"),
        semantic.evidence_ids[0]: _evidence("z-semantic", "python_taint_audit"),
    }
    evidence[scout.evidence_ids[0]].metadata["assurance_level"] = "deterministic_candidate"
    store = CandidateStore(state.run_id)
    store.register(scout, evidence)
    store.register(semantic, evidence)

    cluster = store.correlate()[0]
    delta = DeltaAdjudicator().adjudicate(
        run_id=state.run_id,
        clusters=(cluster,),
        anchor_findings=(),
        evidence_by_id=evidence,
        primary_degraded=False,
        anchor_semantic_digest="c" * 64,
    )[0]

    assert cluster.representative.finding_id == "z-semantic"
    assert set(delta.producer_ids) == {"independent-primary-scout-v1", "python_taint_audit"}
    assert delta.disposition == DeltaDisposition.ACCEPTED
    assert delta.admission_ready is True


@pytest.mark.parametrize("related_rule", ["CWE-602", "CWE-693"])
def test_taxonomy_correction_ignores_unrelated_same_line_anchor(related_rule: str) -> None:
    state = _state()
    candidate = _finding("workflow", line=37, tool="web_workflow_audit").model_copy(
        update={"rule_id": "CWE-840", "path": "subject.php"},
        deep=True,
    )
    evidence = _evidence("workflow", "web_workflow_audit")
    store = CandidateStore(state.run_id)
    store.register(candidate, {evidence.evidence_id: evidence})
    unrelated = _finding("a-unrelated", line=37, tool="primary").model_copy(
        update={"rule_id": "CWE-352", "path": "subject.php", "raw": {"canonical_primary": True}},
        deep=True,
    )
    related = _finding("z-related", line=37, tool="primary").model_copy(
        update={"rule_id": related_rule, "path": "subject.php", "raw": {"canonical_primary": True}},
        deep=True,
    )

    delta = DeltaAdjudicator().adjudicate(
        run_id=state.run_id,
        clusters=store.correlate(),
        anchor_findings=(unrelated, related),
        evidence_by_id={evidence.evidence_id: evidence},
        primary_degraded=False,
        anchor_semantic_digest="c" * 64,
    )[0]

    assert delta.action == DeltaAction.CORRECT
    assert delta.target_finding_id == related.finding_id


def test_verified_deterministic_scenario_finding_uses_typed_delta_admission(admission_stores) -> None:
    state = _state()
    artifact_store, capsule_store = admission_stores
    state.scenario = Scenario.LOG_ANALYSIS
    response = artifact_store.put(b"primary response", run_id=state.run_id, media_type="application/json")
    AdmissionService.admit_baseline(
        state,
        artifact_store=artifact_store,
        capsule_store=capsule_store,
        model_id="deepseek-v4-flash",
        prompt_version="v083",
        prompt_artifact_id=None,
        request_sha256="1" * 64,
        response_sha256=response.sha256,
        response_schema_sha256="3" * 64,
        context_sha256="4" * 64,
        response_artifact_id=response.artifact_id,
        provider_requests=1,
        input_tokens=10,
        output_tokens=10,
        cost_units=0,
        status=RunStatus.COMPLETED,
        executive_summary="Primary completed.",
        findings=[],
        evidence=[],
        decisions=[],
        limitations=[],
        coverage=state.audit_coverage,
    )
    finding = _finding("scenario", line=7, tool="deterministic-scenario-analyzer")
    evidence = _evidence("scenario", "deterministic-scenario-analyzer")
    claim = make_claim(
        claim_type="suspicious_event",
        statement="A deterministic rule matched immutable log evidence.",
        subject_ref=finding.finding_id,
        producer="deterministic-scenario-analyzer",
        confidence=0.9,
    ).model_copy(update={"status": ClaimStatus.VERIFIED})
    state.findings = [finding]
    state.evidence = [evidence]
    _bind_evidence(state, state.evidence, artifact_store)
    state.claims = [claim]
    state.status = RunStatus.COMPLETED
    state.report = AgentReport(
        run_id=state.run_id,
        status=RunStatus.COMPLETED,
        executive_summary="Scenario completed.",
        findings=[finding],
        evidence=[evidence],
    )

    SecMindOrchestrator._register_verified_scenario_deltas(state)  # noqa: SLF001
    snapshot = AdmissionService.seal(
        state,
        state.report,
        artifact_store=artifact_store,
        capsule_store=capsule_store,
    )

    assert snapshot.admitted_finding_ids == [finding.finding_id]
    assert state.audit_coverage["typed_deltas"][0]["reason_code"] == "deterministic_scenario_verified"
    assert snapshot.report.coverage["accepted_delta_count"] == 1
    assert snapshot.report.coverage["admitted_new_finding_count"] == 1


def test_single_high_specificity_candidate_rescues_degraded_primary() -> None:
    state = _state()
    finding = _finding("rescue", line=22, tool="semantic-sast")
    evidence = {finding.evidence_ids[0]: _evidence("rescue", "semantic-sast")}
    store = CandidateStore(state.run_id)
    store.register(finding, evidence)
    clusters = store.correlate()
    delta = DeltaAdjudicator().adjudicate(
        run_id=state.run_id,
        clusters=clusters,
        anchor_findings=(),
        evidence_by_id=evidence,
        primary_degraded=True,
        anchor_semantic_digest="d" * 64,
    )[0]

    assert len(clusters[0].producer_ids) == 1
    assert delta.reason_code == "single_producer_high_specificity_degraded_rescue"
    assert delta.admission_ready is True


def test_quarantine_is_replayable_and_anchor_bytes_are_unchanged() -> None:
    state = _state()
    candidate = _finding("noise", line=8, tool="noisy-scan", assurance="integrity_verified", complete=False)
    evidence = {candidate.evidence_ids[0]: _evidence("noise", "noisy-scan", complete=False)}
    store = CandidateStore(state.run_id)
    record = store.register(candidate, evidence)
    store.transition(record.candidate_id, CandidateState.QUARANTINED, "insufficient_independent_specificity")
    store.persist(state)

    replayed = CandidateStore.from_state(state)
    assert [item.finding.finding_id for item in replayed.replay()] == ["noise"]
    assert replayed.replay()[0].state == CandidateState.QUARANTINED
    assert any(item.get("event") == "transition" for item in replayed.events())

    anchor = build_anchor_report(
        run_id=state.run_id,
        receipt_id="receipt-1",
        request_sha256="1" * 64,
        response_sha256="2" * 64,
        response_schema_sha256="3" * 64,
        prompt_version="fixed-v1",
        prompt_artifact_id=None,
        context_sha256="4" * 64,
        response_artifact_id="5" * 64,
        findings=(),
        evidence=(),
        limitations=(),
        coverage={},
    )
    before = anchor.model_dump(mode="json")
    assert isinstance(anchor, AnchorReport)
    with pytest.raises((TypeError, ValueError)):
        anchor.response_sha256 = "f" * 64  # type: ignore[misc]
    assert anchor.model_dump(mode="json") == before


def test_direct_gain_and_admission_share_one_typed_delta_condition(admission_stores) -> None:
    state = _state()
    artifact_store, capsule_store = admission_stores
    state.audit_coverage.update(
        {
            "canonical_primary_attempted": True,
            "canonical_primary_completed": False,
        }
    )
    candidate = _finding("admit", line=31, tool="python_taint_audit")
    evidence = _evidence("admit", "python_taint_audit", signed=True)
    state.findings = [candidate]
    state.evidence = [evidence]
    _bind_evidence(state, state.evidence, artifact_store)
    state.report = AgentReport(
        run_id=state.run_id,
        status=state.status,
        executive_summary="degraded primary",
        findings=[candidate],
        evidence=[evidence],
    )

    summary = ToolGainGate.apply(state)
    assert summary.accepted_new == 1
    snapshot = AdmissionService.seal(
        state,
        state.report,
        artifact_store=artifact_store,
        capsule_store=capsule_store,
    )

    assert [item.finding_id for item in snapshot.report.findings] == ["admit"]
    assert snapshot.report.coverage["admission_authority"] == "unified-direct-delta"
    assert snapshot.report.coverage["primary_preserved"] is False


@pytest.mark.asyncio
async def test_orchestrator_direct_path_runs_correlation_before_gain_gate(admission_stores) -> None:
    events: list[str] = []

    class Analyst:
        async def run(self, state: AgentState) -> AgentState:
            events.append("correlation")
            return state

    class Admission:
        def adjudicate_deltas(self, state: AgentState, **_stores) -> None:
            del state
            events.append("gain_gate")

    class Critic:
        async def run(self, state: AgentState) -> AgentState:
            events.append("critic")
            return state

    class Verifier:
        async def run(self, state: AgentState) -> AgentState:
            events.append("verifier")
            return state

    orchestrator = object.__new__(SecMindOrchestrator)
    orchestrator.analyst = Analyst()  # type: ignore[assignment]
    orchestrator.admission_service = Admission()  # type: ignore[assignment]
    orchestrator.delta_critic = Critic()  # type: ignore[assignment]
    orchestrator.delta_verifier = Verifier()  # type: ignore[assignment]
    orchestrator.investigation_store = None  # type: ignore[assignment]
    orchestrator.artifact_store, orchestrator.capsule_store = admission_stores
    orchestrator._active_authority = SimpleNamespace(get=lambda: None)  # type: ignore[assignment]

    async def checkpoint(state: AgentState, _event_type: str, _payload: dict[str, object]) -> dict[str, object]:
        return {"agent": state.model_dump(mode="json")}

    orchestrator._checkpoint = checkpoint  # type: ignore[method-assign]
    await orchestrator._correlate({"agent": _state().model_dump(mode="json")})  # noqa: SLF001

    assert events == ["correlation", "gain_gate", "critic", "verifier"]
