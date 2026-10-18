from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace
from typing import Any

import pytest

import secmind.orchestration.correlation_runtime as correlation_runtime
import secmind.orchestration.eirs_runtime as eirs_runtime
import secmind.orchestration.primary_runtime as primary_runtime
import secmind.orchestration.report_runtime as report_runtime
from secmind.artifact_store import ContentAddressedArtifactStore
from secmind.canonical_primary import CanonicalProjection
from secmind.context_manager import ContextItemStore
from secmind.direct_anchor_pipeline import DeltaDisposition
from secmind.domain_answers import EvidenceGapAnswer, ExactAnswer, TimelineAnswer
from secmind.evidence_graph import make_claim, make_link
from secmind.gap_plan import (
    GapAction,
    GapActionBudget,
    GapActionKind,
    GapDomain,
    GapPlan,
)
from secmind.investigation.contracts import EvidenceRequest
from secmind.orchestration.evidence_integrity import bind_canonical_baseline_claims
from secmind.schemas import (
    AgentReport,
    AgentState,
    AuditUnitResult,
    BudgetState,
    ClaimStatus,
    ContextTaint,
    Evidence,
    Finding,
    InputArtifact,
    InstructionLayer,
    ModelUsage,
    PlanStep,
    PublishedBaselineProjection,
    RiskLevel,
    RunStatus,
    Scenario,
    StepRuntime,
    StepStatus,
    TaskRequest,
    ToolHealth,
    ToolManifest,
    ToolResult,
    ToolStatus,
)
from secmind.task_contract import BeliefState, EvidenceCompilerReceipt, EvidenceFact


def _state(*, run_id: str = "runtime-coverage", scenario: Scenario = Scenario.CODE_AUDIT) -> AgentState:
    return AgentState(
        run_id=run_id,
        task=TaskRequest(objective="exercise bounded runtime branches"),
        scenario=scenario,
    )


def _timeline_answer(*, execution_status: str = "success") -> TimelineAnswer:
    return TimelineAnswer(
        task_id="runtime-coverage",
        execution_status=execution_status,
        epistemic_status="conclusive" if execution_status == "success" else "insufficient_evidence",
        executive_summary="provider summary",
        events=[{"event_id": "model-event", "timestamp": "2026-01-01T00:00:00Z", "event_type": "model"}],
        facts=[{"fact_id": "model-fact"}],
    )


def _exact_answer() -> ExactAnswer:
    return ExactAnswer(
        task_id="runtime-coverage",
        execution_status="success",
        epistemic_status="conclusive",
        values="provider-value",
        items=[{"item_id": "model-item"}],
        mapping={"model": "value"},
        derivation=["provider-derivation"],
        source_offsets=[{"start": 1}],
        validation={"provider": True},
    )


def _evidence_gap_answer() -> EvidenceGapAnswer:
    return EvidenceGapAnswer(
        task_id="runtime-coverage",
        execution_status="success",
        epistemic_status="conclusive",
        observations=[{"observation_id": "model-observation"}],
        known=["model-known"],
        unknown_fields=["model-unknown"],
        conflicts=[{"hypothesis_id": "model-conflict", "statement": "provider hypothesis"}],
        blocked_claims=[{"claim_id": "model-blocked"}],
        next_evidence=[{"request": "model-request"}],
    )


def test_primary_fusion_preserves_deterministic_timeline_extensions_and_status() -> None:
    state = _state(scenario=Scenario.LOG_ANALYSIS)
    state.audit_coverage["pre_primary_scenario_projection"] = {
        "scenario": "log_analysis",
        "answer_payload": {
            "answer_kind": "timeline",
            "events": [{"event_id": "parser-event", "timestamp": "2026-01-01", "event_type": "parser"}],
            "facts": [{"fact_id": "shared"}, {"fact_id": "parser-fact"}],
            "inferences": [{"inference": "parser"}],
            "actors": [{"actor_id": "parser-actor", "name": "Parser"}],
            "iocs": [{"ioc": "parser-ioc"}],
            "techniques": [{"technique": "T1001"}],
            "gaps": [{"gap": "parser-gap"}],
            "extensions": {
                "coverage": {"parser": True},
                "policy_actions": [
                    {"action_id": "parser-action", "subject_ref": "incident", "rollback_condition": "x"}
                ],
                "provider_notes": ["parser-note"],
                "merge_me": {"parser": 1},
            },
            "execution_status": "partial",
            "limitations": ["parser-limited"],
        },
    }
    fused = primary_runtime.fuse_pre_primary_scenario_answer(state, _timeline_answer())
    assert isinstance(fused, TimelineAnswer)
    assert [item["event_id"] for item in fused.events] == ["parser-event"]
    assert {item.get("fact_id") for item in fused.facts} == {"shared", "parser-fact", "model-fact"}
    assert fused.extensions["coverage"] == {"parser": True}
    assert fused.extensions["provider_notes"] == ["parser-note"]
    assert fused.extensions["merge_me"] == {"parser": 1}
    assert fused.execution_status == "partial"
    assert fused.epistemic_status == "insufficient_evidence"
    assert "parser-limited" in fused.limitations
    assert state.audit_coverage["domain_answer_fusion"]["deterministic_fields_preserved"] is True


def test_primary_fusion_exact_and_gap_branches_merge_rows_and_mappings() -> None:
    exact_state = _state()
    exact_state.audit_coverage["pre_primary_scenario_projection"] = {
        "answer_payload": {
            "answer_kind": "exact",
            "values": {"parser": 1},
            "items": [{"item_id": "parser-item"}],
            "source_offsets": [{"start": 0}],
            "derivation": ["parser-derivation"],
            "mapping": {"parser": "value"},
            "validation": {"parser": True},
            "extensions": {"coverage": {"exact": True}},
        }
    }
    fused_exact = primary_runtime.fuse_pre_primary_scenario_answer(exact_state, _exact_answer())
    assert isinstance(fused_exact, ExactAnswer)
    assert fused_exact.values == {"parser": 1}
    assert fused_exact.mapping["parser"] == "value"
    assert fused_exact.items[0]["item_id"] == "parser-item"
    assert fused_exact.extensions["coverage"] == {"exact": True}

    gap_state = _state()
    gap_state.audit_coverage["pre_primary_scenario_projection"] = {
        "answer_payload": {
            "answer_kind": "evidence_gap",
            "observations": [{"id": "parser-observation"}],
            "known": ["parser-known"],
            "unknown_fields": ["parser-unknown"],
            "conflicts": [{"hypothesis_id": "parser-conflict", "statement": "parser conflict"}],
            "blocked_claims": [{"id": "parser-blocked"}],
            "next_evidence": [{"id": "parser-request"}],
            "extensions": {"coverage": {"gap": True}},
        }
    }
    fused_gap = primary_runtime.fuse_pre_primary_scenario_answer(gap_state, _evidence_gap_answer())
    assert isinstance(fused_gap, EvidenceGapAnswer)
    assert fused_gap.observations[0]["id"] == "parser-observation"
    assert fused_gap.unknown_fields[0] == "parser-unknown"
    assert fused_gap.extensions["coverage"] == {"gap": True}

    mismatch = _state()
    mismatch.audit_coverage["pre_primary_scenario_projection"] = {"answer_payload": {"answer_kind": "exact"}}
    original = _timeline_answer()
    assert primary_runtime.fuse_pre_primary_scenario_answer(mismatch, original) is original


def test_primary_fusion_duplicate_caps_and_advisory_reference_errors() -> None:
    state = _state()
    state.audit_coverage["pre_primary_scenario_projection"] = {
        "answer_payload": {
            "answer_kind": "exact",
            "items": [{"item_id": str(index)} for index in range(1000)],
            "source_offsets": [],
            "extensions": {"provider_notes": ["parser-note"], "merge_me": {"parser": 1}},
        }
    }
    answer = _exact_answer().model_copy(
        update={
            "extensions": {"provider_notes": ["parser-note", "model-note"], "merge_me": {"model": 2}},
            "items": [{"item_id": "0"}],
        }
    )
    fused = primary_runtime.fuse_pre_primary_scenario_answer(state, answer)
    assert len(fused.items) == 1000
    assert fused.items[0]["item_id"] == "0"
    assert fused.extensions["provider_notes"] == ["parser-note", "model-note"]
    assert fused.extensions["merge_me"] == {"model": 2, "parser": 1}

    malformed = _state()
    malformed.audit_coverage["pre_primary_scenario_projection"] = {"answer_payload": "not-a-dict"}
    original = _exact_answer()
    assert primary_runtime.fuse_pre_primary_scenario_answer(malformed, original) is original

    class FakeAnswer:
        def model_dump(self, mode: str = "json") -> dict[str, Any]:
            del mode
            return {"answer_kind": "timeline", "events": [], "extensions": "invalid"}

        @classmethod
        def model_validate(cls, payload: dict[str, Any]) -> dict[str, Any]:
            return payload

    invalid_extensions = _state()
    invalid_extensions.audit_coverage["pre_primary_scenario_projection"] = {
        "answer_payload": {
            "answer_kind": "timeline",
            "extensions": "invalid",
            "timeline_graph": {"graph": "deterministic"},
        }
    }
    assert (
        primary_runtime.fuse_pre_primary_scenario_answer(invalid_extensions, FakeAnswer())["answer_kind"] == "timeline"
    )

    class UnsupportedAnswer(FakeAnswer):
        def model_dump(self, mode: str = "json") -> dict[str, Any]:
            del mode
            return {"answer_kind": "unsupported", "extensions": {}}

    unsupported = _state()
    unsupported.audit_coverage["pre_primary_scenario_projection"] = {"answer_payload": {"answer_kind": "unsupported"}}
    original_unsupported = UnsupportedAnswer()
    assert primary_runtime.fuse_pre_primary_scenario_answer(unsupported, original_unsupported) is original_unsupported


def test_primary_advisory_context_reads_and_skips_bad_references() -> None:
    state = _state(run_id="advisory-reference-run")
    state.context_items = [
        SimpleNamespace(
            context_id="bad",
            kind="audit_skill",
            source="bad",
        ),
        SimpleNamespace(
            context_id="good",
            kind="knowledge",
            source="good",
            authority_level=InstructionLayer.RETRIEVED_KNOWLEDGE,
            taint=ContextTaint.UNTRUSTED,
            content_hash="a" * 64,
        ),
        SimpleNamespace(context_id="empty", kind="knowledge", source="empty"),
    ]

    class Store:
        def read_text(self, reference: Any, *, run_id: str) -> str:
            assert run_id == state.run_id
            if reference.context_id == "bad":
                raise ValueError("missing context")
            if reference.context_id == "empty":
                return ""
            return "knowledge bytes"

    selected = primary_runtime.primary_advisory_context(
        SimpleNamespace(settings=SimpleNamespace(primary_advisory_context_bytes=8192), context_item_store=Store()),
        state,
    )
    assert [item["context_id"] for item in selected] == ["good"]
    assert selected[0]["truncated"] is False


def test_primary_advisory_context_is_bounded_and_accounts_provider_usage(tmp_path) -> None:
    state = _state(run_id="advisory-run")
    cas = ContentAddressedArtifactStore(tmp_path / "cas")
    store = ContextItemStore(cas)
    skill = store.add_text(
        run_id=state.run_id,
        kind="audit_skill",
        source="skill-a",
        authority_level=InstructionLayer.SELECTED_SKILL,
        taint=ContextTaint.ADVISORY,
        content="skill context",
    )
    knowledge = store.add_text(
        run_id=state.run_id,
        kind="knowledge",
        source="knowledge-a",
        authority_level=InstructionLayer.RETRIEVED_KNOWLEDGE,
        taint=ContextTaint.UNTRUSTED,
        content="knowledge context",
    )
    state.context_items = [knowledge, skill]
    state.evidence_compiler_receipt = EvidenceCompilerReceipt(
        run_id=state.run_id,
        contract_digest="a" * 64,
        input_manifest_digest="b" * 64,
        facts=[
            EvidenceFact(
                fact_id="fact-1",
                fact_type="line",
                value="x",
                source_ref="fixture.py",
                source_sha256="c" * 64,
            )
        ],
        output_digest="d" * 64,
    )
    host = SimpleNamespace(
        settings=SimpleNamespace(primary_advisory_context_bytes=120),
        context_item_store=store,
    )
    selected = primary_runtime.primary_advisory_context(host, state)
    assert selected
    assert selected[0]["kind"] == "compiled_evidence"
    assert state.audit_coverage["primary_advisory_context"]["bytes"] <= 120

    class Gateway:
        def provider_attempts_for(self, _run_id: str) -> list[Any]:
            return [
                SimpleNamespace(
                    usage=ModelUsage(
                        input_tokens=4,
                        output_tokens=3,
                        cache_hit_input_tokens=2,
                        cache_miss_input_tokens=2,
                        cost_units=0.5,
                    )
                ),
                SimpleNamespace(
                    usage=ModelUsage(
                        input_tokens=1,
                        output_tokens=2,
                        cache_hit_input_tokens=0,
                        cache_miss_input_tokens=1,
                        cost_units=0.25,
                    )
                ),
            ]

    count = primary_runtime.account_failed_primary_attempts(SimpleNamespace(gateway=Gateway()), state)
    assert count == 2
    assert state.budget.usage.provider_requests == 2
    assert state.budget.usage.input_tokens == 5
    assert state.budget.usage.output_tokens == 5
    assert state.budget.usage.cost_units == pytest.approx(0.75)


def _evidence(evidence_id: str, *, metadata: dict[str, Any] | None = None) -> Evidence:
    return Evidence(evidence_id=evidence_id, source="tool:test", summary=evidence_id, metadata=metadata or {})


def _finding(finding_id: str, evidence_ids: list[str], *, path: str = "fixture.py") -> Finding:
    return Finding(
        finding_id=finding_id,
        rule_id="CWE-89",
        severity="HIGH",
        confidence="HIGH",
        path=path,
        line=1,
        title=finding_id,
        description="bounded finding",
        evidence_ids=evidence_ids,
        raw={"model_id": "model"},
    )


def test_correlation_supplement_and_latest_request_are_location_bound() -> None:
    state = _state(run_id="correlation-run")
    target_claim = make_claim(
        claim_type="finding",
        statement="target",
        subject_ref="finding-original",
        producer="model-source-review",
        confidence=0.9,
    )
    state.findings = [_finding("finding-original", ["original-evidence"])]
    state.claims = [target_claim]
    state.evidence = [_evidence("supplement-evidence"), _evidence("other-evidence")]
    state.active_evidence_request_ids = ["request-1"]

    def _request(version: int, target: str = target_claim.claim_id) -> dict[str, Any]:
        return EvidenceRequest(
            request_id="request-1",
            run_id=state.run_id,
            target_claim_id=target,
            reason_code="verify",
            requested_evidence_types=["finding"],
            immutable_scope=["fixture.py"],
            allowed_capabilities=["sast"],
            success_criteria=["same location"],
            dedupe_key="request-dedupe",
            request_version=version,
            content_digest="a" * 64,
        ).model_dump(mode="json")

    class Store:
        def list_objects(self, _run_id: str, _kind: str) -> list[dict[str, Any]]:
            return [_request(1), _request(2), _request(1, target="missing")]

    host = SimpleNamespace(investigation_store=Store())
    latest = correlation_runtime.latest_evidence_requests(host, state)
    assert latest["request-1"].request_version == 2

    supplement_finding = _finding("supplement", ["supplement-evidence"])
    unrelated = _finding("unrelated", ["supplement-evidence"], path="other.py")
    state.observations = [
        SimpleNamespace(
            data={"findings": [supplement_finding.model_dump(mode="json"), unrelated.model_dump(mode="json"), "bad"]},
            evidence=[_evidence("supplement-evidence")],
            status="observed",
        )
    ]
    state.step_runtime = {
        "supplement-one": StepRuntime(
            step_id="supplement-one",
            status=StepStatus.SUCCEEDED,
            observation_indexes=[0],
        ),
        "ordinary": StepRuntime(step_id="ordinary", status=StepStatus.SUCCEEDED, observation_indexes=[0]),
    }
    links = correlation_runtime.supplement_evidence_links(
        host, state, [target_claim], {item.evidence_id: item for item in state.evidence}
    )
    assert len(links) == 1
    assert links[0].claim_id == target_claim.claim_id
    assert links[0].evidence_id == "supplement-evidence"


@pytest.mark.asyncio
async def test_correlate_builds_claims_links_and_coverage_evidence() -> None:
    state = _state(run_id="correlate-run")
    evidence = _evidence("finding-evidence")
    coverage = _evidence(
        "coverage-evidence",
        metadata={"step_id": "sast-step", "evidence_type": "execution_coverage"},
    )
    negative = _evidence(
        "negative-evidence",
        metadata={"evidence_type": "canonical_primary_negative_coverage", "path": "clean.py"},
    )
    state.evidence = [evidence, coverage, negative]
    state.findings = [_finding("finding-1", [evidence.evidence_id])]
    state.plan = [
        PlanStep(
            step_id="sast-step",
            objective="run SAST",
            agent_role="worker",
            capability="sast",
            tool_candidates=["sast"],
        )
    ]
    state.step_runtime = {"sast-step": StepRuntime(step_id="sast-step", status=StepStatus.SUCCEEDED)}

    class Stage:
        async def run(self, current: AgentState) -> AgentState:
            return current

    async def checkpoint(current: AgentState, *_args: Any, **_kwargs: Any) -> dict[str, Any]:
        return {"agent": current.model_dump(mode="json")}

    host = SimpleNamespace(
        _state=lambda value: AgentState.model_validate(value),
        analyst=Stage(),
        delta_critic=Stage(),
        delta_verifier=Stage(),
        _adjudicate_deltas=lambda *_args: True,
        investigation_store=None,
        _checkpoint=checkpoint,
    )
    result = await correlation_runtime.correlate(host, state.model_dump(mode="json"))
    correlated = AgentState.model_validate(result["agent"])
    assert any(item.subject_ref == "finding-1" for item in correlated.claims)
    assert any(item.claim_type == "code_audit.negative_coverage" for item in correlated.claims)
    assert any(item.claim_type == "sast.coverage" for item in correlated.claims)
    assert correlated.evidence_links


@pytest.mark.asyncio
async def test_correlate_direct_anchor_and_audit_units_cover_producer_lineage() -> None:
    state = _state(run_id="correlate-direct-anchor")
    state.audit_coverage["direct_anchor_pipeline"] = True
    evidence = _evidence("lineage-evidence")
    observation = ToolResult(
        status=ToolStatus.SUCCESS,
        summary="lineage",
        evidence=[evidence],
    )
    state.observations = [observation]
    state.step_runtime = {
        "worker-step": StepRuntime(
            step_id="worker-step",
            status=StepStatus.SUCCEEDED,
            observation_indexes=[0, 4],
        )
    }
    state.plan = [
        PlanStep(
            step_id="worker-step",
            objective="lineage check",
            agent_role="worker",
            capability="sast",
        ),
        PlanStep(
            step_id="missing-runtime",
            objective="missing runtime",
            agent_role="worker",
            capability="sast",
        ),
    ]
    state.evidence = [evidence]
    state.findings = [
        _finding("lineage-finding", [evidence.evidence_id], path="fixture.py").model_copy(update={"raw": {}})
    ]
    canonical = make_claim(
        claim_type="canonical",
        statement="canonical",
        subject_ref="canonical-subject",
        producer="canonical-primary",
        confidence=1,
    )
    state.claims = [canonical]
    state.evidence_links = [make_link(claim_id=canonical.claim_id, evidence_id=evidence.evidence_id)]
    state.audit_units = [
        AuditUnitResult(
            unit_id="unit-" + "a" * 64,
            path="fixture.py",
            source_sha256="b" * 64,
            baseline_verdict="not_vulnerable",
            final_verdict="not_vulnerable",
            action="keep_baseline",
            confidence=0.8,
            primary_receipt_id="receipt",
            decision_digest="c" * 64,
            evidence_ids=[evidence.evidence_id],
        ),
        AuditUnitResult(
            unit_id="unit-" + "d" * 64,
            path="inconclusive.py",
            source_sha256="e" * 64,
            baseline_verdict="inconclusive",
            final_verdict="inconclusive",
            action="keep_baseline",
            confidence=0.2,
            primary_receipt_id="receipt",
            decision_digest="f" * 64,
        ),
    ]

    class Stage:
        async def run(self, current: AgentState) -> AgentState:
            return current

    async def checkpoint(current: AgentState, *_args: Any, **_kwargs: Any) -> dict[str, Any]:
        return {"agent": current.model_dump(mode="json")}

    host = SimpleNamespace(
        _state=lambda value: AgentState.model_validate(value),
        analyst=Stage(),
        delta_critic=Stage(),
        delta_verifier=Stage(),
        _adjudicate_deltas=lambda *_args: True,
        investigation_store=None,
        _checkpoint=checkpoint,
    )
    correlated = AgentState.model_validate(
        (await correlation_runtime.correlate(host, state.model_dump(mode="json")))["agent"]
    )
    assert any(item.claim_type == "model_source_review.coverage" for item in correlated.claims)
    assert any(item.producer == "canonical-primary" for item in correlated.claims)


def test_register_verified_scenario_delta_is_evidence_complete() -> None:
    state = _state(run_id="scenario-delta")
    state.audit_coverage["direct_anchor_pipeline"] = True
    candidate = _finding("scenario-finding", ["scenario-evidence"], path="fixture.py").model_copy(
        update={
            "raw": {
                "assurance_level": "semantically_corroborated",
                "sink": "execute_query",
                "file_sha256": "a" * 64,
                "rule_digest": "b" * 64,
            }
        }
    )
    evidence = _evidence(
        "scenario-evidence",
        metadata={
            "assurance_level": "semantically_corroborated",
            "file_sha256": "a" * 64,
            "rule_digest": "b" * 64,
        },
    )
    verifier_claim = make_claim(
        claim_type="scenario",
        statement="verified scenario",
        subject_ref=candidate.finding_id,
        producer="deterministic-scenario-analyzer",
        confidence=1,
    ).model_copy(update={"status": ClaimStatus.VERIFIED})
    state.findings = [candidate]
    state.evidence = [evidence]
    state.claims = [verifier_claim]
    state.published_baseline = PublishedBaselineProjection(
        projection_id="baseline-projection-" + "c" * 64,
        run_id=state.run_id,
        receipt_id="receipt",
        admission_id="admission",
        semantic_digest="d" * 64,
        integrity_digest="e" * 64,
        status=RunStatus.PARTIAL,
        executive_summary="baseline",
        findings=[],
        evidence=[],
    )
    correlation_runtime.register_verified_scenario_deltas(state)
    rows = state.audit_coverage["typed_deltas"]
    assert len(rows) == 1
    assert rows[0]["finding"]["finding_id"] == candidate.finding_id
    assert rows[0]["disposition"] == DeltaDisposition.ACCEPTED.value


def test_correlation_delta_registration_skips_baseline_unverified_and_duplicate_rows() -> None:
    state = _state(run_id="scenario-delta-skips")
    state.audit_coverage["direct_anchor_pipeline"] = True
    baseline_finding = _finding("baseline", ["evidence-baseline"])
    unverified = _finding("unverified", ["evidence-unverified"])
    missing_evidence = _finding("missing-evidence", ["evidence-missing"])
    state.findings = [baseline_finding, unverified, missing_evidence]
    state.evidence = [_evidence("evidence-baseline"), _evidence("evidence-unverified")]
    state.claims = [
        make_claim(
            claim_type="scenario",
            statement="baseline",
            subject_ref=baseline_finding.finding_id,
            producer="deterministic-scenario-analyzer",
            confidence=1,
        ).model_copy(update={"status": ClaimStatus.VERIFIED}),
        make_claim(
            claim_type="scenario",
            statement="unverified",
            subject_ref=unverified.finding_id,
            producer="deterministic-scenario-analyzer",
            confidence=1,
        ),
    ]
    state.published_baseline = PublishedBaselineProjection(
        projection_id="baseline-projection-" + "1" * 64,
        run_id=state.run_id,
        receipt_id="receipt",
        admission_id="admission",
        semantic_digest="2" * 64,
        integrity_digest="3" * 64,
        status=RunStatus.PARTIAL,
        executive_summary="baseline",
        findings=[baseline_finding],
    )
    state.audit_coverage["typed_deltas"] = [{"finding": {"finding_id": "missing-evidence"}}]
    correlation_runtime.register_verified_scenario_deltas(state)
    assert state.audit_coverage["typed_deltas"] == [{"finding": {"finding_id": "missing-evidence"}}]


def test_correlation_supplement_and_request_guards_skip_missing_targets() -> None:
    state = _state(run_id="supplement-guards")
    state.active_evidence_request_ids = ["unknown-request"]
    host = SimpleNamespace(investigation_store=None)
    assert correlation_runtime.latest_evidence_requests(host, state) == {}
    assert correlation_runtime.supplement_evidence_links(host, state, [], {}) == []

    class Store:
        def list_objects(self, _run_id: str, _kind: str) -> list[dict[str, Any]]:
            return [
                EvidenceRequest(
                    request_id="inactive",
                    run_id=state.run_id,
                    reason_code="verify",
                    requested_evidence_types=["finding"],
                    immutable_scope=["fixture.py"],
                    allowed_capabilities=["sast"],
                    success_criteria=["target"],
                    dedupe_key="inactive",
                    content_digest="a" * 64,
                ).model_dump(mode="json"),
                EvidenceRequest(
                    request_id="unknown-request",
                    run_id=state.run_id,
                    target_claim_id="missing-claim",
                    reason_code="verify",
                    requested_evidence_types=["finding"],
                    immutable_scope=["fixture.py"],
                    allowed_capabilities=["sast"],
                    success_criteria=["target"],
                    dedupe_key="unknown",
                    content_digest="b" * 64,
                ).model_dump(mode="json"),
            ]

    active_host = SimpleNamespace(investigation_store=Store())
    assert set(correlation_runtime.latest_evidence_requests(active_host, state)) == {"unknown-request"}
    target_claim = make_claim(
        claim_type="finding",
        statement="target",
        subject_ref="target-finding",
        producer="model",
        confidence=1,
    )
    state.claims = [target_claim]
    state.findings = [_finding("target-finding", ["target-evidence"])]
    state.step_runtime = {"supplement-skip": StepRuntime(step_id="supplement-skip", observation_indexes=[99])}
    state.active_evidence_request_ids = ["unknown-request"]
    assert correlation_runtime.supplement_evidence_links(active_host, state, [], {}) == []


def test_evidence_integrity_binds_valid_rows_and_rejects_tampered_rows(tmp_path) -> None:
    source = b"print('ok')\nraise RuntimeError()\n"
    digest = hashlib.sha256(source).hexdigest()
    artifact_store = ContentAddressedArtifactStore(tmp_path / "cas")
    stored = artifact_store.put(source, run_id="integrity-run")
    state = _state(run_id="integrity-run")
    state.input_artifacts = [
        InputArtifact(
            artifact_id="input-1",
            original_name="fixture.py",
            relative_path="fixture.py",
            sha256=digest,
            size_bytes=len(source),
        )
    ]
    valid_evidence = Evidence(
        evidence_id="valid-evidence",
        source="primary",
        summary="valid",
        artifact_ref=stored.sha256,
        sha256=digest,
    )
    domain_evidence = Evidence(
        evidence_id="domain-evidence",
        source="primary",
        summary="domain",
        artifact_ref=stored.sha256,
        sha256=digest,
        metadata={"evidence_type": "canonical_primary_domain_reference"},
    )
    wrong_evidence = Evidence(
        evidence_id="wrong-evidence",
        source="primary",
        summary="wrong",
        artifact_ref="f" * 64,
        sha256="f" * 64,
    )
    projection = CanonicalProjection(
        findings=(
            _finding("valid-finding", ["valid-evidence"]),
            _finding("dot-finding", ["valid-evidence"], path="."),
            _finding("wrong-path", ["valid-evidence"], path="other.py"),
            _finding("wrong-evidence", ["wrong-evidence"]),
        ),
        evidence=(valid_evidence, domain_evidence, wrong_evidence),
        limitations=(),
        coverage={},
    )
    bind_canonical_baseline_claims(state, projection, artifact_store)
    assert {item.subject_ref for item in state.claims} == {"valid-finding", "domain-answer:domain-evidence"}
    assert len(state.evidence_links) == 2
    assert all(item.verifier_status == ClaimStatus.VERIFIED for item in state.evidence_links)


def test_evidence_integrity_handles_line_free_read_failures_and_bad_bytes(tmp_path) -> None:
    state = _state(run_id="integrity-edge")
    artifact_store = ContentAddressedArtifactStore(tmp_path / "cas")
    source = b"one line\n"
    digest = hashlib.sha256(source).hexdigest()
    stored = artifact_store.put(source, run_id=state.run_id)
    state.input_artifacts = [
        InputArtifact(
            original_name="fixture.py",
            relative_path="fixture.py",
            sha256=digest,
            size_bytes=len(source),
        )
    ]
    evidence = Evidence(
        evidence_id="edge-evidence",
        source="primary",
        summary="edge",
        artifact_ref=stored.sha256,
        sha256=digest,
    )
    line_free = _finding("line-free", [evidence.evidence_id]).model_copy(update={"line": None})

    def projection_for(*findings: Finding) -> CanonicalProjection:
        return CanonicalProjection(
            findings=findings,
            evidence=(evidence,),
            limitations=(),
            coverage={},
        )

    projection = projection_for(line_free)
    bind_canonical_baseline_claims(state, projection, artifact_store)
    assert any(item.subject_ref == "line-free" for item in state.claims)

    class MissingStore:
        def read(self, _sha: str) -> bytes:
            raise ValueError("missing CAS bytes")

    line_one = _finding("read-failure", [evidence.evidence_id])
    bind_canonical_baseline_claims(
        state,
        projection_for(line_one),
        MissingStore(),  # type: ignore[arg-type]
    )
    assert not any(item.subject_ref == "read-failure" for item in state.claims)

    class CorruptStore:
        def read(self, _sha: str) -> bytes:
            return b"tampered\n"

    bind_canonical_baseline_claims(
        state,
        projection_for(line_one),
        CorruptStore(),  # type: ignore[arg-type]
    )
    assert not any(item.subject_ref == "read-failure" for item in state.claims)

    too_high = _finding("line-too-high", [evidence.evidence_id]).model_copy(update={"line": 99})
    bind_canonical_baseline_claims(
        state,
        projection_for(too_high),
        artifact_store,
    )
    assert not any(item.subject_ref == "line-too-high" for item in state.claims)

    wrong_domain = Evidence(
        evidence_id="wrong-domain",
        source="primary",
        summary="wrong domain",
        artifact_ref="f" * 64,
        sha256="f" * 64,
        metadata={"evidence_type": "canonical_primary_domain_reference"},
    )
    bind_canonical_baseline_claims(
        state,
        CanonicalProjection(findings=(), evidence=(wrong_domain,), limitations=(), coverage={}),
        artifact_store,
    )
    assert not any(item.subject_ref == "domain-answer:wrong-domain" for item in state.claims)


def test_report_finalization_covers_empty_pending_failed_and_successful_plans() -> None:
    untouched = _state()
    untouched.audit_coverage["augmentation_status"] = "completed"
    report_runtime.finalize_augmentation_status(untouched)
    assert untouched.audit_coverage["augmentation_status"] == "completed"

    for current, expected in (("pending", "not_applicable"), ("running", "skipped")):
        state = _state()
        state.audit_coverage["augmentation_status"] = current
        report_runtime.finalize_augmentation_status(state)
        assert state.audit_coverage["augmentation_status"] == expected

    pending = _state()
    pending.audit_coverage["augmentation_status"] = "pending"
    pending.plan = [PlanStep(step_id="one", objective="one", agent_role="worker")]
    report_runtime.finalize_augmentation_status(pending)
    assert pending.audit_coverage["augmentation_status"] == "partial"

    failed = _state()
    failed.audit_coverage["augmentation_status"] = "running"
    failed.plan = [PlanStep(step_id="one", objective="one", agent_role="worker")]
    failed.step_runtime = {"one": StepRuntime(step_id="one", status=StepStatus.FAILED)}
    report_runtime.finalize_augmentation_status(failed)
    assert failed.audit_coverage["augmentation_status"] == "partial"

    completed = _state()
    completed.audit_coverage["augmentation_status"] = "running"
    completed.plan = [PlanStep(step_id="one", objective="one", agent_role="worker")]
    completed.step_runtime = {"one": StepRuntime(step_id="one", status=StepStatus.SUCCEEDED)}
    report_runtime.finalize_augmentation_status(completed)
    assert completed.audit_coverage["augmentation_status"] == "completed"


@pytest.mark.asyncio
async def test_report_degrades_to_partial_when_structured_reporter_fails() -> None:
    state = _state(run_id="report-fallback")
    state.status = RunStatus.RUNNING
    state.report = AgentReport(
        run_id=state.run_id,
        status=state.status,
        executive_summary="pre-existing",
        answer_payload={"answer_kind": "finding", "findings": []},
    )

    class BrokenReporter:
        async def run(self, _state: AgentState) -> AgentState:
            raise RuntimeError("reporter unavailable")

    async def checkpoint(current: AgentState, *_args: Any, **_kwargs: Any) -> dict[str, Any]:
        return {"agent": current.model_dump(mode="json")}

    host = SimpleNamespace(
        _state=lambda value: AgentState.model_validate(value),
        reporter=BrokenReporter(),
        _checkpoint=checkpoint,
        _seal_admission=lambda _state: None,
    )
    result = await report_runtime.report(host, state.model_dump(mode="json"))
    reported = AgentState.model_validate(result["agent"])
    assert reported.status == RunStatus.PARTIAL
    assert reported.report is not None
    assert "Structured reporter degraded safely" in reported.last_error
    assert any("Structured reporter degraded safely" in item for item in reported.report.limitations)


@pytest.mark.asyncio
async def test_report_handles_typed_replay_and_evidence_projection_failures(monkeypatch) -> None:
    state = _state(run_id="report-projection-failure")
    state.scenario = Scenario.CODE_AUDIT
    state.status = RunStatus.RUNNING
    state.report = AgentReport(
        run_id=state.run_id,
        status=state.status,
        executive_summary="existing",
        findings=[_finding("report-finding", ["missing"])],
    )
    state.published_baseline = PublishedBaselineProjection(
        projection_id="baseline-projection-" + "a" * 64,
        run_id=state.run_id,
        receipt_id="receipt",
        admission_id="admission",
        semantic_digest="b" * 64,
        integrity_digest="c" * 64,
        status=RunStatus.PARTIAL,
        executive_summary="baseline",
    )

    class Reporter:
        async def run(self, current: AgentState) -> AgentState:
            return current

    async def checkpoint(current: AgentState, *_args: Any, **_kwargs: Any) -> dict[str, Any]:
        return {"agent": current.model_dump(mode="json")}

    monkeypatch.setattr(report_runtime, "_safe_active_answer", lambda _state: None)
    monkeypatch.setattr(
        report_runtime,
        "EvidenceGraph",
        lambda **_kwargs: (_ for _ in ()).throw(ValueError("invalid evidence graph")),
    )
    host = SimpleNamespace(
        _state=lambda value: AgentState.model_validate(value),
        reporter=Reporter(),
        _checkpoint=checkpoint,
        _seal_admission=lambda _state: None,
    )
    result = await report_runtime.report(host, state.model_dump(mode="json"))
    reported = AgentState.model_validate(result["agent"])
    assert reported.status == RunStatus.PARTIAL
    assert "Evidence projection degraded safely" in reported.last_error
    assert reported.report is not None
    assert any("Evidence projection degraded safely" in item for item in reported.report.limitations)


@pytest.mark.asyncio
async def test_report_projects_enhanced_anchor_artifact(monkeypatch) -> None:
    state = _state(run_id="report-anchor")
    state.report = AgentReport(
        run_id=state.run_id,
        status=RunStatus.PARTIAL,
        executive_summary="anchor",
    )
    state.audit_coverage["anchor_report"] = {"run_id": state.run_id}

    class FakeAnchor:
        @classmethod
        def model_validate(cls, payload: Any) -> Any:
            return payload

    class FakeEnhanced:
        def model_dump(self, mode: str = "json") -> dict[str, Any]:
            del mode
            return {"publishable": True, "rows": []}

    monkeypatch.setattr(report_runtime, "AnchorReport", FakeAnchor)
    monkeypatch.setattr(report_runtime, "build_enhanced_report", lambda **_kwargs: FakeEnhanced())
    monkeypatch.setattr(report_runtime, "stable_digest", lambda _value: "a" * 64)
    monkeypatch.setattr(
        report_runtime,
        "persist_projection_artifact",
        lambda *_args, **_kwargs: SimpleNamespace(artifact_id="enhanced-artifact"),
    )

    class Reporter:
        async def run(self, current: AgentState) -> AgentState:
            return current

    async def checkpoint(current: AgentState, *_args: Any, **_kwargs: Any) -> dict[str, Any]:
        return {"agent": current.model_dump(mode="json")}

    host = SimpleNamespace(
        _state=lambda value: AgentState.model_validate(value),
        reporter=Reporter(),
        _checkpoint=checkpoint,
        _seal_admission=lambda _state: None,
    )
    result = await report_runtime.report(host, state.model_dump(mode="json"))
    reported = AgentState.model_validate(result["agent"])
    assert reported.audit_coverage["enhanced_report"]["publishable"] is True
    assert "rows" not in reported.audit_coverage["enhanced_report"]
    assert reported.audit_coverage["enhanced_report"]["artifact_id"] == "enhanced-artifact"
    assert reported.audit_coverage["enhanced_report_artifact_id"] == "enhanced-artifact"

    fallback_state = _state(run_id="report-anchor-fallback")
    fallback_state.report = AgentReport(
        run_id=fallback_state.run_id,
        status=RunStatus.PARTIAL,
        executive_summary="anchor fallback",
    )
    fallback_state.audit_coverage["anchor_report"] = {"run_id": fallback_state.run_id}
    fallback_state.audit_coverage["canonical_primary_completed"] = True
    monkeypatch.setattr(
        report_runtime,
        "persist_projection_artifact",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(TypeError("CAS unavailable")),
    )
    fallback_result = await report_runtime.report(host, fallback_state.model_dump(mode="json"))
    fallback_report = AgentState.model_validate(fallback_result["agent"])
    assert fallback_report.audit_coverage["enhanced_report"]["publishable"] is False


@pytest.mark.asyncio
async def test_report_keeps_replay_payload_internal_and_public_coverage_bounded(monkeypatch) -> None:
    state = _state(run_id="report-bounded-public-coverage")
    state.report = AgentReport(
        run_id=state.run_id,
        status=RunStatus.PARTIAL,
        executive_summary="bounded",
    )
    state.audit_coverage.update(
        {
            "candidate_store": {
                "version": "candidate-store-v1",
                "records": [{"candidate_id": f"candidate-{index}", "body": "x" * 4096} for index in range(256)],
                "events": [{"event": "transition", "body": "y" * 2048} for _ in range(256)],
                "quarantined_candidate_ids": [f"candidate-{index}" for index in range(128)],
                "store_digest": "c" * 64,
            },
            "typed_deltas": [
                {"delta_id": f"delta-{index}", "disposition": "quarantined", "body": "z" * 4096} for index in range(256)
            ],
            "eirs_runtime": {
                "status": "published",
                "result": {"observations": [{"body": "o" * 4096} for _ in range(256)]},
            },
            "independent_scout": {
                "ran": True,
                "scout_id": "bounded-scout",
                "candidate_count": 256,
                "evidence_count": 256,
                "finding_payloads": [{"body": "f" * 4096} for _ in range(256)],
                "evidence_payloads": [{"body": "e" * 4096} for _ in range(256)],
            },
        }
    )

    class Reporter:
        async def run(self, current: AgentState) -> AgentState:
            return current

    async def checkpoint(current: AgentState, *_args: Any, **_kwargs: Any) -> dict[str, Any]:
        return {"agent": current.model_dump(mode="json")}

    host = SimpleNamespace(
        _state=lambda value: AgentState.model_validate(value),
        reporter=Reporter(),
        _checkpoint=checkpoint,
        _seal_admission=lambda _state: None,
    )
    result = await report_runtime.report(host, state.model_dump(mode="json"))
    reported = AgentState.model_validate(result["agent"])
    assert reported.report is not None
    public_payload = json.dumps(reported.report.coverage, ensure_ascii=False).encode("utf-8")
    assert len(public_payload) < 256 * 1024
    assert reported.report.coverage["candidate_store"]["record_count"] == 256
    assert "records" not in reported.report.coverage["candidate_store"]
    assert reported.report.coverage["typed_deltas"]["delta_count"] == 256
    assert "finding_payloads" not in reported.report.coverage["independent_scout"]
    # The durable control-plane value remains complete for deterministic replay.
    assert len(reported.audit_coverage["candidate_store"]["records"]) == 256


def _gap_action(
    action_id: str,
    *,
    kind: GapActionKind = GapActionKind.RETRIEVE_DOMAIN,
    domain: GapDomain = GapDomain.CODE,
    capability: str = "sast",
    tool_name: str | None = None,
) -> GapAction:
    return GapAction(
        action_id=action_id,
        kind=kind,
        obligation_ids=["obligation-1"],
        capability=capability,
        domain=domain,
        tool_name=tool_name,
        input_refs=["artifact:fixture.py"],
        output_refs=[f"output:{action_id}"],
        max_tool_calls=1 if kind == GapActionKind.RUN_TOOL else 0,
        budget=GapActionBudget(max_tool_calls=1 if kind == GapActionKind.RUN_TOOL else 0),
        stop_condition="bounded",
    )


def _gap_plan(state: AgentState) -> GapPlan:
    actions = [
        _gap_action("action-1"),
        _gap_action("action-2", domain=GapDomain.LOG, capability="log_timeline_retrieval"),
    ]
    return GapPlan(
        plan_id="gap-plan-coverage",
        run_id=state.run_id,
        contract_digest="a" * 64,
        belief_digest="b" * 64,
        max_actions=2,
        max_tool_calls=0,
        actions=actions,
        stop_reasons=["bounded"],
        plan_digest="c" * 64,
    )


def test_eirs_payload_helpers_cover_all_typed_domains_and_fallbacks(monkeypatch) -> None:
    observation = SimpleNamespace(
        observation_id="obs-1",
        output_refs=("receipt-1",),
        evidence_ids=("e1",),
        domain=GapDomain.API,
    )
    proposal = SimpleNamespace(proposal_id="proposal-1")
    fake_active = SimpleNamespace(
        answer=SimpleNamespace(
            model_dump=lambda mode="python": {
                "findings": [
                    {
                        "finding_id": "f1",
                        "rule_id": "CWE-89",
                        "path": "fixture.py",
                        "line": 2,
                        "title": "finding",
                        "description": "desc",
                        "severity": "HIGH",
                        "evidence_ids": ["e1"],
                    }
                ],
                "events": [{"event_id": "event-1", "timestamp": "now", "event_type": "login", "evidence_ids": ["e1"]}],
                "actors": [{"actor_id": "actor-1", "name": "alice", "evidence_ids": ["e1"]}],
                "operations": [{"operation_id": "op-1", "method": "get", "path": "/x", "evidence_ids": ["e1"]}],
                "items": [{"answer_id": "answer-1", "value": "yes", "evidence_ids": ["e1"]}],
            }
        )
    )
    monkeypatch.setattr(eirs_runtime, "active_answer", lambda _state: fake_active)
    observation.status = "observed"
    result = SimpleNamespace(observations=[observation])
    state = _state()
    evidence = ["e1"]
    cases = [
        (eirs_runtime.RevisionField.FINDINGS, {"/findings": "replace"}),
        (eirs_runtime.RevisionField.TIMELINE, {"/events": "supplement"}),
        (eirs_runtime.RevisionField.ACTOR, {"/actors": "supplement"}),
        (eirs_runtime.RevisionField.API_OPERATION, {"/operations": "replace"}),
        (eirs_runtime.RevisionField.EXACT_ANSWER, {"/answer": "supplement"}),
    ]
    for field, _ in cases:
        payload, target = eirs_runtime._revision_payload(
            state,
            field,
            eirs_runtime.RevisionOperation.SUPPLEMENT,
            result,
            proposal,
            evidence,
        )
        assert payload is not None
        assert target
    assert eirs_runtime._revision_field("/findings/0", GapDomain.EXACT) == eirs_runtime.RevisionField.FINDINGS
    assert eirs_runtime._revision_field("/unknown", GapDomain.API) == eirs_runtime.RevisionField.API_OPERATION
    assert eirs_runtime._revision_field("/unknown", GapDomain.FORENSICS) == eirs_runtime.RevisionField.ACTOR
    assert eirs_runtime._revision_field("/unknown", GapDomain.LOG) == eirs_runtime.RevisionField.TIMELINE
    assert eirs_runtime._revision_field("/unknown", GapDomain.EXACT) == eirs_runtime.RevisionField.EXACT_ANSWER
    assert eirs_runtime._revision_field("/unknown", GapDomain.PATCH) is None
    assert eirs_runtime._revision_operation("replace") == eirs_runtime.RevisionOperation.REPLACE
    assert eirs_runtime._revision_operation("retract") == eirs_runtime.RevisionOperation.RETRACT
    assert eirs_runtime._revision_operation("other") == eirs_runtime.RevisionOperation.SUPPLEMENT
    assert eirs_runtime._row_evidence({"evidence_ids": ["e1", ""]}) == {"e1"}
    assert eirs_runtime._observation_ref(None) is None
    assert eirs_runtime._observation_ref(observation) == "receipt-1"


def test_eirs_effective_payload_and_pipeline_helpers() -> None:
    state = _state()
    state.report = AgentReport(
        run_id=state.run_id,
        status=RunStatus.PARTIAL,
        executive_summary="answer",
        answer_payload={"findings": [], "negative_evidence": ["old"]},
    )
    state.findings = [_finding("admitted", ["evidence-1"]), _finding("quarantined", ["evidence-2"])]
    state.claims = [
        make_claim(
            claim_type="finding",
            statement="verified",
            subject_ref="admitted",
            producer="verifier",
        ).model_copy(update={"status": ClaimStatus.VERIFIED})
    ]
    state.evidence = [
        _evidence("evidence-1", metadata={"path": "fixture.py"}),
        _evidence("evidence-2", metadata={"path": "other.py"}),
    ]
    state.input_artifacts = [
        InputArtifact(original_name="fixture.py", relative_path="fixture.py", sha256="a" * 64, size_bytes=1)
    ]
    state.audit_coverage["tool_gain_gate"] = {"quarantined_finding_ids": ["quarantined"]}
    state.audit_coverage["negative_coverage_complete"] = False
    # A security contract can be represented with the minimal validated task envelope.
    from secmind.task_contract import compile_resolved_task_contract

    state.resolved_task_contract = compile_resolved_task_contract(
        {
            "task_spec_id": "effective-payload",
            "run_id": state.run_id,
            "revision": 1,
            "content_digest": "b" * 64,
            "objectives": [state.task.objective],
            "primary_scenario": "code_audit",
            "primary_domain": "code_audit_and_patch",
            "secondary_scenarios": [],
            "secondary_capabilities": [],
            "scoring_mode": "security_finding",
            "interaction_mode": "unattended",
            "autonomy_policy": "automatic",
            "authorized_scope": ["fixture.py"],
            "constraints": [],
            "prohibited_actions": [],
            "expected_outputs": [],
            "success_criteria": [],
            "output_contract": {},
            "asset_ids": [],
        },
        input_manifest_digest="c" * 64,
    )
    payload = eirs_runtime.effective_answer_payload(state)
    assert [item["finding_id"] for item in payload["findings"]] == ["admitted"]
    assert payload["checked_paths"] == ["fixture.py", "other.py"]
    state.findings = []
    state.audit_coverage["negative_coverage_complete"] = True
    payload = eirs_runtime.effective_answer_payload(state)
    assert "negative_evidence" in payload
    assert payload["checked_paths"] == ["fixture.py", "other.py"]


def test_eirs_gap_tool_candidates_selects_safe_template_and_resolver_fallback() -> None:
    state = _state()
    state.input_artifacts = [
        InputArtifact(original_name="fixture.py", relative_path="fixture.py", sha256="a" * 64, size_bytes=1)
    ]

    def manifest(
        name: str,
        *,
        tags: list[str],
        risk: RiskLevel = RiskLevel.R0,
        health: ToolHealth = ToolHealth.HEALTHY,
        langs: list[str] | None = None,
    ) -> Any:
        return ToolManifest(
            name=name,
            version="1",
            description=name,
            scenarios=[Scenario.CODE_AUDIT],
            input_schema={},
            output_schema={},
            risk_level=risk,
            platform_risk=risk,
            health_status=health,
            capability_tags=tags,
            supported_languages=langs or ["python"],
            evidence_types=["finding"],
            concurrency_key=name,
        )

    manifests = {
        "good": manifest("good", tags=["sast"]),
        "bad-risk": manifest("bad-risk", tags=["sast"], risk=RiskLevel.R2),
        "bad-health": manifest("bad-health", tags=["sast"], health=ToolHealth.UNAVAILABLE),
    }
    state.plan = [
        PlanStep(
            step_id="existing",
            objective="existing",
            agent_role="worker",
            capability="sast",
            tool_candidates=["good", "missing", "bad-risk", "bad-health"],
        )
    ]
    registry = SimpleNamespace(get=lambda name: SimpleNamespace(manifest=manifests[name]))
    host = SimpleNamespace(broker=SimpleNamespace(registry=registry))
    template_result = eirs_runtime.gap_tool_candidates(
        host,
        state,
        _gap_action("run", kind=GapActionKind.RUN_TOOL, tool_name="good"),
    )
    assert template_result is not None
    assert template_result[1] == ["good"]

    state.plan.append(
        PlanStep(
            step_id="eirs-template",
            objective="already scheduled",
            agent_role="worker",
            capability="sast",
            tool_candidates=["good"],
        )
    )
    assert (
        eirs_runtime.gap_tool_candidates(
            host,
            state,
            _gap_action("skip-eirs", kind=GapActionKind.RUN_TOOL, tool_name="good"),
        )
        is not None
    )

    resolver_manifest = manifest("resolved", tags=["custom"])
    resolver_item = SimpleNamespace(manifest=resolver_manifest, score=0.1)
    fallback_host = SimpleNamespace(
        broker=SimpleNamespace(registry=SimpleNamespace(get=lambda _name: (_ for _ in ()).throw(KeyError("missing")))),
        capability_resolver=SimpleNamespace(resolve=lambda *_args, **_kwargs: [resolver_item]),
    )
    fallback = eirs_runtime.gap_tool_candidates(
        fallback_host,
        state,
        _gap_action("fallback", capability="missing-capability", domain=GapDomain.CODE),
    )
    assert fallback is not None
    assert fallback[1] == ["resolved"]
    assert eirs_runtime.gap_tool_candidates(
        fallback_host,
        state,
        _gap_action("sorted", kind=GapActionKind.RUN_TOOL, tool_name="resolved"),
    )[1] == ["resolved"]


def test_eirs_gap_tool_candidates_rejects_wrong_domain_risk_and_language() -> None:
    state = _state()
    state.input_artifacts = [
        InputArtifact(original_name="fixture.py", relative_path="fixture.py", sha256="a" * 64, size_bytes=1)
    ]
    manifests = {
        "wrong-domain": ToolManifest(
            name="wrong-domain",
            version="1",
            description="wrong",
            scenarios=[Scenario.CODE_AUDIT],
            input_schema={},
            output_schema={},
            risk_level=RiskLevel.R0,
            capability_tags=["inventory"],
            supported_languages=["python"],
            evidence_types=["finding"],
        ),
        "unsupported-language": ToolManifest(
            name="unsupported-language",
            version="1",
            description="unsupported",
            scenarios=[Scenario.CODE_AUDIT],
            input_schema={},
            output_schema={},
            risk_level=RiskLevel.R0,
            capability_tags=["sast"],
            supported_languages=["java"],
            evidence_types=["finding"],
        ),
    }
    state.plan = [
        PlanStep(
            step_id="wrong-domain-step",
            objective="wrong domain",
            agent_role="worker",
            capability="inventory",
            tool_candidates=["wrong-domain"],
        ),
        PlanStep(
            step_id="unsupported-step",
            objective="unsupported",
            agent_role="worker",
            capability="sast",
            tool_candidates=["unsupported-language"],
        ),
    ]
    registry = SimpleNamespace(get=lambda name: SimpleNamespace(manifest=manifests[name]))
    host = SimpleNamespace(
        broker=SimpleNamespace(registry=registry),
        capability_resolver=SimpleNamespace(resolve=lambda *_args, **_kwargs: []),
    )
    assert (
        eirs_runtime.gap_tool_candidates(
            host,
            state,
            _gap_action("wrong", capability="sast", domain=GapDomain.LOG),
        )
        is None
    )
    assert (
        eirs_runtime.gap_tool_candidates(
            host,
            state,
            _gap_action("unsupported", kind=GapActionKind.RUN_TOOL, tool_name="unsupported-language"),
        )
        is None
    )


def test_eirs_private_candidate_and_semantic_helpers_cover_mapping_and_fallbacks() -> None:
    state = _state(scenario=Scenario.INCIDENT_RESPONSE)
    assert eirs_runtime._candidate_row(
        {"mapping": {"answer": {"value": "x", "evidence_ids": ["e1"]}}},
        eirs_runtime.RevisionField.EXACT_ANSWER,
        ["e1"],
    ) == {"value": "x", "evidence_ids": ["e1"], "answer_id": "answer"}
    assert eirs_runtime._candidate_row({"events": "not-a-list"}, eirs_runtime.RevisionField.TIMELINE, ["e1"]) is None
    state.findings = [_finding("candidate", ["e1"])]
    assert eirs_runtime._finding_candidate(state, ["e1"])["finding_id"] == "candidate"
    assert eirs_runtime._finding_candidate(state, ["other"]) is None

    state.audit_coverage["scenario_semantic_delta"] = {
        "scenario": "incident_response",
        "answer_kind": "evidence_gap",
        "incident_response": {"actions": [{"action": 1}], "hypotheses": [{"hypothesis": 1}]},
    }
    assert eirs_runtime._semantic_candidate_count(state, GapDomain.IR) == 2
    state.audit_coverage["scenario_semantic_delta"] = {
        "scenario": "api_assessment",
        "answer_kind": "unknown",
        "endpoint_graph": {"nodes": ["one"]},
    }
    assert eirs_runtime._semantic_candidate_count(state, GapDomain.API) == 1
    state.audit_coverage["scenario_semantic_delta"] = {
        "scenario": "log_analysis",
        "answer_kind": "timeline",
        "evidence_ids": ["e1"],
    }
    assert eirs_runtime._semantic_candidate_count(state, GapDomain.LOG) == 1
    assert eirs_runtime._semantic_candidate_count(state, GapDomain.CODE) == 0


def test_publish_eirs_revision_observes_all_admission_gates(monkeypatch) -> None:
    state = _state(run_id="publish-gates")
    state.report = AgentReport(run_id=state.run_id, status=RunStatus.PARTIAL, executive_summary="baseline")
    first = _evidence("publish-a")
    second = _evidence("publish-b")
    claim = make_claim(
        claim_type="finding",
        statement="verified",
        subject_ref="finding",
        producer="verifier",
        confidence=1,
    ).model_copy(update={"status": ClaimStatus.VERIFIED})
    state.evidence = [first, second]
    state.claims = [claim]
    state.evidence_links = [
        make_link(claim_id=claim.claim_id, evidence_id=item.evidence_id).model_copy(
            update={"verifier_status": ClaimStatus.VERIFIED}
        )
        for item in (first, second)
    ]
    proposal = SimpleNamespace(proposal_id="proposal-gates", field_impacts=[])
    result = SimpleNamespace(
        revision_proposals=[proposal],
        observations=[SimpleNamespace(status="observed", evidence_ids=[first.evidence_id, second.evidence_id])],
        result_digest="a" * 64,
    )
    monkeypatch.setattr(eirs_runtime, "active_answer", lambda _state: SimpleNamespace())

    state.evidence_links = []
    assert eirs_runtime.publish_eirs_revision(SimpleNamespace(), state, result) == (False, ())
    state.evidence_links = [
        make_link(claim_id=claim.claim_id, evidence_id=item.evidence_id).model_copy(
            update={"verifier_status": ClaimStatus.VERIFIED}
        )
        for item in (first, second)
    ]

    class GraphViews:
        def independent_evidence(self, _candidate_ids: list[str]) -> list[Any]:
            return [SimpleNamespace(evidence=first)]

    monkeypatch.setattr(eirs_runtime, "InvestigationEvidenceGraph", lambda _views: GraphViews())
    monkeypatch.setattr(eirs_runtime, "build_lineage_graph_views", lambda *_args: ())
    assert eirs_runtime.publish_eirs_revision(SimpleNamespace(), state, result) == (False, (first.evidence_id,))

    two_graph = type(
        "TwoGraph",
        (),
        {
            "independent_evidence": lambda self, _ids: [
                SimpleNamespace(evidence=first),
                SimpleNamespace(evidence=second),
            ]
        },
    )
    monkeypatch.setattr(eirs_runtime, "InvestigationEvidenceGraph", lambda _views: two_graph())
    monkeypatch.setattr(eirs_runtime, "gap_independence_proof", lambda *_args, **_kwargs: None)
    assert eirs_runtime.publish_eirs_revision(SimpleNamespace(), state, result) == (
        False,
        (first.evidence_id, second.evidence_id),
    )

    monkeypatch.setattr(eirs_runtime, "gap_independence_proof", lambda *_args, **_kwargs: object())
    state.audit_coverage["typed_answer_runtime"] = {"revision_proposal_ids": [proposal.proposal_id]}
    assert eirs_runtime.publish_eirs_revision(SimpleNamespace(), state, result) == (
        True,
        (first.evidence_id, second.evidence_id),
    )
    state.audit_coverage["typed_answer_runtime"] = {}
    monkeypatch.setattr(eirs_runtime, "_typed_eirs_revision", lambda *_args: None)
    assert eirs_runtime.publish_eirs_revision(
        SimpleNamespace(_adjudicate_deltas=lambda *_args: True), state, result
    ) == (
        False,
        (first.evidence_id, second.evidence_id),
    )

    monkeypatch.setattr(
        eirs_runtime,
        "_typed_eirs_revision",
        lambda *_args: (
            eirs_runtime.RevisionOperation.SUPPLEMENT,
            eirs_runtime.RevisionField.EXACT_ANSWER,
            None,
            None,
        ),
    )
    assert eirs_runtime.publish_eirs_revision(
        SimpleNamespace(_adjudicate_deltas=lambda *_args: False), state, result
    ) == (
        False,
        (first.evidence_id, second.evidence_id),
    )

    revision = SimpleNamespace(
        revision_id="revision-gates",
        field=eirs_runtime.RevisionField.EXACT_ANSWER,
        operation=eirs_runtime.RevisionOperation.SUPPLEMENT,
    )
    active = SimpleNamespace(answer=SimpleNamespace(model_dump=lambda mode="json": {"value": "revised"}))
    monkeypatch.setattr(
        eirs_runtime,
        "_typed_eirs_revision",
        lambda *_args: (
            eirs_runtime.RevisionOperation.SUPPLEMENT,
            eirs_runtime.RevisionField.EXACT_ANSWER,
            SimpleNamespace(answer_id="answer"),
            "answer",
        ),
    )
    monkeypatch.setattr(eirs_runtime, "revise_active_answer", lambda *_args, **_kwargs: None)
    assert eirs_runtime.publish_eirs_revision(
        SimpleNamespace(_adjudicate_deltas=lambda *_args: True), state, result
    ) == (
        False,
        (first.evidence_id, second.evidence_id),
    )
    monkeypatch.setattr(eirs_runtime, "revise_active_answer", lambda *_args, **_kwargs: (active, revision))
    monkeypatch.setattr(eirs_runtime, "project_active_answer", lambda *_args, **_kwargs: active)
    state.audit_coverage["eirs_runtime"] = "corrupt"
    published, ids = eirs_runtime.publish_eirs_revision(
        SimpleNamespace(_adjudicate_deltas=lambda *_args: True),
        state,
        result,
    )
    assert published is True
    assert ids == (first.evidence_id, second.evidence_id)
    assert state.audit_coverage["eirs_runtime"]["typed_revision_id"] == revision.revision_id


def test_eirs_revision_spec_and_payload_validation_fail_closed(monkeypatch) -> None:
    state = _state(run_id="revision-spec")
    empty_result = SimpleNamespace(field_impacts=[])
    empty_proposal = SimpleNamespace(field_impacts=[])
    assert eirs_runtime._typed_eirs_revision(state, empty_result, empty_proposal, ["e1"]) is None

    impact = SimpleNamespace(field_path="/unknown", domain=GapDomain.PATCH, impact_kind="replace")
    result = SimpleNamespace(field_impacts=[impact])
    assert eirs_runtime._typed_eirs_revision(state, result, empty_proposal, ["e1"]) is None

    impact.field_path = "/answer"
    monkeypatch.setattr(eirs_runtime, "active_answer", lambda _state: None)
    assert eirs_runtime._typed_eirs_revision(state, result, empty_proposal, ["e1"]) is None

    original_revision_payload = eirs_runtime._revision_payload
    monkeypatch.setattr(eirs_runtime, "_revision_payload", lambda *_args: (SimpleNamespace(), None))
    impact.impact_kind = "replace"
    replacement = eirs_runtime._typed_eirs_revision(state, result, empty_proposal, ["e1"])
    assert replacement is not None
    assert replacement[0] == eirs_runtime.RevisionOperation.SUPPLEMENT
    monkeypatch.setattr(eirs_runtime, "_revision_payload", lambda *_args: (SimpleNamespace(), "target"))
    impact.impact_kind = "retract"
    retraction = eirs_runtime._typed_eirs_revision(state, result, empty_proposal, ["e1"])
    assert retraction is not None
    assert retraction[0] == eirs_runtime.RevisionOperation.RETRACT
    assert retraction[2] is None
    monkeypatch.setattr(eirs_runtime, "_revision_payload", original_revision_payload)

    active = SimpleNamespace(
        answer=SimpleNamespace(
            model_dump=lambda mode="python": {
                "findings": [{"finding_id": "bad", "evidence_ids": ["e1"]}],
                "events": [{}],
                "actors": [{}],
                "operations": [{"method": "INVALID", "path": ""}],
                "items": [{}],
            }
        )
    )
    monkeypatch.setattr(eirs_runtime, "active_answer", lambda _state: active)
    observed = SimpleNamespace(status="observed", observation_id="obs", output_refs=(), evidence_ids=())
    proposal = SimpleNamespace(proposal_id="bad-proposal", field_impacts=[])
    payload_result = SimpleNamespace(observations=[observed], field_impacts=[impact])
    assert eirs_runtime._revision_payload(
        state,
        eirs_runtime.RevisionField.FINDINGS,
        eirs_runtime.RevisionOperation.SUPPLEMENT,
        payload_result,
        proposal,
        ["e1"],
    ) == (None, None)
    assert (
        eirs_runtime._revision_payload(
            state,
            eirs_runtime.RevisionField.TIMELINE,
            eirs_runtime.RevisionOperation.SUPPLEMENT,
            payload_result,
            proposal,
            ["e1"],
        )[0]
        is not None
    )
    assert (
        eirs_runtime._revision_payload(
            state,
            eirs_runtime.RevisionField.ACTOR,
            eirs_runtime.RevisionOperation.SUPPLEMENT,
            payload_result,
            proposal,
            ["e1"],
        )[0]
        is not None
    )
    assert eirs_runtime._revision_payload(
        state,
        eirs_runtime.RevisionField.API_OPERATION,
        eirs_runtime.RevisionOperation.SUPPLEMENT,
        payload_result,
        proposal,
        ["e1"],
    ) == (None, None)
    assert (
        eirs_runtime._revision_payload(
            state,
            eirs_runtime.RevisionField.EXACT_ANSWER,
            eirs_runtime.RevisionOperation.SUPPLEMENT,
            payload_result,
            proposal,
            ["e1"],
        )[0]
        is not None
    )
    assert eirs_runtime._candidate_row(
        {"items": [{"value": "no evidence"}]}, eirs_runtime.RevisionField.EXACT_ANSWER, ["e1"]
    ) == {"value": "no evidence"}
    assert eirs_runtime._exact_values({}, observed, ["e1"], "proposal")["value"]["observation_id"] == "obs"


def test_eirs_materialize_steps_respects_budget_and_store_boundaries() -> None:
    state = _state()
    step = PlanStep(step_id="eirs-step", objective="bounded", agent_role="worker")
    state.budget = BudgetState(max_steps=1)
    assert eirs_runtime.materialize_eirs_steps(SimpleNamespace(), state, []) is False
    assert eirs_runtime.materialize_eirs_steps(SimpleNamespace(), state, [step, step]) is False

    activated = SimpleNamespace(
        investigation_store=object(),
        _activate_supplement_steps=lambda _state, _steps: True,
    )
    assert eirs_runtime.materialize_eirs_steps(activated, state, [step]) is True

    state2 = _state(run_id="materialize-no-store")
    state2.budget = BudgetState(max_steps=3)

    class Scheduler:
        def initialize(self, _state: AgentState) -> None:
            self.called = True

    scheduler = Scheduler()
    no_store = SimpleNamespace(
        investigation_store=None,
        _compile_outcome_contract=lambda item: SimpleNamespace(contract_id=f"contract-{item.step_id}"),
        dag_scheduler=scheduler,
    )
    assert eirs_runtime.materialize_eirs_steps(no_store, state2, [step]) is True
    assert state2.plan[0].outcome_contract_id == "contract-eirs-step"
    assert scheduler.called

    failing = SimpleNamespace(
        investigation_store=None,
        _compile_outcome_contract=lambda _item: (_ for _ in ()).throw(ValueError("bad contract")),
    )
    assert (
        eirs_runtime.materialize_eirs_steps(
            failing,
            state2,
            [PlanStep(step_id="other", objective="x", agent_role="worker")],
        )
        is False
    )


def test_advance_eirs_runtime_handles_terminal_corrupt_and_invalid_plans(monkeypatch) -> None:
    host = SimpleNamespace(investigation_store=None)
    for status in ("published", "blocked", "exhausted"):
        state = _state(run_id=f"terminal-{status}")
        state.audit_coverage["eirs_runtime"] = {"status": status, "marker": 1}
        scheduled, runtime = eirs_runtime.advance_eirs_runtime(host, state)
        assert scheduled is False
        assert runtime["status"] == status

    corrupt = _state(run_id="corrupt-plan")
    corrupt.audit_coverage["eirs_runtime"] = {"status": "scheduled", "plan": {"bad": True}}
    scheduled, runtime = eirs_runtime.advance_eirs_runtime(host, corrupt)
    assert scheduled is False
    assert runtime["reason"] == "gap_plan_corrupt"

    invalid_budget = _state(run_id="invalid-budget")
    monkeypatch.setattr(
        eirs_runtime,
        "compile_eirs_gap_plan",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("bad budget")),
    )
    scheduled, runtime = eirs_runtime.advance_eirs_runtime(host, invalid_budget)
    assert scheduled is False
    assert runtime == {"status": "blocked", "reason": "eirs_budget_invalid"}


def test_advance_eirs_runtime_covers_scheduled_wait_and_deterministic_paths(monkeypatch) -> None:
    state = _state(run_id="scheduled-wait")
    plan = _gap_plan(state)
    state.audit_coverage["eirs_runtime"] = {
        "status": "scheduled",
        "plan": plan.model_dump(mode="json"),
        "action_steps": {"action-1": "step-1"},
    }
    state.step_runtime = {"step-1": StepRuntime(step_id="step-1", status=StepStatus.RUNNING)}
    host = SimpleNamespace(investigation_store=None)
    scheduled, runtime = eirs_runtime.advance_eirs_runtime(host, state)
    assert scheduled is True
    assert runtime["status"] == "scheduled"

    done = _state(run_id="scheduled-done")
    done.audit_coverage["eirs_runtime"] = {
        "status": "scheduled",
        "plan": plan.model_dump(mode="json"),
        "action_steps": {"action-1": "step-1"},
        "deterministic_observations": [],
    }
    done.step_runtime = {"step-1": StepRuntime(step_id="step-1", status=StepStatus.SUCCEEDED)}
    monkeypatch.setattr(
        eirs_runtime,
        "gap_observation_for_step",
        lambda *_args: SimpleNamespace(status="observed"),
    )
    monkeypatch.setattr(
        eirs_runtime,
        "build_gap_investigation_result",
        lambda *_args: SimpleNamespace(
            model_dump=lambda mode="json": {"observations": []},
            observations=[],
            plan=plan,
            revision_proposals=[],
            field_impacts=[],
            result_digest="d" * 64,
        ),
    )
    monkeypatch.setattr(eirs_runtime, "publish_eirs_revision", lambda *_args: (False, ()))
    monkeypatch.setattr(eirs_runtime, "_record_cross_domain_pipeline", lambda *_args, **_kwargs: None)
    scheduled, runtime = eirs_runtime.advance_eirs_runtime(host, done)
    assert scheduled is False
    assert runtime["status"] == "blocked"
    assert runtime["reason"] == "verifier_or_independence_gate"

    closed = _state(run_id="closed")
    monkeypatch.setattr(eirs_runtime, "compile_eirs_gap_plan", lambda *_args, **_kwargs: None)
    scheduled, runtime = eirs_runtime.advance_eirs_runtime(host, closed)
    assert scheduled is False
    assert runtime["status"] == "closed"


@pytest.mark.asyncio
async def test_advance_eirs_runtime_materializes_deterministic_observations_and_updates_belief(monkeypatch) -> None:
    state = _state(run_id="deterministic-eirs")
    plan = _gap_plan(state)
    observation = SimpleNamespace(
        status="observed",
        model_dump=lambda mode="json": {"status": "observed"},
    )
    compiled = SimpleNamespace(plan=plan, result_digest="a" * 64)
    folded = SimpleNamespace(
        observations=[observation],
        revision_proposals=[],
        field_impacts=[],
        result_digest="b" * 64,
        model_dump=lambda mode="json": {"status": "observed"},
    )
    monkeypatch.setattr(eirs_runtime, "compile_eirs_gap_plan", lambda *_args, **_kwargs: compiled)
    monkeypatch.setattr(eirs_runtime, "gap_plan_steps", lambda *_args, **_kwargs: ([], {}, [observation]))
    monkeypatch.setattr(eirs_runtime, "build_gap_investigation_result", lambda *_args: folded)
    monkeypatch.setattr(eirs_runtime, "publish_eirs_revision", lambda *_args: (False, ()))
    monkeypatch.setattr(eirs_runtime, "_record_cross_domain_pipeline", lambda *_args, **_kwargs: None)
    schedule, runtime = eirs_runtime.advance_eirs_runtime(SimpleNamespace(investigation_store=None), state)
    assert schedule is False
    assert runtime["status"] == "blocked"
    assert runtime["reason"] == "deterministic_only"

    update_state = _state(run_id="belief-update")
    update_state.belief_state = BeliefState(belief_digest="c" * 64)
    belief = SimpleNamespace(
        belief_digest="d" * 64,
        revision=2,
        known_facts=["fact"],
        open_obligation_ids=[],
        contradictions=[],
        stagnation_count=0,
    )
    monkeypatch.setattr(eirs_runtime, "update_cognitive_belief", lambda _state: belief)
    monkeypatch.setattr(eirs_runtime, "compile_gap_plan", lambda _state: None)
    monkeypatch.setattr(eirs_runtime, "advance_eirs_runtime", lambda *_args: (False, {"status": "closed"}))

    async def checkpoint(current: AgentState, *_args: Any, **_kwargs: Any) -> dict[str, Any]:
        return {"agent": current.model_dump(mode="json")}

    host = SimpleNamespace(_state=lambda value: AgentState.model_validate(value), _checkpoint=checkpoint)
    result = await eirs_runtime.update_belief(host, update_state.model_dump(mode="json"))
    updated = AgentState.model_validate(result["agent"])
    assert updated.belief_state.belief_digest == "d" * 64
    assert updated.audit_coverage["eirs_runtime"]["status"] == "closed"


def test_advance_eirs_runtime_schedules_legal_steps(monkeypatch) -> None:
    state = _state(run_id="schedule-eirs")
    plan = _gap_plan(state)
    compiled = SimpleNamespace(plan=plan, result_digest="a" * 64)
    step = PlanStep(step_id="scheduled-step", objective="retrieve", agent_role="worker")
    deterministic = SimpleNamespace(model_dump=lambda mode="json": {"status": "observed"})
    monkeypatch.setattr(eirs_runtime, "compile_eirs_gap_plan", lambda *_args, **_kwargs: compiled)
    monkeypatch.setattr(
        eirs_runtime,
        "gap_plan_steps",
        lambda *_args, **_kwargs: ([step], {"action-1": step.step_id}, [deterministic]),
    )
    monkeypatch.setattr(eirs_runtime, "materialize_eirs_steps", lambda *_args: True)
    schedule, runtime = eirs_runtime.advance_eirs_runtime(SimpleNamespace(), state)
    assert schedule is True
    assert runtime["status"] == "scheduled"
    assert state.status == RunStatus.RUNNING


@pytest.mark.asyncio
async def test_update_belief_recomputes_after_published_eirs_revision(monkeypatch) -> None:
    state = _state(run_id="belief-published")
    state.belief_state = BeliefState(belief_digest="a" * 64)
    first = SimpleNamespace(
        belief_digest="b" * 64,
        revision=1,
        known_facts=[],
        open_obligation_ids=[],
        contradictions=[],
        stagnation_count=0,
    )
    second = SimpleNamespace(
        belief_digest="c" * 64,
        revision=2,
        known_facts=["new"],
        open_obligation_ids=[],
        contradictions=[],
        stagnation_count=0,
    )
    calls = iter([first, second])
    monkeypatch.setattr(eirs_runtime, "update_cognitive_belief", lambda _state: next(calls))
    monkeypatch.setattr(eirs_runtime, "compile_gap_plan", lambda _state: None)
    monkeypatch.setattr(eirs_runtime, "advance_eirs_runtime", lambda *_args: (False, {"status": "published"}))

    async def checkpoint(current: AgentState, *_args: Any, **_kwargs: Any) -> dict[str, Any]:
        return {"agent": current.model_dump(mode="json")}

    host = SimpleNamespace(_state=lambda value: AgentState.model_validate(value), _checkpoint=checkpoint)
    result = await eirs_runtime.update_belief(host, state.model_dump(mode="json"))
    updated = AgentState.model_validate(result["agent"])
    assert updated.belief_state.belief_digest == "c" * 64
    assert updated.belief_state.revision == 2


def test_eirs_metric_and_semantic_helpers_are_monotonic() -> None:
    state = _state(run_id="semantic-pipeline", scenario=Scenario.LOG_ANALYSIS)
    evidence = _evidence("semantic-evidence")
    state.evidence = [evidence]
    claim = make_claim(
        claim_type="event",
        statement="event",
        subject_ref="event",
        producer="deterministic",
        confidence=1,
    ).model_copy(update={"status": ClaimStatus.VERIFIED})
    state.claims = [claim]
    state.evidence_links = [make_link(claim_id=claim.claim_id, evidence_id=evidence.evidence_id)]
    state.audit_coverage["scenario_semantic_delta"] = {
        "scenario": "log_analysis",
        "answer_kind": "timeline",
        "facts": [{"event_id": "event"}],
        "evidence_ids": [evidence.evidence_id],
        "delta_id": "d1",
        "disposition": "accepted",
        "admission_ready": True,
    }
    state.report = AgentReport(
        run_id=state.run_id,
        status=RunStatus.PARTIAL,
        executive_summary="semantic",
        answer_payload={"semantic_delta": {"delta_id": "d1"}},
    )
    eirs_runtime._record_current_semantic_pipeline(state)
    assert eirs_runtime._metric_int(True) == 0
    assert eirs_runtime._metric_int(-1) == 0
    assert eirs_runtime._metric_int(2) == 2
    fields = eirs_runtime._pipeline_runtime_fields(state)
    assert fields["accepted_delta_count"] == 1
    eirs_runtime._write_cross_domain_pipeline(state, {"log": {"candidate_count": 1, "verified_count": 1}})
    assert state.report.coverage["cross_domain_capability_pipeline"]["candidate_count"] == 1
