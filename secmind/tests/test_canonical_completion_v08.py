from __future__ import annotations

import hashlib
from pathlib import Path

from conftest import seal_execution_contract

from secmind.artifact_store import ContentAddressedArtifactStore
from secmind.canonical_primary import canonical_input_manifest, canonical_manifest_digest
from secmind.evidence_gap import EvidenceGapCompiler
from secmind.evidence_graph import EvidenceGraph, make_claim, make_link
from secmind.investigation.contracts import CompletionOutcome, ObligationStatus
from secmind.investigation.evidence import DeterministicCompletionEvaluator, ReplanContext
from secmind.orchestration.evidence_projection import (
    build_investigation_evidence_graph,
    build_requirement_obligations,
    seal_canonical_primary_policy,
)
from secmind.orchestration.obligation_runtime import (
    critical_investigation_requirements,
    refresh_obligation_set,
)
from secmind.orchestrator import SecMindOrchestrator
from secmind.primary_baseline import publish_primary_baseline
from secmind.schemas import (
    AgentState,
    ClaimStatus,
    Evidence,
    Finding,
    InputArtifact,
    RepositoryIndexRef,
    RunStatus,
    Scenario,
    TaskRequest,
)
from secmind.task_contract import canonical_digest as task_contract_digest
from secmind.task_contract import resolved_contract_digest

_INPUT_SHA = "a" * 64
_SNAPSHOT_SHA = "b" * 64
_CONTEXT_SHA = "c" * 64


def _canonical_state(*, high_finding: bool = False, response_sha256: str = "d" * 64) -> AgentState:
    artifact = InputArtifact(
        artifact_id="input-app",
        original_name="app.py",
        relative_path="project/app.py",
        sha256=_INPUT_SHA,
        size_bytes=24,
        media_type="text/x-python",
    )
    manifest = canonical_input_manifest([artifact])
    evidence: list[Evidence] = []
    findings: list[Finding] = []
    claims = []
    links = []
    if high_finding:
        item = Evidence(
            evidence_id="primary-flow",
            source="secmind:canonical-primary:deepseek-v4-flash",
            summary="request data reaches eval",
            artifact_ref=_INPUT_SHA,
            sha256=_INPUT_SHA,
            metadata={
                "evidence_type": "canonical_primary_finding",
                "assurance_level": "model_proposed",
                "path": "app.py",
                "line": 1,
            },
        )
        finding = Finding(
            finding_id="primary-high",
            rule_id="CWE-95",
            severity="HIGH",
            confidence="HIGH",
            path="app.py",
            line=1,
            title="Unsafe evaluation",
            description="Untrusted request data reaches eval.",
            remediation="Use a strict parser.",
            evidence_ids=[item.evidence_id],
            raw={
                "canonical_primary": True,
                "data_flow": "request -> eval",
                "root_cause": "dynamic evaluation of request data",
                "attack_path_summary": "remote request controls an expression",
                "preconditions": ["the endpoint is reachable"],
                "impact": "arbitrary code execution",
            },
        )
        claim = make_claim(
            claim_type="canonical_primary.baseline_binding",
            statement="The Primary finding is bound to immutable input bytes; semantics remain model-proposed.",
            subject_ref=finding.finding_id,
            producer="canonical-primary",
            severity="HIGH",
            confidence=0.9,
        ).model_copy(update={"status": ClaimStatus.VERIFIED})
        link = make_link(
            claim_id=claim.claim_id,
            evidence_id=item.evidence_id,
            grader_id="canonical-primary-provenance-binding-v1",
        ).model_copy(update={"verifier_status": ClaimStatus.VERIFIED})
        evidence = [item]
        findings = [finding]
        claims = [claim]
        links = [link]

    coverage = {
        "canonical_primary_completed": True,
        "canonical_primary_status": "completed",
        "primary_answer_status": "completed",
        "context_sha256": _CONTEXT_SHA,
        "input_manifest_digest": canonical_manifest_digest(manifest),
        "repository_snapshot_digest": _SNAPSHOT_SHA,
        "input_count": 1,
        "viewed_count": 1,
        "omitted_count": 0,
        "negative_coverage_complete": not findings,
    }
    state = AgentState(
        run_id="run-canonical-completion-v08",
        task=TaskRequest(
            objective="Audit the supplied Python source",
            target_scope=["."],
            autonomy_policy="automatic",
        ),
        scenario=Scenario.CODE_AUDIT,
        status=RunStatus.RUNNING,
        input_artifacts=[artifact],
        repository_index=RepositoryIndexRef(
            index_id="repository-index",
            run_id="run-canonical-completion-v08",
            artifact_id=_SNAPSHOT_SHA,
            digest=_SNAPSHOT_SHA,
            file_count=1,
            total_bytes=artifact.size_bytes,
            languages=["python"],
        ),
        findings=findings,
        evidence=evidence,
        claims=claims,
        evidence_links=links,
        audit_coverage=coverage,
    )
    seal_execution_contract(state)
    contract = state.resolved_task_contract
    assert contract is not None
    contract_payload = contract.model_dump(mode="json", exclude={"contract_digest"})
    contract_payload["input_manifest_digest"] = task_contract_digest(
        [
            {
                "artifact_id": item.artifact_id,
                "relative_path": item.relative_path,
                "sha256": item.sha256.lower(),
                "size_bytes": item.size_bytes,
                "media_type": item.media_type,
            }
            for item in state.input_artifacts
        ]
    )
    contract_payload["contract_digest"] = resolved_contract_digest(contract_payload)
    state.resolved_task_contract = type(contract).model_validate(contract_payload)
    seal_canonical_primary_policy(state, network_enabled=True)
    publish_primary_baseline(
        state,
        model_id="deepseek-v4-flash",
        prompt_version="secmind-canonical-primary-v2",
        prompt_artifact_id=None,
        request_sha256="e" * 64,
        response_sha256=response_sha256,
        response_schema_sha256="f" * 64,
        context_sha256=_CONTEXT_SHA,
        response_artifact_id=response_sha256,
        provider_requests=1,
        input_tokens=100,
        output_tokens=40,
        cost_units=0.01,
        status=RunStatus.COMPLETED,
        executive_summary="Canonical Primary completed.",
        findings=findings,
        evidence=evidence,
        decisions=[],
        limitations=[],
        coverage=coverage,
        bound_finding_ids={item.finding_id for item in findings},
    )
    return state


def _evaluate(state: AgentState):
    refresh_obligation_set(
        state,
        {
            "findings": [item.model_dump(mode="json") for item in state.findings],
            "checked_paths": [item.relative_path for item in state.input_artifacts],
            "negative_evidence": ([] if state.findings else ["complete immutable-source review"]),
        },
        evidence_ids=[item.evidence_id for item in state.evidence],
    )
    graph = EvidenceGraph(claims=state.claims, evidence=state.evidence, links=state.evidence_links)
    evidence_graph = build_investigation_evidence_graph(state, graph)
    obligations = build_requirement_obligations(state, evidence_graph)
    critical_obligations = critical_investigation_requirements(state, obligations)
    evaluator = DeterministicCompletionEvaluator()
    snapshot = evaluator.build_snapshot(
        snapshot_id="snapshot-canonical-v08",
        run_id=state.run_id,
        run_state_version=state.state_version,
        run_fence=1,
        quiet_epoch=1,
        input_integrity=True,
        artifact_integrity=True,
        evidence_integrity=True,
        ledger_integrity=True,
        requirement_obligations=[item.obligation_id for item in critical_obligations],
    )
    evaluation = evaluator.evaluate(
        snapshot,
        obligations=critical_obligations,
        evidence_graph=evidence_graph,
        # High-risk second-source assurance is an optional enhancement.  The
        # runtime records it separately rather than feeding it into the
        # status-authoritative completion evaluator.
        findings=[],
        replan_context=ReplanContext(
            budget_available=False,
            approved_independent_source_available=False,
        ),
    )
    return obligations, evaluation


def test_complete_zero_finding_primary_has_a_proven_negative_coverage_obligation() -> None:
    state = _canonical_state()
    obligations, evaluation = _evaluate(state)

    assert EvidenceGapCompiler().gap_codes(state) == ()
    assert {item.source_type for item in obligations} == {
        "canonical_primary_baseline",
        "resolved_task_contract",
        "task_obligation_set_receipt",
    }
    canonical = next(item for item in obligations if item.source_type == "canonical_primary_baseline")
    assert canonical.status == ObligationStatus.SATISFIED
    assert canonical.satisfied_by_evidence_ids
    assert evaluation.outcome == CompletionOutcome.COMPLETE
    assert evaluation.gaps == ()


def test_model_only_high_primary_preserves_baseline_and_keeps_assurance_gap_optional() -> None:
    state = _canonical_state(high_finding=True)
    obligations, evaluation = _evaluate(state)

    assert [item.finding_id for item in state.published_baseline.findings] == ["primary-high"]
    assert {item.source_type for item in obligations} == {
        "canonical_primary_baseline",
        "high_risk_finding",
        "resolved_task_contract",
        "task_obligation_set_receipt",
    }
    statuses = {item.source_type: item.status for item in obligations}
    assert statuses["canonical_primary_baseline"] == ObligationStatus.SATISFIED
    assert statuses["high_risk_finding"] == ObligationStatus.UNVERIFIED
    assert evaluation.outcome == CompletionOutcome.COMPLETE


def test_primary_completion_fails_closed_when_the_input_manifest_drifts() -> None:
    state = _canonical_state()
    state.input_artifacts[0].sha256 = "9" * 64

    obligations, evaluation = _evaluate(state)

    canonical = next(item for item in obligations if item.source_type == "canonical_primary_baseline")
    assert canonical.status == ObligationStatus.UNVERIFIED
    assert evaluation.outcome == CompletionOutcome.PARTIAL


def test_required_primary_baseline_cannot_disappear_from_recovery_state() -> None:
    state = _canonical_state()
    state.published_baseline = None
    state.baseline_admission = None
    state.raw_primary_receipt = None

    obligations, evaluation = _evaluate(state)

    assert len(obligations) == 3
    canonical = next(item for item in obligations if item.source_type == "canonical_primary_baseline")
    assert canonical.source_ref == "missing-required-primary-baseline"
    assert canonical.status == ObligationStatus.UNVERIFIED
    assert evaluation.outcome == CompletionOutcome.PARTIAL


def test_explicit_deterministic_only_run_does_not_invent_a_primary_obligation() -> None:
    state = _canonical_state()
    state.published_baseline = None
    state.baseline_admission = None
    state.raw_primary_receipt = None
    seal_canonical_primary_policy(state, network_enabled=False)

    obligations, evaluation = _evaluate(state)

    assert {item.source_type for item in obligations} == {
        "resolved_task_contract",
        "task_obligation_set_receipt",
    }
    task_receipt = next(item for item in obligations if item.source_type == "task_obligation_set_receipt")
    assert task_receipt.status == ObligationStatus.SATISFIED
    assert evaluation.outcome == CompletionOutcome.COMPLETE


def test_unsealed_deterministic_only_marker_cannot_waive_required_primary() -> None:
    state = _canonical_state()
    state.published_baseline = None
    state.baseline_admission = None
    state.raw_primary_receipt = None
    # Simulate stale/corrupt recovery state changing only the legacy display
    # marker while the run-bound policy receipt remains required.
    state.audit_coverage["canonical_primary_policy"] = "deterministic_only"

    obligations, evaluation = _evaluate(state)

    canonical = next(item for item in obligations if item.source_type == "canonical_primary_baseline")
    assert canonical.status == ObligationStatus.UNVERIFIED
    assert evaluation.outcome == CompletionOutcome.PARTIAL


def test_deterministic_only_completion_ignores_the_legacy_display_marker() -> None:
    state = _canonical_state()
    state.published_baseline = None
    state.baseline_admission = None
    state.raw_primary_receipt = None
    seal_canonical_primary_policy(state, network_enabled=False)
    state.audit_coverage["canonical_primary_policy"] = "untrusted-display-value"

    obligations, evaluation = _evaluate(state)

    assert {item.source_type for item in obligations} == {
        "resolved_task_contract",
        "task_obligation_set_receipt",
    }
    assert evaluation.outcome == CompletionOutcome.COMPLETE


def test_missing_or_corrupt_policy_receipt_cannot_waive_required_primary() -> None:
    for mutation in ("missing", "bad-digest", "inconsistent-policy"):
        state = _canonical_state()
        state.published_baseline = None
        state.baseline_admission = None
        state.raw_primary_receipt = None
        seal_canonical_primary_policy(state, network_enabled=False)
        if mutation == "missing":
            state.audit_coverage.pop("canonical_primary_policy_receipt")
        elif mutation == "bad-digest":
            state.audit_coverage["canonical_primary_policy_receipt"]["receipt_digest"] = "0" * 64
        else:
            receipt = state.audit_coverage["canonical_primary_policy_receipt"]
            receipt["policy"] = "required"
            receipt_payload = {key: value for key, value in receipt.items() if key != "receipt_digest"}
            # Re-digest the tampered payload to prove that the semantic
            # network/policy consistency check is independent of integrity.
            receipt["receipt_digest"] = task_contract_digest(receipt_payload)

        obligations, evaluation = _evaluate(state)

        canonical = next(item for item in obligations if item.source_type == "canonical_primary_baseline")
        assert canonical.status == ObligationStatus.UNVERIFIED, mutation
        assert evaluation.outcome == CompletionOutcome.PARTIAL, mutation


def test_deterministic_only_policy_receipt_fails_closed_when_manifest_drifts() -> None:
    state = _canonical_state()
    state.published_baseline = None
    state.baseline_admission = None
    state.raw_primary_receipt = None
    seal_canonical_primary_policy(state, network_enabled=False)
    state.input_artifacts[0].sha256 = "9" * 64

    obligations, evaluation = _evaluate(state)

    canonical = next(item for item in obligations if item.source_type == "canonical_primary_baseline")
    assert canonical.status == ObligationStatus.UNVERIFIED
    assert evaluation.outcome == CompletionOutcome.PARTIAL


def test_primary_receipt_requires_the_durable_raw_response_artifact(tmp_path: Path) -> None:
    raw_response = b'{"status":"completed","findings":[]}'
    response_sha256 = hashlib.sha256(raw_response).hexdigest()
    state = _canonical_state(response_sha256=response_sha256)
    store = ContentAddressedArtifactStore(tmp_path / "artifacts")
    stored = store.put(raw_response, run_id=state.run_id)
    orchestrator = object.__new__(SecMindOrchestrator)
    orchestrator.artifact_store = store

    assert stored.artifact_id == response_sha256
    assert orchestrator._verify_primary_receipt_artifact(state)  # noqa: SLF001

    store.path_for(stored.artifact_id).unlink()
    assert not orchestrator._verify_primary_receipt_artifact(state)  # noqa: SLF001
