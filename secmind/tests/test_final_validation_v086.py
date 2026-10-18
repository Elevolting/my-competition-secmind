from __future__ import annotations

from hashlib import sha256
from uuid import NAMESPACE_URL, uuid5

import pytest

from secmind.final_validation import (
    build_exact_answer_attestation,
    build_final_validation,
    validate_final_validation_payload,
)
from secmind.integrations.test3 import trusted_exact_answer_values
from secmind.investigation.contracts import (
    CompletionOutcome,
    CompletionReceipt,
    CompletionSnapshotV2,
    seal_contract,
)
from secmind.orchestration.obligation_runtime import refresh_obligation_set
from secmind.schemas import (
    AgentReport,
    AgentState,
    Claim,
    ClaimStatus,
    Evidence,
    EvidenceLink,
    EvidenceRelation,
    Finding,
    RunStatus,
    Scenario,
    TaskRequest,
    TaskSpecRef,
)
from secmind.task_contract import canonical_digest, compile_resolved_task_contract


def _validated_state() -> AgentState:
    state = AgentState(
        run_id="run-final-validation-v086",
        task=TaskRequest(objective="extract the exact value"),
        scenario=Scenario.API_ASSESSMENT,
        status=RunStatus.COMPLETED,
    )
    contract = compile_resolved_task_contract(
        {
            "task_spec_id": "task-final-validation-v086",
            "run_id": state.run_id,
            "revision": 1,
            "content_digest": "a" * 64,
            "objectives": ["extract the exact value"],
            "primary_scenario": "api_assessment",
            "primary_domain": "complex_input_understanding",
            "secondary_scenarios": [],
            "secondary_capabilities": [],
            "scoring_mode": "exact_answer_with_evidence",
            "interaction_mode": "unattended",
            "authorized_scope": ["artifact:fixture"],
            "asset_ids": ["fixture"],
        },
        input_manifest_digest="b" * 64,
    )
    state.resolved_task_contract = contract
    state.task_spec_ref = TaskSpecRef(
        task_spec_id=contract.task_spec_id,
        revision=contract.task_spec_revision,
        content_digest=contract.task_spec_digest,
    )
    answer = {
        "answer_kind": "exact_answer",
        "execution_status": "success",
        "epistemic_status": "conclusive",
        "values": {"answer": 42},
        "source_offsets": [{"source_ref": "artifact:fixture", "offset": 0, "evidence_ids": ["evidence-v086"]}],
    }
    refresh_obligation_set(state, answer)
    state.evidence = [
        Evidence(
            evidence_id="evidence-v086",
            source="secmind:test",
            summary="The exact value was read from immutable fixture bytes.",
            artifact_ref="b" * 64,
            sha256="b" * 64,
        )
    ]
    state.claims = [
        Claim(
            claim_id="claim-v086",
            claim_type="exact_value_binding",
            statement="The exact value is bound to immutable fixture bytes.",
            subject_ref="answer:42",
            status=ClaimStatus.VERIFIED,
            confidence=1.0,
            producer="deterministic-test-verifier",
        )
    ]
    state.evidence_links = [
        EvidenceLink(
            link_id="link-v086",
            claim_id="claim-v086",
            evidence_id="evidence-v086",
            relation=EvidenceRelation.SUPPORTS,
            verifier_status=ClaimStatus.VERIFIED,
            grader_id="deterministic-test-verifier",
        )
    ]
    snapshot = seal_contract(
        CompletionSnapshotV2,
        digest_field="snapshot_digest",
        snapshot_id="snapshot-v086",
        run_id=state.run_id,
        run_state_version=state.state_version,
        run_fence=1,
        quiet_epoch=1,
        input_integrity=True,
        artifact_integrity=True,
        evidence_integrity=True,
        ledger_integrity=True,
        requirement_obligations=[],
        report_claim_ids=["claim-v086"],
    )
    receipt = seal_contract(
        CompletionReceipt,
        digest_field="receipt_digest",
        receipt_id="receipt-v086",
        run_id=state.run_id,
        snapshot_id=snapshot.snapshot_id,
        decision=CompletionOutcome.COMPLETE,
        satisfied_obligation_ids=[],
        unsatisfied_obligation_ids=[],
        gate_rule_version="test-v086",
    )
    state.completion_snapshot_id = snapshot.snapshot_id
    state.completion_receipt_id = receipt.receipt_id
    state.audit_coverage["completion_proof"] = {
        "snapshot": snapshot.model_dump(mode="json"),
        "receipt": receipt.model_dump(mode="json"),
    }
    state.report = AgentReport(
        run_id=state.run_id,
        status=RunStatus.COMPLETED,
        executive_summary="The exact value is 42.",
        answer_type="exact_answer",
        answer_payload=answer,
        evidence=list(state.evidence),
    )
    return state


def test_final_validation_reports_only_properties_it_can_prove() -> None:
    state = _validated_state()
    assert state.report is not None

    receipt = build_final_validation(state, state.report)

    assert receipt["status"] == "passed"
    assert receipt["model_independent"] is True
    assert receipt["semantic_model_independence"] is False
    assert all(receipt["checks"].values())
    assert receipt["input_manifest_digest"] == "b" * 64
    assert len(receipt["validation_digest"]) == 64


def test_final_validation_fails_closed_on_missing_public_evidence_reference() -> None:
    state = _validated_state()
    assert state.report is not None
    state.report = state.report.model_copy(
        update={
            "answer_payload": {
                **state.report.answer_payload,
                "items": [{"evidence_ids": ["missing-evidence"]}],
            }
        }
    )

    receipt = build_final_validation(state, state.report)

    assert receipt["status"] == "partial"
    assert receipt["checks"]["evidence_reference_closure"] is False
    assert receipt["missing_evidence_ids"] == ["missing-evidence"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("evidence_id", "custom-reference-without-a-prefix"),
        ("evidence_ids", ["custom-reference-without-a-prefix"]),
        ("evidence_refs", ["custom-reference-without-a-prefix"]),
        ("source_evidence_ids", ["custom-reference-without-a-prefix"]),
        ("supporting_evidence_ids", ["custom-reference-without-a-prefix"]),
    ],
)
def test_final_validation_treats_every_explicit_reference_field_as_authoritative(
    field: str,
    value: object,
) -> None:
    state = _validated_state()
    assert state.report is not None
    state.report = state.report.model_copy(update={"answer_payload": {**state.report.answer_payload, field: value}})

    receipt = build_final_validation(state, state.report)

    assert receipt["status"] == "partial"
    assert receipt["checks"]["evidence_reference_closure"] is False
    assert "custom-reference-without-a-prefix" in receipt["missing_evidence_ids"]


@pytest.mark.parametrize("field", ["evidence", "supporting_evidence"])
def test_final_validation_ignores_bare_natural_language_evidence_fields(field: str) -> None:
    state = _validated_state()
    assert state.report is not None
    state.report = state.report.model_copy(
        update={"answer_payload": {**state.report.answer_payload, field: ["prose, not an evidence ID"]}}
    )

    receipt = build_final_validation(state, state.report)

    assert receipt["status"] == "passed"
    assert receipt["checks"]["evidence_reference_closure"] is True


def test_final_validation_never_passes_for_non_completed_or_unverified_output() -> None:
    state = _validated_state()
    assert state.report is not None
    state.status = RunStatus.PARTIAL
    state.report = state.report.model_copy(update={"status": RunStatus.PARTIAL})
    assert build_final_validation(state, state.report)["status"] == "partial"

    state = _validated_state()
    assert state.report is not None
    state.claims = []
    state.evidence_links = []
    receipt = build_final_validation(state, state.report)
    assert receipt["status"] == "partial"
    assert receipt["checks"]["verified_support_chain_present"] is False


def test_final_validation_rejects_tampered_completion_proof() -> None:
    state = _validated_state()
    assert state.report is not None
    proof = dict(state.audit_coverage["completion_proof"])
    proof["receipt"] = {**proof["receipt"], "run_id": "another-run"}
    state.audit_coverage["completion_proof"] = proof

    receipt = build_final_validation(state, state.report)

    assert receipt["status"] == "partial"
    assert receipt["checks"]["completion_proof_valid"] is False


def test_public_validation_contract_rejects_self_digested_lookalikes() -> None:
    lookalike = {
        "schema_version": "secmind-final-validation-v1",
        "validator_id": "secmind-deterministic-contract-evidence-verifier",
        "semantic_model_independence": False,
    }
    lookalike["validation_digest"] = canonical_digest(lookalike)

    valid, reason = validate_final_validation_payload(lookalike)

    assert valid is False
    assert reason == "validation receipt is not a deterministic runtime projection"


def test_public_validation_contract_rejects_status_that_disagrees_with_checks() -> None:
    state = _validated_state()
    assert state.report is not None
    receipt = build_final_validation(state, state.report)
    receipt["checks"]["typed_answer_present"] = False
    receipt["validation_digest"] = canonical_digest(
        {key: value for key, value in receipt.items() if key != "validation_digest"}
    )

    valid, reason = validate_final_validation_payload(receipt)

    assert valid is False
    assert reason == "validation status conflicts with its checks"


def test_public_validation_rejects_tampered_manifest_or_receipt_digest() -> None:
    state = _validated_state()
    assert state.report is not None
    receipt = build_final_validation(state, state.report)

    tampered_manifest = dict(receipt)
    tampered_manifest["input_manifest_digest"] = "c" * 64
    valid, reason = validate_final_validation_payload(tampered_manifest)
    assert valid is False
    assert reason == "validation digest mismatch"

    tampered_receipt_digest = dict(receipt)
    tampered_receipt_digest["validation_digest"] = "0" * 64
    valid, reason = validate_final_validation_payload(tampered_receipt_digest)
    assert valid is False
    assert reason == "validation digest mismatch"


def test_required_verified_evidence_and_support_claims_are_projected_before_stable_fill() -> None:
    """A required exact reference must not be lost behind the 1,000-item cap."""

    state = _validated_state()
    assert state.report is not None
    filler_evidence = [
        Evidence(
            evidence_id=f"evidence-{index:04d}",
            source="secmind:filler",
            summary="A verified non-required evidence row.",
            artifact_ref="b" * 64,
            sha256="b" * 64,
        )
        for index in range(1_000)
    ]
    filler_claims = [
        Claim(
            claim_id=f"claim-{index:04d}",
            claim_type="filler_binding",
            statement="A verified non-required claim.",
            subject_ref=f"evidence-{index:04d}",
            status=ClaimStatus.VERIFIED,
            confidence=1.0,
            producer="deterministic-test-verifier",
        )
        for index in range(1_000)
    ]
    filler_links = [
        EvidenceLink(
            link_id=f"link-{index:04d}",
            claim_id=f"claim-{index:04d}",
            evidence_id=f"evidence-{index:04d}",
            relation=EvidenceRelation.SUPPORTS,
            verifier_status=ClaimStatus.VERIFIED,
            grader_id="deterministic-test-verifier",
        )
        for index in range(1_000)
    ]
    state.evidence.extend(filler_evidence)
    state.claims.extend(filler_claims)
    state.evidence_links.extend(filler_links)
    state.report = state.report.model_copy(update={"evidence": list(state.evidence)})

    receipt = build_final_validation(state, state.report)

    assert receipt["status"] == "passed"
    assert receipt["required_evidence_projection_overflow"] is False
    assert receipt["verified_evidence_ids"][0] == "evidence-v086"
    assert receipt["verified_claim_ids"][0] == "claim-v086"
    assert len(receipt["verified_evidence_ids"]) == 1_000
    assert len(receipt["verified_claim_ids"]) == 1_000
    valid, reason = validate_final_validation_payload(receipt)
    assert valid is True
    assert reason is None


def test_required_evidence_projection_overflow_is_terminal_fail_closed() -> None:
    state = _validated_state()
    assert state.report is not None
    overflow_ids = [f"required-evidence-{index:04d}" for index in range(1_001)]
    finding = (
        state.report.findings[0]
        if state.report.findings
        else Finding(
            rule_id="TEST-REQUIRED-CLOSURE",
            path="fixture",
            title="Required closure overflow",
            description="Synthetic bounded-receipt regression.",
            evidence_ids=overflow_ids,
        )
    )
    if state.report.findings:
        finding = finding.model_copy(update={"evidence_ids": overflow_ids})
    state.report = state.report.model_copy(update={"findings": [finding]})

    receipt = build_final_validation(state, state.report)

    assert receipt["status"] == "partial"
    assert receipt["required_evidence_projection_overflow"] is True
    assert receipt["checks"]["required_evidence_verified"] is False
    assert any("bounded public receipt capacity" in item for item in receipt["limitations"])
    valid, reason = validate_final_validation_payload(receipt)
    assert valid is True
    assert reason is None


def test_bounded_projection_keeps_runtime_verified_exact_answer_trusted() -> None:
    """The raw server report remains a valid exact release after projection."""

    state = _validated_state()
    assert state.report is not None
    exact_value = "exact-value-v086"
    artifact_digest = "a" * 64
    byte_offset = 7
    evidence_id = str(uuid5(NAMESPACE_URL, f"secmind:exact-source:{artifact_digest}:{byte_offset}:{exact_value}"))
    locator = {"source_ref": "fixture.bin", "byte_offset": byte_offset, "byte_length": len(exact_value)}
    attestation = build_exact_answer_attestation(
        run_id=state.run_id,
        input_manifest_digest="b" * 64,
        evidence_id=evidence_id,
        value_sha256=sha256(exact_value.encode("utf-8")).hexdigest(),
        artifact_sha256=artifact_digest,
        locator=locator,
    )
    assert attestation is not None
    exact_evidence = Evidence(
        evidence_id=evidence_id,
        source="deterministic_exact_source@1.0",
        summary="A deterministic exact observation from the fixture.",
        artifact_ref=artifact_digest,
        sha256=artifact_digest,
        metadata={
            "evidence_type": "exact_value_observation",
            "source_artifact_sha256": artifact_digest,
            "value_sha256": sha256(exact_value.encode("utf-8")).hexdigest(),
            "source_locator": locator,
            "input_manifest_digest": "b" * 64,
            "run_id": state.run_id,
            "verification_status": "verified_support",
            "claim_refs": ["claim-v086"],
            "exact_answer_attestation": attestation,
        },
    )
    state.evidence = [exact_evidence]
    state.evidence_links[0] = state.evidence_links[0].model_copy(update={"evidence_id": evidence_id})
    answer = {
        "answer_kind": "exact",
        "answer_type": "exact",
        "values": [exact_value],
        "items": [{"value": exact_value, "evidence_ids": [evidence_id]}],
    }
    state.report = state.report.model_copy(
        update={"answer_type": "exact", "answer_payload": answer, "evidence": list(state.evidence)}
    )

    filler_evidence = [
        Evidence(
            evidence_id=f"evidence-{index:04d}",
            source="secmind:filler",
            summary="A verified non-required evidence row.",
            artifact_ref=artifact_digest,
            sha256=artifact_digest,
        )
        for index in range(1_000)
    ]
    filler_claims = [
        Claim(
            claim_id=f"claim-{index:04d}",
            claim_type="filler_binding",
            statement="A verified non-required claim.",
            subject_ref=f"evidence-{index:04d}",
            status=ClaimStatus.VERIFIED,
            confidence=1.0,
            producer="deterministic-test-verifier",
        )
        for index in range(1_000)
    ]
    filler_links = [
        EvidenceLink(
            link_id=f"link-{index:04d}",
            claim_id=f"claim-{index:04d}",
            evidence_id=f"evidence-{index:04d}",
            relation=EvidenceRelation.SUPPORTS,
            verifier_status=ClaimStatus.VERIFIED,
            grader_id="deterministic-test-verifier",
        )
        for index in range(1_000)
    ]
    state.evidence.extend(filler_evidence)
    state.claims.extend(filler_claims)
    state.evidence_links.extend(filler_links)
    state.report = state.report.model_copy(update={"evidence": list(state.evidence)})
    receipt = build_final_validation(state, state.report)
    assert receipt["status"] == "passed"
    assert receipt["verified_evidence_ids"][0] == evidence_id

    public_report = state.report.model_dump(mode="json")
    public_report["coverage"] = {
        "final_validation_required": True,
        "final_validation_receipt_digest": receipt["validation_digest"],
        "final_validation_validator_id": receipt["validator_id"],
    }
    public_report["verification_summary"] = receipt
    task = {"required_output": {"scoring_mode": "exact_answer_with_evidence"}}

    trusted = trusted_exact_answer_values(answer, public_report, task, report=public_report)

    assert trusted == frozenset({exact_value})
