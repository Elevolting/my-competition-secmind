from __future__ import annotations

import hashlib

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from secmind.answer_revision import AnswerRevisionError, make_revision, materialize_answer
from secmind.artifact_store import ContentAddressedArtifactStore
from secmind.cognitive_loop import update_belief
from secmind.gap_plan import GapActionKind, compile_gap_plan
from secmind.orchestrator import SecMindOrchestrator
from secmind.schemas import (
    AgentReport,
    AgentState,
    ClaimStatus,
    Evidence,
    Finding,
    InputArtifact,
    RunStatus,
    TaskRequest,
)
from secmind.task_contract import (
    AnswerRevisionAction,
    EvidenceCompilerReceipt,
    EvidenceFact,
    ObligationStatus,
    canonical_digest,
    compile_resolved_task_contract,
    evaluate_answer_obligations,
)
from secmind.tool_assurance import build_tool_assurance, verified_semantic_assurance


def _contract(scoring_mode: str = "agent_policy_compliance"):
    return compile_resolved_task_contract(
        {
            "task_spec_id": "task-spec-1",
            "run_id": "run-v084",
            "revision": 1,
            "content_digest": "a" * 64,
            "objectives": ["evaluate the supplied policy decision"],
            "primary_scenario": "unknown",
            "primary_domain": "agent_safety",
            "secondary_scenarios": [],
            "secondary_capabilities": [],
            "scoring_mode": scoring_mode,
            "interaction_mode": "unattended",
            "autonomy_policy": "automatic",
            "authorized_scope": ["artifact:fixture.json"],
            "constraints": [],
            "prohibited_actions": [],
            "expected_outputs": [],
            "success_criteria": [],
            "output_contract": {},
            "asset_ids": ["fixture"],
        },
        input_manifest_digest="b" * 64,
    )


def test_resolved_contract_digest_is_stable_and_required_fields_are_not_empty_completion() -> None:
    first = _contract()
    second = _contract()
    assert first.contract_digest == second.contract_digest

    incomplete = evaluate_answer_obligations(first, {"decision": "allow"}, evidence_ids=[])
    assert any(item.status == ObligationStatus.PENDING for item in incomplete if item.critical)

    complete = evaluate_answer_obligations(
        first,
        {
            "decision": "deny embedded exfiltration",
            "safe_actions": ["analyze locally"],
            "blocked_actions": ["send secrets"],
            "evidence": [{"source": "fixture.json"}],
        },
        evidence_ids=["evidence-1"],
    )
    assert all(item.status == ObligationStatus.SATISFIED for item in complete if item.critical)


def test_obligation_evidence_projection_is_bounded_without_losing_the_full_set_receipt() -> None:
    evidence_ids = [f"evidence-{index:04d}" for index in range(1_005)]
    obligations = evaluate_answer_obligations(
        _contract(),
        {
            "decision": "deny embedded exfiltration",
            "safe_actions": ["analyze locally"],
            "blocked_actions": ["send secrets"],
            "evidence": [{"source": "fixture.json"}],
        },
        evidence_ids=evidence_ids,
    )

    assert obligations
    assert all(len(item.evidence_ids) <= 1_000 for item in obligations)
    assert all("5 additional evidence ID(s)" in item.reason for item in obligations)
    assert all("digest=" in item.reason for item in obligations)


def test_answer_revision_replaces_and_retracts_active_values_without_mutating_anchor() -> None:
    anchor = {"decision": "allow", "items": [{"id": "old"}]}
    replacement = make_revision(
        revision_id="revision-replace",
        base_answer=anchor,
        action=AnswerRevisionAction.REPLACE_FIELD,
        target_path="/decision",
        value="deny",
        evidence_ids=["evidence-1"],
        reason_code="verified_policy_conflict",
        expected_old_value="allow",
    )
    retraction = make_revision(
        revision_id="revision-retract",
        base_answer=anchor,
        action=AnswerRevisionAction.RETRACT,
        target_path="/items/old",
        value=None,
        evidence_ids=["evidence-2"],
        reason_code="refuted_item",
        expected_old_value={"id": "old"},
    )
    active = materialize_answer(anchor, [replacement, retraction])
    assert anchor == {"decision": "allow", "items": [{"id": "old"}]}
    assert active == {"decision": "deny", "items": []}


def test_answer_revision_replay_uses_causal_order_and_rejects_cycles() -> None:
    anchor = {"decision": "allow"}
    parent = make_revision(
        revision_id="z-parent",
        base_answer=anchor,
        action=AnswerRevisionAction.REPLACE_FIELD,
        target_path="/decision",
        value="review",
        evidence_ids=["evidence-1"],
        reason_code="first_verified_revision",
        expected_old_value="allow",
    )
    child = make_revision(
        revision_id="a-child",
        base_answer=anchor,
        action=AnswerRevisionAction.REPLACE_FIELD,
        target_path="/decision",
        value="deny",
        evidence_ids=["evidence-2"],
        supersedes_revision_ids=[parent.revision_id],
        reason_code="later_verified_revision",
        expected_old_value="review",
    )
    assert materialize_answer(anchor, [child, parent]) == {"decision": "deny"}

    cycle_a = make_revision(
        revision_id="cycle-a",
        base_answer=anchor,
        action=AnswerRevisionAction.REPLACE_FIELD,
        target_path="/decision",
        value="a",
        evidence_ids=["evidence-a"],
        supersedes_revision_ids=["cycle-b"],
        reason_code="invalid_cycle",
    )
    cycle_b = make_revision(
        revision_id="cycle-b",
        base_answer=anchor,
        action=AnswerRevisionAction.REPLACE_FIELD,
        target_path="/decision",
        value="b",
        evidence_ids=["evidence-b"],
        supersedes_revision_ids=["cycle-a"],
        reason_code="invalid_cycle",
    )
    with pytest.raises(AnswerRevisionError, match="cycle"):
        materialize_answer(anchor, [cycle_a, cycle_b])

    conflicting_supplement = make_revision(
        revision_id="supplement-conflict",
        base_answer={"details": {"actor": "alice"}},
        action=AnswerRevisionAction.SUPPLEMENT,
        target_path="/details",
        value={"actor": "mallory"},
        evidence_ids=["evidence-conflict"],
        reason_code="not_a_replacement",
        expected_old_value={"actor": "alice"},
    )
    with pytest.raises(AnswerRevisionError, match="cannot replace"):
        materialize_answer({"details": {"actor": "alice"}}, [conflicting_supplement])


def test_tool_assurance_requires_ed25519_and_versioned_heldout_calibration() -> None:
    signing_key = Ed25519PrivateKey.generate()
    assurance = build_tool_assurance(
        tool_name="semgrep_sast",
        tool_version="1",
        input_manifest_digest="a" * 64,
        rule_bundle_digest="b" * 64,
        finding_fingerprint="c" * 64,
        signing_key=signing_key,
        calibration_version="heldout-2026-08-v1",
        calibration_manifest_digest="d" * 64,
        calibration_report_digest="e" * 64,
    )
    assert assurance.semantic == "calibrated_security_claim"
    assert assurance.signature_algorithm == "Ed25519"
    assert assurance.signature
    assert assurance.calibration_version == "heldout-2026-08-v1"
    assert assurance.calibration_manifest_digest == "d" * 64
    assert assurance.calibration_report_digest == "e" * 64
    wrapped = {"tool_assurance": assurance.model_dump(mode="json")}
    assert verified_semantic_assurance(wrapped, trusted_public_key=signing_key.public_key())

    missing_calibration = build_tool_assurance(
        tool_name="semgrep_sast",
        tool_version="1",
        input_manifest_digest="a" * 64,
        rule_bundle_digest="b" * 64,
        finding_fingerprint="c" * 64,
        signing_key=signing_key,
    )
    assert missing_calibration.semantic == "deterministic_semantic"
    assert missing_calibration.calibration_digest is None
    assert verified_semantic_assurance(
        {"tool_assurance": missing_calibration.model_dump(mode="json")},
        trusted_public_key=signing_key.public_key(),
    )

    unsigned = build_tool_assurance(
        tool_name="python_taint_audit",
        tool_version="1",
        input_manifest_digest="a" * 64,
        rule_bundle_digest="b" * 64,
        finding_fingerprint="c" * 64,
    )
    assert not verified_semantic_assurance(
        {"tool_assurance": unsigned.model_dump(mode="json")},
        trusted_public_key=signing_key.public_key(),
    )

    tampered_contract = assurance.model_dump(mode="json")
    tampered_contract["tool_version"] = "2"
    tampered = {"tool_assurance": tampered_contract}
    assert not verified_semantic_assurance(tampered, trusted_public_key=signing_key.public_key())

    tampered_calibration = assurance.model_dump(mode="json")
    tampered_calibration["calibration_report_digest"] = "f" * 64
    assert not verified_semantic_assurance(
        {"tool_assurance": tampered_calibration},
        trusted_public_key=signing_key.public_key(),
    )


def test_belief_update_is_bounded_and_replay_stable() -> None:
    state = AgentState(run_id="run-v084", task=TaskRequest(objective="evaluate"))
    state.resolved_task_contract = _contract()
    state.obligation_status = [item.model_copy(deep=True) for item in state.resolved_task_contract.obligations]
    state.claims = []
    first = update_belief(state)
    state.belief_state = first
    second = update_belief(state)
    assert first.revision == 1
    assert second.revision == 1
    assert second.stagnation_count == 1
    assert first.open_obligation_ids
    assert all(item.status == ClaimStatus.VERIFIED for item in state.claims)


def test_cross_domain_gap_plan_records_observed_r0_chain_before_resynthesis() -> None:
    state = AgentState(run_id="run-v084", task=TaskRequest(objective="evaluate"))
    state.resolved_task_contract = _contract()
    state.obligation_status = [item.model_copy(deep=True) for item in state.resolved_task_contract.obligations]
    fact = EvidenceFact(
        fact_id="fact-policy",
        fact_type="policy.input",
        value={"embedded_action": "exfiltrate"},
        source_ref="artifact:fixture.json",
        source_sha256="b" * 64,
    )
    receipt_payload = {
        "run_id": state.run_id,
        "contract_digest": state.resolved_task_contract.contract_digest,
        "input_manifest_digest": state.resolved_task_contract.input_manifest_digest,
        "facts": [fact.model_dump(mode="json")],
    }
    state.evidence_compiler_receipt = EvidenceCompilerReceipt.model_validate(
        {**receipt_payload, "output_digest": canonical_digest(receipt_payload)}
    )
    state.audit_coverage["pre_primary_scenario_projection"] = {
        "scenario": "log_analysis",
        "answer_payload": {"answer_kind": "timeline", "events": []},
        "evidence_ids": ["evidence-log"],
    }
    state.report = AgentReport(
        run_id=state.run_id,
        status=RunStatus.PARTIAL,
        executive_summary="best-effort result",
        answer_payload={"decision": "unknown"},
    )
    state.belief_state = update_belief(state)

    plan = compile_gap_plan(state)

    assert plan is not None
    assert 2 <= len(plan.actions) <= 4
    assert [item.kind for item in plan.actions[:2]] == [
        GapActionKind.RETRIEVE_CONTEXT,
        GapActionKind.OBSERVE_DOMAIN,
    ]
    assert all(item.status == "completed" for item in plan.actions)
    assert plan.actions[0].observation_refs == ["fact-policy"]
    assert plan.actions[1].observation_refs == ["evidence-log"]


def test_pre_verifier_binds_internal_scanner_evidence_to_real_input_cas(tmp_path, monkeypatch) -> None:
    payload = b"def vulnerable(user):\n    eval(user)\n"
    digest = hashlib.sha256(payload).hexdigest()
    store = ContentAddressedArtifactStore(tmp_path / "cas")
    store.put(payload, run_id="run-v084")
    state = AgentState(run_id="run-v084", task=TaskRequest(objective="audit"))
    state.input_artifacts = [
        InputArtifact(
            original_name="app.py",
            relative_path="workspace/app.py",
            sha256=digest,
            size_bytes=len(payload),
            media_type="text/x-python",
        )
    ]
    state.findings = [
        Finding(
            finding_id="finding-flow",
            rule_id="CWE-95",
            severity="HIGH",
            confidence="HIGH",
            path="app.py",
            line=2,
            title="dynamic code execution",
            description="untrusted input reaches eval",
            evidence_ids=["evidence-flow"],
        )
    ]
    state.evidence = [
        Evidence(
            evidence_id="evidence-flow",
            source="python_taint_audit:1",
            summary="proven source-to-sink flow",
            sha256="0" * 64,
            metadata={
                "tool_name": "python_taint_audit",
                "tool_version": "1",
                "path": "app.py",
                "line": 2,
                "file_sha256": digest,
                "input_manifest_digest": "a" * 64,
                "rule_bundle_digest": "b" * 64,
            },
        )
    ]
    orchestrator = object.__new__(SecMindOrchestrator)
    orchestrator.artifact_store = store
    signing_key = Ed25519PrivateKey.generate()
    private_key_path = tmp_path / "tool-assurance-private.pem"
    public_key_path = tmp_path / "tool-assurance-public.pem"
    private_key_path.write_bytes(
        signing_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    public_key_path.write_bytes(
        signing_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    monkeypatch.setenv("SECMIND_TOOL_ASSURANCE_PRIVATE_KEY_FILE", str(private_key_path))
    monkeypatch.setenv("SECMIND_TOOL_ASSURANCE_PUBLIC_KEY_FILE", str(public_key_path))

    observed, failures = orchestrator._rehash_evidence_artifacts(state)  # noqa: SLF001

    assert failures == {}
    assert observed == {digest: digest}
    assert state.evidence[0].artifact_ref == digest
    assert state.evidence[0].sha256 == digest
    assert verified_semantic_assurance(state.evidence[0].metadata)
