from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

import pytest

from secmind.audit_kernel import (
    AuditUnit,
    CandidateFlow,
    CodeSite,
    CriticVerdict,
    EmpiricalGate,
    FlowVerdict,
    GainAction,
    GainGate,
    GainPolicy,
    PatchIdentity,
    PatchReleaseConflict,
    PatchReleaseRecord,
    PatchReleaseRegistry,
    PatchReleaseStatus,
    PrimaryVerdict,
    ReviewVerdict,
    SemanticCertificate,
    SemanticCheck,
)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


PROFILE_DIGEST = _digest("extended-profile")
SOURCE_DIGEST = _digest("source")
MANIFEST_DIGEST = _digest("manifest")
RULE_DIGEST = _digest("rules")
PARSER_DIGEST = _digest("tree-sitter-java")
MODEL_POLICY_DIGEST = _digest("critic-model-policy")


def _unit() -> AuditUnit:
    return AuditUnit.create(
        run_id="run-release",
        input_manifest_digest=MANIFEST_DIGEST,
        profile_digest=PROFILE_DIGEST,
        primary_path="src/AuditTarget.java",
        source_sha256=SOURCE_DIGEST,
        target_cwes=(89,),
    )


def _flow(unit: AuditUnit) -> CandidateFlow:
    source = CodeSite(
        node_id="source",
        path=unit.primary_path,
        line=2,
        family="http_parameter",
        file_sha256=unit.source_sha256,
    )
    sink = CodeSite(
        node_id="sink",
        path=unit.primary_path,
        line=4,
        family="sql_execution",
        file_sha256=unit.source_sha256,
    )
    return CandidateFlow.create(
        unit_id=unit.unit_id,
        cwe=89,
        source_site=source,
        sink_site=sink,
        propagation_edges=(),
        tool_name="java-flow",
        tool_version="1.0.0",
        rule_bundle_digest=RULE_DIGEST,
        verdict=FlowVerdict.CANDIDATE_POSITIVE,
        confidence=0.98,
        evidence_ids=("tool-evidence",),
    )


def _identity(unit: AuditUnit, flow: CandidateFlow) -> PatchIdentity:
    return PatchIdentity.create(
        target_profile_digest=unit.profile_digest,
        cwe=flow.cwe,
        patch_kind="source-to-sink-addition",
        tool_name=flow.tool_name,
        tool_version=flow.tool_version,
        rule_bundle_digest=flow.rule_bundle_digest,
        parser_name="tree-sitter-java",
        parser_digest=PARSER_DIGEST,
        critic_prompt_version="critic-v1",
        critic_model_policy_digest=MODEL_POLICY_DIGEST,
    )


def _release(
    identity: PatchIdentity,
    *,
    status: PatchReleaseStatus = PatchReleaseStatus.AUTHORITATIVE,
    expires_at: datetime | None = None,
) -> PatchReleaseRecord:
    return PatchReleaseRecord.create(
        identity=identity,
        status=status,
        evaluation_dataset_digest=_digest("sealed-holdout"),
        baseline_arm_digest=_digest("baseline-arm"),
        candidate_arm_digest=_digest("candidate-arm"),
        sample_size=480,
        tp_fixed=24,
        fp_introduced=1,
        fn_introduced=0,
        precision=0.98,
        recall=0.92,
        f1_delta=0.04,
        coverage_delta=0.0,
        paired_bootstrap_ci_low=0.01,
        paired_bootstrap_ci_high=0.07,
        mcnemar_p=0.02,
        approved_by=(
            "operator:test" if status in {PatchReleaseStatus.CANARY, PatchReleaseStatus.AUTHORITATIVE} else None
        ),
        approved_at=datetime(2099, 1, 1, tzinfo=UTC),
        expires_at=expires_at or datetime(2100, 1, 1, tzinfo=UTC),
    )


def _structural_inputs(
    unit: AuditUnit, flow: CandidateFlow
) -> tuple[GainPolicy, PrimaryVerdict, SemanticCertificate, CriticVerdict]:
    policy = GainPolicy.create(
        policy_id="gain-policy",
        version="1",
        approved_tool_names=(flow.tool_name,),
        approved_rule_bundle_digests=(flow.rule_bundle_digest,),
        allowed_cwes=(flow.cwe,),
        minimum_tool_confidence=0.9,
        minimum_critic_confidence=0.9,
    )
    baseline = PrimaryVerdict(
        unit_id=unit.unit_id,
        verdict=ReviewVerdict.NOT_VULNERABLE,
        confidence=0.8,
        receipt_id="primary-receipt",
        model_id="primary-5.4",
        prompt_version="primary-v2",
        evidence_ids=("baseline-evidence",),
    )
    certificate = SemanticCertificate.create(
        unit_id=unit.unit_id,
        flow_id=flow.flow_id,
        checks=(SemanticCheck(check_id="parser-backed", passed=True),),
        evidence_ids=flow.evidence_ids,
    )
    assert flow.source_site is not None
    critic = CriticVerdict(
        unit_id=unit.unit_id,
        verdict=ReviewVerdict.VULNERABLE,
        cwe=flow.cwe,
        source_node_id=flow.source_site.node_id,
        sink_node_id=flow.sink_site.node_id,
        confidence=0.95,
        receipt_id="critic-receipt",
        lineage_id="model:critic-v1",
        model_id="critic-5.4",
        prompt_version="critic-v2",
        evidence_ids=("critic-evidence",),
    )
    return policy, baseline, certificate, critic


def test_patch_key_is_stable_and_captures_every_versioned_input() -> None:
    unit = _unit()
    flow = _flow(unit)
    first = _identity(unit, flow)
    second = _identity(unit, flow)

    assert first == second
    assert first.patch_key == second.patch_key
    changed = PatchIdentity.create(
        **{
            **first.model_dump(exclude={"schema_version", "patch_key"}),
            "parser_digest": _digest("tree-sitter-java-v2"),
        }
    )
    assert changed.patch_key != first.patch_key


def test_gain_gate_rejects_same_model_critic() -> None:
    unit = _unit()
    flow = _flow(unit)
    policy, baseline, certificate, critic = _structural_inputs(unit, flow)
    critic = critic.model_copy(update={"model_id": baseline.model_id})

    decision = GainGate().decide(
        unit,
        baseline,
        policy=policy,
        flow=flow,
        certificate=certificate,
        critic=critic,
        patch_identity=_identity(unit, flow),
        release=_release(_identity(unit, flow)),
        now=datetime(2099, 6, 1, tzinfo=UTC),
    )

    assert decision.action == GainAction.KEEP_BASELINE
    assert "critic_model_not_independent" in decision.reason_codes


def test_empirical_gate_requires_exact_unexpired_authoritative_release() -> None:
    unit = _unit()
    identity = _identity(unit, _flow(unit))
    now = datetime(2099, 6, 1, tzinfo=UTC)
    gate = EmpiricalGate()

    assert not gate.evaluate(identity, now=now).allowed
    shadow = _release(identity, status=PatchReleaseStatus.SHADOW)
    assert gate.evaluate(identity, release=shadow, now=now).reason == ("patch_release_not_authoritative")
    expired = _release(
        identity,
        expires_at=now - timedelta(seconds=1),
    )
    assert gate.evaluate(identity, release=expired, now=now).reason == ("patch_release_expired")
    authoritative = _release(identity)
    assert gate.evaluate(identity, release=authoritative, now=now).allowed


def test_registry_updates_are_cas_protected_and_revoke_is_immediate() -> None:
    unit = _unit()
    identity = _identity(unit, _flow(unit))
    record = _release(identity)
    registry = PatchReleaseRegistry()

    assert registry.put(record) is record
    assert registry.put(record) is record
    with pytest.raises(PatchReleaseConflict, match="CAS"):
        registry.put(record.revoke("regression"), expected_release_digest="0" * 64)

    revoked = registry.revoke(
        record.patch_release_id,
        "paired evaluation regressed",
        revoked_at=datetime(2099, 7, 1, tzinfo=UTC),
    )
    assert revoked.status == PatchReleaseStatus.REVOKED
    assert revoked.digest_valid()
    result = EmpiricalGate(registry).evaluate(identity, now=datetime(2099, 7, 2, tzinfo=UTC))
    assert not result.allowed
    assert result.reason == "patch_release_revoked"


def test_gain_gate_defaults_to_baseline_without_release_and_accepts_exact_release() -> None:
    unit = _unit()
    flow = _flow(unit)
    identity = _identity(unit, flow)
    policy, baseline, certificate, critic = _structural_inputs(unit, flow)
    gate = GainGate()

    missing = gate.decide(
        unit,
        baseline,
        policy=policy,
        flow=flow,
        certificate=certificate,
        critic=critic,
        patch_identity=identity,
        now=datetime(2099, 6, 1, tzinfo=UTC),
    )
    assert missing.action == GainAction.KEEP_BASELINE
    assert missing.final_verdict == baseline.verdict
    assert missing.reason_codes == ("patch_release_missing",)

    accepted = gate.decide(
        unit,
        baseline,
        policy=policy,
        flow=flow,
        certificate=certificate,
        critic=critic,
        patch_identity=identity,
        release=_release(identity),
        now=datetime(2099, 6, 1, tzinfo=UTC),
    )
    assert accepted.action == GainAction.ACCEPT_ENHANCEMENT
    assert accepted.final_verdict == ReviewVerdict.VULNERABLE
    assert "authoritative_patch_release_matched" in accepted.reason_codes


def test_gain_gate_rejects_identity_not_bound_to_candidate() -> None:
    unit = _unit()
    flow = _flow(unit)
    identity = PatchIdentity.create(
        **{
            **_identity(unit, flow).model_dump(exclude={"schema_version", "patch_key", "tool_version"}),
            "tool_version": "2.0.0",
        }
    )
    policy, baseline, certificate, critic = _structural_inputs(unit, flow)
    decision = GainGate().decide(
        unit,
        baseline,
        policy=policy,
        flow=flow,
        certificate=certificate,
        critic=critic,
        patch_identity=identity,
        release=_release(identity),
        now=datetime(2099, 6, 1, tzinfo=UTC),
    )

    assert decision.action == GainAction.KEEP_BASELINE
    assert decision.reason_codes == ("patch_identity_candidate_mismatch",)


def test_authoritative_negative_patch_can_correct_a_false_positive() -> None:
    unit = _unit()
    positive = _flow(unit)
    sanitizer = CodeSite(
        node_id="sanitizer",
        path=unit.primary_path,
        line=3,
        family="sql_validation",
        file_sha256=unit.source_sha256,
    )
    flow = CandidateFlow.create(
        unit_id=unit.unit_id,
        cwe=89,
        source_site=positive.source_site,
        sink_site=positive.sink_site,
        propagation_edges=positive.propagation_edges,
        sanitizer_sites=(sanitizer,),
        tool_name=positive.tool_name,
        tool_version=positive.tool_version,
        rule_bundle_digest=positive.rule_bundle_digest,
        verdict=FlowVerdict.CANDIDATE_NEGATIVE,
        confidence=0.95,
        evidence_ids=("negative-tool-evidence",),
    )
    identity = _identity(unit, flow)
    policy = GainPolicy.create(
        policy_id="correction-policy",
        version="1",
        approved_tool_names=(flow.tool_name,),
        approved_rule_bundle_digests=(flow.rule_bundle_digest,),
        allowed_cwes=(89,),
    )
    baseline = PrimaryVerdict(
        unit_id=unit.unit_id,
        verdict=ReviewVerdict.VULNERABLE,
        cwe=89,
        source_node_id="baseline-source",
        sink_node_id="baseline-sink",
        confidence=0.9,
        receipt_id="positive-baseline",
        model_id="primary-5.4",
        prompt_version="primary-v2",
    )
    certificate = SemanticCertificate.create(
        unit_id=unit.unit_id,
        flow_id=flow.flow_id,
        checks=(SemanticCheck(check_id="effective-sanitizer", passed=True),),
        evidence_ids=flow.evidence_ids,
    )
    critic = CriticVerdict(
        unit_id=unit.unit_id,
        verdict=ReviewVerdict.NOT_VULNERABLE,
        confidence=0.95,
        receipt_id="negative-critic",
        lineage_id="model:independent-negative-critic",
        model_id="critic-5.4",
        prompt_version="critic-v2",
        evidence_ids=("critic-negative-evidence",),
    )

    decision = GainGate().decide(
        unit,
        baseline,
        policy=policy,
        flow=flow,
        certificate=certificate,
        critic=critic,
        patch_identity=identity,
        release=_release(identity),
        now=datetime(2099, 6, 1, tzinfo=UTC),
    )

    assert decision.action == GainAction.ACCEPT_CORRECTION
    assert decision.final_verdict == ReviewVerdict.NOT_VULNERABLE
    assert decision.final_cwe is None
