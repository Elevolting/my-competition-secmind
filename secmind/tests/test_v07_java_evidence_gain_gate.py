from __future__ import annotations

import hashlib
from typing import Any, cast

import pytest

from secmind.audit_kernel import (
    AuditUnit,
    CriticVerdict,
    FlowVerdict,
    GainAction,
    GainGate,
    GainPolicy,
    JavaEvidenceError,
    JavaEvidenceExtractor,
    PrimaryVerdict,
    ReviewVerdict,
    validate_semantic_flow,
)

MANIFEST_DIGEST = hashlib.sha256(b"manifest").hexdigest()
PROFILE_DIGEST = hashlib.sha256(b"java-profile").hexdigest()
RULE_DIGEST = hashlib.sha256(b"generic-java-taint-rules-v1").hexdigest()
TOOL_NAME = "java_flow_scan"
TOOL_VERSION = "1.0.0"


def _unit(source: str, *, run_id: str = "run-1", target_cwes: tuple[int, ...] = (89,)) -> AuditUnit:
    return AuditUnit.create(
        run_id=run_id,
        input_manifest_digest=MANIFEST_DIGEST,
        profile_digest=PROFILE_DIGEST,
        primary_path="src/main/java/example/AuditTarget.java",
        source_sha256=hashlib.sha256(source.encode()).hexdigest(),
        target_cwes=target_cwes,
    )


def _extractor() -> JavaEvidenceExtractor:
    return JavaEvidenceExtractor(
        tool_name=TOOL_NAME,
        tool_version=TOOL_VERSION,
        rule_bundle_digest=RULE_DIGEST,
    )


def _policy() -> GainPolicy:
    return GainPolicy.create(
        policy_id="java-cognitive-gain",
        version="1",
        approved_tool_names=(TOOL_NAME,),
        approved_rule_bundle_digests=(RULE_DIGEST,),
        allowed_cwes=(89,),
        minimum_tool_confidence=0.85,
        minimum_critic_confidence=0.85,
    )


def _baseline(unit: AuditUnit, verdict: ReviewVerdict = ReviewVerdict.NOT_VULNERABLE) -> PrimaryVerdict:
    positive = verdict == ReviewVerdict.VULNERABLE
    return PrimaryVerdict(
        unit_id=unit.unit_id,
        verdict=verdict,
        cwe=89 if positive else None,
        source_node_id="baseline-source" if positive else None,
        sink_node_id="baseline-sink" if positive else None,
        confidence=0.9,
        receipt_id="primary-receipt",
        model_id="primary-5.4",
        prompt_version="primary-v2",
        evidence_ids=("baseline-evidence",),
    )


def _critic(unit: AuditUnit, flow: Any, *, verdict: ReviewVerdict = ReviewVerdict.VULNERABLE) -> CriticVerdict:
    positive = verdict == ReviewVerdict.VULNERABLE
    return CriticVerdict(
        unit_id=unit.unit_id,
        verdict=verdict,
        cwe=flow.cwe if positive else None,
        source_node_id=flow.source_site.node_id if positive else None,
        sink_node_id=flow.sink_site.node_id if positive else None,
        confidence=0.92,
        receipt_id="critic-receipt",
        lineage_id="model:critic-deep:receipt-1",
        model_id="critic-5.4",
        prompt_version="critic-v2",
        evidence_ids=("critic-evidence",),
    )


SQL_FLOW = """
package example;
class AuditTarget {
    void execute(HttpServletRequest request, Statement statement) throws Exception {
        String user = request.getParameter("name");
        String query = "SELECT * FROM users WHERE name='" + user + "'";
        statement.executeQuery(query);
    }
}
"""


def test_unit_identity_is_stable_across_runs_and_input_order() -> None:
    first = _unit(SQL_FLOW, run_id="run-a", target_cwes=(89, 22))
    second = _unit(SQL_FLOW, run_id="run-b", target_cwes=(22, 89, 22))

    assert first.unit_id == second.unit_id
    assert first.scope_digest == second.scope_digest
    assert first.target_cwes == (22, 89)
    assert first.run_id != second.run_id


def test_java_extractor_builds_deterministic_connected_candidate() -> None:
    unit = _unit(SQL_FLOW)
    first = _extractor().extract(unit, SQL_FLOW)
    second = _extractor().extract(unit, SQL_FLOW)

    assert first == second
    assert len(first) == 1
    flow = first[0]
    assert flow.cwe == 89
    assert flow.verdict == FlowVerdict.CANDIDATE_POSITIVE
    assert flow.source_site is not None
    assert flow.source_site.family == "http_parameter"
    assert flow.sink_site.family == "sql_execution"
    assert flow.propagation_edges

    certificate = validate_semantic_flow(unit, flow)
    assert certificate.valid
    assert certificate.digest_valid()
    assert all(check.passed for check in certificate.checks)


def test_java_extractor_rejects_source_content_not_bound_to_unit() -> None:
    unit = _unit(SQL_FLOW)

    with pytest.raises(JavaEvidenceError, match="immutable AuditUnit"):
        _extractor().extract(unit, SQL_FLOW + "// changed")


def test_sanitizer_on_path_prevents_positive_semantic_certificate() -> None:
    source = """
class AuditTarget {
    void execute(HttpServletRequest request, Statement statement) throws Exception {
        String user = request.getParameter("name");
        String safe = validate(user);
        statement.executeQuery(safe);
    }
}
"""
    unit = _unit(source)
    flow = _extractor().extract(unit, source)[0]

    assert flow.verdict == FlowVerdict.CANDIDATE_NEGATIVE
    certificate = validate_semantic_flow(unit, flow)
    assert not certificate.valid
    assert "positive-candidate" in {check.check_id for check in certificate.checks if not check.passed}
    assert "no-effective-sanitizer" in {check.check_id for check in certificate.checks if not check.passed}


def test_literals_and_comments_do_not_create_attacker_sources() -> None:
    source = """
class AuditTarget {
    void execute(Statement statement) throws Exception {
        // request.getParameter("not-code");
        String query = "request.getParameter and executeQuery are only text";
        statement.executeQuery(query);
    }
}
"""
    unit = _unit(source)
    flow = _extractor().extract(unit, source)[0]

    assert flow.source_site is None
    assert flow.verdict == FlowVerdict.UNKNOWN
    assert not validate_semantic_flow(unit, flow).valid


def test_runtime_variable_exec_preserves_attacker_controlled_command_flow() -> None:
    source = """
class AuditTarget {
    void execute(HttpServletRequest request) throws Exception {
        Runtime runtime = Runtime.getRuntime();
        String command = request.getParameter("command");
        runtime.exec(command);
    }
}
"""
    unit = _unit(source, target_cwes=(78,))
    flows = _extractor().extract(unit, source)

    assert len(flows) == 1
    flow = flows[0]
    assert flow.cwe == 78
    assert flow.verdict == FlowVerdict.CANDIDATE_POSITIVE
    assert flow.sink_site.family == "command_execution"
    assert flow.sink_site.symbol == "runtime"
    assert validate_semantic_flow(unit, flow).valid


def test_arbitrary_exec_method_is_not_misclassified_as_runtime_execution() -> None:
    source = """
class AuditTarget {
    void execute(HttpServletRequest request, QueryExecutor executor) throws Exception {
        String query = request.getParameter("query");
        executor.exec(query);
    }
}
"""
    unit = _unit(source, target_cwes=(78,))

    assert _extractor().extract(unit, source) == ()


def test_process_builder_command_is_only_a_sink_when_builder_starts() -> None:
    source = """
class AuditTarget {
    void execute(HttpServletRequest request) throws Exception {
        String command = request.getParameter("command");
        ProcessBuilder builder = new ProcessBuilder("echo", "safe-default");
        builder.command("sh", "-c", command);
        builder.start();
    }
}
"""
    unit = _unit(source, target_cwes=(78,))
    flows = _extractor().extract(unit, source)

    assert len(flows) == 1
    flow = flows[0]
    assert flow.verdict == FlowVerdict.CANDIDATE_POSITIVE
    assert flow.sink_site.symbol == "builder"
    assert any(edge.kind.value == "call" for edge in flow.propagation_edges)
    assert validate_semantic_flow(unit, flow).valid


@pytest.mark.parametrize(
    "configuration",
    [
        'ProcessBuilder builder = new ProcessBuilder("sh", "-c", command);',
        ('ProcessBuilder builder = new ProcessBuilder("sh", "-c");\n        builder.command().add(command);'),
    ],
)
def test_process_builder_constructor_and_command_list_propagate_until_start(
    configuration: str,
) -> None:
    source = f"""
class AuditTarget {{
    void execute(HttpServletRequest request) throws Exception {{
        String command = request.getParameter("command");
        {configuration}
        builder.start();
    }}
}}
"""
    unit = _unit(source, target_cwes=(78,))
    flow = _extractor().extract(unit, source)[0]

    assert flow.verdict == FlowVerdict.CANDIDATE_POSITIVE
    assert validate_semantic_flow(unit, flow).valid


def test_process_builder_configuration_without_start_does_not_emit_execution() -> None:
    source = """
class AuditTarget {
    ProcessBuilder configure(HttpServletRequest request) {
        String command = request.getParameter("command");
        return new ProcessBuilder("sh", "-c", command);
    }
}
"""
    unit = _unit(source, target_cwes=(78,))

    assert _extractor().extract(unit, source) == ()


def test_constant_or_sanitized_process_builder_command_cannot_form_positive_certificate() -> None:
    constant_source = """
class AuditTarget {
    void execute() throws Exception {
        ProcessBuilder builder = new ProcessBuilder("echo", "constant");
        builder.start();
    }
}
"""
    constant_unit = _unit(constant_source, target_cwes=(78,))
    constant_flow = _extractor().extract(constant_unit, constant_source)[0]
    assert constant_flow.verdict == FlowVerdict.UNKNOWN
    assert not validate_semantic_flow(constant_unit, constant_flow).valid

    sanitized_source = """
class AuditTarget {
    void execute(HttpServletRequest request) throws Exception {
        String raw = request.getParameter("command");
        String command = sanitizeCommand(raw);
        ProcessBuilder builder = new ProcessBuilder(command);
        builder.start();
    }
}
"""
    sanitized_unit = _unit(sanitized_source, target_cwes=(78,))
    sanitized_flow = _extractor().extract(sanitized_unit, sanitized_source)[0]
    assert sanitized_flow.verdict == FlowVerdict.CANDIDATE_NEGATIVE
    assert not validate_semantic_flow(sanitized_unit, sanitized_flow).valid


def test_gain_gate_requires_empirical_release_and_still_unions_evidence() -> None:
    unit = _unit(SQL_FLOW)
    flow = _extractor().extract(unit, SQL_FLOW)[0]
    certificate = validate_semantic_flow(unit, flow)
    baseline = _baseline(unit)
    critic = _critic(unit, flow)

    decision = GainGate().decide(
        unit,
        baseline,
        policy=_policy(),
        flow=flow,
        certificate=certificate,
        critic=critic,
    )

    assert decision.action == GainAction.KEEP_BASELINE
    assert decision.baseline_verdict == ReviewVerdict.NOT_VULNERABLE
    assert decision.final_verdict == ReviewVerdict.NOT_VULNERABLE
    assert decision.final_cwe is None
    assert "patch_identity_missing" in decision.reason_codes
    assert decision.evidence_ids == tuple(sorted({"baseline-evidence", "critic-evidence", *flow.evidence_ids}))
    assert decision.digest_valid()


@pytest.mark.parametrize("policy", [None, _policy().model_copy(update={"policy_digest": None})])
def test_missing_or_invalid_policy_keeps_direct_baseline(
    policy: GainPolicy | None,
) -> None:
    unit = _unit(SQL_FLOW)
    flow = _extractor().extract(unit, SQL_FLOW)[0]
    decision = GainGate().decide(
        unit,
        _baseline(unit),
        policy=policy,
        flow=flow,
        certificate=validate_semantic_flow(unit, flow),
        critic=_critic(unit, flow),
    )

    assert decision.action == GainAction.KEEP_BASELINE
    assert decision.final_verdict == ReviewVerdict.NOT_VULNERABLE
    assert "policy_missing_or_invalid" in decision.reason_codes


def test_invalid_certificate_or_same_lineage_keeps_baseline() -> None:
    unit = _unit(SQL_FLOW)
    flow = _extractor().extract(unit, SQL_FLOW)[0]
    certificate = validate_semantic_flow(unit, flow)
    baseline = _baseline(unit)

    tampered = certificate.model_copy(update={"certificate_digest": "0" * 64})
    invalid_certificate = GainGate().decide(
        unit,
        baseline,
        policy=_policy(),
        flow=flow,
        certificate=tampered,
        critic=_critic(unit, flow),
    )
    same_lineage = _critic(unit, flow).model_copy(update={"lineage_id": flow.lineage_id})
    dependent_critic = GainGate().decide(
        unit,
        baseline,
        policy=_policy(),
        flow=flow,
        certificate=certificate,
        critic=same_lineage,
    )

    assert invalid_certificate.action == GainAction.KEEP_BASELINE
    assert "semantic_certificate_invalid" in invalid_certificate.reason_codes
    assert dependent_critic.action == GainAction.KEEP_BASELINE
    assert "lineage_not_independent" in dependent_critic.reason_codes


def test_positive_baseline_rejects_a_positive_flow_as_a_correction() -> None:
    unit = _unit(SQL_FLOW)
    flow = _extractor().extract(unit, SQL_FLOW)[0]
    critic = _critic(unit, flow, verdict=ReviewVerdict.NOT_VULNERABLE)

    decision = GainGate().decide(
        unit,
        _baseline(unit, ReviewVerdict.VULNERABLE),
        policy=_policy(),
        flow=flow,
        certificate=validate_semantic_flow(unit, flow),
        critic=critic,
    )

    assert decision.action == GainAction.KEEP_BASELINE
    assert decision.final_verdict == ReviewVerdict.VULNERABLE
    assert "tool_flow_direction_mismatch" in decision.reason_codes


def test_enhancement_exception_cannot_erase_baseline() -> None:
    class ExplodingFlow:
        @property
        def evidence_ids(self) -> tuple[str, ...]:
            raise RuntimeError("optional enhancement failed")

    unit = _unit(SQL_FLOW)
    baseline = _baseline(unit)
    decision = GainGate().decide(
        unit,
        baseline,
        policy=_policy(),
        flow=cast(Any, ExplodingFlow()),
    )

    assert decision.action == GainAction.KEEP_BASELINE
    assert decision.final_verdict == baseline.verdict
    assert decision.evidence_ids == baseline.evidence_ids
    assert "enhancement_error" in decision.reason_codes
