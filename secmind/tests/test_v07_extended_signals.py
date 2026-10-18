from __future__ import annotations

import hashlib

import pytest

from secmind.audit_kernel import (
    EXTENDED_TARGET_CWES,
    AuditUnit,
    JavaConfigurationEvidenceExtractor,
    JavaEvidenceExtractor,
    resolve_audit_profile,
    validate_semantic_flow,
)

MANIFEST_DIGEST = hashlib.sha256(b"manifest").hexdigest()
PROFILE_DIGEST = hashlib.sha256(b"extended-java-profile").hexdigest()
CONFIG_RULE_DIGEST = hashlib.sha256(b"configuration-rules").hexdigest()
FLOW_RULE_DIGEST = hashlib.sha256(b"flow-rules").hexdigest()


def _unit(source: str, target_cwes: tuple[int, ...]) -> AuditUnit:
    return AuditUnit.create(
        run_id="run-extended",
        input_manifest_digest=MANIFEST_DIGEST,
        profile_digest=PROFILE_DIGEST,
        primary_path="src/main/java/example/AuditTarget.java",
        source_sha256=hashlib.sha256(source.encode()).hexdigest(),
        target_cwes=target_cwes,
    )


def _configuration_flows(source: str, cwe: int):
    unit = _unit(source, (cwe,))
    flows = JavaConfigurationEvidenceExtractor(
        tool_name="java-configuration",
        tool_version="1.0.0",
        rule_bundle_digest=CONFIG_RULE_DIGEST,
    ).extract(unit, source)
    return unit, flows


def test_extended_profile_covers_all_blind_evaluation_families() -> None:
    assert resolve_audit_profile("core").target_cwes == (22, 78, 79, 89)
    assert resolve_audit_profile("extended").target_cwes == EXTENDED_TARGET_CWES
    assert EXTENDED_TARGET_CWES == (22, 78, 79, 89, 90, 327, 328, 330, 501, 614)


@pytest.mark.parametrize(
    ("cwe", "unsafe_expression", "safe_expression"),
    [
        (
            327,
            'Cipher.getInstance("DES/CBC/PKCS5Padding")',
            'Cipher.getInstance("AES/GCM/NoPadding")',
        ),
        (
            328,
            'MessageDigest.getInstance("SHA-1")',
            'MessageDigest.getInstance("SHA-512")',
        ),
        (330, "new java.util.Random()", "new java.security.SecureRandom()"),
        (614, "cookie.setSecure(false)", "cookie.setSecure(true)"),
    ],
)
def test_configuration_signals_are_conservative_and_semantically_bound(
    cwe: int, unsafe_expression: str, safe_expression: str
) -> None:
    unsafe = f"class AuditTarget {{ void f() throws Exception {{ {unsafe_expression}; }} }}"
    unit, flows = _configuration_flows(unsafe, cwe)

    assert len(flows) == 1
    assert flows[0].cwe == cwe
    certificate = validate_semantic_flow(unit, flows[0])
    assert certificate.valid
    assert certificate.digest_valid()

    safe = f"class AuditTarget {{ void f() throws Exception {{ {safe_expression}; }} }}"
    _, safe_flows = _configuration_flows(safe, cwe)
    assert safe_flows == ()


def test_session_trust_boundary_produces_a_connected_cwe501_candidate() -> None:
    source = """
class AuditTarget {
    void save(HttpServletRequest request) {
        String value = request.getParameter("value");
        request.getSession().setAttribute("trusted-user", value);
    }
}
"""
    unit = _unit(source, (501,))
    flows = JavaEvidenceExtractor(
        tool_name="java-flow",
        tool_version="1.1.0",
        rule_bundle_digest=FLOW_RULE_DIGEST,
    ).extract(unit, source)

    assert len(flows) == 1
    assert flows[0].cwe == 501
    assert validate_semantic_flow(unit, flows[0]).valid
