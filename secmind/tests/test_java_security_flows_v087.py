from __future__ import annotations

import hashlib

from secmind.java_security_flows import (
    LDAP_FILTER_CONCAT_RULE,
    SENSITIVE_LOG_VALUE_RULE,
    analyze_java_security_flows,
)
from secmind.java_semantic_sast import JavaSource, analyze_java_sources
from secmind.schemas import Finding

LDAP_SOURCE = """
class DirectoryLookup {
    void search(HttpServletRequest request) throws Exception {
        String param = request.getParameter("uid");
        String value = helper.doSomething(param);
        String filter = "(&(objectClass=person)(uid=" + value + "))";
        DirContext context = manager.getDirContext();
        context.search("ou=users", filter, controls);
    }
}
"""


def test_request_value_concatenated_into_ldap_filter_is_proven() -> None:
    flows = analyze_java_security_flows(LDAP_SOURCE)

    assert len(flows) == 1
    assert flows[0].native_rule_id == LDAP_FILTER_CONCAT_RULE
    assert flows[0].rule_id == "CWE-90"
    assert flows[0].line == 6
    assert flows[0].sink == "DirContext.search"


def test_ldap_filter_encoder_blocks_the_deterministic_flow() -> None:
    safe = LDAP_SOURCE.replace("helper.doSomething(param)", "LdapEncoder.escapeFilter(param)")

    assert analyze_java_security_flows(safe) == ()


def test_ldap_search_before_filter_assignment_is_not_a_flow() -> None:
    reordered = """
class DirectoryLookup {
    void search(HttpServletRequest request) throws Exception {
        String param = request.getParameter("uid");
        String value = helper.doSomething(param);
        DirContext context = manager.getDirContext();
        context.search("ou=users", filter, controls);
        String filter = "(&(objectClass=person)(uid=" + value + "))";
    }
}
"""

    assert analyze_java_security_flows(reordered) == ()


def test_sensitive_value_passed_as_log_argument_is_proven_but_event_label_is_not() -> None:
    source = """
class ApiKeys {
    void issue(User user) {
        String apiKey = provider.generateApiKey(user);
        log.info("API key issued for {}", user.getEmail());
        log.debug("API key for {}: {}", user.getEmail(), apiKey);
    }
}
"""

    flows = analyze_java_security_flows(source)

    assert len(flows) == 1
    assert flows[0].native_rule_id == SENSITIVE_LOG_VALUE_RULE
    assert flows[0].rule_id == "CWE-532"
    assert flows[0].line == 6


def test_java_semantic_materializes_hash_bound_general_flows() -> None:
    digest = hashlib.sha256(LDAP_SOURCE.encode()).hexdigest()
    evidence, raw_findings = analyze_java_sources(
        run_id="java-ldap",
        sources=(JavaSource(path="subject.java", source=LDAP_SOURCE, sha256=digest),),
    )

    assert len(evidence) == len(raw_findings) == 1
    finding = Finding.model_validate(raw_findings[0])
    assert finding.rule_id == "CWE-90"
    assert finding.raw["native_rule_id"] == LDAP_FILTER_CONCAT_RULE
    assert finding.raw["file_sha256"] == digest
    assert evidence[0].metadata["file_sha256"] == digest
    assert evidence[0].metadata["data_flow"]
