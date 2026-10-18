"""Bounded, high-specificity Java security-flow recognizers.

The recognizers in this module are deliberately smaller than a Java parser.
They emit a result only when source, transformation and sink are all present in
the same immutable source unit.  Comments are masked and every regex is size
bounded by the caller's two-megabyte file limit.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final, Literal

LDAP_FILTER_CONCAT_RULE: Final = "JAVA-LDAP-FILTER-CONCAT-001"
SENSITIVE_LOG_VALUE_RULE: Final = "JAVA-SENSITIVE-LOG-VALUE-001"

_ASSIGNMENT = re.compile(
    r"(?m)(?:^|[;{}])\s*(?:(?:final|var)\s+)?(?:[A-Za-z_$][\w$<>.?\[\]]*\s+)?"
    r"(?P<name>[A-Za-z_$][\w$]*)\s*=\s*(?P<value>[^;]{1,3000});",
)
_REQUEST_SOURCE = re.compile(r"\b(?:request|req)\s*\.\s*getParameter\s*\(", re.IGNORECASE)
_LDAP_CONTEXT = re.compile(r"\b(?:DirContext|InitialDirContext|SearchControls|LDAPManager)\b")
_LDAP_SEARCH = re.compile(
    r"\b[A-Za-z_$][\w$]*\s*\.\s*search\s*\((?P<arguments>[^;]{1,3000})\)\s*;",
    re.DOTALL,
)
_LDAP_SANITIZER = re.compile(
    r"\b(?:encodeForLDAP|escapeLdap|escapeLDAP|escapeFilter|LdapEncoder)\b",
    re.IGNORECASE,
)
_LOG_CALL = re.compile(
    r"\b(?P<receiver>[A-Za-z_$][\w$]*)\s*\.\s*"
    r"(?P<method>trace|debug|info|warn|warning|error|fatal)\s*"
    r"\((?P<arguments>[^;]{1,4000})\)\s*;",
    re.IGNORECASE | re.DOTALL,
)
_STRING_LITERAL = re.compile(r'"(?:\\.|[^"\\])*"')
_IDENTIFIER = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")
_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


@dataclass(frozen=True, slots=True)
class JavaSecurityFlow:
    rule_id: str
    native_rule_id: str
    title: str
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"]
    confidence: Literal["LOW", "MEDIUM", "HIGH", "UNKNOWN"]
    line: int
    description: str
    impact: str
    remediation: str
    data_flow: tuple[str, ...]
    sink: str


def analyze_java_security_flows(source: str) -> tuple[JavaSecurityFlow, ...]:
    code = _mask_comments(source)
    findings = [*_ldap_filter_flows(code), *_sensitive_log_flows(code)]
    unique = {(item.native_rule_id, item.line, item.sink): item for item in findings}
    return tuple(unique[key] for key in sorted(unique))


def _ldap_filter_flows(code: str) -> list[JavaSecurityFlow]:
    if _LDAP_CONTEXT.search(code) is None:
        return []
    tainted: dict[str, tuple[str, int]] = {}
    filter_candidates: list[tuple[str, int, int, str, tuple[str, int]]] = []
    for match in _ASSIGNMENT.finditer(code):
        name = match.group("name")
        value = match.group("value")
        line = _line(code, match.start("name"))
        if _REQUEST_SOURCE.search(value) is not None:
            tainted[name] = (name, line)
            continue
        origins = [tainted[item] for item in _identifier_names(value) if item in tainted]
        if not origins:
            tainted.pop(name, None)
            continue
        if _LDAP_SANITIZER.search(value) is not None:
            tainted.pop(name, None)
            continue
        origin = min(origins, key=lambda item: (item[1], item[0]))
        tainted[name] = origin
        if "+" in value and ('"' in value or "'" in value):
            filter_candidates.append((name, line, match.end(), value, origin))

    search_calls = list(_LDAP_SEARCH.finditer(code))
    findings: list[JavaSecurityFlow] = []
    for name, line, assignment_end, _value, (source_name, source_line) in filter_candidates:
        sink = next(
            (
                item
                for item in search_calls
                if item.start() > assignment_end
                and re.search(rf"\b{re.escape(name)}\b", item.group("arguments")) is not None
            ),
            None,
        )
        if sink is None:
            continue
        sink_line = _line(code, sink.start())
        findings.append(
            JavaSecurityFlow(
                rule_id="CWE-90",
                native_rule_id=LDAP_FILTER_CONCAT_RULE,
                title="Request-derived value is concatenated into an LDAP search filter",
                severity="HIGH",
                confidence="HIGH",
                line=line,
                description=(
                    "A value derived from an HTTP request is propagated into an LDAP filter by string "
                    "concatenation and the resulting filter reaches a directory search without a proven "
                    "LDAP-filter escaping operation."
                ),
                impact="An attacker may inject LDAP filter metacharacters and alter the executed directory query.",
                remediation=(
                    "Escape the untrusted value for LDAP filter syntax with a reviewed encoder, validate it "
                    "against the intended identifier grammar, and avoid string-built filters."
                ),
                data_flow=(
                    f"request_parameter:{source_name}@{source_line}",
                    f"ldap_filter_concat:{name}@{line}",
                    f"ldap_search_sink:@{sink_line}",
                ),
                sink="DirContext.search",
            )
        )
    return findings


def _sensitive_log_flows(code: str) -> list[JavaSecurityFlow]:
    findings: list[JavaSecurityFlow] = []
    for match in _LOG_CALL.finditer(code):
        receiver = match.group("receiver")
        if "log" not in receiver.casefold():
            continue
        arguments = match.group("arguments")
        without_literals = _STRING_LITERAL.sub("", arguments)
        sensitive = next(
            (
                identifier
                for identifier in _IDENTIFIER.findall(without_literals)
                if _is_sensitive_identifier(identifier)
            ),
            None,
        )
        if sensitive is None or ("{}" not in arguments and "%s" not in arguments and "%d" not in arguments):
            continue
        line = _line(code, match.start())
        sink = f"{receiver}.{match.group('method')}"
        findings.append(
            JavaSecurityFlow(
                rule_id="CWE-532",
                native_rule_id=SENSITIVE_LOG_VALUE_RULE,
                title="Sensitive authentication value is written to application logs",
                severity="HIGH",
                confidence="HIGH",
                line=line,
                description=(
                    f"The logging call passes the sensitive value {sensitive} as a formatting argument, "
                    "which writes the value rather than only a non-sensitive event label."
                ),
                impact="Anyone with log access may recover credentials or authentication material.",
                remediation=(
                    "Remove the sensitive formatting argument; log only a stable event identifier and redact "
                    "credential-bearing values before they cross the logging boundary."
                ),
                data_flow=(f"sensitive_value:{sensitive}", f"logging_sink:{sink}@{line}"),
                sink=sink,
            )
        )
    return findings


def _is_sensitive_identifier(value: str) -> bool:
    tokens = {item.casefold() for item in re.split(r"[^A-Za-z0-9]+", _CAMEL_BOUNDARY.sub("_", value)) if item}
    return (
        bool(tokens.intersection({"password", "passwd", "pwd", "secret", "credential", "token"}))
        or {
            "api",
            "key",
        }
        <= tokens
    )


def _identifier_names(value: str) -> set[str]:
    return set(_IDENTIFIER.findall(_STRING_LITERAL.sub("", value)))


def _line(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def _mask_comments(source: str) -> str:
    output = list(source)
    state = "normal"
    escaped = False
    index = 0
    while index < len(source):
        current = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if state == "normal":
            if current == "/" and following == "/":
                output[index] = output[index + 1] = " "
                state = "line_comment"
                index += 2
                continue
            if current == "/" and following == "*":
                output[index] = output[index + 1] = " "
                state = "block_comment"
                index += 2
                continue
            if current == '"':
                state = "string"
            elif current == "'":
                state = "character"
        elif state == "line_comment":
            if current == "\n":
                state = "normal"
            else:
                output[index] = " "
        elif state == "block_comment":
            if current == "*" and following == "/":
                output[index] = output[index + 1] = " "
                state = "normal"
                index += 2
                continue
            if current != "\n":
                output[index] = " "
        else:
            if escaped:
                escaped = False
            elif current == "\\":
                escaped = True
            elif (state == "string" and current == '"') or (state == "character" and current == "'"):
                state = "normal"
        index += 1
    return "".join(output)


__all__ = [
    "LDAP_FILTER_CONCAT_RULE",
    "SENSITIVE_LOG_VALUE_RULE",
    "JavaSecurityFlow",
    "analyze_java_security_flows",
]
