from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from secmind.audit_kernel.contracts import (
    AuditUnit,
    CandidateFlow,
    CodeSite,
    FlowEdge,
    FlowEdgeKind,
    FlowVerdict,
    content_digest,
)


class JavaConfigurationError(ValueError):
    """The immutable Java input cannot be inspected for configuration risks."""


@dataclass(frozen=True, slots=True)
class _ConfigurationMatch:
    cwe: int
    start: int
    source_family: str
    sink_family: str
    symbol: str
    confidence: float


_CIPHER_CALL = re.compile(
    r"\b(?:javax\s*\.\s*crypto\s*\.\s*)?Cipher\s*\.\s*getInstance\s*"
    r"\(\s*\"(?P<algorithm>[^\"\r\n]{1,96})\"",
    re.IGNORECASE,
)
_DIGEST_CALL = re.compile(
    r"\b(?:java\s*\.\s*security\s*\.\s*)?MessageDigest\s*\.\s*getInstance\s*"
    r"\(\s*\"(?P<algorithm>[^\"\r\n]{1,96})\"",
    re.IGNORECASE,
)
_RANDOM_CALL = re.compile(
    r"\bnew\s+(?:java\s*\.\s*util\s*\.\s*)?Random\s*\(|"
    r"\b(?:java\s*\.\s*lang\s*\.\s*)?Math\s*\.\s*random\s*\(",
    re.IGNORECASE,
)
_INSECURE_COOKIE = re.compile(
    r"\b(?P<cookie>[A-Za-z_$][A-Za-z0-9_$]*)\s*\.\s*setSecure\s*\(\s*false\s*\)",
    re.IGNORECASE,
)

_WEAK_CIPHERS = frozenset({"DES", "DESEDE", "TRIPLEDES", "RC2", "RC4", "ARCFOUR", "BLOWFISH"})
_WEAK_DIGESTS = frozenset({"MD2", "MD4", "MD5", "SHA", "SHA1"})


def _code_without_comments(source: str) -> str:
    """Mask Java comments while preserving literals, offsets and line numbers."""

    result = list(source)
    state = "normal"
    escaped = False
    index = 0
    while index < len(source):
        character = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if state == "normal":
            if character == "/" and following == "/":
                result[index] = result[index + 1] = " "
                state = "line_comment"
                index += 2
                continue
            if character == "/" and following == "*":
                result[index] = result[index + 1] = " "
                state = "block_comment"
                index += 2
                continue
            if character == '"':
                state = "string"
            elif character == "'":
                state = "character"
        elif state == "line_comment":
            if character == "\n":
                state = "normal"
            else:
                result[index] = " "
        elif state == "block_comment":
            if character == "*" and following == "/":
                result[index] = result[index + 1] = " "
                state = "normal"
                index += 2
                continue
            if character != "\n":
                result[index] = " "
        else:
            if character == "\n":
                state = "normal"
                escaped = False
            elif escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif (state == "string" and character == '"') or (state == "character" and character == "'"):
                state = "normal"
        index += 1
    return "".join(result)


def _line_column(source: str, offset: int) -> tuple[int, int]:
    line = source.count("\n", 0, offset) + 1
    previous_newline = source.rfind("\n", 0, offset)
    return line, offset - previous_newline


def _stable_id(prefix: str, payload: dict[str, object]) -> str:
    return f"{prefix}-{content_digest(payload)}"


def _site(
    unit: AuditUnit,
    match: _ConfigurationMatch,
    *,
    family: str,
    kind: str,
    source: str,
) -> CodeSite:
    line, column = _line_column(source, match.start)
    return CodeSite(
        node_id=_stable_id(
            "node",
            {
                "unit_id": unit.unit_id,
                "path": unit.primary_path,
                "line": line,
                "column": column,
                "family": family,
                "symbol": match.symbol,
                "kind": kind,
            },
        ),
        path=unit.primary_path,
        line=line,
        column=column,
        family=family,
        symbol=match.symbol,
        file_sha256=unit.source_sha256,
    )


def _normalize_algorithm(value: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", value.split("/", 1)[0].upper())


class JavaConfigurationEvidenceExtractor:
    """Conservative candidate generator for non-taint Java weaknesses.

    The rules intentionally ignore dynamic algorithm names and implicit cookie
    defaults. Every match remains a candidate and still needs the GainGate's
    independent critic before it can change an authoritative verdict.
    """

    def __init__(self, *, tool_name: str, tool_version: str, rule_bundle_digest: str) -> None:
        if not tool_name or not tool_version:
            raise JavaConfigurationError("tool identity is required")
        if len(rule_bundle_digest) != 64 or any(
            character not in "0123456789abcdef" for character in rule_bundle_digest
        ):
            raise JavaConfigurationError("a pinned lowercase rule bundle digest is required")
        self.tool_name = tool_name
        self.tool_version = tool_version
        self.rule_bundle_digest = rule_bundle_digest

    def extract(self, unit: AuditUnit, source: str) -> tuple[CandidateFlow, ...]:
        if hashlib.sha256(source.encode("utf-8")).hexdigest() != unit.source_sha256:
            raise JavaConfigurationError("Java source does not match the immutable AuditUnit digest")
        code = _code_without_comments(source)
        matches: list[_ConfigurationMatch] = []
        if 327 in unit.target_cwes:
            for regex_match in _CIPHER_CALL.finditer(code):
                algorithm = _normalize_algorithm(regex_match.group("algorithm"))
                if algorithm in _WEAK_CIPHERS:
                    matches.append(
                        _ConfigurationMatch(
                            327,
                            regex_match.start(),
                            "weak_cipher_algorithm",
                            "crypto_operation",
                            algorithm,
                            0.99,
                        )
                    )
        if 328 in unit.target_cwes:
            for regex_match in _DIGEST_CALL.finditer(code):
                algorithm = _normalize_algorithm(regex_match.group("algorithm"))
                if algorithm in _WEAK_DIGESTS:
                    matches.append(
                        _ConfigurationMatch(
                            328,
                            regex_match.start(),
                            "weak_digest_algorithm",
                            "digest_operation",
                            algorithm,
                            0.99,
                        )
                    )
        if 330 in unit.target_cwes:
            matches.extend(
                _ConfigurationMatch(
                    330,
                    regex_match.start(),
                    "predictable_random_source",
                    "security_random_value",
                    "java-insecure-prng",
                    0.98,
                )
                for regex_match in _RANDOM_CALL.finditer(code)
            )
        if 614 in unit.target_cwes:
            matches.extend(
                _ConfigurationMatch(
                    614,
                    regex_match.start(),
                    "insecure_cookie_flag",
                    "cookie_transport",
                    regex_match.group("cookie"),
                    0.99,
                )
                for regex_match in _INSECURE_COOKIE.finditer(code)
            )

        flows: dict[str, CandidateFlow] = {}
        for configuration_match in matches:
            source_site = _site(
                unit,
                configuration_match,
                family=configuration_match.source_family,
                kind="configuration",
                source=source,
            )
            sink_site = _site(
                unit,
                configuration_match,
                family=configuration_match.sink_family,
                kind="security_effect",
                source=source,
            )
            edge = FlowEdge(
                edge_id=_stable_id(
                    "edge",
                    {
                        "from": source_site.node_id,
                        "to": sink_site.node_id,
                        "kind": FlowEdgeKind.CONFIGURATION.value,
                        "symbol": configuration_match.symbol,
                    },
                ),
                from_node_id=source_site.node_id,
                to_node_id=sink_site.node_id,
                kind=FlowEdgeKind.CONFIGURATION,
                symbol=configuration_match.symbol,
            )
            evidence_id = _stable_id(
                "java-config",
                {
                    "unit_id": unit.unit_id,
                    "cwe": configuration_match.cwe,
                    "line": source_site.line,
                    "column": source_site.column,
                    "symbol": configuration_match.symbol,
                    "tool_name": self.tool_name,
                    "tool_version": self.tool_version,
                    "rule_bundle_digest": self.rule_bundle_digest,
                },
            )
            flow = CandidateFlow.create(
                unit_id=unit.unit_id,
                cwe=configuration_match.cwe,
                source_site=source_site,
                sink_site=sink_site,
                propagation_edges=(edge,),
                tool_name=self.tool_name,
                tool_version=self.tool_version,
                rule_bundle_digest=self.rule_bundle_digest,
                verdict=FlowVerdict.CANDIDATE_POSITIVE,
                confidence=configuration_match.confidence,
                evidence_ids=(evidence_id,),
            )
            flows[flow.flow_id] = flow
        return tuple(sorted(flows.values(), key=lambda value: value.flow_id))
