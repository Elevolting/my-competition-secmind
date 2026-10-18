"""Bounded, read-only static checks for firmware text and configuration artifacts.

The firmware lane is deliberately a small evidence compiler.  It never imports,
executes, extracts, or follows content from an artifact.  Every finding is
created from a concrete source line and every clean result retains a whole-file
scan evidence row, so a caller can distinguish a verified negative scan from an
unavailable or truncated input.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Literal
from uuid import NAMESPACE_URL, uuid5

from secmind.schemas import Evidence, Finding, InputArtifact, RunStatus

FIRMWARE_STATIC_CAPABILITY = "firmware_static_audit"
FindingSeverity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"]

_DEFAULT_MAX_ARTIFACTS = 100
_DEFAULT_MAX_ARTIFACT_BYTES = 8 * 1024 * 1024
_DEFAULT_MAX_TOTAL_BYTES = 32 * 1024 * 1024
_DEFAULT_MAX_LINES = 200_000
_DEFAULT_MAX_FINDINGS = 200
_DEFAULT_MAX_EVIDENCE = 500

_HASH_PATTERN = re.compile(
    r"(?<![A-Za-z0-9])(?P<value>\$(?P<algorithm>1|2a|2b|2y|5|6|apr1)\$"
    r"[A-Za-z0-9./]{1,32}\$[A-Za-z0-9./]{8,256})(?![A-Za-z0-9./])"
)
_HASH_CONTEXT_PATTERN = re.compile(r"(?i)(?:password|passwd|passphrase|credential|shadow|secret|admin|root|user)")
_WIRELESS_PATTERN = re.compile(r"(?i)(?:\bssid\b|wifi|wi[-_ ]?fi|wireless|network[_ -]?name)")
_MAX_LENGTH_PATTERN = re.compile(
    r"(?i)(?:max(?:imum)?[_ -]?(?:length|len)|maxlength|length[_ -]?max|limit)\s*"
    r"(?:[=:({]\s*)?(?P<value>[0-9]{1,6})"
)
_VALIDATION_DISABLED_PATTERN = re.compile(
    r"(?i)(?:validation|validate|input[_ -]?check|saniti[sz]e|filter)\s*"
    r"(?:[=:]\s*|\()?(?:false|off|none|disabled|0)\b"
)
_CLEAR_TRANSPORT_PATTERN = re.compile(r"(?i)(?P<scheme>http|ftp|telnet|tftp|mqtt)://[^\s\"'<>]{1,512}")
_CLEAR_CONFIG_PATTERN = re.compile(
    r"(?i)(?:url|uri|endpoint|server|upload|download|transport|protocol|update|callback|firmware)"
)
_INSECURE_TLS_PATTERN = re.compile(
    r"(?i)(?:tls|ssl|verify[_ -]?ssl|certificate|cert|secure)\s*"
    r"(?:[=:]\s*|\()?(?:false|off|none|disabled|0)\b"
)
_INSECURE_FLAG_PATTERN = re.compile(r"(?i)\binsecure\s*(?:[=:]\s*|\()?(?:true|on|1)\b")
_SHELL_SINK_PATTERN = re.compile(
    r"(?i)\b(?:os\.execute|io\.popen|luci\.sys\.call|system|popen|eval|"
    r"subprocess\.(?:run|popen|call|check_output))\s*\("
)
_INPUT_SOURCE_PATTERN = re.compile(
    r"(?i)(?:formvalue|request|query|query_string|input|argv|parameter|cgi|"
    r"environment|env\[|user[_ -]?input|new[_ -]?cc|ssid|country)"
)
_SANITIZER_PATTERN = re.compile(
    r"(?i)(?:shellquote|shlex\.quote|escap(?:e|ed)|saniti[sz]e|allowlist|"
    r"whitelist|validate|checked|bounded|literal)"
)
_ASSIGNMENT_PATTERN = re.compile(r"(?i)\b(?:local\s+|let\s+|var\s+|const\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=")
_COMMENT_PREFIXES = ("#", "//", ";", "--")


@dataclass(frozen=True, slots=True)
class FirmwareAuditLimits:
    """Hard limits for one deterministic firmware audit invocation."""

    max_artifacts: int = _DEFAULT_MAX_ARTIFACTS
    max_bytes_per_artifact: int = _DEFAULT_MAX_ARTIFACT_BYTES
    max_total_bytes: int = _DEFAULT_MAX_TOTAL_BYTES
    max_lines_per_artifact: int = _DEFAULT_MAX_LINES
    max_findings: int = _DEFAULT_MAX_FINDINGS
    max_evidence: int = _DEFAULT_MAX_EVIDENCE

    def __post_init__(self) -> None:
        values = {
            "max_artifacts": self.max_artifacts,
            "max_bytes_per_artifact": self.max_bytes_per_artifact,
            "max_total_bytes": self.max_total_bytes,
            "max_lines_per_artifact": self.max_lines_per_artifact,
            "max_findings": self.max_findings,
            "max_evidence": self.max_evidence,
        }
        if any(not isinstance(value, int) or isinstance(value, bool) or value < 1 for value in values.values()):
            raise ValueError("firmware audit limits must be positive integers")
        if self.max_bytes_per_artifact > self.max_total_bytes:
            raise ValueError("per-artifact byte limit cannot exceed total byte limit")


@dataclass(frozen=True, slots=True)
class FirmwareAuditSource:
    """One already manifest/CAS-verified source supplied by the executor."""

    artifact: InputArtifact
    content: bytes


@dataclass(frozen=True, slots=True)
class FirmwareAuditResult:
    status: RunStatus
    findings: tuple[Finding, ...]
    evidence: tuple[Evidence, ...]
    observations: tuple[dict[str, Any], ...]
    checked_paths: tuple[str, ...]
    limitations: tuple[str, ...]
    coverage: dict[str, Any]


@dataclass(frozen=True, slots=True)
class _SourceLine:
    number: int
    text: str
    byte_offset: int
    byte_length: int
    encoding: str = "utf-8"


def audit_firmware_sources(
    sources: Sequence[FirmwareAuditSource],
    *,
    limits: FirmwareAuditLimits | None = None,
) -> FirmwareAuditResult:
    """Analyze bounded immutable source bytes without executing their contents."""

    active_limits = limits or FirmwareAuditLimits()
    findings: list[Finding] = []
    evidence: list[Evidence] = []
    observations: list[dict[str, Any]] = []
    checked_paths: list[str] = []
    limitations: list[str] = []
    total_bytes = 0
    truncated = False

    ordered_sources = sorted(sources, key=lambda item: item.artifact.relative_path.casefold())
    if len(ordered_sources) > active_limits.max_artifacts:
        omitted = len(ordered_sources) - active_limits.max_artifacts
        limitations.append(
            f"{omitted} firmware artifact(s) omitted by the {active_limits.max_artifacts}-artifact bound"
        )
        truncated = True
    for source in ordered_sources[: active_limits.max_artifacts]:
        artifact = source.artifact
        content = source.content
        path = artifact.relative_path
        if artifact.size_bytes != len(content):
            limitations.append(f"{path}: manifest size does not match immutable content")
            truncated = True
            continue
        if len(content) > active_limits.max_bytes_per_artifact:
            limitations.append(f"{path}: artifact exceeds the {active_limits.max_bytes_per_artifact}-byte bound")
            truncated = True
            continue
        if total_bytes + len(content) > active_limits.max_total_bytes:
            limitations.append(f"{path}: total firmware audit byte budget exhausted")
            truncated = True
            break
        digest = hashlib.sha256(content).hexdigest()
        if digest != artifact.sha256.casefold():
            limitations.append(f"{path}: immutable content digest does not match the manifest")
            truncated = True
            continue
        total_bytes += len(content)
        checked_paths.append(path)

        scan_evidence = _make_evidence(
            artifact,
            rule_id="FW-SCAN-SCOPE",
            category="scan_scope",
            byte_offset=0,
            byte_length=len(content),
            line_number=1,
            observation="whole_file_scan",
        )
        if len(evidence) >= active_limits.max_evidence:
            limitations.append("firmware evidence budget exhausted before scan scope could be retained")
            truncated = True
            break
        evidence.append(scan_evidence)
        lines = _source_lines(content)
        if len(lines) > active_limits.max_lines_per_artifact:
            limitations.append(
                f"{path}: lines beyond the {active_limits.max_lines_per_artifact}-line bound were omitted"
            )
            truncated = True
        observations.append(
            {
                "kind": "artifact_scan_scope",
                "path": path,
                "line_count": min(len(lines), active_limits.max_lines_per_artifact),
                "evidence_ids": [scan_evidence.evidence_id],
                "source_locator": scan_evidence.metadata["source_locator"],
            }
        )
        source_findings, source_evidence, source_observations = _analyze_source(
            source,
            lines[: active_limits.max_lines_per_artifact],
            evidence,
            active_limits,
        )
        remaining_findings = active_limits.max_findings - len(findings)
        if len(source_findings) > remaining_findings:
            limitations.append(f"{path}: findings beyond the {active_limits.max_findings}-finding bound were omitted")
            truncated = True
        findings.extend(source_findings[:remaining_findings])
        evidence.extend(source_evidence[: max(0, active_limits.max_evidence - len(evidence))])
        observations.extend(source_observations)
        if len(evidence) >= active_limits.max_evidence and source_evidence:
            limitations.append("firmware evidence budget exhausted; later observations were not published")
            truncated = True
            break
        if len(findings) >= active_limits.max_findings:
            limitations.append("firmware finding budget exhausted; later findings were not published")
            truncated = True
            break

    published_evidence_ids = {item.evidence_id for item in evidence}
    findings = [item for item in findings if set(item.evidence_ids).issubset(published_evidence_ids)]
    if not checked_paths:
        status = RunStatus.PARTIAL
    elif limitations or truncated:
        status = RunStatus.PARTIAL
    else:
        status = RunStatus.COMPLETED
    coverage = {
        "capability": FIRMWARE_STATIC_CAPABILITY,
        "sources_seen": len(ordered_sources),
        "sources_checked": len(checked_paths),
        "bytes_checked": total_bytes,
        "findings_emitted": len(findings),
        "evidence_emitted": len(evidence),
        "truncated": truncated,
        "network_requests": 0,
        "execution_performed": False,
    }
    return FirmwareAuditResult(
        status=status,
        findings=tuple(sorted(findings, key=lambda item: (item.path, item.line or 0, item.rule_id, item.finding_id))),
        evidence=tuple(sorted(evidence, key=lambda item: item.evidence_id)),
        observations=tuple(observations[: active_limits.max_evidence]),
        checked_paths=tuple(checked_paths),
        limitations=tuple(sorted(set(limitations))),
        coverage=coverage,
    )


def _analyze_source(
    source: FirmwareAuditSource,
    lines: Sequence[_SourceLine],
    existing_evidence: Sequence[Evidence],
    limits: FirmwareAuditLimits,
) -> tuple[list[Finding], list[Evidence], list[dict[str, Any]]]:
    findings: list[Finding] = []
    evidence: list[Evidence] = []
    observations: list[dict[str, Any]] = []
    seen_rules: set[tuple[int, str]] = set()
    tainted_variables: set[str] = set()
    path_context = source.artifact.relative_path.casefold()
    credential_path = any(token in path_context for token in ("shadow", "passwd", "credential", "secret"))

    for line in lines:
        text = line.text
        stripped = text.strip()
        if not stripped or stripped.startswith(_COMMENT_PREFIXES):
            continue
        if _ASSIGNMENT_PATTERN.search(text) and _INPUT_SOURCE_PATTERN.search(text):
            assignment = _ASSIGNMENT_PATTERN.search(text)
            if assignment is not None:
                tainted_variables.add(assignment.group("name").casefold())

        for match in _HASH_PATTERN.finditer(text):
            algorithm = match.group("algorithm").casefold()
            if not (_HASH_CONTEXT_PATTERN.search(text) or credential_path):
                continue
            rule_id = "FW-WEAK-CREDENTIAL-HASH" if algorithm in {"1", "apr1"} else "FW-CREDENTIAL-HASH-MATERIAL"
            if (line.number, rule_id) in seen_rules:
                continue
            seen_rules.add((line.number, rule_id))
            algorithm_name = {"1": "md5-crypt", "apr1": "apr1-md5", "5": "sha256-crypt", "6": "sha512-crypt"}.get(
                algorithm,
                "bcrypt",
            )
            cwes = ["CWE-312"] if rule_id == "FW-CREDENTIAL-HASH-MATERIAL" else ["CWE-916", "CWE-521"]
            evidence_item = _make_evidence(
                source.artifact,
                rule_id=rule_id,
                category="credential_hash_material",
                byte_offset=line.byte_offset + _text_byte_offset(text, match.start(), line.encoding),
                byte_length=_text_byte_length(text, match.start(), match.end(), line.encoding),
                line_number=line.number,
                observation=hashlib.sha256(match.group("value").encode("utf-8")).hexdigest(),
            )
            evidence.append(evidence_item)
            findings.append(
                _make_finding(
                    source.artifact,
                    line,
                    rule_id=rule_id,
                    severity="HIGH" if rule_id == "FW-WEAK-CREDENTIAL-HASH" else "MEDIUM",
                    title=(
                        "Weak credential hash algorithm in firmware artifact"
                        if rule_id == "FW-WEAK-CREDENTIAL-HASH"
                        else "Credential hash material retained in firmware artifact"
                    ),
                    description=(
                        f"The immutable artifact contains {algorithm_name} credential hash material in a credential "
                        "or backup context; the material should not be exposed in a distributable firmware backup."
                    ),
                    remediation=(
                        "Remove credential material from distributable backups and migrate to a reviewed "
                        "password-storage scheme."
                    ),
                    evidence_item=evidence_item,
                    cwes=cwes,
                    details={"algorithm": algorithm_name, "value_sha256": evidence_item.metadata["observation_digest"]},
                )
            )

        length_match = _MAX_LENGTH_PATTERN.search(text)
        if length_match is not None and _WIRELESS_PATTERN.search(text):
            maximum = int(length_match.group("value"))
            if maximum > 32 and (line.number, "FW-WIRELESS-INPUT-LENGTH") not in seen_rules:
                seen_rules.add((line.number, "FW-WIRELESS-INPUT-LENGTH"))
                evidence_item = _make_evidence(
                    source.artifact,
                    rule_id="FW-WIRELESS-INPUT-LENGTH",
                    category="input_validation_constraint",
                    byte_offset=line.byte_offset,
                    byte_length=line.byte_length,
                    line_number=line.number,
                    observation=f"wireless_max_length:{maximum}",
                )
                evidence.append(evidence_item)
                findings.append(
                    _make_finding(
                        source.artifact,
                        line,
                        rule_id="FW-WIRELESS-INPUT-LENGTH",
                        severity="MEDIUM",
                        title="Wireless identifier length constraint exceeds the protocol bound",
                        description=(
                            f"The firmware configuration accepts a wireless identifier up to {maximum} characters; "
                            "this exceeds the conventional 32-character SSID bound and should be validated before use."
                        ),
                        remediation=(
                            "Enforce the protocol-specific SSID length and reject overlong values before storage "
                            "or command construction."
                        ),
                        evidence_item=evidence_item,
                        cwes=["CWE-20"],
                        details={"maximum_length": maximum, "protocol_bound": 32},
                    )
                )
        if _VALIDATION_DISABLED_PATTERN.search(text) and _INPUT_SOURCE_PATTERN.search(text):
            rule_id = "FW-INPUT-VALIDATION-DISABLED"
            if (line.number, rule_id) not in seen_rules:
                seen_rules.add((line.number, rule_id))
                evidence_item = _make_evidence(
                    source.artifact,
                    rule_id=rule_id,
                    category="input_validation_constraint",
                    byte_offset=line.byte_offset,
                    byte_length=line.byte_length,
                    line_number=line.number,
                    observation="input_validation_disabled",
                )
                evidence.append(evidence_item)
                findings.append(
                    _make_finding(
                        source.artifact,
                        line,
                        rule_id=rule_id,
                        severity="HIGH",
                        title="Validation is explicitly disabled for externally sourced input",
                        description=(
                            "The artifact explicitly disables validation for an input-bearing configuration path."
                        ),
                        remediation=(
                            "Enable validation and enforce a typed, bounded allowlist before consuming the input."
                        ),
                        evidence_item=evidence_item,
                        cwes=["CWE-20"],
                        details={"validation_disabled": True},
                    )
                )

        clear_match = _CLEAR_TRANSPORT_PATTERN.search(text)
        if clear_match is not None and _CLEAR_CONFIG_PATTERN.search(text):
            rule_id = "FW-CLEARTEXT-TRANSPORT"
            if (line.number, rule_id) not in seen_rules:
                seen_rules.add((line.number, rule_id))
                evidence_item = _make_evidence(
                    source.artifact,
                    rule_id=rule_id,
                    category="cleartext_transport_configuration",
                    byte_offset=line.byte_offset + _text_byte_offset(text, clear_match.start(), line.encoding),
                    byte_length=_text_byte_length(text, clear_match.start(), clear_match.end(), line.encoding),
                    line_number=line.number,
                    observation=clear_match.group("scheme").casefold(),
                )
                evidence.append(evidence_item)
                findings.append(
                    _make_finding(
                        source.artifact,
                        line,
                        rule_id=rule_id,
                        severity="HIGH",
                        title="Firmware configuration enables a cleartext transport",
                        description=(
                            f"An explicit {clear_match.group('scheme').casefold()} transport appears in a firmware "
                            "endpoint/configuration context without transport confidentiality."
                        ),
                        remediation="Use a reviewed TLS-protected transport and verify the peer certificate.",
                        evidence_item=evidence_item,
                        cwes=["CWE-319"],
                        details={"scheme": clear_match.group("scheme").casefold()},
                    )
                )
        elif (
            _INSECURE_TLS_PATTERN.search(text) or _INSECURE_FLAG_PATTERN.search(text)
        ) and _CLEAR_CONFIG_PATTERN.search(text):
            rule_id = "FW-INSECURE-TRANSPORT-VERIFICATION"
            if (line.number, rule_id) not in seen_rules:
                seen_rules.add((line.number, rule_id))
                evidence_item = _make_evidence(
                    source.artifact,
                    rule_id=rule_id,
                    category="cleartext_transport_configuration",
                    byte_offset=line.byte_offset,
                    byte_length=line.byte_length,
                    line_number=line.number,
                    observation="transport_verification_disabled",
                )
                evidence.append(evidence_item)
                findings.append(
                    _make_finding(
                        source.artifact,
                        line,
                        rule_id=rule_id,
                        severity="HIGH",
                        title="Firmware transport verification is explicitly disabled",
                        description=(
                            "The firmware configuration explicitly disables a TLS or certificate verification control."
                        ),
                        remediation=(
                            "Require certificate validation and fail closed when transport verification cannot be "
                            "established."
                        ),
                        evidence_item=evidence_item,
                        cwes=["CWE-319"],
                        details={"verification_disabled": True},
                    )
                )

        sink = _SHELL_SINK_PATTERN.search(text)
        if sink is not None:
            variable_taint = any(
                re.search(rf"(?i)\b{re.escape(variable)}\b", text) is not None for variable in tainted_variables
            )
            has_input = bool(_INPUT_SOURCE_PATTERN.search(text)) or variable_taint
            sanitized = bool(_SANITIZER_PATTERN.search(text))
            if has_input and sanitized:
                evidence_item = _make_evidence(
                    source.artifact,
                    rule_id="FW-SHELL-SINK-GUARDED",
                    category="shell_dataflow",
                    byte_offset=line.byte_offset + _text_byte_offset(text, sink.start(), line.encoding),
                    byte_length=_text_byte_length(text, sink.start(), sink.end(), line.encoding),
                    line_number=line.number,
                    observation="guarded_shell_sink",
                )
                observations.append(
                    {
                        "kind": "guarded_shell_sink",
                        "path": source.artifact.relative_path,
                        "line": line.number,
                        "evidence_ids": [evidence_item.evidence_id],
                        "source_locator": evidence_item.metadata["source_locator"],
                        "note": (
                            "A source-to-shell path was observed with an explicit sanitizer/validator; "
                            "no risk finding was published."
                        ),
                    }
                )
                evidence.append(evidence_item)
            elif has_input:
                rule_id = "FW-UNTRUSTED-SHELL-DATAFLOW"
                if (line.number, rule_id) not in seen_rules:
                    seen_rules.add((line.number, rule_id))
                    evidence_item = _make_evidence(
                        source.artifact,
                        rule_id=rule_id,
                        category="shell_dataflow",
                        byte_offset=line.byte_offset + _text_byte_offset(text, sink.start(), line.encoding),
                        byte_length=_text_byte_length(text, sink.start(), sink.end(), line.encoding),
                        line_number=line.number,
                        observation="untrusted_shell_sink",
                    )
                    evidence.append(evidence_item)
                    findings.append(
                        _make_finding(
                            source.artifact,
                            line,
                            rule_id=rule_id,
                            severity="HIGH",
                            title="Externally sourced data reaches a shell execution sink",
                            description=(
                                "The bounded source scan found input-bearing data reaching a shell execution sink "
                                "without an explicit sanitizer or allowlist in the same source context."
                            ),
                            remediation=(
                                "Use a non-shell API or validate/allowlist the value before constructing the command."
                            ),
                            evidence_item=evidence_item,
                            cwes=["CWE-78"],
                            details={"sink": sink.group(0).strip()},
                        )
                    )

    # Do not expose a finding whose evidence was not emitted under the budget.
    evidence_ids = {item.evidence_id for item in [*existing_evidence, *evidence]}
    findings = [item for item in findings if set(item.evidence_ids).issubset(evidence_ids)]
    return findings, evidence, observations


def _make_finding(
    artifact: InputArtifact,
    line: _SourceLine,
    *,
    rule_id: str,
    severity: FindingSeverity,
    title: str,
    description: str,
    remediation: str,
    evidence_item: Evidence,
    cwes: list[str],
    details: dict[str, Any],
) -> Finding:
    finding_id = str(uuid5(NAMESPACE_URL, f"secmind:firmware:finding:{artifact.sha256}:{line.number}:{rule_id}"))
    return Finding(
        finding_id=finding_id,
        rule_id=rule_id,
        severity=severity,
        confidence="HIGH",
        path=artifact.relative_path,
        line=line.number,
        title=title,
        description=description,
        remediation=remediation,
        evidence_ids=[evidence_item.evidence_id],
        raw={
            "domain": "firmware_static_audit",
            "cwe_ids": cwes,
            "category": evidence_item.metadata.get("category"),
            "evidence_binding": {
                "evidence_ids": [evidence_item.evidence_id],
                "source_locator": evidence_item.metadata.get("source_locator"),
            },
            **details,
        },
    )


def _make_evidence(
    artifact: InputArtifact,
    *,
    rule_id: str,
    category: str,
    byte_offset: int,
    byte_length: int,
    line_number: int,
    observation: str,
) -> Evidence:
    locator = {
        "source_ref": artifact.relative_path,
        "segment_id": rule_id.casefold(),
        "record_number": 0,
        "line_number": line_number,
        "byte_offset": byte_offset,
        "byte_length": byte_length,
        "locator_scope": "whole_file" if rule_id == "FW-SCAN-SCOPE" else "line",
    }
    evidence_id = str(
        uuid5(
            NAMESPACE_URL,
            f"secmind:firmware:evidence:{artifact.sha256}:{rule_id}:{byte_offset}:{byte_length}",
        )
    )
    return Evidence(
        evidence_id=evidence_id,
        source="deterministic_firmware_static_audit@1.0",
        summary="A bounded firmware static-audit observation was retained from immutable source bytes.",
        artifact_ref=artifact.sha256.casefold(),
        sha256=artifact.sha256.casefold(),
        metadata={
            "evidence_type": "firmware_static_observation",
            "assurance_level": "deterministic",
            "category": category,
            "rule_id": rule_id,
            "source_artifact_sha256": artifact.sha256.casefold(),
            "source_locator": locator,
            "observation_digest": hashlib.sha256(observation.encode("utf-8")).hexdigest(),
        },
    )


def _source_lines(content: bytes) -> list[_SourceLine]:
    """Decode text without losing byte offsets; no parser or interpreter is used."""

    utf16 = content.startswith((b"\xff\xfe", b"\xfe\xff")) or content[:512].count(b"\x00") > 8
    if utf16:
        encoding = "utf-16" if content.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-16le"
        try:
            text = content.decode(encoding, errors="replace")
        except (LookupError, UnicodeError):
            text = content.decode("utf-8", errors="replace")
        prefix = 2 if content.startswith((b"\xff\xfe", b"\xfe\xff")) else 0
        rows: list[_SourceLine] = []
        cursor = 0
        for number, segment in enumerate(text.splitlines(keepends=True), start=1):
            encoded = segment.encode("utf-16le", errors="replace")
            rows.append(
                _SourceLine(
                    number=number,
                    text=segment.rstrip("\r\n"),
                    byte_offset=prefix + cursor,
                    byte_length=len(encoded),
                    encoding="utf-16le",
                )
            )
            cursor += len(encoded)
        return rows or [
            _SourceLine(
                number=1,
                text=text,
                byte_offset=prefix,
                byte_length=len(content) - prefix,
                encoding="utf-16le",
            )
        ]

    rows = []
    cursor = 0
    for number, raw in enumerate(content.splitlines(keepends=True), start=1):
        text = raw.decode("utf-8", errors="replace")
        rows.append(
            _SourceLine(
                number=number,
                text=text.rstrip("\r\n"),
                byte_offset=cursor,
                byte_length=len(raw),
            )
        )
        cursor += len(raw)
    return rows or [_SourceLine(number=1, text="", byte_offset=0, byte_length=len(content))]


def _text_byte_offset(text: str, character_offset: int, encoding: str) -> int:
    return len(text[:character_offset].encode(encoding, errors="replace"))


def _text_byte_length(text: str, character_start: int, character_end: int, encoding: str) -> int:
    return len(text[character_start:character_end].encode(encoding, errors="replace"))


__all__ = [
    "FIRMWARE_STATIC_CAPABILITY",
    "FirmwareAuditLimits",
    "FirmwareAuditResult",
    "FirmwareAuditSource",
    "audit_firmware_sources",
]
