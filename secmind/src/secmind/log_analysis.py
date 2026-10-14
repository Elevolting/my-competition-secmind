"""Bounded, deterministic primitives for the offline security-log scenario.

This module is deliberately isolated from the orchestration and execution planes.
It performs no network, model, database, Docker, or subprocess operations.  Its
domain records are internal normalizer output; public evidence uses the existing
``secmind.schemas.Evidence`` contract.
"""

from __future__ import annotations

import csv
import hashlib
import ipaddress
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass, field, replace
from datetime import UTC, datetime
from itertools import islice
from pathlib import PurePosixPath
from typing import Any, Literal
from urllib.parse import urlsplit, urlunsplit
from uuid import NAMESPACE_URL, uuid5

from secmind import PUBLIC_VERSION
from secmind.log_parsers import (
    ArchiveSafetyError,
    BinaryParseLimits,
    BinaryParseResult,
    detect_binary_format,
    extract_safe_zip,
    parse_binary_log,
)
from secmind.schemas import Evidence
from secmind.secret_scrubber import REDACTED, is_sensitive_key, scrub_text, scrub_value

_NORMALIZER_VERSION = PUBLIC_VERSION
_RULE_BUNDLE_VERSION = "secmind-log-rules/2026.07-beta.1"
_CORRELATION_BUNDLE_VERSION = "secmind-log-correlations/2026.08-beta.1"
_ATTACK_VERSION = "enterprise-attack/beta-pinned-2026.07"

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_FORMULA_PREFIX = ("=", "+", "-", "@")
_HEX_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_URL = re.compile(r"\bhttps?://[^\s<>\"']+", re.IGNORECASE)
_EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}\b", re.IGNORECASE)
_DOMAIN = re.compile(r"(?<![@\w.-])(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,63}\b")
_FILELIKE_DOMAIN_SUFFIXES = frozenset(
    {
        "bat",
        "bin",
        "cmd",
        "cpl",
        "dll",
        "drv",
        "dylib",
        "exe",
        "jar",
        "js",
        "msi",
        "ocx",
        "ps1",
        "scr",
        "sys",
        "vbs",
    }
)
_MAX_CORRELATION_EVENT_REFS = 64
_MAX_SOURCE_ATTACK_ANNOTATIONS = 8
_WINRM_CORRELATION_RULE_ID = "SECMIND-CORR-WINRM-CMD-WHOAMI-001"
_RDP_CONTEXT_RULE_ID = "SECMIND-CORR-RDP-CONTEXT-001"
_SOURCE_ATTACK_ANNOTATION_RULE_ID = "SECMIND-SOURCE-ATTACK-ANNOTATION-001"
_SOURCE_ATTACK_ID = re.compile(r"(?i)(?:^|[,;])\s*technique_id\s*=\s*(T\d{4}(?:\.\d{3})?)\b")
_SAFE_EXECUTABLE_BASENAME = re.compile(r"(?i)^[a-z0-9_.-]{1,128}\.(?:bat|cmd|com|dll|exe|ps1)$")
_RFC5424 = re.compile(
    r"^<(?P<pri>\d{1,3})>1\s+(?P<timestamp>\S+)\s+(?P<host>\S+)\s+"
    r"(?P<app>\S+)\s+(?P<proc>\S+)\s+(?P<msgid>\S+)\s+(?P<rest>.*)$"
)
_RFC3164 = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<app>[^:\[]+)(?:\[(?P<proc>\d+)\])?:\s*(?P<message>.*)$"
)

LogFormat = Literal["auto", "jsonl", "csv", "tsv", "syslog", "evtx", "pcap", "pcapng", "zip"]
ResultStatus = Literal["completed", "partial", "failed"]
TimestampQuality = Literal["exact", "assumed_timezone", "missing", "invalid"]


class LogAnalysisError(ValueError):
    """Base class for typed log-analysis failures."""


class LogLimitError(LogAnalysisError):
    """The input exceeded a whole-artifact safety bound."""


class LogFormatError(LogAnalysisError):
    """The requested log format could not be safely normalized."""


@dataclass(frozen=True, slots=True)
class LogAnalysisLimits:
    max_input_bytes: int = 8 * 1024 * 1024
    max_record_bytes: int = 64 * 1024
    max_records: int = 10_000
    max_fields: int = 256
    max_field_chars: int = 16 * 1024
    max_json_depth: int = 16
    max_json_nodes: int = 10_000
    max_rules: int = 256
    max_rule_matches: int = 2_000
    max_iocs_per_event: int = 128
    max_iocs: int = 2_000
    # Public graph state and reports retain a representative, source-bound
    # evidence set. The complete normalized timeline is persisted as a CAS
    # artifact, so retaining thousands of near-identical packet rows here only
    # inflates checkpoints and can make otherwise valid API reads fail.
    max_evidence: int = 1_000
    # Parser diagnostics are explanatory samples, not one durable object per
    # rejected record.  Keeping this independently bounded prevents malformed
    # JSONL/CSV input from turning a small parse failure into tens of thousands
    # of Evidence rows and oversized graph checkpoints.
    max_diagnostics: int = 256
    max_archive_members: int = 100
    max_archive_member_bytes: int = 2 * 1024 * 1024
    max_archive_total_bytes: int = 8 * 1024 * 1024
    max_archive_ratio: int = 100

    def __post_init__(self) -> None:
        for name, value in asdict(self).items():
            if value < 1:
                raise ValueError(f"{name} must be positive")


@dataclass(frozen=True, slots=True)
class SourceLocator:
    source_ref: str
    segment_id: str
    record_number: int
    line_number: int
    byte_offset: int
    byte_length: int


@dataclass(frozen=True, slots=True)
class EntityRef:
    kind: str
    value: str


@dataclass(frozen=True, slots=True)
class NormalizedSecurityEvent:
    event_id: str
    timestamp_utc: str | None
    timestamp_quality: TimestampQuality
    source_format: str
    event_type: str
    severity: str
    message: str
    entities: tuple[EntityRef, ...]
    attributes: Mapping[str, Any]
    locator: SourceLocator
    content_sha256: str


@dataclass(frozen=True, slots=True)
class ParserDiagnostic:
    code: str
    message: str
    severity: Literal["info", "warning", "error"]
    locator: SourceLocator | None = None


@dataclass(frozen=True, slots=True)
class SigmaLikeRule:
    rule_id: str
    title: str
    message_contains_any: tuple[str, ...]
    event_types: tuple[str, ...] = ()
    severity: str = "MEDIUM"
    attack_ids: tuple[str, ...] = ()
    version: str = _RULE_BUNDLE_VERSION


@dataclass(frozen=True, slots=True)
class RuleMatch:
    match_id: str
    rule_id: str
    rule_version: str
    title: str
    severity: str
    event_id: str
    attack_ids: tuple[str, ...]
    matched_on: tuple[str, ...]
    locator: SourceLocator


@dataclass(frozen=True, slots=True)
class IocObservation:
    observation_id: str
    ioc_type: Literal["ipv4", "domain", "url", "email", "sha256"]
    normalized_value: str
    display_value: str
    confidence: float
    event_id: str
    locator: SourceLocator


@dataclass(frozen=True, slots=True)
class AttackMapping:
    technique_id: str
    technique_name: str
    knowledge_version: str
    event_ids: tuple[str, ...]
    rule_ids: tuple[str, ...]
    confidence: float
    interpretation: str = "deterministic_supporting_mapping_not_fact"
    source_refs: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class LogAnalysisResult:
    status: ResultStatus
    source_format: str
    events: tuple[NormalizedSecurityEvent, ...]
    timeline_event_ids: tuple[str, ...]
    rule_matches: tuple[RuleMatch, ...]
    iocs: tuple[IocObservation, ...]
    attack_mappings: tuple[AttackMapping, ...]
    diagnostics: tuple[ParserDiagnostic, ...]
    evidence: tuple[Evidence, ...]
    coverage: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class _CorrelationOutcome:
    mappings: tuple[AttackMapping, ...]
    candidate_count: int
    correlated_count: int
    verified_count: int
    rejected_count: int
    event_limit_reached: bool


DEFAULT_RULES: tuple[SigmaLikeRule, ...] = (
    SigmaLikeRule(
        rule_id="SECMIND-AUTH-BRUTEFORCE-001",
        title="Authentication failure observed",
        message_contains_any=("failed password", "authentication failure", "login failed", "invalid user"),
        severity="MEDIUM",
        attack_ids=("T1110",),
    ),
    SigmaLikeRule(
        rule_id="SECMIND-POWERSHELL-ENCODED-001",
        title="Encoded PowerShell execution observed",
        message_contains_any=("powershell -enc", "powershell.exe -encodedcommand", "encodedcommand"),
        severity="HIGH",
        attack_ids=("T1059.001",),
    ),
    SigmaLikeRule(
        rule_id="SECMIND-SUDO-FAILURE-001",
        title="Privilege escalation authentication failure",
        message_contains_any=("sudo: authentication failure", "user not in sudoers"),
        severity="MEDIUM",
        attack_ids=("T1548.003",),
    ),
    SigmaLikeRule(
        rule_id="SECMIND-AD-REPLICATION-001",
        title="Active Directory replication right used",
        message_contains_any=(
            "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
            "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
        ),
        event_types=("windows_event:4662",),
        severity="HIGH",
        attack_ids=("T1003.006",),
    ),
)

_ATTACK_CATALOG: Mapping[str, str] = {
    "T1003.006": "DCSync",
    "T1110": "Brute Force",
    "T1059.001": "PowerShell",
    "T1059.003": "Windows Command Shell",
    "T1021.001": "Remote Desktop Protocol",
    "T1021.006": "Windows Remote Management",
    "T1033": "System Owner/User Discovery",
    "T1088": "Bypass User Account Control",
    "T1112": "Modify Registry",
    "T1548.003": "Sudo and Sudo Caching",
}


def analyze_offline_logs(
    content: bytes,
    *,
    source_ref: str,
    artifact_ref: str,
    artifact_sha256: str | None = None,
    log_format: LogFormat = "auto",
    limits: LogAnalysisLimits | None = None,
    rules: Iterable[SigmaLikeRule] = DEFAULT_RULES,
    default_year: int = 2026,
    allow_binary: bool = False,
) -> LogAnalysisResult:
    """Normalize and analyze an immutable log artifact without side effects."""

    active_limits = limits or LogAnalysisLimits()
    _validate_source_ref(source_ref)
    if not artifact_ref:
        raise ValueError("artifact_ref is required for evidence provenance")
    if len(content) > active_limits.max_input_bytes:
        raise LogLimitError(f"input exceeds {active_limits.max_input_bytes} bytes")
    digest = artifact_sha256 or hashlib.sha256(content).hexdigest()
    if not re.fullmatch(r"[a-fA-F0-9]{64}", digest):
        raise ValueError("artifact_sha256 must be a SHA-256 hex digest")

    selected, events, diagnostics, total_records, source_artifacts = _normalize_input(
        content,
        source_ref=source_ref,
        requested_format=log_format,
        limits=active_limits,
        default_year=default_year,
        allow_binary=allow_binary,
    )

    if total_records == 0:
        diagnostics.append(
            ParserDiagnostic(
                code="input.empty",
                message="no security-log records were available for analysis",
                severity="warning",
            )
        )
    normalized_records = len(events)
    events, duplicate_diagnostics = _deduplicate(events)
    diagnostics.extend(duplicate_diagnostics)
    ordered = tuple(sorted(events, key=_timeline_key))
    rule_tuple = tuple(islice(rules, active_limits.max_rules + 1))
    if len(rule_tuple) > active_limits.max_rules:
        raise LogLimitError(f"rule bundle exceeds {active_limits.max_rules} rules")
    matches, match_limit_reached = _match_rules(ordered, rule_tuple, active_limits.max_rule_matches)
    iocs, ioc_limit_reached = _extract_iocs(
        ordered,
        max_per_event=active_limits.max_iocs_per_event,
        max_total=active_limits.max_iocs,
    )
    if match_limit_reached:
        diagnostics.append(
            ParserDiagnostic(
                code="analysis.rule_match_limit",
                message="rule matching reached its output limit; coverage is partial",
                severity="warning",
            )
        )
    if ioc_limit_reached:
        diagnostics.append(
            ParserDiagnostic(
                code="analysis.ioc_limit",
                message="IOC extraction reached its output limit; coverage is partial",
                severity="warning",
            )
        )
    correlation = _correlate_attack(ordered)
    source_annotations = _map_source_attack_annotations(ordered)
    attack_mappings = merge_attack_mappings(_map_attack(matches), source_annotations, correlation.mappings)
    if correlation.event_limit_reached:
        diagnostics.append(
            ParserDiagnostic(
                code="analysis.correlation_event_limit",
                message="correlation evidence references reached their bounded output limit; coverage is partial",
                severity="warning",
            )
        )
    unbounded_evidence_count = len(ordered) + len(matches) + len(iocs) + len(attack_mappings) + len(diagnostics)
    if unbounded_evidence_count > active_limits.max_evidence:
        diagnostics.append(
            ParserDiagnostic(
                code="evidence.limit",
                message="evidence generation reached its output limit; coverage is partial",
                severity="warning",
            )
        )
    diagnostic_count = len(diagnostics)
    duplicate_count = sum(item.code == "record.duplicate" for item in diagnostics)
    invalid_records = max(
        sum(item.code.startswith("record.") and item.severity == "error" for item in diagnostics),
        total_records - normalized_records,
    )
    diagnostics_truncated = diagnostic_count > active_limits.max_diagnostics
    if diagnostics_truncated:
        retained = diagnostics[: max(0, active_limits.max_diagnostics - 1)]
        retained.append(
            ParserDiagnostic(
                code="parser.diagnostic_limit",
                message=(
                    f"{diagnostic_count} parser diagnostic(s) were observed; "
                    "only a bounded representative set was retained"
                ),
                severity="warning",
            )
        )
        diagnostics = retained
    evidence = _build_evidence(
        ordered,
        matches,
        iocs,
        attack_mappings,
        diagnostics,
        artifact_ref=artifact_ref,
        artifact_sha256=digest.lower(),
        source_artifacts=source_artifacts,
        limit=active_limits.max_evidence,
    )
    status: ResultStatus = "completed"
    if diagnostics:
        status = "partial" if ordered else "failed"
    return LogAnalysisResult(
        status=status,
        source_format=selected,
        events=ordered,
        timeline_event_ids=tuple(event.event_id for event in ordered),
        rule_matches=matches,
        iocs=iocs,
        attack_mappings=attack_mappings,
        diagnostics=tuple(diagnostics),
        evidence=evidence,
        coverage={
            "records_seen": total_records,
            "records_emitted": normalized_records,
            "records_normalized": len(ordered),
            "records_rejected": invalid_records,
            "duplicates_removed": duplicate_count,
            "timestamped_records": sum(event.timestamp_utc is not None for event in ordered),
            "rule_bundle_version": _RULE_BUNDLE_VERSION,
            "rule_bundle_digest": _rules_digest(rule_tuple),
            "attack_knowledge_version": _ATTACK_VERSION,
            "correlation_bundle_version": _CORRELATION_BUNDLE_VERSION,
            "correlation_candidate_count": correlation.candidate_count,
            "correlation_correlated_count": correlation.correlated_count,
            "correlation_verified_count": correlation.verified_count,
            "correlation_rejected_count": correlation.rejected_count,
            "correlation_event_limit_reached": correlation.event_limit_reached,
            "source_attack_annotation_count": len(source_annotations),
            "rule_match_limit_reached": match_limit_reached,
            "ioc_limit_reached": ioc_limit_reached,
            "evidence_truncated": unbounded_evidence_count > active_limits.max_evidence,
            "diagnostics_seen": diagnostic_count,
            "diagnostics_truncated": diagnostics_truncated,
            "network_access_performed": False,
            "model_calls": 0,
            "provider_cost": 0,
        },
    )


def _normalize_input(
    content: bytes,
    *,
    source_ref: str,
    requested_format: LogFormat,
    limits: LogAnalysisLimits,
    default_year: int,
    allow_binary: bool,
) -> tuple[
    str,
    list[NormalizedSecurityEvent],
    list[ParserDiagnostic],
    int,
    dict[str, tuple[str, str]],
]:
    detected_binary = detect_binary_format(content)
    selected = detected_binary if requested_format == "auto" and detected_binary else requested_format
    if selected == "auto":
        selected = _detect_format(source_ref, content)
    if selected in {"evtx", "pcap", "pcapng", "zip"} and not allow_binary:
        raise LogFormatError("binary and archive log parsing is disabled")
    if selected == "zip":
        return _normalize_archive(content, source_ref, limits, default_year)
    if selected in {"evtx", "pcap", "pcapng"}:
        result = parse_binary_log(
            content,
            source_ref=source_ref,
            limits=_binary_limits(limits),
        )
        events, diagnostics = _convert_binary_result(result, content)
        return result.format_detected, events, diagnostics, result.records_seen, {}
    events, diagnostics, total_records = _normalize_text(
        content,
        source_ref=source_ref,
        selected=str(selected),
        limits=limits,
        default_year=default_year,
    )
    return str(selected), events, diagnostics, total_records, {}


def _normalize_archive(
    content: bytes,
    source_ref: str,
    limits: LogAnalysisLimits,
    default_year: int,
) -> tuple[
    str,
    list[NormalizedSecurityEvent],
    list[ParserDiagnostic],
    int,
    dict[str, tuple[str, str]],
]:
    try:
        archive = extract_safe_zip(content, limits=_binary_limits(limits))
    except ArchiveSafetyError as exc:
        raise LogFormatError(str(exc)) from exc
    members = archive.members
    events: list[NormalizedSecurityEvent] = []
    diagnostics: list[ParserDiagnostic] = []
    source_artifacts: dict[str, tuple[str, str]] = {}
    if archive.skipped_member_paths:
        diagnostics.append(
            ParserDiagnostic(
                code="archive.members_skipped",
                message=f"{len(archive.skipped_member_paths)} unsupported archive member(s) were not analyzed",
                severity="warning",
            )
        )
    total_records = 0
    for member_index, member in enumerate(members):
        remaining_records = limits.max_records - total_records
        if remaining_records <= 0:
            diagnostics.append(_archive_record_limit_diagnostic())
            break
        member_limits = replace(limits, max_records=remaining_records)
        member_ref = f"{source_ref}!{member.path}"
        member_digest = hashlib.sha256(member.content).hexdigest()
        # ArtifactStore identifiers are content digests. Scenario execution
        # persists these exact member bytes before evidence verification.
        source_artifacts[member_ref] = (member_digest, member_digest)
        detected = detect_binary_format(member.content)
        try:
            if detected in {"evtx", "pcap", "pcapng"}:
                result = parse_binary_log(
                    member.content,
                    source_ref=member_ref,
                    limits=_binary_limits(member_limits),
                )
                normalized, parser_diagnostics = _convert_binary_result(result, member.content)
                events.extend(normalized)
                diagnostics.extend(parser_diagnostics)
                total_records += min(result.records_seen, remaining_records)
            else:
                selected = _detect_format(member_ref, member.content)
                normalized, parser_diagnostics, records = _normalize_text(
                    member.content,
                    source_ref=member_ref,
                    selected=selected,
                    limits=member_limits,
                    default_year=default_year,
                )
                events.extend(normalized)
                diagnostics.extend(parser_diagnostics)
                total_records += min(records, remaining_records)
        except LogAnalysisError as exc:
            diagnostics.append(
                ParserDiagnostic(
                    code="archive.member_invalid",
                    message=f"{member.path}: {_safe_error(exc)}",
                    severity="warning",
                )
            )
        if total_records >= limits.max_records and member_index + 1 < len(members):
            diagnostics.append(_archive_record_limit_diagnostic())
            break
    if not members:
        diagnostics.append(
            ParserDiagnostic(
                code="archive.empty",
                message="ZIP contained no allowlisted log members",
                severity="warning",
            )
        )
    return "zip", events, diagnostics, total_records, source_artifacts


def _archive_record_limit_diagnostic() -> ParserDiagnostic:
    return ParserDiagnostic(
        code="archive.record_limit",
        message="archive-wide record limit reached; remaining members were not analyzed",
        severity="warning",
    )


def _normalize_text(
    content: bytes,
    *,
    source_ref: str,
    selected: str,
    limits: LogAnalysisLimits,
    default_year: int,
) -> tuple[list[NormalizedSecurityEvent], list[ParserDiagnostic], int]:
    if selected == "jsonl":
        return _normalize_jsonl(content, source_ref, limits)
    if selected in {"csv", "tsv"}:
        return _normalize_delimited(
            content,
            source_ref,
            limits,
            delimiter="\t" if selected == "tsv" else ",",
            source_format=selected,
        )
    if selected == "syslog":
        return _normalize_syslog(content, source_ref, limits, default_year)
    raise LogFormatError(f"unsupported log format: {selected}")


def _binary_limits(limits: LogAnalysisLimits) -> BinaryParseLimits:
    return BinaryParseLimits(
        max_input_bytes=limits.max_input_bytes,
        max_records=limits.max_records,
        max_event_fields=limits.max_fields,
        max_string_chars=limits.max_field_chars,
        max_archive_members=limits.max_archive_members,
        max_archive_member_bytes=limits.max_archive_member_bytes,
        max_archive_total_bytes=limits.max_archive_total_bytes,
        max_archive_ratio=limits.max_archive_ratio,
    )


def _convert_binary_result(
    result: BinaryParseResult,
    content: bytes,
) -> tuple[list[NormalizedSecurityEvent], list[ParserDiagnostic]]:
    artifact_digest = hashlib.sha256(content).hexdigest()
    events: list[NormalizedSecurityEvent] = []
    for item in result.events:
        has_exact_record_locator = (
            item.locator_scope == "record"
            and item.byte_offset >= 0
            and item.byte_length > 0
            and item.byte_offset + item.byte_length <= len(content)
        )
        locator = SourceLocator(
            source_ref=result.source_ref,
            segment_id=(result.format_detected if has_exact_record_locator else f"{result.format_detected}:whole-file"),
            record_number=item.record_number,
            line_number=0,
            byte_offset=item.byte_offset if has_exact_record_locator else 0,
            byte_length=item.byte_length if has_exact_record_locator else len(content),
        )
        attributes = _flatten_and_scrub(item.attributes)
        _augment_typed_source_metadata(attributes, item.attributes)
        entities = _entities(attributes)
        event_type = _text_value(item.event_type, "binary_event")
        message = _text_value(item.message, "binary security event", max_chars=4_096)
        content_digest = _digest(
            {
                "timestamp_utc": item.timestamp_utc,
                "timestamp_quality": "exact" if item.timestamp_utc else "missing",
                "source_format": result.format_detected,
                "event_type": event_type,
                "severity": "UNKNOWN",
                "message": message,
                "entities": [asdict(entity) for entity in entities],
                "attributes": attributes,
                "record_number": item.record_number,
                "artifact_sha256": artifact_digest,
            }
        )
        events.append(
            NormalizedSecurityEvent(
                event_id=str(
                    uuid5(
                        NAMESPACE_URL,
                        f"secmind:binary-event:{result.source_ref}:{item.event_id}:{content_digest}",
                    )
                ),
                timestamp_utc=item.timestamp_utc,
                timestamp_quality="exact" if item.timestamp_utc else "missing",
                source_format=result.format_detected,
                event_type=event_type,
                severity="UNKNOWN",
                message=message,
                entities=entities,
                attributes=attributes,
                locator=locator,
                content_sha256=content_digest,
            )
        )
    diagnostics = [
        ParserDiagnostic(
            code=item.code,
            message=scrub_text(item.message)[:512],
            severity=item.severity,
            locator=(
                SourceLocator(
                    source_ref=result.source_ref,
                    segment_id=result.format_detected,
                    record_number=item.record_number,
                    line_number=0,
                    byte_offset=0,
                    byte_length=0,
                )
                if item.record_number is not None
                else None
            ),
        )
        for item in result.diagnostics
    ]
    if result.truncated:
        diagnostics.append(
            ParserDiagnostic(
                code="binary.truncated",
                message="binary parser reached its record limit; coverage is partial",
                severity="warning",
            )
        )
    return events, diagnostics


def _normalize_jsonl(
    content: bytes,
    source_ref: str,
    limits: LogAnalysisLimits,
) -> tuple[list[NormalizedSecurityEvent], list[ParserDiagnostic], int]:
    if _should_parse_json_document(content, source_ref):
        document = _try_parse_json_document(content)
        if document is not None:
            return _normalize_json_document(document, content, source_ref, limits)

    events: list[NormalizedSecurityEvent] = []
    diagnostics: list[ParserDiagnostic] = []
    seen = 0
    for locator, raw in _bounded_lines(content, source_ref, limits):
        if not raw.strip():
            continue
        seen += 1
        if seen > limits.max_records:
            diagnostics.append(
                _diagnostic("record.limit", "record limit reached; remaining input was not analyzed", locator)
            )
            break
        try:
            text = _decode_record(raw)
            value = json.loads(text, object_pairs_hook=_unique_object)
            _validate_json(value, limits)
            if not isinstance(value, Mapping):
                raise LogFormatError("JSONL record must be an object")
            events.append(_event_from_mapping(value, locator, "jsonl"))
        except (json.JSONDecodeError, UnicodeDecodeError, LogAnalysisError, RecursionError) as exc:
            diagnostics.append(_diagnostic("record.invalid_json", _safe_error(exc), locator))
    return events, diagnostics, seen


def _should_parse_json_document(content: bytes, source_ref: str) -> bool:
    suffix = PurePosixPath(source_ref.replace("\\", "/")).suffix.casefold()
    return suffix == ".json" or content.lstrip().startswith(b"[")


def _try_parse_json_document(content: bytes) -> Any | None:
    """Return a complete JSON document, or ``None`` for JSONL/fault isolation."""

    try:
        text = content.decode("utf-8", errors="strict")
        if not text.strip():
            return None
        return json.loads(text, object_pairs_hook=_unique_object)
    except (json.JSONDecodeError, UnicodeDecodeError, LogAnalysisError, RecursionError):
        return None


def _normalize_json_document(
    document: Any,
    content: bytes,
    source_ref: str,
    limits: LogAnalysisLimits,
) -> tuple[list[NormalizedSecurityEvent], list[ParserDiagnostic], int]:
    records = document if isinstance(document, list) else [document]
    events: list[NormalizedSecurityEvent] = []
    diagnostics: list[ParserDiagnostic] = []
    if not records:
        locator = _json_document_locator(source_ref, len(content), 1, "json-array-empty")
        diagnostics.append(_diagnostic("record.invalid_json", "JSON array contains no object records", locator))
        return events, diagnostics, 0

    seen = 0
    for index, value in enumerate(records, start=1):
        seen += 1
        locator = _json_document_locator(
            source_ref,
            len(content),
            index,
            "json-document" if not isinstance(document, list) else f"json-array-{index}",
        )
        if seen > limits.max_records:
            diagnostics.append(
                _diagnostic("record.limit", "record limit reached; remaining input was not analyzed", locator)
            )
            break
        try:
            _validate_json(value, limits)
            if not isinstance(value, Mapping):
                raise LogFormatError("JSON document record must be an object")
            encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str).encode()
            if len(encoded) > limits.max_record_bytes:
                raise LogLimitError("JSON document record exceeds the byte limit")
            events.append(_event_from_mapping(value, locator, "jsonl"))
        except (LogAnalysisError, RecursionError) as exc:
            diagnostics.append(_diagnostic("record.invalid_json", _safe_error(exc), locator))
    return events, diagnostics, seen


def _json_document_locator(source_ref: str, content_length: int, record_number: int, segment_id: str) -> SourceLocator:
    return SourceLocator(
        source_ref=source_ref,
        segment_id=segment_id,
        record_number=record_number,
        line_number=0,
        byte_offset=0,
        byte_length=content_length,
    )


def _normalize_delimited(
    content: bytes,
    source_ref: str,
    limits: LogAnalysisLimits,
    *,
    delimiter: str,
    source_format: str,
) -> tuple[list[NormalizedSecurityEvent], list[ParserDiagnostic], int]:
    lines = list(_bounded_lines(content, source_ref, limits))
    diagnostics: list[ParserDiagnostic] = []
    if not lines:
        return [], diagnostics, 0
    header_locator, header_raw = lines[0]
    try:
        header = next(csv.reader([_decode_record(header_raw)], delimiter=delimiter, strict=True))
    except (csv.Error, UnicodeDecodeError) as exc:
        raise LogFormatError(f"invalid delimited header: {_safe_error(exc)}") from exc
    if not header or len(header) > limits.max_fields:
        raise LogFormatError("delimited header is empty or exceeds the field limit")
    normalized_header: list[str] = []
    for index, name in enumerate(header):
        cleaned = name.strip()
        if not cleaned or _CONTROL.search(cleaned) or cleaned.lstrip().startswith(_FORMULA_PREFIX):
            cleaned = f"column_{index + 1}"
            diagnostics.append(
                ParserDiagnostic(
                    code="header.sanitized",
                    message="an unsafe or empty column name was replaced",
                    severity="warning",
                    locator=header_locator,
                )
            )
        if cleaned in normalized_header:
            raise LogFormatError("duplicate delimited column name")
        normalized_header.append(cleaned[:256])

    events: list[NormalizedSecurityEvent] = []
    seen = 0
    for locator, raw in lines[1:]:
        if not raw.strip():
            continue
        seen += 1
        if seen > limits.max_records:
            diagnostics.append(
                _diagnostic("record.limit", "record limit reached; remaining input was not analyzed", locator)
            )
            break
        try:
            values = next(csv.reader([_decode_record(raw)], delimiter=delimiter, strict=True))
            if len(values) != len(normalized_header):
                raise LogFormatError("delimited record width does not match header")
            unsafe_formula_fields: list[str] = []
            mapping: dict[str, Any] = {}
            for key, value in zip(normalized_header, values, strict=True):
                if len(value) > limits.max_field_chars:
                    raise LogFormatError("delimited field exceeds the character limit")
                if value.lstrip().startswith(_FORMULA_PREFIX):
                    mapping[key] = "[FORMULA_REDACTED]"
                    unsafe_formula_fields.append(key)
                else:
                    mapping[key] = value
            if unsafe_formula_fields:
                diagnostics.append(
                    ParserDiagnostic(
                        code="record.formula_redacted",
                        message=f"formula-like values were redacted in {len(unsafe_formula_fields)} field(s)",
                        severity="warning",
                        locator=locator,
                    )
                )
            events.append(_event_from_mapping(mapping, locator, source_format))
        except (csv.Error, UnicodeDecodeError, LogAnalysisError) as exc:
            diagnostics.append(_diagnostic("record.invalid_delimited", _safe_error(exc), locator))
    return events, diagnostics, seen


def _normalize_syslog(
    content: bytes,
    source_ref: str,
    limits: LogAnalysisLimits,
    default_year: int,
) -> tuple[list[NormalizedSecurityEvent], list[ParserDiagnostic], int]:
    events: list[NormalizedSecurityEvent] = []
    diagnostics: list[ParserDiagnostic] = []
    seen = 0
    for locator, raw in _bounded_lines(content, source_ref, limits):
        if not raw.strip():
            continue
        seen += 1
        if seen > limits.max_records:
            diagnostics.append(
                _diagnostic("record.limit", "record limit reached; remaining input was not analyzed", locator)
            )
            break
        try:
            text = _decode_record(raw)
            match5424 = _RFC5424.fullmatch(text)
            match3164 = _RFC3164.fullmatch(text)
            if match5424:
                _validate_syslog_pri(match5424["pri"])
                values: dict[str, Any] = {
                    "timestamp": match5424["timestamp"],
                    "host": match5424["host"],
                    "process": match5424["app"],
                    "process_id": match5424["proc"],
                    "event_type": match5424["msgid"],
                    "message": _strip_structured_data(match5424["rest"]),
                    "syslog_pri": match5424["pri"],
                }
            elif match3164:
                _validate_syslog_pri(match3164["pri"])
                timestamp = datetime.strptime(
                    f"{default_year} {match3164['timestamp']}",
                    "%Y %b %d %H:%M:%S",
                ).replace(tzinfo=UTC)
                values = {
                    "timestamp": timestamp.isoformat(),
                    "timestamp_assumed": True,
                    "host": match3164["host"],
                    "process": match3164["app"].strip(),
                    "process_id": match3164["proc"] or "-",
                    "event_type": "syslog",
                    "message": match3164["message"],
                    "syslog_pri": match3164["pri"],
                }
            else:
                raise LogFormatError("record is not RFC 3164 or RFC 5424 syslog")
            events.append(_event_from_mapping(values, locator, "syslog"))
        except (UnicodeDecodeError, ValueError, LogAnalysisError) as exc:
            diagnostics.append(_diagnostic("record.invalid_syslog", _safe_error(exc), locator))
    return events, diagnostics, seen


def _bounded_lines(content: bytes, source_ref: str, limits: LogAnalysisLimits) -> Iterable[tuple[SourceLocator, bytes]]:
    offset = 0
    for line_number, line in enumerate(content.splitlines(keepends=True), start=1):
        raw = line.rstrip(b"\r\n")
        locator = SourceLocator(
            source_ref=source_ref,
            segment_id=f"line-{line_number}",
            record_number=line_number,
            line_number=line_number,
            byte_offset=offset,
            byte_length=len(raw),
        )
        offset += len(line)
        if len(raw) > limits.max_record_bytes:
            yield locator, b"\x00"
            continue
        if _CONTROL.search(raw.decode("utf-8", errors="ignore")):
            yield locator, b"\x00"
            continue
        yield locator, raw


def _event_from_mapping(
    values: Mapping[str, Any], locator: SourceLocator, source_format: str
) -> NormalizedSecurityEvent:
    safe = _flatten_and_scrub(values)
    _augment_typed_source_metadata(safe, values)
    timestamp_value = _first_casefold_text(
        safe,
        "@timestamp",
        "timestamp",
        "system.timestamp",
        "utctime",
        "event_data.utctime",
        "time",
        "ts",
        "event_time",
        "date",
    )
    timestamp_utc, timestamp_quality = _normalize_timestamp(timestamp_value)
    timestamp_assumed = _first_casefold_text(safe, "timestamp_assumed")
    if timestamp_assumed is not None and timestamp_assumed.casefold() == "true" and timestamp_utc:
        timestamp_quality = "assumed_timezone"
    event_type_value = _first_casefold_text(
        safe,
        "event.action",
        "event_type",
        "action",
        "type",
        "category",
        "msgid",
        "system.eventid",
        "eventid",
    )
    provider_context = _first_casefold_text(safe, "provider", "system.provider", "channel", "system.channel") or ""
    is_windows_numeric_event = (
        event_type_value is not None
        and event_type_value.isdigit()
        and "microsoft-windows" in provider_context.casefold()
    )
    if is_windows_numeric_event:
        event_type_value = f"windows_event:{event_type_value}"
    event_type = _text_value(
        event_type_value,
        "unknown",
    )
    severity = _normalize_severity(_first_casefold_text(safe, "event.severity", "severity", "level", "log.level"), safe)
    message = _text_value(
        _first_casefold_text(safe, "message", "msg", "event.original", "description", "event"),
        event_type,
        max_chars=4_096,
    )
    entities = _entities(safe)
    canonical = {
        "timestamp_utc": timestamp_utc,
        "timestamp_quality": timestamp_quality,
        "source_format": source_format,
        "event_type": event_type,
        "severity": severity,
        "message": message,
        "entities": [asdict(item) for item in entities],
        "attributes": safe,
    }
    content_digest = _digest(canonical)
    event_id = str(
        uuid5(NAMESPACE_URL, f"secmind:log-event:{content_digest}:{locator.source_ref}:{locator.byte_offset}")
    )
    return NormalizedSecurityEvent(
        event_id=event_id,
        timestamp_utc=timestamp_utc,
        timestamp_quality=timestamp_quality,
        source_format=source_format,
        event_type=event_type,
        severity=severity,
        message=message,
        entities=entities,
        attributes=safe,
        locator=locator,
        content_sha256=content_digest,
    )


def _flatten_and_scrub(values: Mapping[str, Any]) -> dict[str, Any]:
    scrubbed = scrub_value(values, max_depth=10, max_items=512)
    if not isinstance(scrubbed, dict):  # defensive contract guard for future scrubber implementations
        raise LogFormatError("normalized record scrubber returned an invalid mapping")
    output: dict[str, Any] = {}

    def visit(value: Any, prefix: str, depth: int) -> None:
        if len(output) >= 256 or depth > 8:
            return
        if isinstance(value, Mapping):
            for key in sorted(value, key=str):
                name = f"{prefix}.{key}" if prefix else str(key)
                visit(value[key], name, depth + 1)
            return
        if isinstance(value, list):
            output[prefix] = [scrub_text(str(item))[:1_024] for item in value[:32] if _is_scalar(item)]
            return
        if _is_scalar(value):
            if isinstance(value, str):
                output[prefix] = scrub_text(value)[:16_384]
            else:
                output[prefix] = value

    visit(scrubbed, "", 0)
    return output


def _augment_typed_source_metadata(target: dict[str, Any], values: Mapping[str, Any]) -> None:
    """Restore only validated, non-secret source metadata after scrubbing."""

    attack_ids, image_names, parent_names = _typed_source_metadata(values)
    if attack_ids:
        # Arbitrary ``key=value`` text is scrubbed globally. Recover only the
        # strict ATT&CK ID from RuleName into a typed contextual annotation.
        target["secmind.attack.technique_ids"] = list(attack_ids)
    if image_names:
        target["secmind.process.image_basenames"] = list(image_names)
    if parent_names:
        target["secmind.process.parent_image_basenames"] = list(parent_names)


def _typed_source_metadata(
    values: Mapping[str, Any],
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    """Extract bounded ATT&CK IDs and executable basenames in one pass."""

    attack_ids: set[str] = set()
    images: set[str] = set()
    parents: set[str] = set()
    visited = 0

    def visit(value: Any, *, key: str = "", depth: int = 0) -> None:
        nonlocal visited
        visited += 1
        if visited > 512 or depth > 8:
            return
        if isinstance(value, Mapping):
            for child_key in sorted(value, key=str):
                visit(value[child_key], key=str(child_key), depth=depth + 1)
            return
        if isinstance(value, list):
            for item in value[:32]:
                visit(item, key=key, depth=depth + 1)
            return
        if not isinstance(value, str):
            return
        leaf = key.casefold().rsplit(".", 1)[-1]
        if leaf == "rulename":
            for match in _SOURCE_ATTACK_ID.finditer(value[:4_096]):
                attack_ids.add(match.group(1).upper())
                if len(attack_ids) >= _MAX_SOURCE_ATTACK_ANNOTATIONS:
                    break
            return
        if leaf not in {"image", "parentimage"}:
            return
        basename = re.split(r"[\\/]", value.strip().strip('"'))[-1].casefold()
        if not _SAFE_EXECUTABLE_BASENAME.fullmatch(basename):
            return
        (parents if leaf == "parentimage" else images).add(basename)

    visit(values)
    return tuple(sorted(attack_ids)), tuple(sorted(images)), tuple(sorted(parents))


def _normalize_timestamp(value: Any) -> tuple[str | None, TimestampQuality]:
    if value is None or value == "" or value == "-":
        return None, "missing"
    try:
        if isinstance(value, (int, float)) or (isinstance(value, str) and value.strip().isdigit()):
            numeric = float(value)
            if numeric > 10_000_000_000:
                numeric /= 1_000
            parsed = datetime.fromtimestamp(numeric, tz=UTC)
            return parsed.isoformat().replace("+00:00", "Z"), "exact"
        text = str(value).strip()
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        quality: TimestampQuality = "exact"
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
            quality = "assumed_timezone"
        return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z"), quality
    except (OverflowError, OSError, ValueError):
        return None, "invalid"


def _entities(values: Mapping[str, Any]) -> tuple[EntityRef, ...]:
    aliases: Mapping[str, tuple[str, ...]] = {
        "user": ("user.name", "user", "username", "account", "subjectusername", "targetusername"),
        "host": ("host.name", "host", "hostname", "computer_name", "computer"),
        "process": (
            "process.name",
            "process",
            "app",
            "program",
            "image",
            "secmind.process.image_basenames",
        ),
        "source_ip": ("source.ip", "src_ip", "source_ip", "client_ip", "sourceip"),
        "destination_ip": (
            "destination.ip",
            "dst_ip",
            "dest_ip",
            "destination_ip",
            "destinationip",
        ),
        "session": ("session.id", "session_id", "terminalsessionid"),
    }
    found: set[tuple[str, str]] = set()
    for kind, keys in aliases.items():
        for value in _mapping_attribute_values(values, *keys):
            found.add((kind, value[:512]))
    return tuple(EntityRef(kind=kind, value=value) for kind, value in sorted(found))


def _mapping_attribute_values(values: Mapping[str, Any], *aliases: str) -> tuple[str, ...]:
    """Read bounded scalar fields by exact or leaf key, without case sensitivity."""

    normalized_aliases = {alias.casefold() for alias in aliases}
    leaf_aliases = {alias.rsplit(".", 1)[-1] for alias in normalized_aliases}
    found: set[str] = set()
    for key, value in sorted(values.items(), key=lambda item: (str(item[0]).casefold(), str(item[0]))):
        normalized_key = str(key).casefold()
        leaf_key = normalized_key.rsplit(".", 1)[-1]
        if normalized_key not in normalized_aliases and leaf_key not in leaf_aliases:
            continue
        candidates = value if isinstance(value, list) else [value]
        for candidate in candidates[:32]:
            if _is_scalar(candidate) and candidate not in {None, "", "-", REDACTED}:
                found.add(scrub_text(str(candidate))[:1_024])
    return tuple(sorted(found, key=lambda item: (item.casefold(), item)))


def _first_casefold_text(values: Mapping[str, Any], *aliases: str) -> str | None:
    ordered_items = sorted(values.items(), key=lambda item: (str(item[0]).casefold(), str(item[0])))
    for alias in aliases:
        normalized_alias = alias.casefold()
        leaf_alias = normalized_alias.rsplit(".", 1)[-1]
        exact = [value for key, value in ordered_items if str(key).casefold() == normalized_alias]
        candidates = exact or [
            value for key, value in ordered_items if str(key).casefold().rsplit(".", 1)[-1] == leaf_alias
        ]
        for candidate in candidates:
            if _is_scalar(candidate) and candidate not in {None, "", "-", REDACTED}:
                return scrub_text(str(candidate))[:1_024]
    return None


def _deduplicate(
    events: Iterable[NormalizedSecurityEvent],
) -> tuple[list[NormalizedSecurityEvent], list[ParserDiagnostic]]:
    unique: list[NormalizedSecurityEvent] = []
    diagnostics: list[ParserDiagnostic] = []
    seen: set[str] = set()
    for event in events:
        if event.content_sha256 in seen:
            diagnostics.append(
                ParserDiagnostic(
                    code="record.duplicate",
                    message="a duplicate normalized event was removed",
                    severity="warning",
                    locator=event.locator,
                )
            )
            continue
        seen.add(event.content_sha256)
        unique.append(event)
    return unique, diagnostics


def _match_rules(
    events: Iterable[NormalizedSecurityEvent],
    rules: tuple[SigmaLikeRule, ...],
    max_matches: int,
) -> tuple[tuple[RuleMatch, ...], bool]:
    matches: list[RuleMatch] = []
    prepared_rules = tuple(
        (
            rule,
            tuple((term, term.casefold()) for term in sorted(rule.message_contains_any)),
            frozenset(item.casefold() for item in rule.event_types),
        )
        for rule in sorted(rules, key=lambda item: (item.rule_id, item.version))
    )
    for event in events:
        # Bounded normalized attributes contain the security-relevant fields of
        # structured records such as EVTX. Rules must not be restricted to the
        # human-readable message, which often contains only an event number.
        attribute_text = " ".join(
            str(value)[:4_096]
            for key, value in sorted(event.attributes.items(), key=lambda item: str(item[0]))
            if not is_sensitive_key(str(key))
        )[:32_768]
        haystack = f"{event.event_type} {event.message} {attribute_text}".casefold()
        event_type = event.event_type.casefold()
        for rule, terms, event_types in prepared_rules:
            matched_terms = tuple(term for term, normalized in terms if normalized in haystack)
            type_match = not event_types or event_type in event_types
            if not matched_terms or not type_match:
                continue
            if len(matches) >= max_matches:
                return tuple(matches), True
            identity = _digest({"rule": rule.rule_id, "version": rule.version, "event": event.event_id})
            matches.append(
                RuleMatch(
                    match_id=str(uuid5(NAMESPACE_URL, f"secmind:log-rule-match:{identity}")),
                    rule_id=rule.rule_id,
                    rule_version=rule.version,
                    title=rule.title,
                    severity=rule.severity,
                    event_id=event.event_id,
                    attack_ids=rule.attack_ids,
                    matched_on=matched_terms,
                    locator=event.locator,
                )
            )
    return tuple(matches), False


def _correlate_attack(events: tuple[NormalizedSecurityEvent, ...]) -> _CorrelationOutcome:
    """Build a small set of evidence-bound, non-authoritative ATT&CK mappings.

    These correlations deliberately do not become ``RuleMatch`` objects: a
    process/service relationship is useful investigation context, but it is
    not by itself proof of malicious activity.  Keeping the result in
    ``AttackMapping`` prevents the scenario layer from publishing a
    high-confidence suspicious-event finding for normal administrative use.
    """

    winrm_processes: list[NormalizedSecurityEvent] = []
    winrm_network: list[NormalizedSecurityEvent] = []
    command_shells: list[NormalizedSecurityEvent] = []
    user_discovery: list[NormalizedSecurityEvent] = []
    rdp_context: list[NormalizedSecurityEvent] = []

    for event in events:
        image_names = _image_basenames(
            event,
            "image",
            "process.image",
            "process.name",
            "secmind.process.image_basenames",
        )
        command_line = _event_field_text(event, "commandline", "process.command_line", "command")
        provider_context = _event_field_text(event, "provider", "channel", "event.provider", "log.channel")
        native_event_ids = {
            value.casefold() for value in _event_attribute_values(event, "eventid", "event.id", "native_event_id")
        }
        native_event_ids.add(event.event_type.casefold().removeprefix("windows_event:"))

        is_winrm_process = bool(
            image_names
            & {
                "roguewinrm.exe",
                "winrm.exe",
                "winrm.cmd",
                "winrs.exe",
                "wsmprovhost.exe",
            }
        ) or any(
            token in command_line
            for token in ("roguewinrm.exe", "winrm.exe", "winrm.cmd", "winrs.exe", "wsmprovhost.exe")
        )
        if is_winrm_process:
            winrm_processes.append(event)

        ports = set(
            _event_attribute_values(
                event,
                "destinationport",
                "destination.port",
                "dest_port",
                "sourceport",
                "source.port",
                "src_port",
            )
        )
        if ports & {"5985", "5986"}:
            winrm_network.append(event)

        if "cmd.exe" in image_names:
            command_shells.append(event)
        if "whoami.exe" in image_names or _starts_with_command(command_line, "whoami"):
            user_discovery.append(event)

        if "104" in native_event_ids and any(
            token in provider_context for token in ("rdpcorets", "remote desktop services")
        ):
            rdp_context.append(event)

    winrm_process_keys = {key for event in winrm_processes for key in _process_identity_keys(event, parent=False)}
    linked_network = [
        event
        for event in winrm_network
        if _image_basenames(
            event,
            "image",
            "process.image",
            "process.name",
            "secmind.process.image_basenames",
        )
        & {"roguewinrm.exe", "winrm.exe", "winrm.cmd", "winrs.exe", "wsmprovhost.exe"}
        or bool(_process_identity_keys(event, parent=False) & winrm_process_keys)
        or "windows-winrm" in _event_field_text(event, "provider", "channel", "event.provider", "log.channel")
    ]
    linked_shells = [
        event
        for event in command_shells
        if _image_basenames(
            event,
            "parentimage",
            "parent.image",
            "process.parent.name",
            "secmind.process.parent_image_basenames",
        )
        & {"roguewinrm.exe", "winrm.exe", "winrm.cmd", "winrs.exe", "wsmprovhost.exe"}
        or bool(_process_identity_keys(event, parent=True) & winrm_process_keys)
    ]
    shell_process_keys = {key for event in linked_shells for key in _process_identity_keys(event, parent=False)}
    linked_discovery = [
        event
        for event in user_discovery
        if "cmd.exe"
        in _image_basenames(
            event,
            "parentimage",
            "parent.image",
            "process.parent.name",
            "secmind.process.parent_image_basenames",
        )
        or bool(_process_identity_keys(event, parent=True) & shell_process_keys)
    ]

    mappings: list[AttackMapping] = []
    candidate_count = 3 if winrm_processes else 0
    event_limit_reached = False
    if winrm_processes and linked_network and linked_shells and linked_discovery:
        mapping_inputs = (
            ("T1021.006", (*winrm_processes, *linked_network)),
            ("T1059.003", (*winrm_processes, *linked_shells)),
            ("T1033", (*linked_shells, *linked_discovery)),
        )
        for technique_id, supporting_events in mapping_inputs:
            event_ids, truncated = _bounded_correlation_event_ids(supporting_events)
            event_limit_reached = event_limit_reached or truncated
            mappings.append(
                AttackMapping(
                    technique_id=technique_id,
                    technique_name=_ATTACK_CATALOG[technique_id],
                    knowledge_version=_ATTACK_VERSION,
                    event_ids=event_ids,
                    rule_ids=(_WINRM_CORRELATION_RULE_ID,),
                    confidence=0.78 if technique_id == "T1021.006" else 0.85,
                    interpretation="deterministic_supporting_mapping_not_fact",
                    source_refs=tuple(sorted({event.locator.source_ref for event in supporting_events}))[
                        :_MAX_CORRELATION_EVENT_REFS
                    ],
                )
            )

    if rdp_context:
        candidate_count += 1
        event_ids, truncated = _bounded_correlation_event_ids(rdp_context)
        event_limit_reached = event_limit_reached or truncated
        mappings.append(
            AttackMapping(
                technique_id="T1021.001",
                technique_name=_ATTACK_CATALOG["T1021.001"],
                knowledge_version=_ATTACK_VERSION,
                event_ids=event_ids,
                rule_ids=(_RDP_CONTEXT_RULE_ID,),
                confidence=0.4,
                interpretation=("low_confidence_context_only_not_proof_of_malicious_activity_or_successful_session"),
                source_refs=tuple(sorted({event.locator.source_ref for event in rdp_context}))[
                    :_MAX_CORRELATION_EVENT_REFS
                ],
            )
        )

    ordered = tuple(sorted(mappings, key=lambda item: item.technique_id))
    known_event_ids = {event.event_id for event in events}
    verified_count = sum(bool(item.event_ids) and set(item.event_ids) <= known_event_ids for item in ordered)
    return _CorrelationOutcome(
        mappings=ordered,
        candidate_count=candidate_count,
        correlated_count=len(ordered),
        verified_count=verified_count,
        rejected_count=max(0, candidate_count - len(ordered)),
        event_limit_reached=event_limit_reached,
    )


def _event_attribute_values(event: NormalizedSecurityEvent, *aliases: str) -> tuple[str, ...]:
    return _mapping_attribute_values(event.attributes, *aliases)


def _event_field_text(event: NormalizedSecurityEvent, *aliases: str) -> str:
    return " ".join(_event_attribute_values(event, *aliases)).casefold()


def _image_basenames(event: NormalizedSecurityEvent, *aliases: str) -> frozenset[str]:
    return frozenset(
        re.split(r"[\\/]", value.strip().strip('"'))[-1].casefold()
        for value in _event_attribute_values(event, *aliases)
        if value.strip().strip('"')
    )


def _process_identity_keys(event: NormalizedSecurityEvent, *, parent: bool) -> frozenset[str]:
    guid_aliases = ("parentprocessguid", "process.parent.guid") if parent else ("processguid", "process.guid")
    pid_aliases = ("parentprocessid", "process.parent.pid") if parent else ("processid", "process.pid")
    guids = _event_attribute_values(event, *guid_aliases)
    pids = _event_attribute_values(event, *pid_aliases)
    return frozenset([*(f"guid:{value.casefold()}" for value in guids), *(f"pid:{value.casefold()}" for value in pids)])


def _starts_with_command(command_line: str, executable: str) -> bool:
    candidate = command_line.lstrip().lstrip('"')
    return bool(re.match(rf"(?:[^\s\\/]+[\\/])*{re.escape(executable)}(?:\.exe)?(?:\s|$)", candidate))


def _bounded_correlation_event_ids(
    events: Iterable[NormalizedSecurityEvent],
) -> tuple[tuple[str, ...], bool]:
    ordered = sorted({event.event_id: event for event in events}.values(), key=_timeline_key)
    event_ids = tuple(event.event_id for event in ordered[:_MAX_CORRELATION_EVENT_REFS])
    return event_ids, len(ordered) > _MAX_CORRELATION_EVENT_REFS


def _extract_iocs(
    events: Iterable[NormalizedSecurityEvent],
    *,
    max_per_event: int,
    max_total: int,
) -> tuple[tuple[IocObservation, ...], bool]:
    observations: list[IocObservation] = []
    seen: set[tuple[str, str, str]] = set()
    for event in events:
        text = f"{event.message} " + " ".join(
            str(value) for key, value in event.attributes.items() if not is_sensitive_key(key)
        )
        candidates: list[tuple[str, str, str, float]] = []
        urls = list(_URL.findall(text))
        for value in urls:
            normalized = _normalize_url(value)
            if normalized:
                candidates.append(("url", normalized, normalized, 0.95))
        for value in _EMAIL.findall(text):
            normalized = value.casefold()
            local, _, domain = normalized.partition("@")
            candidates.append(("email", normalized, f"{local[:1]}***@{domain}", 0.9))
        for value in _IPV4.findall(text):
            try:
                normalized = str(ipaddress.ip_address(value))
            except ValueError:
                continue
            candidates.append(("ipv4", normalized, normalized, 0.98))
        for value in _HEX_SHA256.findall(text):
            candidates.append(("sha256", value.lower(), value.lower(), 0.99))
        url_domains = {urlsplit(value).hostname for value in urls}
        for value in _DOMAIN.findall(text):
            normalized = value.casefold().rstrip(".")
            suffix = normalized.rpartition(".")[2]
            if normalized not in url_domains and suffix not in _FILELIKE_DOMAIN_SUFFIXES:
                candidates.append(("domain", normalized, normalized, 0.9))

        event_count = 0
        for ioc_type, normalized, display, confidence in sorted(candidates):
            key = (ioc_type, normalized, event.event_id)
            if key in seen or REDACTED in normalized:
                continue
            if event_count >= max_per_event or len(observations) >= max_total:
                return tuple(observations), True
            seen.add(key)
            event_count += 1
            identity = _digest({"type": ioc_type, "value": normalized, "event": event.event_id})
            observations.append(
                IocObservation(
                    observation_id=str(uuid5(NAMESPACE_URL, f"secmind:ioc:{identity}")),
                    ioc_type=ioc_type,  # type: ignore[arg-type]
                    normalized_value=normalized,
                    display_value=display,
                    confidence=confidence,
                    event_id=event.event_id,
                    locator=event.locator,
                )
            )
    return tuple(observations), False


def _map_attack(matches: Iterable[RuleMatch]) -> tuple[AttackMapping, ...]:
    grouped: dict[str, dict[str, set[str]]] = {}
    for match in matches:
        for technique_id in match.attack_ids:
            target = grouped.setdefault(technique_id, {"events": set(), "rules": set(), "sources": set()})
            target["events"].add(match.event_id)
            target["rules"].add(match.rule_id)
            target["sources"].add(match.locator.source_ref)
    return tuple(
        AttackMapping(
            technique_id=technique_id,
            technique_name=_ATTACK_CATALOG.get(technique_id, "Unresolved technique"),
            knowledge_version=_ATTACK_VERSION,
            event_ids=tuple(sorted(values["events"])),
            rule_ids=tuple(sorted(values["rules"])),
            confidence=0.85 if technique_id in _ATTACK_CATALOG else 0.5,
            source_refs=tuple(sorted(values["sources"]))[:_MAX_CORRELATION_EVENT_REFS],
        )
        for technique_id, values in sorted(grouped.items())
    )


def _map_source_attack_annotations(
    events: Iterable[NormalizedSecurityEvent],
) -> tuple[AttackMapping, ...]:
    """Project source-embedded ATT&CK labels as evidence-bound context.

    Sysmon and similar pipelines may carry a ``RuleName`` annotation with an
    explicit ATT&CK ID. It is useful for deterministic fallback when a model
    is unavailable, but it is still untrusted source metadata: confidence is
    capped and the interpretation explicitly prevents treating the label as
    proof that an attack succeeded.
    """

    grouped: dict[str, dict[str, set[str]]] = {}
    known_event_ids: set[str] = set()
    for event in events:
        known_event_ids.add(event.event_id)
        for technique_id in _event_attribute_values(event, "secmind.attack.technique_ids"):
            if re.fullmatch(r"T\d{4}(?:\.\d{3})?", technique_id) is None:
                continue
            target = grouped.setdefault(technique_id, {"events": set(), "sources": set()})
            target["events"].add(event.event_id)
            target["sources"].add(event.locator.source_ref)
    return tuple(
        AttackMapping(
            technique_id=technique_id,
            technique_name=_ATTACK_CATALOG.get(technique_id, "Source-annotated ATT&CK technique"),
            knowledge_version=_ATTACK_VERSION,
            event_ids=tuple(sorted(values["events"] & known_event_ids))[:_MAX_CORRELATION_EVENT_REFS],
            rule_ids=(_SOURCE_ATTACK_ANNOTATION_RULE_ID,),
            confidence=0.75,
            interpretation="source_embedded_attack_annotation_not_independent_fact",
            source_refs=tuple(sorted(values["sources"]))[:_MAX_CORRELATION_EVENT_REFS],
        )
        for technique_id, values in sorted(grouped.items())
        if values["events"] & known_event_ids
    )


def merge_attack_mappings(*groups: Iterable[AttackMapping]) -> tuple[AttackMapping, ...]:
    """Deterministically coalesce one technique across source views.

    Native captures and attested derived views may both describe the same
    technique.  The mapping remains one hypothesis while retaining bounded
    source provenance; input order therefore cannot change the public result.
    """

    grouped: dict[str, dict[str, Any]] = {}
    for mapping in (item for group in groups for item in group):
        target = grouped.setdefault(
            mapping.technique_id,
            {
                "names": set(),
                "events": set(),
                "rules": set(),
                "sources": set(),
                "confidence": 0.0,
                "interpretations": set(),
            },
        )
        target["names"].add(mapping.technique_name)
        target["events"].update(mapping.event_ids)
        target["rules"].update(mapping.rule_ids)
        target["sources"].update(mapping.source_refs)
        target["confidence"] = max(float(target["confidence"]), mapping.confidence)
        target["interpretations"].add(mapping.interpretation)

    output: list[AttackMapping] = []
    for technique_id, values in sorted(grouped.items()):
        interpretations = sorted(str(item) for item in values["interpretations"])
        interpretation = (
            interpretations[0] if len(interpretations) == 1 else "multiple_deterministic_supporting_mappings_not_fact"
        )
        output.append(
            AttackMapping(
                technique_id=technique_id,
                technique_name=_ATTACK_CATALOG.get(technique_id, sorted(str(item) for item in values["names"])[0]),
                knowledge_version=_ATTACK_VERSION,
                event_ids=tuple(sorted(str(item) for item in values["events"]))[:_MAX_CORRELATION_EVENT_REFS],
                rule_ids=tuple(sorted(str(item) for item in values["rules"]))[:_MAX_CORRELATION_EVENT_REFS],
                confidence=float(values["confidence"]),
                interpretation=interpretation,
                source_refs=tuple(sorted(str(item) for item in values["sources"]))[:_MAX_CORRELATION_EVENT_REFS],
            )
        )
    return tuple(output)


def _build_evidence(
    events: tuple[NormalizedSecurityEvent, ...],
    matches: tuple[RuleMatch, ...],
    iocs: tuple[IocObservation, ...],
    mappings: tuple[AttackMapping, ...],
    diagnostics: list[ParserDiagnostic],
    *,
    artifact_ref: str,
    artifact_sha256: str,
    source_artifacts: Mapping[str, tuple[str, str]],
    limit: int,
) -> tuple[Evidence, ...]:
    evidence: list[Evidence] = []

    def add(kind: str, identity: str, summary: str, locator: SourceLocator | None, metadata: Mapping[str, Any]) -> None:
        if len(evidence) >= limit:
            return
        safe_metadata = scrub_value(dict(metadata))
        if not isinstance(safe_metadata, dict):  # defensive contract guard
            raise LogFormatError("evidence scrubber returned an invalid mapping")
        if locator is not None:
            safe_metadata["source_locator"] = asdict(locator)
        evidence_artifact_ref = artifact_ref
        evidence_artifact_sha256 = artifact_sha256
        if locator is not None:
            bound_artifact = source_artifacts.get(locator.source_ref)
            if bound_artifact is not None:
                evidence_artifact_ref, evidence_artifact_sha256 = bound_artifact
        safe_metadata.update(
            {
                "evidence_type": kind,
                "normalizer_version": _NORMALIZER_VERSION,
                "source_artifact_sha256": evidence_artifact_sha256,
            }
        )
        evidence.append(
            Evidence(
                evidence_id=str(uuid5(NAMESPACE_URL, f"secmind:log-evidence:{kind}:{identity}")),
                source=f"offline_log_analysis@{_NORMALIZER_VERSION}",
                summary=scrub_text(summary),
                artifact_ref=evidence_artifact_ref,
                sha256=evidence_artifact_sha256,
                metadata=safe_metadata,
            )
        )

    # Correlation receipts get first claim on the evidence bound. A large IOC
    # fan-out must not orphan an ATT&CK mapping from its immutable event chain.
    event_by_id = {event.event_id: event for event in events}
    for mapping in mappings:
        source_bindings = [
            {
                "event_id": event_id,
                "event_content_sha256": event_by_id[event_id].content_sha256,
                "source_locator": asdict(event_by_id[event_id].locator),
            }
            for event_id in mapping.event_ids[:_MAX_CORRELATION_EVENT_REFS]
            if event_id in event_by_id
        ]
        if mapping.interpretation.startswith("low_confidence_context_only"):
            summary = (
                f"Evidence-bound event context maps to ATT&CK {mapping.technique_id} at low confidence; "
                "this does not prove malicious activity or a successful remote session."
            )
        else:
            summary = (
                f"Evidence-bound rule/correlation context maps to ATT&CK {mapping.technique_id}; "
                "the mapping is supporting context, not fact."
            )
        add(
            "correlation_trace",
            _digest(asdict(mapping)),
            summary,
            None,
            {
                "technique_id": mapping.technique_id,
                "technique_name": mapping.technique_name,
                "knowledge_version": mapping.knowledge_version,
                "correlation_bundle_version": _CORRELATION_BUNDLE_VERSION,
                "event_ids": list(mapping.event_ids),
                "rule_ids": list(mapping.rule_ids),
                "confidence": mapping.confidence,
                "interpretation": mapping.interpretation,
                "source_refs": list(mapping.source_refs),
                "source_bindings": source_bindings,
            },
        )
    for match in matches:
        add(
            "sigma_match",
            match.match_id,
            f"Offline rule {match.rule_id} matched normalized event {match.event_id}.",
            match.locator,
            {
                "match_id": match.match_id,
                "event_id": match.event_id,
                "rule_id": match.rule_id,
                "rule_version": match.rule_version,
                "rule_bundle_version": _RULE_BUNDLE_VERSION,
                "attack_ids": list(match.attack_ids),
            },
        )
    for observation in iocs:
        add(
            "ioc_occurrence",
            observation.observation_id,
            f"{observation.ioc_type} indicator observed in normalized event {observation.event_id}.",
            observation.locator,
            {
                "observation_id": observation.observation_id,
                "event_id": observation.event_id,
                "ioc_type": observation.ioc_type,
                "normalized_value": observation.normalized_value,
                "display_value": observation.display_value,
                "confidence": observation.confidence,
            },
        )
    exact_token = re.compile(r"(?i)\b(?:flag|ctf|secmind)\{[^{}\r\n]{1,256}\}")
    prioritized_events = sorted(
        events,
        key=lambda event: (
            0 if exact_token.search(json.dumps(asdict(event), ensure_ascii=False, sort_keys=True, default=str)) else 1,
            _timeline_key(event),
        ),
    )
    for event in prioritized_events:
        add(
            "normalized_event",
            event.event_id,
            f"Normalized event {event.event_id} at {event.timestamp_utc or 'unknown time'}.",
            event.locator,
            {
                "event_id": event.event_id,
                "event_content_sha256": event.content_sha256,
                "timestamp_utc": event.timestamp_utc,
                "timestamp_quality": event.timestamp_quality,
            },
        )
    for diagnostic in diagnostics:
        identity = _digest(
            {
                "code": diagnostic.code,
                "locator": asdict(diagnostic.locator) if diagnostic.locator else None,
            }
        )
        add(
            "parser_diagnostic",
            identity,
            diagnostic.message,
            diagnostic.locator,
            {"code": diagnostic.code, "severity": diagnostic.severity},
        )
    return tuple(evidence)


def _detect_format(source_ref: str, content: bytes) -> Literal["jsonl", "csv", "tsv", "syslog"]:
    suffix = PurePosixPath(source_ref.replace("\\", "/")).suffix.lower()
    if suffix in {".jsonl", ".ndjson", ".json"}:
        return "jsonl"
    if suffix == ".csv":
        return "csv"
    if suffix == ".tsv":
        return "tsv"
    if suffix in {".log", ".syslog"}:
        return "syslog"
    prefix = content.lstrip()[:256]
    if prefix.startswith((b"{", b"[")):
        return "jsonl"
    if prefix.startswith(b"<"):
        return "syslog"
    first_line = prefix.partition(b"\n")[0]
    if b"\t" in first_line:
        return "tsv"
    if b"," in first_line:
        return "csv"
    raise LogFormatError("unable to detect an allowlisted log format")


def _validate_source_ref(source_ref: str) -> None:
    normalized = source_ref.replace("\\", "/")
    path = PurePosixPath(normalized)
    if (
        not source_ref
        or len(source_ref) > 1_024
        or path.is_absolute()
        or ".." in path.parts
        or _CONTROL.search(source_ref)
    ):
        raise ValueError("source_ref must be a safe relative artifact path")


def _decode_record(raw: bytes) -> str:
    if not raw or raw == b"\x00":
        raise LogFormatError("record is empty, oversized, or contains a control character")
    return raw.decode("utf-8", errors="strict")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise LogFormatError("duplicate JSON key")
        output[key] = value
    return output


def _validate_json(value: Any, limits: LogAnalysisLimits) -> None:
    nodes = 0
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > limits.max_json_nodes:
            raise LogLimitError("JSON record exceeds the node limit")
        if depth > limits.max_json_depth:
            raise LogLimitError("JSON record exceeds the nesting limit")
        if isinstance(current, Mapping):
            if len(current) > limits.max_fields:
                raise LogLimitError("JSON record exceeds the field limit")
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)
        elif isinstance(current, str) and len(current) > limits.max_field_chars:
            raise LogLimitError("JSON field exceeds the character limit")


def _text_value(value: Any, default: str, *, max_chars: int = 256) -> str:
    if value is None:
        return default
    text = scrub_text(str(value)).strip()
    return text[:max_chars] if text else default


def _normalize_severity(value: Any, values: Mapping[str, Any]) -> str:
    if value is not None:
        text = str(value).casefold()
        aliases = {
            "critical": "CRITICAL",
            "fatal": "CRITICAL",
            "high": "HIGH",
            "error": "HIGH",
            "medium": "MEDIUM",
            "warning": "MEDIUM",
            "warn": "MEDIUM",
            "low": "LOW",
            "info": "LOW",
        }
        if text in aliases:
            return aliases[text]
        if text.isdigit():
            number = int(text)
            return "HIGH" if number <= 3 else "MEDIUM" if number <= 5 else "LOW"
    pri = values.get("syslog_pri")
    if pri is not None and str(pri).isdigit():
        number = int(str(pri)) % 8
        return "CRITICAL" if number <= 2 else "HIGH" if number == 3 else "MEDIUM" if number == 4 else "LOW"
    return "UNKNOWN"


def _strip_structured_data(value: str) -> str:
    if value.startswith("["):
        closing = value.find("]")
        if closing >= 0:
            return value[closing + 1 :].strip() or "syslog event"
    return value


def _validate_syslog_pri(value: str) -> None:
    priority = int(value)
    if priority < 0 or priority > 191:
        raise LogFormatError("syslog PRI must be between 0 and 191")


def _normalize_url(value: str) -> str | None:
    try:
        parsed = urlsplit(value.rstrip(".,);]"))
        if parsed.scheme.casefold() not in {"http", "https"} or not parsed.hostname:
            return None
        host = parsed.hostname.casefold()
        port = f":{parsed.port}" if parsed.port else ""
        return urlunsplit((parsed.scheme.casefold(), f"{host}{port}", parsed.path or "/", "", ""))
    except ValueError:
        return None


def _timeline_key(event: NormalizedSecurityEvent) -> tuple[int, str, str, int, str]:
    return (
        1 if event.timestamp_utc is None else 0,
        event.timestamp_utc or "",
        event.locator.source_ref,
        event.locator.byte_offset,
        event.event_id,
    )


def _diagnostic(code: str, message: str, locator: SourceLocator) -> ParserDiagnostic:
    return ParserDiagnostic(code=code, message=scrub_text(message)[:512], severity="error", locator=locator)


def _safe_error(error: Exception) -> str:
    # Parser exception messages can contain a short structural reason, but no raw record.
    if isinstance(error, json.JSONDecodeError):
        return f"invalid JSON at column {error.colno}"
    return scrub_text(str(error))[:256]


def _rules_digest(rules: tuple[SigmaLikeRule, ...]) -> str:
    return _digest([asdict(rule) for rule in sorted(rules, key=lambda item: (item.rule_id, item.version))])


def _digest(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(encoded).hexdigest()


def _is_scalar(value: Any) -> bool:
    return value is None or isinstance(value, (bool, int, float, str))


__all__ = [
    "AttackMapping",
    "DEFAULT_RULES",
    "EntityRef",
    "IocObservation",
    "LogAnalysisError",
    "LogAnalysisLimits",
    "LogAnalysisResult",
    "LogFormatError",
    "LogLimitError",
    "NormalizedSecurityEvent",
    "ParserDiagnostic",
    "RuleMatch",
    "SigmaLikeRule",
    "SourceLocator",
    "analyze_offline_logs",
    "merge_attack_mappings",
]
