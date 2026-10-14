"""Bounded, read-only triage for high-confidence static reverse patterns.

This module deliberately recognizes only complete, distinctive API chains.  It
does not execute samples, disassemble binaries, infer intent from a single API,
or replace the semantic model lane.  Its output is an evidence-bound fallback
when a provider is unavailable and a verified supplement when the provider
succeeds.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from secmind.schemas import Evidence, InputArtifact, RunStatus

REVERSE_TRIAGE_CAPABILITY = "static_reverse_triage"
REVERSE_RULE_BUNDLE_VERSION = "secmind-static-reverse-rules-v2"

_DEFAULT_MAX_ARTIFACTS = 32
_DEFAULT_MAX_ARTIFACT_BYTES = 1024 * 1024
_DEFAULT_MAX_TOTAL_BYTES = 4 * 1024 * 1024
_TEXT_SUFFIXES = frozenset({".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".txt"})
_TEXT_MEDIA_TYPES = frozenset(
    {
        "text/plain",
        "text/x-c",
        "text/x-c++src",
        "text/x-c++hdr",
        "text/x-chdr",
    }
)
_NETWORK_MARKERS = re.compile(rb"(?i)(?:https?://|(?:winhttp|wininet|internetopen|wsastartup|connect|socket)\s*\()")


@dataclass(frozen=True, slots=True)
class ReverseTriageLimits:
    max_artifacts: int = _DEFAULT_MAX_ARTIFACTS
    max_bytes_per_artifact: int = _DEFAULT_MAX_ARTIFACT_BYTES
    max_total_bytes: int = _DEFAULT_MAX_TOTAL_BYTES

    def __post_init__(self) -> None:
        values = (self.max_artifacts, self.max_bytes_per_artifact, self.max_total_bytes)
        if any(not isinstance(value, int) or isinstance(value, bool) or value < 1 for value in values):
            raise ValueError("reverse-triage limits must be positive integers")
        if self.max_bytes_per_artifact > self.max_total_bytes:
            raise ValueError("per-artifact reverse limit cannot exceed total byte limit")


@dataclass(frozen=True, slots=True)
class ReverseTriageSource:
    artifact: InputArtifact
    content: bytes


@dataclass(frozen=True, slots=True)
class ReverseTriageResult:
    status: RunStatus
    behaviors: tuple[dict[str, Any], ...]
    injection: tuple[dict[str, Any], ...]
    evasion: tuple[dict[str, Any], ...]
    mitre_attack: tuple[str, ...]
    evidence: tuple[Evidence, ...]
    checked_paths: tuple[str, ...]
    limitations: tuple[str, ...]
    c2_observation: str | None
    coverage: dict[str, Any]


@dataclass(frozen=True, slots=True)
class _Rule:
    rule_id: str
    behavior: str
    title: str
    mitre_id: str
    mitre_name: str
    groups: tuple[tuple[bytes, ...], ...]
    injection: bool = True


@dataclass(frozen=True, slots=True)
class _AntiRule:
    rule_id: str
    behavior: str
    description: str
    groups: tuple[tuple[bytes, ...], ...]
    mitre_id: str = "T1622"
    mitre_name: str = "Debugger Evasion"


_RULES = (
    _Rule(
        rule_id="RE-PROCESS-HOLLOWING",
        behavior="process_hollowing",
        title="Process hollowing",
        mitre_id="T1055.012",
        mitre_name="Process Injection: Process Hollowing",
        groups=(
            (b"CreateProcessA", b"CreateProcessW", b"CreateProcess"),
            (b"CREATE_SUSPENDED",),
            (b"NtUnmapViewOfSection", b"ZwUnmapViewOfSection"),
            (b"VirtualAllocEx",),
            (b"WriteProcessMemory",),
            (b"SetThreadContext",),
            (b"ResumeThread",),
        ),
    ),
    _Rule(
        rule_id="RE-DLL-INJECTION",
        behavior="dll_injection",
        title="DLL injection",
        mitre_id="T1055.001",
        mitre_name="Process Injection: Dynamic-link Library Injection",
        groups=(
            (b"OpenProcess",),
            (b"VirtualAllocEx",),
            (b"WriteProcessMemory",),
            (b"CreateRemoteThread",),
            (b"LoadLibraryA", b"LoadLibraryW"),
        ),
    ),
    _Rule(
        rule_id="RE-APC-INJECTION",
        behavior="apc_injection",
        title="Asynchronous Procedure Call injection",
        mitre_id="T1055.004",
        mitre_name="Process Injection: Asynchronous Procedure Call",
        groups=(
            (b"NtOpenProcess", b"OpenProcess"),
            (b"NtAllocateVirtualMemory", b"VirtualAllocEx"),
            (b"NtWriteVirtualMemory", b"WriteProcessMemory"),
            (b"NtQueueApcThread", b"QueueUserAPC"),
            (b"NtAlertResumeThread", b"ResumeThread"),
            (b"PAGE_EXECUTE_READWRITE",),
        ),
    ),
    _Rule(
        rule_id="RE-RC4-PAYLOAD",
        behavior="encrypted_payload_decryption",
        title="Embedded RC4 payload decryption",
        mitre_id="T1027",
        mitre_name="Obfuscated Files or Information",
        groups=(
            (b"rc4_init",),
            (b"rc4_crypt",),
            (b"encrypted_shellcode",),
            (b"rc4_key",),
        ),
        injection=False,
    ),
    _Rule(
        rule_id="RE-NATIVE-API-RESOLUTION",
        behavior="dynamic_native_api_resolution",
        title="Dynamic Native API resolution",
        mitre_id="T1106",
        mitre_name="Native API",
        groups=(
            (b"ntdll.dll",),
            (b"GetProcAddress",),
            (b"NtAllocateVirtualMemory",),
            (b"NtWriteVirtualMemory",),
            (b"NtQueueApcThread",),
        ),
        injection=False,
    ),
)
_ANTI_ANALYSIS = (
    _AntiRule("RE-ANTI-PEB", "peb_being_debugged", "PEB BeingDebugged check", ((b"BeingDebugged",),)),
    _AntiRule(
        "RE-ANTI-ISDEBUGGERPRESENT",
        "is_debugger_present",
        "IsDebuggerPresent check",
        ((b"IsDebuggerPresent",),),
    ),
    _AntiRule(
        "RE-ANTI-REMOTE-DEBUGGER",
        "check_remote_debugger_present",
        "CheckRemoteDebuggerPresent check",
        ((b"CheckRemoteDebuggerPresent",),),
    ),
    _AntiRule(
        "RE-ANTI-NTQUERY-SYMBOLIC",
        "ntqueryinformationprocess_debug",
        "NtQueryInformationProcess debug-state check",
        ((b"NtQueryInformationProcess",), (b"ProcessDebugPort", b"ProcessDebugFlags")),
    ),
    _AntiRule(
        "RE-ANTI-NTQUERY-DEBUGPORT",
        "ntqueryinformationprocess_debug",
        "NtQueryInformationProcess debug-port sentinel check",
        ((b"NtQueryInformationProcess",), (b"debugPort",), (b"0xFFFFFFFF",)),
    ),
)
REVERSE_RULE_BUNDLE_DIGEST = hashlib.sha256(
    json.dumps(
        {
            "version": REVERSE_RULE_BUNDLE_VERSION,
            "rules": [
                {
                    "id": rule.rule_id,
                    "behavior": rule.behavior,
                    "mitre": rule.mitre_id,
                    "groups": [[token.decode("ascii") for token in group] for group in rule.groups],
                }
                for rule in _RULES
            ],
            "anti_analysis": [
                {
                    "id": rule.rule_id,
                    "behavior": rule.behavior,
                    "mitre": rule.mitre_id,
                    "groups": [[token.decode("ascii") for token in group] for group in rule.groups],
                }
                for rule in _ANTI_ANALYSIS
            ],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
).hexdigest()


def _is_supported_source(artifact: InputArtifact, content: bytes) -> bool:
    suffix = PurePosixPath(artifact.relative_path.replace("\\", "/")).suffix.casefold()
    media_type = artifact.media_type.split(";", 1)[0].strip().casefold()
    return (suffix in _TEXT_SUFFIXES or media_type in _TEXT_MEDIA_TYPES) and b"\x00" not in content[:4096]


def _find_token(lowered_content: bytes, alternatives: Sequence[bytes]) -> tuple[bytes, int] | None:
    hits = [(token, lowered_content.find(token.lower())) for token in alternatives]
    present = [(token, offset) for token, offset in hits if offset >= 0]
    return min(present, key=lambda item: item[1]) if present else None


def _locator(artifact: InputArtifact, content: bytes, offset: int, length: int) -> dict[str, Any]:
    return {
        "source_ref": artifact.relative_path.replace("\\", "/"),
        "segment_id": f"byte-{offset}",
        "record_number": 0,
        "line_number": content[:offset].count(b"\n") + 1,
        "byte_offset": offset,
        "byte_length": length,
        "locator_scope": "record",
        "artifact_sha256": artifact.sha256.lower(),
    }


def _evidence(
    artifact: InputArtifact,
    content: bytes,
    *,
    rule_id: str,
    indicator: bytes,
    offset: int,
) -> Evidence:
    locator = _locator(artifact, content, offset, len(indicator))
    evidence_id = str(
        uuid5(
            NAMESPACE_URL,
            f"secmind:reverse:{artifact.sha256.lower()}:{rule_id}:{offset}:{indicator.decode('ascii')}",
        )
    )
    return Evidence(
        evidence_id=evidence_id,
        source=f"deterministic_reverse_triage@{REVERSE_RULE_BUNDLE_VERSION}",
        summary=f"The immutable source contains an API-chain indicator for {rule_id}.",
        artifact_ref=artifact.sha256.lower(),
        sha256=artifact.sha256.lower(),
        metadata={
            "evidence_type": "static_reverse_indicator",
            "rule_id": rule_id,
            "indicator": indicator.decode("ascii"),
            "source_artifact_sha256": artifact.sha256.lower(),
            "rule_bundle_digest": REVERSE_RULE_BUNDLE_DIGEST,
            "source_locator": locator,
        },
    )


def _binding(evidence: Sequence[Evidence]) -> dict[str, Any]:
    locators = [item.metadata["source_locator"] for item in evidence]
    return {
        "evidence_ids": [item.evidence_id for item in evidence],
        "source_locator": locators[0],
        "source_locators": locators,
        "record_locator": locators[0],
        "raw_artifact_digests": sorted({str(item.sha256).lower() for item in evidence if item.sha256}),
        "derived_artifact_digests": [],
        "evidence_binding_status": "complete",
        "evidence_binding_unknowns": [],
    }


def _match_rule(
    source: ReverseTriageSource,
    lowered_content: bytes,
    rule: _Rule,
) -> tuple[dict[str, Any], list[Evidence]] | None:
    matches = [_find_token(lowered_content, group) for group in rule.groups]
    if any(item is None for item in matches):
        return None
    evidence = [
        _evidence(
            source.artifact,
            source.content,
            rule_id=rule.rule_id,
            indicator=item[0],
            offset=item[1],
        )
        for item in matches
        if item is not None
    ]
    indicators = [str(item.metadata["indicator"]) for item in evidence]
    row = {
        "behavior": rule.behavior,
        "core_behavior": rule.behavior,
        "title": rule.title,
        "description": (
            f"The complete static API chain {' -> '.join(indicators)} supports {rule.title}; "
            "this is a source-level capability observation, not proof that the sample executed."
        ),
        "confidence": "high",
        "rule_id": rule.rule_id,
        "mitre_attack_id": rule.mitre_id,
        "mitre_attack_name": rule.mitre_name,
        "api_sequence": indicators,
        **_binding(evidence),
    }
    return row, evidence


def _match_anti_analysis(
    source: ReverseTriageSource,
    lowered_content: bytes,
) -> tuple[list[dict[str, Any]], list[Evidence]]:
    rows: list[dict[str, Any]] = []
    all_evidence: list[Evidence] = []
    for rule in _ANTI_ANALYSIS:
        matches = [_find_token(lowered_content, group) for group in rule.groups]
        if any(item is None for item in matches):
            continue
        evidence = [
            _evidence(
                source.artifact,
                source.content,
                rule_id=rule.rule_id,
                indicator=item[0],
                offset=item[1],
            )
            for item in matches
            if item is not None
        ]
        rows.append(
            {
                "behavior": rule.behavior,
                "description": rule.description,
                "confidence": "medium",
                "rule_id": rule.rule_id,
                "mitre_attack_id": rule.mitre_id,
                "mitre_attack_name": rule.mitre_name,
                **_binding(evidence),
            }
        )
        all_evidence.extend(evidence)
    return rows, all_evidence


def analyze_reverse_sources(
    sources: Sequence[ReverseTriageSource],
    *,
    limits: ReverseTriageLimits | None = None,
    preexisting_limitations: Sequence[str] = (),
) -> ReverseTriageResult:
    """Recognize complete static chains in manifest-bound source bytes."""

    active = limits or ReverseTriageLimits()
    ordered = sorted(sources, key=lambda item: item.artifact.relative_path.casefold())
    limitations = list(preexisting_limitations)
    checked: list[str] = []
    behaviors: list[dict[str, Any]] = []
    injection: list[dict[str, Any]] = []
    evasion: list[dict[str, Any]] = []
    evidence_by_id: dict[str, Evidence] = {}
    mitre: set[str] = set()
    total_bytes = 0
    network_observed = False
    if len(ordered) > active.max_artifacts:
        limitations.append(f"{len(ordered) - active.max_artifacts} reverse source(s) omitted by the artifact bound")

    for source in ordered[: active.max_artifacts]:
        artifact, content = source.artifact, source.content
        if len(content) != artifact.size_bytes or hashlib.sha256(content).hexdigest() != artifact.sha256.lower():
            limitations.append(f"{artifact.relative_path}: immutable source does not match its manifest entry")
            continue
        if len(content) > active.max_bytes_per_artifact:
            limitations.append(f"{artifact.relative_path}: source exceeds the per-artifact byte bound")
            continue
        if total_bytes + len(content) > active.max_total_bytes:
            limitations.append(f"{artifact.relative_path}: total reverse-triage byte budget exhausted")
            break
        if not _is_supported_source(artifact, content):
            limitations.append(f"{artifact.relative_path}: only bounded textual C/C++ inputs are supported")
            continue
        total_bytes += len(content)
        checked.append(artifact.relative_path.replace("\\", "/"))
        network_observed = network_observed or _NETWORK_MARKERS.search(content) is not None
        lowered_content = content.lower()
        for rule in _RULES:
            matched = _match_rule(source, lowered_content, rule)
            if matched is None:
                continue
            row, row_evidence = matched
            behaviors.append(row)
            if rule.injection:
                injection.append(dict(row))
            mitre.update((rule.mitre_id, rule.mitre_name, rule.behavior))
            evidence_by_id.update({item.evidence_id: item for item in row_evidence})
        anti_rows, anti_evidence = _match_anti_analysis(source, lowered_content)
        evasion.extend(anti_rows)
        for row in anti_rows:
            mitre.update(
                (
                    str(row["mitre_attack_id"]),
                    str(row["mitre_attack_name"]),
                    str(row["behavior"]),
                )
            )
        evidence_by_id.update({item.evidence_id: item for item in anti_evidence})

    status = RunStatus.COMPLETED if checked and not limitations else RunStatus.PARTIAL
    c2_observation = None
    if status == RunStatus.COMPLETED and not network_observed:
        c2_observation = "No C2 or network endpoint was observed in the fully scanned bounded source inputs."
    coverage = {
        "capability": REVERSE_TRIAGE_CAPABILITY,
        "rule_bundle_version": REVERSE_RULE_BUNDLE_VERSION,
        "rule_bundle_digest": REVERSE_RULE_BUNDLE_DIGEST,
        "sources_seen": len(ordered),
        "sources_checked": len(checked),
        "bytes_checked": total_bytes,
        "behavior_count": len(behaviors),
        "evasion_count": len(evasion),
        "network_marker_observed": network_observed,
        "network_requests": 0,
        "execution_performed": False,
        "model_calls": 0,
    }
    return ReverseTriageResult(
        status=status,
        behaviors=tuple(behaviors),
        injection=tuple(injection),
        evasion=tuple(evasion),
        mitre_attack=tuple(sorted(mitre)),
        evidence=tuple(sorted(evidence_by_id.values(), key=lambda item: item.evidence_id)),
        checked_paths=tuple(checked),
        limitations=tuple(sorted(set(limitations))),
        c2_observation=c2_observation,
        coverage=coverage,
    )


__all__ = [
    "REVERSE_RULE_BUNDLE_DIGEST",
    "REVERSE_RULE_BUNDLE_VERSION",
    "REVERSE_TRIAGE_CAPABILITY",
    "ReverseTriageLimits",
    "ReverseTriageResult",
    "ReverseTriageSource",
    "analyze_reverse_sources",
]
