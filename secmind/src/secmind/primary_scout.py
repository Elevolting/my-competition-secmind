"""Bounded, independent deterministic coverage for Canonical Primary runs."""

from __future__ import annotations

import hashlib
import inspect
import json
import re
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Any, Literal, Protocol

from secmind.schemas import Evidence, Finding, InputArtifact

ReadArtifact = Callable[[InputArtifact], bytes | Awaitable[bytes]]


@dataclass(frozen=True, slots=True)
class ScoutLimits:
    max_file_bytes: int = 512_000
    max_total_bytes: int = 2_000_000
    max_findings: int = 32

    def __post_init__(self) -> None:
        if self.max_file_bytes < 1 or self.max_total_bytes < self.max_file_bytes or self.max_findings < 1:
            raise ValueError("independent scout limits are invalid")


@dataclass(frozen=True, slots=True)
class IndependentScoutResult:
    ran: bool
    scout_id: str
    findings: tuple[Finding, ...]
    evidence: tuple[Evidence, ...]
    viewed_paths: tuple[str, ...]
    omitted_paths: tuple[str, ...]
    truncated_paths: tuple[str, ...]
    reason: str
    digest: str

    @property
    def candidate_count(self) -> int:
        return len(self.findings)

    def summary(self) -> dict[str, Any]:
        return {
            "ran": self.ran,
            "scout_id": self.scout_id,
            "candidate_count": self.candidate_count,
            "evidence_count": len(self.evidence),
            "viewed_paths": list(self.viewed_paths),
            "omitted_paths": list(self.omitted_paths),
            "truncated_paths": list(self.truncated_paths),
            "reason": self.reason,
            "digest": self.digest,
            "finding_payloads": [item.model_dump(mode="json") for item in self.findings],
            "evidence_payloads": [item.model_dump(mode="json") for item in self.evidence],
        }


class Scout(Protocol):
    async def run(
        self,
        *,
        run_id: str,
        artifacts: Sequence[InputArtifact],
        read_artifact: ReadArtifact,
        objective: str = "",
    ) -> IndependentScoutResult: ...


@dataclass(frozen=True, slots=True)
class _Rule:
    rule_id: str
    name: str
    suffixes: tuple[str, ...]
    pattern: re.Pattern[str]
    confidence: Literal["HIGH", "MEDIUM"]


_RULES: tuple[_Rule, ...] = (
    _Rule(
        "CWE-95",
        "dynamic-code-evaluation",
        (".py", ".js", ".jsx", ".ts", ".tsx"),
        re.compile(r"\b(?:eval|exec|compile)\s*\(", re.IGNORECASE),
        "HIGH",
    ),
    _Rule(
        "CWE-78",
        "shell-command-with-user-controlled-execution",
        (".py",),
        re.compile(
            r"\b(?:subprocess\.(?:run|call|Popen)|os\.system)\s*\([^\n]*\bshell\s*=\s*True",
            re.IGNORECASE,
        ),
        "HIGH",
    ),
    _Rule(
        "CWE-78",
        "javascript-command-execution",
        (".js", ".jsx", ".ts", ".tsx"),
        re.compile(r"\b(?:child_process\.)?(?:exec|execSync|spawn)\s*\(", re.IGNORECASE),
        "MEDIUM",
    ),
    _Rule(
        "CWE-78",
        "java-runtime-command-execution",
        (".java", ".kt"),
        re.compile(r"\b(?:Runtime\.getRuntime\(\)\.exec|new\s+ProcessBuilder)\s*\(", re.IGNORECASE),
        "HIGH",
    ),
    _Rule(
        "CWE-89",
        "sql-string-concatenation",
        (".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".kt", ".php"),
        re.compile(r"(?:execute|query|raw)\s*\([^\n]*(?:\+|f[\"']|\.format\s*\()", re.IGNORECASE),
        "MEDIUM",
    ),
)


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


class DeterministicIndependentScout:
    """Run bounded language-aware scanning and return candidate-only output."""

    scout_id = "independent-primary-scout-v1"

    def __init__(self, limits: ScoutLimits | None = None) -> None:
        self.limits = limits or ScoutLimits()

    async def run(
        self,
        *,
        run_id: str,
        artifacts: Sequence[InputArtifact],
        read_artifact: ReadArtifact,
        objective: str = "",
    ) -> IndependentScoutResult:
        del objective
        viewed: list[str] = []
        omitted: list[str] = []
        truncated: list[str] = []
        findings: list[Finding] = []
        evidence: list[Evidence] = []
        remaining = self.limits.max_total_bytes

        for artifact in sorted(artifacts, key=lambda item: item.relative_path.casefold()):
            path = artifact.relative_path.replace("\\", "/")
            suffix = path.casefold()
            if remaining <= 0 or artifact.size_bytes > self.limits.max_file_bytes:
                omitted.append(path)
                continue
            if not any(suffix.endswith(rule_suffix) for rule in _RULES for rule_suffix in rule.suffixes):
                continue
            try:
                raw = read_artifact(artifact)
                payload = await raw if inspect.isawaitable(raw) else raw
            except (OSError, KeyError, TypeError, ValueError):
                omitted.append(path)
                continue
            if hashlib.sha256(payload).hexdigest() != artifact.sha256.lower():
                omitted.append(path)
                continue
            limit = min(len(payload), remaining, self.limits.max_file_bytes)
            text = payload[:limit].decode("utf-8", errors="replace")
            viewed.append(path)
            remaining -= limit
            if limit < len(payload):
                truncated.append(path)
            for rule in _RULES:
                if not suffix.endswith(rule.suffixes):
                    continue
                for match in rule.pattern.finditer(text):
                    if len(findings) >= self.limits.max_findings:
                        break
                    line = _line_number(text, match.start())
                    rule_digest = _digest({"scout": self.scout_id, "rule": rule.name, "pattern": rule.pattern.pattern})
                    evidence_id = (
                        "scout-evidence-"
                        + _digest(
                            {
                                "run_id": run_id,
                                "sha256": artifact.sha256,
                                "path": path,
                                "line": line,
                                "rule": rule_digest,
                            }
                        )[:32]
                    )
                    finding_id = (
                        "scout-finding-"
                        + _digest(
                            {
                                "run_id": run_id,
                                "path": path,
                                "line": line,
                                "rule": rule.rule_id,
                                "rule_digest": rule_digest,
                            }
                        )[:32]
                    )
                    lines = text.splitlines()
                    excerpt = lines[line - 1][:400] if line <= len(lines) else match.group(0)
                    evidence.append(
                        Evidence(
                            evidence_id=evidence_id,
                            source=f"{self.scout_id}:{rule.name}",
                            summary=excerpt,
                            artifact_ref=artifact.sha256,
                            sha256=artifact.sha256,
                            metadata={
                                "evidence_type": "independent_scout_candidate",
                                "path": path,
                                "line": line,
                                "rule_digest": rule_digest,
                                "source_sha256": artifact.sha256,
                                "assurance_level": "deterministic_candidate",
                            },
                        )
                    )
                    findings.append(
                        Finding(
                            finding_id=finding_id,
                            rule_id=rule.rule_id,
                            severity="HIGH" if rule.confidence == "HIGH" else "MEDIUM",
                            confidence=rule.confidence,
                            path=path,
                            line=line,
                            title=rule.name,
                            description=f"Independent bounded scout candidate for {rule.rule_id}.",
                            evidence_ids=[evidence_id],
                            raw={
                                "independent_scout": True,
                                "scout_id": self.scout_id,
                                "rule_digest": rule_digest,
                                "source_sha256": artifact.sha256,
                                "typed_delta": "add_finding",
                                "assurance_level": "deterministic_candidate",
                                "evidence_excerpt": excerpt,
                            },
                        )
                    )

        findings.sort(key=lambda item: (item.path, item.line or 0, item.rule_id, item.finding_id))
        evidence.sort(key=lambda item: item.evidence_id)
        summary = {
            "scout_id": self.scout_id,
            "findings": [item.model_dump(mode="json") for item in findings],
            "evidence": [item.model_dump(mode="json") for item in evidence],
            "viewed": viewed,
            "omitted": sorted(set(omitted)),
            "truncated": sorted(set(truncated)),
            "limits": {
                "max_file_bytes": self.limits.max_file_bytes,
                "max_total_bytes": self.limits.max_total_bytes,
                "max_findings": self.limits.max_findings,
            },
        }
        return IndependentScoutResult(
            ran=True,
            scout_id=self.scout_id,
            findings=tuple(findings),
            evidence=tuple(evidence),
            viewed_paths=tuple(viewed),
            omitted_paths=tuple(sorted(set(omitted))),
            truncated_paths=tuple(sorted(set(truncated))),
            reason="bounded deterministic coverage completed",
            digest=_digest(summary),
        )


IndependentScout = DeterministicIndependentScout


__all__ = [
    "DeterministicIndependentScout",
    "IndependentScout",
    "IndependentScoutResult",
    "ReadArtifact",
    "Scout",
    "ScoutLimits",
]
