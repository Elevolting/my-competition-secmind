from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from secmind.language_registry import normalize_languages
from secmind.schemas import CapabilityDescriptor, RiskLevel, Scenario, ToolHealth, ToolManifest

_IMMUTABLE_IMAGE = re.compile(r"^(?:sha256:|.+@sha256:)[a-fA-F0-9]{64}$")
_DIGEST = re.compile(r"^[a-fA-F0-9]{64}$")
_FALLBACK_ERRORS = {
    "DOCKER_UNAVAILABLE",
    "EXTERNAL_TOOL_FAILED",
    "RUNNER_BUSY",
    "SANDBOX_TIMEOUT",
    "TOOL_BUSY",
    "TOOL_EXECUTION_FAILED",
    "TOOL_UNAVAILABLE",
}


class CapabilityResolutionError(ValueError):
    pass


@dataclass(frozen=True)
class CapabilityRuntimeStats:
    reliability: float = 1.0
    average_latency_ms: int = 0
    expected_cost_units: float = 0.0
    active_invocations: int = 0

    def __post_init__(self) -> None:
        if not 0 <= self.reliability <= 1:
            raise ValueError("reliability must be between zero and one")
        if self.average_latency_ms < 0 or self.expected_cost_units < 0 or self.active_invocations < 0:
            raise ValueError("capability runtime statistics cannot be negative")


@dataclass(frozen=True)
class ResolvedCapability:
    descriptor: CapabilityDescriptor
    manifest: ToolManifest
    score: tuple[Any, ...]
    ranking_reasons: tuple[str, ...]
    coverage: dict[str, tuple[str, ...]] = field(default_factory=dict)


class CapabilityResolver:
    """Deterministically rank approved tools without exposing full schemas early."""

    def __init__(
        self,
        manifests: Iterable[ToolManifest],
        *,
        canonical_examples: dict[str, tuple[dict[str, Any], ...]] | None = None,
        runtime_stats: dict[str, CapabilityRuntimeStats] | None = None,
        require_rule_bundle_for: set[str] | None = None,
    ) -> None:
        self._manifests: dict[str, ToolManifest] = {}
        for manifest in manifests:
            if manifest.name in self._manifests:
                raise CapabilityResolutionError(f"duplicate tool manifest: {manifest.name}")
            self._manifests[manifest.name] = manifest.model_copy(deep=True)
        self._examples = {name: tuple(items) for name, items in (canonical_examples or {}).items()}
        self._stats = dict(runtime_stats or {})
        self._require_rule_bundle_for = set(require_rule_bundle_for or set())

    def catalog(self) -> list[CapabilityDescriptor]:
        descriptors = [
            self._descriptor(manifest, capability_id)
            for manifest in self._manifests.values()
            for capability_id in sorted(set(manifest.capability_tags) or {"unclassified"})
        ]
        return sorted(descriptors, key=lambda item: (item.capability_id, item.tool_name))

    def materialize(self, tool_name: str) -> tuple[ToolManifest, tuple[dict[str, Any], ...]]:
        """Load the full manifest and examples only after a capability was selected."""

        try:
            manifest = self._manifests[tool_name]
        except KeyError as exc:
            raise KeyError(tool_name) from exc
        return manifest.model_copy(deep=True), tuple(dict(item) for item in self._examples.get(tool_name, ()))

    def resolve(
        self,
        capability_id: str,
        *,
        scenario: Scenario,
        languages: set[str] | None = None,
        maximum_risk: RiskLevel = RiskLevel.R1,
        required_evidence_types: set[str] | None = None,
        allowed_tools: set[str] | None = None,
        allow_degraded: bool = True,
    ) -> list[ResolvedCapability]:
        normalized_languages = normalize_languages(languages or set())
        required_evidence = set(required_evidence_types or set())
        allowed = None if allowed_tools is None else set(allowed_tools)
        resolved: list[ResolvedCapability] = []
        for manifest in self._manifests.values():
            if capability_id not in manifest.capability_tags:
                continue
            if allowed is not None and manifest.name not in allowed:
                continue
            if scenario not in manifest.scenarios:
                continue
            if manifest.health_status == ToolHealth.UNAVAILABLE:
                continue
            if manifest.health_status == ToolHealth.DEGRADED and not allow_degraded:
                continue
            if self._effective_risk(manifest) > maximum_risk:
                continue
            supported = normalize_languages(manifest.supported_languages)
            if normalized_languages and supported and not normalized_languages.intersection(supported):
                continue
            if required_evidence and not {item.casefold() for item in required_evidence}.issubset(
                {item.casefold() for item in manifest.evidence_types}
            ):
                continue
            if not self._supply_chain_valid(manifest):
                continue
            stats = self._stats.get(manifest.name, CapabilityRuntimeStats())
            if stats.active_invocations >= manifest.max_parallelism:
                continue
            language_exact = len(normalized_languages.intersection(supported))
            health_rank = 0 if manifest.health_status == ToolHealth.HEALTHY else 1
            retry_rank = 0 if manifest.idempotent else 1
            network_rank = 0 if not manifest.requires_network else 1
            latency = stats.average_latency_ms or manifest.timeout_seconds * 1_000
            score = (
                health_rank,
                -language_exact,
                -stats.reliability,
                stats.expected_cost_units,
                latency,
                retry_rank,
                network_rank,
                _manifest_stability_key(manifest),
            )
            reasons = (
                f"health={manifest.health_status.value}",
                f"language_matches={language_exact}",
                f"reliability={stats.reliability:.4f}",
                f"latency_ms={latency}",
                f"idempotent={str(manifest.idempotent).lower()}",
            )
            resolved.append(
                ResolvedCapability(
                    self._descriptor(manifest, capability_id),
                    manifest.model_copy(deep=True),
                    score,
                    reasons,
                    capability_coverage(manifest),
                )
            )
        return sorted(resolved, key=lambda item: item.score)

    def fallback(
        self,
        candidates: list[ResolvedCapability],
        *,
        failed_tool: str,
        error_code: str,
        approved_tools: set[str] | None = None,
    ) -> ResolvedCapability | None:
        """Return an equivalent safe fallback for a typed retryable failure."""

        failed = next((item for item in candidates if item.manifest.name == failed_tool), None)
        if failed is None or error_code not in _FALLBACK_ERRORS or not failed.manifest.idempotent:
            return None
        allowed = None if approved_tools is None else set(approved_tools)
        failed_capabilities = set(failed.manifest.capability_tags)
        failed_evidence = set(failed.manifest.evidence_types)
        failed_risk = self._effective_risk(failed.manifest)
        for candidate in candidates:
            manifest = candidate.manifest
            if manifest.name == failed_tool:
                continue
            if allowed is not None and manifest.name not in allowed:
                continue
            if self._effective_risk(manifest) > failed_risk:
                continue
            if not failed_capabilities.intersection(manifest.capability_tags):
                continue
            if not failed_evidence.issubset(set(manifest.evidence_types)):
                continue
            if not manifest.idempotent:
                continue
            return candidate
        return None

    def update_runtime_stats(self, tool_name: str, stats: CapabilityRuntimeStats) -> None:
        if tool_name not in self._manifests:
            raise KeyError(tool_name)
        self._stats[tool_name] = stats

    def resolve_for_repository(
        self,
        capability_id: str,
        *,
        scenario: Scenario,
        repository: object,
        maximum_risk: RiskLevel = RiskLevel.R1,
        required_evidence_types: set[str] | None = None,
        allowed_tools: set[str] | None = None,
        allow_degraded: bool = True,
    ) -> list[ResolvedCapability]:
        """Resolve against an indexed repository without rereading source bytes."""

        languages = set(getattr(repository, "languages", {}) or {})
        if not languages:
            languages = {
                str(getattr(item, "language", ""))
                for item in getattr(repository, "files", ())
                if getattr(item, "language", None)
            }
        return self.resolve(
            capability_id,
            scenario=scenario,
            languages=languages,
            maximum_risk=maximum_risk,
            required_evidence_types=required_evidence_types,
            allowed_tools=allowed_tools,
            allow_degraded=allow_degraded,
        )

    def _descriptor(self, manifest: ToolManifest, capability_id: str) -> CapabilityDescriptor:
        stats = self._stats.get(manifest.name, CapabilityRuntimeStats())
        return CapabilityDescriptor(
            capability_id=capability_id,
            short_description=manifest.description,
            supported_languages=sorted(set(manifest.supported_languages)),
            evidence_types=sorted(set(manifest.evidence_types)),
            risk=self._effective_risk(manifest),
            health=manifest.health_status if self._supply_chain_valid(manifest) else ToolHealth.UNAVAILABLE,
            expected_latency_ms=stats.average_latency_ms or manifest.timeout_seconds * 1_000,
            expected_cost_units=stats.expected_cost_units,
            concurrency_key=manifest.concurrency_key,
            version_digest=_manifest_digest(manifest),
            tool_name=manifest.name,
        )

    def _supply_chain_valid(self, manifest: ToolManifest) -> bool:
        policy = manifest.execution
        if bool(policy.image_digest) != bool(policy.entrypoint):
            return False
        if policy.image_digest and not _IMMUTABLE_IMAGE.fullmatch(policy.image_digest):
            return False
        if manifest.rule_bundle_digest is not None and not _DIGEST.fullmatch(manifest.rule_bundle_digest):
            return False
        if manifest.name in self._require_rule_bundle_for and manifest.rule_bundle_digest is None:
            return False
        return True

    @staticmethod
    def _effective_risk(manifest: ToolManifest) -> RiskLevel:
        return max(manifest.risk_level, manifest.platform_risk or RiskLevel.R0)


def _manifest_digest(manifest: ToolManifest) -> str:
    canonical = json.dumps(
        manifest.model_dump(mode="json"),
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(canonical).hexdigest()


def capability_coverage(manifest: ToolManifest) -> dict[str, tuple[str, ...]]:
    """Return a deterministic, explainable lower-bound coverage map."""

    languages = tuple(sorted(normalize_languages(manifest.supported_languages)))
    evidence = tuple(sorted({item.casefold() for item in manifest.evidence_types}))
    capabilities = {item.casefold() for item in manifest.capability_tags}
    description = manifest.description.casefold()
    hints: tuple[str, ...]
    if "java" in languages and ("weak" in description or "messagedigest" in description):
        hints = ("CWE-328", "source-to-sink")
    elif "sast_flow" in evidence or "source-to-sink" in description:
        hints = ("source-to-sink",)
    elif "bandit" in description:
        hints = ("python-rule-set",)
    elif "semgrep" in description or "rule bundle" in description:
        hints = ("rule-bundle",)
    elif "secret_scan" in capabilities:
        hints = ("CWE-798", "redacted-secret")
    elif "sbom" in capabilities:
        hints = ("dependency-inventory",)
    elif "dependency_audit" in capabilities:
        hints = ("CWE-1104", "dependency-vulnerability")
    else:
        hints = ()
    values = tuple(sorted({*evidence, *hints}))
    return {language: values for language in languages} or {"*": values}


def _manifest_stability_key(manifest: ToolManifest) -> tuple[str, ...]:
    """Tie-break on capabilities, never on the display/tool name."""

    return (
        ",".join(sorted(normalize_languages(manifest.supported_languages))),
        ",".join(sorted(item.casefold() for item in manifest.evidence_types)),
        ",".join(sorted(item.casefold() for item in manifest.capability_tags)),
        manifest.rule_bundle_digest or "",
        manifest.version,
        manifest.description,
    )


__all__ = [
    "CapabilityResolutionError",
    "CapabilityResolver",
    "CapabilityRuntimeStats",
    "ResolvedCapability",
    "capability_coverage",
]
