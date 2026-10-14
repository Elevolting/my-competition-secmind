from __future__ import annotations

import pytest

from secmind.capability_resolver import CapabilityResolutionError, CapabilityResolver, CapabilityRuntimeStats
from secmind.schemas import RiskLevel, Scenario, ToolExecutionPolicy, ToolHealth, ToolManifest


def _manifest(
    name: str,
    *,
    capability: str = "sast",
    risk: RiskLevel = RiskLevel.R1,
    health: ToolHealth = ToolHealth.HEALTHY,
    languages: list[str] | None = None,
    evidence_types: list[str] | None = None,
    idempotent: bool = True,
    max_parallelism: int = 2,
    image: str | None = None,
    entrypoint: list[str] | None = None,
    rule_digest: str | None = None,
) -> ToolManifest:
    return ToolManifest(
        name=name,
        version="1.0.0",
        description=f"{name} scanner",
        scenarios=[Scenario.CODE_AUDIT],
        input_schema={"type": "object"},
        output_schema={"type": "object"},
        risk_level=risk,
        idempotent=idempotent,
        execution=ToolExecutionPolicy(image_digest=image, entrypoint=entrypoint or []),
        capability_tags=[capability],
        supported_languages=languages or ["python"],
        evidence_types=evidence_types or ["sast_finding"],
        concurrency_key=capability,
        max_parallelism=max_parallelism,
        health_status=health,
        rule_bundle_digest=rule_digest,
    )


def test_catalog_is_metadata_only_and_full_schema_is_materialized_on_demand() -> None:
    manifest = _manifest("bandit")
    resolver = CapabilityResolver([manifest], canonical_examples={"bandit": ({"target": "."},)})

    descriptor = resolver.catalog()[0]
    assert descriptor.capability_id == "sast"
    assert not hasattr(descriptor, "input_schema")
    loaded, examples = resolver.materialize("bandit")
    assert loaded.input_schema == {"type": "object"}
    assert examples == ({"target": "."},)


def test_resolver_ranks_health_language_reliability_cost_latency_and_idempotency() -> None:
    bandit = _manifest("bandit")
    semgrep = _manifest("semgrep", languages=["python", "javascript"])
    degraded = _manifest("degraded", health=ToolHealth.DEGRADED)
    resolver = CapabilityResolver(
        [bandit, semgrep, degraded],
        runtime_stats={
            "bandit": CapabilityRuntimeStats(reliability=0.95, average_latency_ms=50),
            "semgrep": CapabilityRuntimeStats(reliability=0.99, average_latency_ms=200),
            "degraded": CapabilityRuntimeStats(reliability=1.0, average_latency_ms=1),
        },
    )

    result = resolver.resolve("sast", scenario=Scenario.CODE_AUDIT, languages={"python"})
    assert [item.manifest.name for item in result] == ["semgrep", "bandit", "degraded"]


def test_resolver_enforces_risk_health_evidence_concurrency_and_supply_chain() -> None:
    digest = "sha256:" + ("a" * 64)
    valid = _manifest(
        "valid",
        evidence_types=["sast_finding", "source_location"],
        image=digest,
        entrypoint=["/tool"],
        rule_digest="b" * 64,
    )
    saturated = _manifest("saturated", max_parallelism=1)
    high_risk = _manifest("high", risk=RiskLevel.R2)
    unavailable = _manifest("unavailable", health=ToolHealth.UNAVAILABLE)
    mutable = _manifest("mutable", image="scanner:latest", entrypoint=["/tool"])
    resolver = CapabilityResolver(
        [valid, saturated, high_risk, unavailable, mutable],
        runtime_stats={"saturated": CapabilityRuntimeStats(active_invocations=1)},
        require_rule_bundle_for={"valid"},
    )

    result = resolver.resolve(
        "sast",
        scenario=Scenario.CODE_AUDIT,
        languages={"python"},
        maximum_risk=RiskLevel.R1,
        required_evidence_types={"source_location"},
    )
    assert [item.manifest.name for item in result] == ["valid"]
    assert next(item for item in resolver.catalog() if item.tool_name == "mutable").health == ToolHealth.UNAVAILABLE


def test_fallback_requires_typed_failure_idempotency_equivalence_risk_and_approval() -> None:
    primary = _manifest("primary", evidence_types=["sast_finding"])
    equivalent = _manifest("equivalent", evidence_types=["sast_finding", "source_location"])
    other = _manifest("other", evidence_types=["different"])
    escalated = _manifest("escalated", risk=RiskLevel.R2, evidence_types=["sast_finding"])
    resolver = CapabilityResolver(
        [primary, equivalent, other, escalated],
        runtime_stats={
            "primary": CapabilityRuntimeStats(reliability=1.0),
            "equivalent": CapabilityRuntimeStats(reliability=0.9),
            "other": CapabilityRuntimeStats(reliability=0.8),
        },
    )
    candidates = resolver.resolve("sast", scenario=Scenario.CODE_AUDIT, maximum_risk=RiskLevel.R2)

    fallback = resolver.fallback(
        candidates,
        failed_tool="primary",
        error_code="TOOL_UNAVAILABLE",
        approved_tools={"primary", "equivalent"},
    )
    assert fallback is not None and fallback.manifest.name == "equivalent"
    assert resolver.fallback(candidates, failed_tool="primary", error_code="GUARDRAIL_DENIED") is None

    non_idempotent = _manifest("write-tool", idempotent=False)
    write_resolver = CapabilityResolver([non_idempotent, equivalent])
    write_candidates = write_resolver.resolve("sast", scenario=Scenario.CODE_AUDIT)
    assert (
        write_resolver.fallback(
            write_candidates,
            failed_tool="write-tool",
            error_code="TOOL_EXECUTION_FAILED",
        )
        is None
    )


def test_runtime_stats_duplicate_materialization_and_updates_fail_closed() -> None:
    with pytest.raises(ValueError, match="reliability"):
        CapabilityRuntimeStats(reliability=1.1)
    with pytest.raises(ValueError, match="negative"):
        CapabilityRuntimeStats(average_latency_ms=-1)
    manifest = _manifest("same")
    with pytest.raises(CapabilityResolutionError, match="duplicate"):
        CapabilityResolver([manifest, manifest])
    resolver = CapabilityResolver([manifest])
    with pytest.raises(KeyError):
        resolver.materialize("missing")
    with pytest.raises(KeyError):
        resolver.update_runtime_stats("missing", CapabilityRuntimeStats())
    resolver.update_runtime_stats("same", CapabilityRuntimeStats(average_latency_ms=7))
    assert resolver.catalog()[0].expected_latency_ms == 7


def test_resolver_exercises_all_filter_boundaries_and_supply_chain_rejections() -> None:
    valid = _manifest("valid")
    wrong_capability = _manifest("secret", capability="secret_scan")
    wrong_scenario = _manifest("logs").model_copy(update={"scenarios": [Scenario.LOG_ANALYSIS]})
    degraded = _manifest("degraded", health=ToolHealth.DEGRADED)
    javascript = _manifest("javascript", languages=["javascript"])
    wrong_evidence = _manifest("coverage", evidence_types=["coverage"])
    image_without_entrypoint = _manifest("image-only", image="sha256:" + "a" * 64)
    entrypoint_without_image = _manifest("entry-only", entrypoint=["/tool"])
    invalid_rule = _manifest("invalid-rule", rule_digest="g" * 64)
    missing_required_rule = _manifest("missing-rule")
    resolver = CapabilityResolver(
        [
            valid,
            wrong_capability,
            wrong_scenario,
            degraded,
            javascript,
            wrong_evidence,
            image_without_entrypoint,
            entrypoint_without_image,
            invalid_rule,
            missing_required_rule,
        ],
        require_rule_bundle_for={"missing-rule"},
    )
    assert resolver.resolve("unknown", scenario=Scenario.CODE_AUDIT) == []
    assert resolver.resolve("sast", scenario=Scenario.CODE_AUDIT, allowed_tools=set()) == []
    assert resolver.resolve("sast", scenario=Scenario.CODE_AUDIT, allow_degraded=False)
    assert all(
        item.manifest.name != "javascript"
        for item in resolver.resolve("sast", scenario=Scenario.CODE_AUDIT, languages={"python"})
    )
    assert all(
        item.manifest.name != "coverage"
        for item in resolver.resolve(
            "sast",
            scenario=Scenario.CODE_AUDIT,
            required_evidence_types={"sast_finding"},
        )
    )
    unavailable = {item.tool_name for item in resolver.catalog() if item.health == ToolHealth.UNAVAILABLE}
    assert {"image-only", "entry-only", "invalid-rule", "missing-rule"} <= unavailable


def test_fallback_filters_approval_risk_capability_evidence_and_idempotency() -> None:
    failed = _manifest("failed")
    high = _manifest("high", risk=RiskLevel.R2)
    other_capability = _manifest("secret", capability="secret_scan")
    other_evidence = _manifest("coverage", evidence_types=["coverage"])
    non_idempotent = _manifest("write", idempotent=False)
    valid = _manifest("valid")
    resolver = CapabilityResolver([failed, high, other_capability, other_evidence, non_idempotent, valid])
    candidates = resolver.resolve("sast", scenario=Scenario.CODE_AUDIT, maximum_risk=RiskLevel.R2)
    assert resolver.fallback(candidates, failed_tool="unknown", error_code="TOOL_UNAVAILABLE") is None
    assert (
        resolver.fallback(candidates, failed_tool="failed", error_code="TOOL_UNAVAILABLE", approved_tools=set()) is None
    )
    selected = resolver.fallback(
        candidates,
        failed_tool="failed",
        error_code="TOOL_UNAVAILABLE",
        approved_tools={"high", "secret", "coverage", "write", "valid"},
    )
    assert selected is not None and selected.manifest.name == "valid"
