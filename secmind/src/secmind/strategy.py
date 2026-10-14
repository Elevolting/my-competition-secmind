from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from functools import lru_cache
from typing import Literal
from uuid import NAMESPACE_URL, uuid5

from secmind import PUBLIC_VERSION
from secmind.schemas import (
    BudgetState,
    FailurePolicy,
    PlanCandidate,
    PlanRevision,
    PlanStep,
    ReplanTrigger,
    RiskLevel,
    RouteRecord,
    Scenario,
    ScenarioManifest,
    StrategyMode,
    StrategyProfile,
    ToolHealth,
    ToolManifest,
)

_CORE_CAPABILITIES = ("inventory", "sast")
_AUDIT_CAPABILITIES = ("inventory", "sast", "secret_scan", "sbom", "dependency_audit")
_OPTIONAL_CAPABILITIES = frozenset({"secret_scan", "sbom", "dependency_audit"})
_MAX_PLAN_REVISIONS = 2


def _digest(value: object) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _stable_id(kind: str, digest: str) -> str:
    return str(uuid5(NAMESPACE_URL, f"secmind:v0.5:{kind}:{digest}"))


def default_strategy_profiles() -> tuple[StrategyProfile, ...]:
    """Return isolated copies of the cached, offline strategy portfolio."""

    return tuple(profile.model_copy(deep=True) for profile in _cached_strategy_profiles())


@lru_cache(maxsize=1)
def _cached_strategy_profiles() -> tuple[StrategyProfile, ...]:

    return (
        _strategy_profile(
            StrategyMode.QUICK,
            "Minimum safe code-audit path for deadline or tool-budget pressure.",
            max_parallel_steps=2,
            max_tool_calls=4,
            max_runtime_seconds=240,
            required_capabilities=list(_CORE_CAPABILITIES),
            optional_capabilities=["secret_scan"],
        ),
        _strategy_profile(
            StrategyMode.BALANCED,
            "Default code-audit path balancing coverage, evidence and latency.",
            max_parallel_steps=3,
            max_tool_calls=8,
            max_runtime_seconds=600,
            required_capabilities=["inventory", "sast", "secret_scan"],
            optional_capabilities=["sbom", "dependency_audit"],
        ),
        _strategy_profile(
            StrategyMode.DEEP,
            "Evidence-rich path with bounded fallback tools and verification attempts.",
            max_parallel_steps=3,
            max_tool_calls=12,
            max_runtime_seconds=1200,
            required_capabilities=["inventory", "sast", "secret_scan"],
            optional_capabilities=["sbom", "dependency_audit"],
        ),
    )


def _strategy_profile(
    strategy_id: StrategyMode,
    description: str,
    *,
    max_parallel_steps: int,
    max_tool_calls: int,
    max_runtime_seconds: int,
    required_capabilities: list[str],
    optional_capabilities: list[str],
) -> StrategyProfile:
    payload = {
        "strategy_id": strategy_id.value,
        "description": description,
        "max_parallel_steps": max_parallel_steps,
        "max_tool_calls": max_tool_calls,
        "max_model_calls": 0,
        "max_runtime_seconds": max_runtime_seconds,
        "required_capabilities": required_capabilities,
        "optional_capabilities": optional_capabilities,
    }
    return StrategyProfile(
        strategy_id=strategy_id,
        description=description,
        max_parallel_steps=max_parallel_steps,
        max_tool_calls=max_tool_calls,
        max_model_calls=0,
        max_runtime_seconds=max_runtime_seconds,
        required_capabilities=required_capabilities,
        optional_capabilities=optional_capabilities,
        profile_digest=_digest(payload),
    )


def scenario_manifests() -> tuple[ScenarioManifest, ...]:
    """Return isolated copies of the cached scenario declarations."""

    return tuple(manifest.model_copy(deep=True) for manifest in _cached_scenario_manifests())


@lru_cache(maxsize=1)
def _cached_scenario_manifests() -> tuple[ScenarioManifest, ...]:
    """Build the safe v0.5 paths and their evidence-backed maturity once."""

    return (
        _scenario_manifest(
            Scenario.CODE_AUDIT,
            maturity="scenario-verified",
            accepted_asset_types=[
                "application/zip",
                "text/plain",
                "text/x-python",
                "application/sarif+json",
                "application/vnd.cyclonedx+json",
            ],
            required_capabilities=list(_CORE_CAPABILITIES),
            optional_capabilities=["secret_scan", "sbom", "dependency_audit"],
            strategy_ids=list(StrategyMode),
            claim_types=["code_audit.finding", "code_audit.coverage"],
            evidence_types=["finding", "coverage", "sast_finding", "redacted_secret_finding"],
            report_formats=["json", "markdown", "sarif"],
            enabled=True,
        ),
        _scenario_manifest(
            Scenario.LOG_ANALYSIS,
            maturity="mock-verified",
            accepted_asset_types=["text/plain", "application/json", "application/x-ndjson", "text/csv"],
            required_capabilities=["log_inventory", "log_normalization"],
            optional_capabilities=["sigma_match", "ioc_extract", "timeline"],
            strategy_ids=list(StrategyMode),
            claim_types=["suspicious_event", "coverage_limitation"],
            evidence_types=["source_log_slice", "parser_diagnostic"],
            enabled=True,
        ),
        _scenario_manifest(
            Scenario.INCIDENT_RESPONSE,
            maturity="scaffolded",
            accepted_asset_types=["application/vnd.secmind.evidence+json"],
            required_capabilities=["verified_incident_hypothesis"],
            optional_capabilities=["incident_dry_run"],
            strategy_ids=[StrategyMode.BALANCED, StrategyMode.DEEP],
            claim_types=["incident_hypothesis", "containment_option"],
            evidence_types=["correlation_trace"],
            enabled=False,
        ),
        _scenario_manifest(
            Scenario.API_ASSESSMENT,
            maturity="mock-verified",
            accepted_asset_types=["application/openapi+json", "application/json", "application/yaml"],
            required_capabilities=["api_document_parse"],
            optional_capabilities=["api_static_lint"],
            strategy_ids=list(StrategyMode),
            claim_types=["api_security_finding"],
            evidence_types=["api_document_location"],
            enabled=True,
        ),
        _scenario_manifest(
            Scenario.REVERSE_TRIAGE,
            maturity="scenario-verified",
            accepted_asset_types=["text/plain", "text/x-c", "text/x-c++src"],
            required_capabilities=["static_file_triage"],
            optional_capabilities=["evidence_correlation"],
            strategy_ids=[StrategyMode.QUICK, StrategyMode.BALANCED],
            claim_types=["reverse_static_behavior", "reverse_anti_analysis_behavior"],
            evidence_types=["static_reverse_indicator", "scan_coverage"],
            enabled=True,
        ),
        _scenario_manifest(Scenario.PENETRATION_TEST, maturity="planned"),
        _scenario_manifest(Scenario.UNKNOWN, maturity="planned"),
    )


def _scenario_manifest(
    scenario_id: Scenario,
    *,
    maturity: Literal["planned", "scaffolded", "mock-verified", "scenario-verified", "evaluated"],
    accepted_asset_types: list[str] | None = None,
    required_capabilities: list[str] | None = None,
    optional_capabilities: list[str] | None = None,
    strategy_ids: list[StrategyMode] | None = None,
    claim_types: list[str] | None = None,
    evidence_types: list[str] | None = None,
    report_formats: list[str] | None = None,
    enabled: bool = False,
) -> ScenarioManifest:
    accepted = accepted_asset_types or []
    required = required_capabilities or []
    optional = optional_capabilities or []
    strategies = strategy_ids or []
    claims = claim_types or []
    evidence = evidence_types or []
    reports = report_formats or ["json", "markdown"]
    payload = {
        "scenario_id": scenario_id.value,
        "version": PUBLIC_VERSION,
        "maturity": maturity,
        "accepted_asset_types": accepted,
        "required_capabilities": required,
        "optional_capabilities": optional,
        "strategy_ids": [item.value for item in strategies],
        "claim_types": claims,
        "evidence_types": evidence,
        "report_formats": reports,
        "risk_ceiling": int(RiskLevel.R1),
        "enabled": enabled,
    }
    return ScenarioManifest(
        scenario_id=scenario_id,
        version=PUBLIC_VERSION,
        maturity=maturity,
        accepted_asset_types=accepted,
        required_capabilities=required,
        optional_capabilities=optional,
        strategy_ids=strategies,
        claim_types=claims,
        evidence_types=evidence,
        report_formats=reports,
        risk_ceiling=RiskLevel.R1,
        enabled=enabled,
        package_digest=_digest(payload),
    )


@dataclass(frozen=True)
class StrategySelection:
    candidates: tuple[PlanCandidate, ...]
    route: RouteRecord


@dataclass(frozen=True)
class ReplanDecision:
    action: Literal["revise", "partial"]
    trigger: ReplanTrigger
    rationale_summary: str
    revised_plan: tuple[PlanStep, ...]
    revision: PlanRevision | None = None
    partial_report_recommended: bool = False


def select_strategy(
    *,
    run_id: str,
    task_spec_digest: str,
    scenario: Scenario,
    tool_manifests: list[ToolManifest],
    budget: BudgetState,
) -> StrategySelection:
    """Score bounded candidates without consulting a model or making side effects."""

    scenario_manifest = next(item for item in _cached_scenario_manifests() if item.scenario_id == scenario)
    candidates: list[PlanCandidate] = []
    if scenario_manifest.enabled:
        for profile in _cached_strategy_profiles():
            candidates.append(_build_candidate(profile, tool_manifests, budget))

    selectable = [item for item in candidates if not item.rejection_reasons]
    selected = max(selectable, key=lambda item: (item.score, item.strategy_id.value)) if selectable else None
    scores = {item.candidate_id: item.score for item in candidates}
    policy_ids = ["STRATEGY-PORTFOLIO-V1", "OFFLINE-DETERMINISTIC-V1"]
    budget_snapshot = budget.model_dump(mode="json")
    route_payload = {
        "run_id": run_id,
        "task_spec_digest": task_spec_digest,
        "scenario": scenario.value,
        "candidate_ids": [item.candidate_id for item in candidates],
        "candidate_scores": scores,
        "selected_candidate_id": selected.candidate_id if selected else None,
        "selected_strategy": selected.strategy_id.value if selected else None,
        "budget_snapshot": budget_snapshot,
        "policy_ids": policy_ids,
    }
    route_digest = _digest(route_payload)
    rationale = (
        f"Selected {selected.strategy_id.value} using deterministic coverage, health and budget scoring."
        if selected
        else f"Scenario {scenario.value} is disabled or has no budget-feasible capability plan."
    )
    route = RouteRecord(
        route_id=_stable_id("route", route_digest),
        run_id=run_id,
        task_spec_digest=task_spec_digest,
        scenario=scenario,
        candidate_ids=[item.candidate_id for item in candidates],
        candidate_scores=scores,
        selected_candidate_id=selected.candidate_id if selected else None,
        selected_strategy=selected.strategy_id if selected else None,
        rationale_summary=rationale,
        policy_ids=policy_ids,
        budget_snapshot=budget_snapshot,
        route_digest=route_digest,
    )
    return StrategySelection(candidates=tuple(candidates), route=route)


def _build_candidate(
    profile: StrategyProfile,
    manifests: list[ToolManifest],
    budget: BudgetState,
) -> PlanCandidate:
    available = [
        item
        for item in manifests
        if Scenario.CODE_AUDIT in item.scenarios and item.health_status != ToolHealth.UNAVAILABLE
    ]
    by_capability: dict[str, list[ToolManifest]] = {}
    health_by_name: dict[str, ToolHealth] = {}
    for manifest in available:
        health_by_name.setdefault(manifest.name, manifest.health_status)
        for capability in manifest.capability_tags:
            by_capability.setdefault(capability, []).append(manifest)
    for values in by_capability.values():
        values.sort(key=lambda item: (item.health_status != ToolHealth.HEALTHY, item.name, item.version))

    requested = list(profile.required_capabilities)
    requested.extend(item for item in profile.optional_capabilities if item in by_capability)

    rejection_reasons = [
        f"required_capability_unavailable:{capability}"
        for capability in profile.required_capabilities
        if capability not in by_capability
    ]
    steps = _steps_for_capabilities(profile.strategy_id, requested, by_capability)
    remaining_tool_calls = max(0, budget.max_tool_calls - budget.tool_calls_used)
    if len(steps) > remaining_tool_calls or len(steps) > profile.max_tool_calls:
        rejection_reasons.append("tool_budget_exceeded")
    if profile.max_runtime_seconds > budget.max_runtime_seconds:
        rejection_reasons.append("runtime_budget_exceeded")

    coverage = len({item.capability for item in steps}) / len(_AUDIT_CAPABILITIES)
    healthy_tools = sum(
        1 for step in steps for name in step.tool_candidates[:1] if health_by_name.get(name) == ToolHealth.HEALTHY
    )
    health_ratio = healthy_tools / len(steps) if steps else 0.0
    preference = {
        StrategyMode.QUICK: 18.0,
        StrategyMode.BALANCED: 28.0,
        StrategyMode.DEEP: 24.0,
    }[profile.strategy_id]
    score = round(preference + coverage * 50 + health_ratio * 10 - len(steps) * 1.5, 6)
    payload = {
        "strategy_id": profile.strategy_id.value,
        "steps": [item.model_dump(mode="json") for item in steps],
        "estimated_coverage": coverage,
        "estimated_latency_ms": len(steps) * 30_000,
        "estimated_cost_units": 0.0,
        "score": score,
        "rejection_reasons": rejection_reasons,
    }
    candidate_digest = _digest(payload)
    return PlanCandidate(
        candidate_id=_stable_id("candidate", candidate_digest),
        strategy_id=profile.strategy_id,
        steps=steps,
        estimated_coverage=coverage,
        estimated_latency_ms=len(steps) * 30_000,
        estimated_cost_units=0,
        score=score,
        rejection_reasons=rejection_reasons,
        candidate_digest=candidate_digest,
    )


def _steps_for_capabilities(
    mode: StrategyMode,
    capabilities: list[str],
    manifests: dict[str, list[ToolManifest]],
) -> list[PlanStep]:
    step_names = {
        "inventory": "inventory-project",
        "sast": "scan-sast",
        "secret_scan": "scan-redacted-secrets",  # nosec B105
        "sbom": "generate-sbom",
        "dependency_audit": "audit-dependencies",
    }
    roles = {
        "inventory": "scout",
        "sast": "sast_specialist",
        "secret_scan": "secret_specialist",  # nosec B105
        "sbom": "dependency_specialist",
        "dependency_audit": "dependency_specialist",
    }
    plan: list[PlanStep] = []
    for capability in capabilities:
        choices = manifests.get(capability, [])
        if not choices or capability not in step_names:
            continue
        dependencies: list[str] = []
        if capability in {"sast", "secret_scan", "sbom"}:
            dependencies = ["inventory-project"]
        elif capability == "dependency_audit":
            dependencies = ["generate-sbom"]
        tools = [item.name for item in choices]
        effective_risk = max(max(item.risk_level, item.platform_risk or RiskLevel.R0) for item in choices)
        plan.append(
            PlanStep(
                step_id=step_names[capability],
                objective=f"Collect verifiable {capability} evidence from the immutable workspace.",
                agent_role=roles[capability],
                capability=capability,
                dependencies=dependencies,
                tool_candidates=tools,
                inputs={"target": "."},
                success_criteria=[f"The {capability} result is schema-valid and evidence-backed."],
                failure_policy=(FailurePolicy.FAIL_FAST if capability == "inventory" else FailurePolicy.CONTINUE),
                concurrency_key=choices[0].concurrency_key,
                estimated_tool_calls=1,
                estimated_model_calls=0,
                estimated_tokens=0,
                estimated_cost_units=0,
                risk_hint=effective_risk,
                max_attempts=3 if mode == StrategyMode.DEEP else 2,
                context_requirements=({"tool_candidate_limit": 1} if mode == StrategyMode.QUICK else {}),
            )
        )
    existing = {item.step_id for item in plan}
    return [
        item.model_copy(update={"dependencies": [dep for dep in item.dependencies if dep in existing]}) for item in plan
    ]


def decide_replan(
    *,
    run_id: str,
    trigger: ReplanTrigger,
    current_plan: list[PlanStep],
    revision_count: int,
    tool_manifests: list[ToolManifest],
    unavailable_tools: set[str] | None = None,
) -> ReplanDecision:
    """Produce a bounded structural plan change or recommend a partial report."""

    if revision_count >= _MAX_PLAN_REVISIONS:
        return _partial(trigger, current_plan, "The plan-level replan limit has been exhausted.")

    unavailable = unavailable_tools or set()
    revised: list[PlanStep]
    changed_fields: list[str]
    if trigger == ReplanTrigger.TOOL_UNAVAILABLE:
        revised, changed_fields = _replace_unavailable_tools(current_plan, tool_manifests, unavailable)
    elif trigger == ReplanTrigger.EVIDENCE_INSUFFICIENT:
        revised, changed_fields = _add_evidence_validation_step(current_plan, tool_manifests)
    elif trigger == ReplanTrigger.BUDGET_PRESSURE:
        revised, changed_fields = _reduce_to_quick_plan(current_plan)
    else:
        return _partial(trigger, current_plan, f"No deterministic v0.5-beta policy handles {trigger.value}.")

    parent_digest = _plan_digest(current_plan)
    plan_digest = _plan_digest(revised)
    if not changed_fields or plan_digest == parent_digest:
        return _partial(trigger, current_plan, "No safe structural alternative was available.")
    revision_number = revision_count + 1
    revision_seed = _digest(
        {
            "run_id": run_id,
            "revision": revision_number,
            "trigger": trigger.value,
            "parent_plan_digest": parent_digest,
            "plan_digest": plan_digest,
            "changed_fields": changed_fields,
        }
    )
    revision = PlanRevision(
        revision_id=_stable_id("plan-revision", revision_seed),
        run_id=run_id,
        revision=revision_number,
        parent_plan_digest=parent_digest,
        plan_digest=plan_digest,
        trigger=trigger,
        changed_fields=changed_fields,
        rationale_summary=f"Applied a bounded deterministic response to {trigger.value}.",
    )
    return ReplanDecision(
        action="revise",
        trigger=trigger,
        rationale_summary=revision.rationale_summary,
        revised_plan=tuple(revised),
        revision=revision,
    )


def _replace_unavailable_tools(
    plan: list[PlanStep],
    manifests: list[ToolManifest],
    unavailable: set[str],
) -> tuple[list[PlanStep], list[str]]:
    replacements: dict[str, list[str]] = {}
    for step in plan:
        alternatives = sorted(
            {
                manifest.name
                for manifest in manifests
                if manifest.name not in unavailable
                and manifest.health_status != ToolHealth.UNAVAILABLE
                and step.capability in manifest.capability_tags
                and Scenario.CODE_AUDIT in manifest.scenarios
            }
        )
        retained = [name for name in step.tool_candidates if name not in unavailable]
        combined = [*retained, *(name for name in alternatives if name not in retained)]
        if any(name in unavailable for name in step.tool_candidates) and combined:
            replacements[step.step_id] = combined
    revised = [
        step.model_copy(update={"tool_candidates": replacements[step.step_id]})
        if step.step_id in replacements
        else step.model_copy(deep=True)
        for step in plan
    ]
    return revised, [f"steps[{step_id}].tool_candidates" for step_id in sorted(replacements)]


def _add_evidence_validation_step(
    plan: list[PlanStep], manifests: list[ToolManifest]
) -> tuple[list[PlanStep], list[str]]:
    used_tools = {name for step in plan for name in step.tool_candidates}
    producer = next((step for step in reversed(plan) if step.capability == "sast"), None)
    if producer is None:
        return [step.model_copy(deep=True) for step in plan], []
    alternatives = sorted(
        manifest.name
        for manifest in manifests
        if manifest.name not in used_tools
        and manifest.health_status != ToolHealth.UNAVAILABLE
        and producer.capability in manifest.capability_tags
        and Scenario.CODE_AUDIT in manifest.scenarios
    )
    if not alternatives:
        return [step.model_copy(deep=True) for step in plan], []
    step_id = f"validate-evidence-{len(plan) + 1}"
    validation = producer.model_copy(
        update={
            "step_id": step_id,
            "objective": "Collect independent evidence for claims that did not meet the evidence contract.",
            "dependencies": [producer.step_id],
            "tool_candidates": alternatives,
            "success_criteria": ["Independent evidence resolves or explicitly preserves the evidence gap."],
            "max_attempts": 1,
        },
        deep=True,
    )
    return [*[step.model_copy(deep=True) for step in plan], validation], [f"steps[{step_id}]"]


def _reduce_to_quick_plan(plan: list[PlanStep]) -> tuple[list[PlanStep], list[str]]:
    retained = [step for step in plan if step.capability in _CORE_CAPABILITIES]
    retained_ids = {step.step_id for step in retained}
    revised = [
        step.model_copy(
            update={
                "dependencies": [item for item in step.dependencies if item in retained_ids],
                "tool_candidates": step.tool_candidates[:1],
                "max_attempts": min(step.max_attempts, 2),
            },
            deep=True,
        )
        for step in retained
    ]
    if _plan_digest(revised) == _plan_digest(plan):
        return revised, []
    return revised, ["steps", "tool_candidates", "max_attempts"]


def _plan_digest(plan: list[PlanStep]) -> str:
    return _digest([item.model_dump(mode="json") for item in plan])


def _partial(trigger: ReplanTrigger, plan: list[PlanStep], reason: str) -> ReplanDecision:
    return ReplanDecision(
        action="partial",
        trigger=trigger,
        rationale_summary=reason,
        revised_plan=tuple(step.model_copy(deep=True) for step in plan),
        partial_report_recommended=True,
    )
