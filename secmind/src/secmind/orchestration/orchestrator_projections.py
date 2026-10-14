"""Pure routing and plan projections extracted from the graph façade.

These helpers deliberately receive all runtime collaborators as arguments.
They do not checkpoint, publish, mutate graph state, or access the workspace;
the façade methods remain the compatibility boundary and only delegate here.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from secmind.external_skills import SkillBindingError
from secmind.language_registry import LANGUAGE_SUFFIXES
from secmind.schemas import AgentState, PlanStep, RunStatus, Scenario


def adapt_plan_to_input_languages(
    state: AgentState,
    steps: list[PlanStep],
    *,
    manifests: list[Any] | tuple[Any, ...],
) -> tuple[list[PlanStep], list[str]]:
    """Remove language-specific scanners that cannot inspect this input."""

    languages = {
        language
        for artifact in state.input_artifacts
        if (language := LANGUAGE_SUFFIXES.get(Path(artifact.relative_path).suffix.casefold())) is not None
    }
    manifests_by_name = {item.name: item for item in manifests}
    removed_tools: list[str] = []
    retained: list[PlanStep] = []
    removed_steps: set[str] = set()
    for step in steps:
        compatible: list[str] = []
        for tool_name in step.tool_candidates:
            manifest = manifests_by_name.get(tool_name)
            supported = {item.casefold() for item in manifest.supported_languages} if manifest else set()
            if not supported or languages.intersection(supported):
                compatible.append(tool_name)
            else:
                removed_tools.append(tool_name)
        if step.capability == "sast" and step.estimated_tool_calls and not compatible:
            removed_steps.add(step.step_id)
            continue
        retained.append(step.model_copy(update={"tool_candidates": compatible}, deep=True))
    if removed_steps:
        retained = [
            step.model_copy(
                update={
                    "dependencies": [item for item in step.dependencies if item not in removed_steps],
                    "dependency_bindings": [
                        item for item in step.dependency_bindings if item.upstream_step_id not in removed_steps
                    ],
                },
                deep=True,
            )
            for step in retained
        ]
    return retained, sorted(set(removed_tools))


def bind_available_skill_steps(
    steps: list[PlanStep],
    selection: Any,
    *,
    skill_runtime: Any,
) -> tuple[list[PlanStep], list[str]]:
    """Bind covered steps while preserving independent compatible tools."""

    bound: dict[str, PlanStep] = {}
    skipped: set[str] = set()
    for step in steps:
        try:
            bound[step.step_id] = skill_runtime.bind_steps([step], selection)[0]
        except SkillBindingError:
            skipped.add(step.step_id)

    # A dependent step cannot execute after a prerequisite was removed.
    changed = True
    while changed:
        changed = False
        for step_id, step in list(bound.items()):
            if any(dependency in skipped for dependency in step.dependencies):
                skipped.add(step_id)
                del bound[step_id]
                changed = True
    return [bound[step.step_id] for step in steps if step.step_id in bound], sorted(skipped)


def specialize_tool_skill_binding(step: PlanStep) -> PlanStep:
    """Narrow capability-level Skills to the method needed by one tool."""

    preferred_by_tool = {
        "project_inventory": ("project-inventory",),
        "bandit_python_audit": ("python-security-audit",),
        "python_taint_audit": ("injection-dataflow-review",),
        "web_workflow_audit": ("web-auth-review", "injection-dataflow-review"),
        "semgrep_sast": ("python-security-audit", "injection-dataflow-review"),
        "secret_pattern_scan": ("secret-exposure-review",),
        "gitleaks_secret_scan": ("secret-exposure-review",),
        "syft_sbom": ("supply-chain-audit",),
        "osv_dependency_audit": ("supply-chain-audit",),
    }
    tool_name = step.tool_candidates[0] if len(step.tool_candidates) == 1 else None
    preferred = preferred_by_tool.get(tool_name or "", ())
    selected = [skill_id for skill_id in preferred if skill_id in step.skill_ids]
    if not selected:
        return step
    requirements = dict(step.context_requirements)
    requirements.update(
        {
            "tool_skill_affinity": "exact",
            "active_skill_ids": selected,
        }
    )
    return step.model_copy(
        update={"skill_ids": selected, "context_requirements": requirements},
        deep=True,
    )


def scenario_route(
    state: AgentState,
    *,
    enable_log_analysis: bool,
    enable_incident_dry_run: bool,
    enable_api_static_assessment: bool,
) -> str:
    """Project the next graph route from immutable state and feature flags."""

    if state.status == RunStatus.FAILED:
        return "report"
    if state.scenario == Scenario.CODE_AUDIT:
        # A completed/no-gap Anchor is not a licence to close the
        # independent audit lane.  The bounded scout route is mandatory
        # in v0.8.2; its candidates may be quarantined and replayed but it
        # cannot be skipped by a model self-report of "no gap".
        if state.audit_coverage.get("direct_anchor_pipeline") is not True:
            gap_summary = state.audit_coverage.get("evidence_gap_compiler", {})
            gaps = gap_summary.get("gap_codes") if isinstance(gap_summary, dict) else None
            if state.published_baseline is not None and gaps == []:
                return "complete"
        return "code"
    if state.audit_coverage.get("pre_primary_scenario_executed") is True:
        return "complete"
    enabled = {
        Scenario.LOG_ANALYSIS: enable_log_analysis,
        Scenario.INCIDENT_RESPONSE: enable_incident_dry_run,
        Scenario.API_ASSESSMENT: enable_api_static_assessment,
        Scenario.REVERSE_TRIAGE: True,
    }
    return "scenario" if enabled.get(state.scenario, False) else "report"


__all__ = [
    "adapt_plan_to_input_languages",
    "bind_available_skill_steps",
    "scenario_route",
    "specialize_tool_skill_binding",
]
