"""Read-only catalog and effective-policy HTTP endpoints.

Catalog routes intentionally expose metadata rather than executable prompt or
Skill bodies. Execution authority remains in the orchestrator and ToolBroker.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.encoders import jsonable_encoder

from secmind.policy import ELEVATED_PERMISSIONS, PROHIBITED_PERMISSIONS
from secmind.runtime import ApplicationRuntime
from secmind.schemas import SCHEMA_VERSION, RiskLevel
from secmind.strategy import scenario_manifests
from secmind.task_context import ResolvedTaskContractRequired, require_resolved_task_contract


def _read_catalog(component: Any) -> tuple[bool, list[Any], str | None]:
    """Read an optional registry without making the API itself unavailable."""

    if component is None or not callable(getattr(component, "catalog", None)):
        return False, [], "COMPONENT_NOT_CONFIGURED"
    try:
        items = component.catalog()
    except Exception as exc:
        return False, [], type(exc).__name__
    return True, jsonable_encoder(items), None


def _component(runtime: ApplicationRuntime, name: str) -> Any:
    service = getattr(runtime, "service", None)
    orchestrator = getattr(service, "orchestrator", None)
    return getattr(orchestrator, name, None)


def _run_state(runtime: ApplicationRuntime, run_id: str) -> Any:
    try:
        return runtime.service.state(run_id)
    except KeyError as exc:
        raise HTTPException(404, "Run not found") from exc


def _effective_tool_policy(manifest: Any, autonomy_policy: str) -> dict[str, Any]:
    """Project the platform-enforced risk; model hints can never lower it."""

    permissions = {str(item).casefold() for item in getattr(manifest, "permissions", [])}
    risk = max(
        getattr(manifest, "risk_level", RiskLevel.R0),
        getattr(manifest, "platform_risk", None) or RiskLevel.R0,
    )
    reasons = ["manifest_risk"]
    execution = getattr(manifest, "execution", None)
    network_policy = getattr(execution, "network_policy", "none")
    if permissions & PROHIBITED_PERMISSIONS or risk >= RiskLevel.R3:
        risk = RiskLevel.R3
        action = "deny"
        reasons.append("prohibited_capability")
    elif getattr(manifest, "requires_network", False) or network_policy != "none" or permissions & ELEVATED_PERMISSIONS:
        risk = max(risk, RiskLevel.R2)
        action = "require_approval"
        reasons.append("elevated_execution_boundary")
    elif autonomy_policy == "approval_all" or risk == RiskLevel.R2:
        action = "require_approval"
        reasons.append("autonomy_policy" if autonomy_policy == "approval_all" else "risk_r2")
    else:
        action = "allow"
    return {
        "tool_name": str(getattr(manifest, "name", "unknown")),
        "tool_version": str(getattr(manifest, "version", "unknown")),
        "effective_risk": int(risk),
        "effective_risk_label": risk.name,
        "action": action,
        "network_policy": network_policy,
        "reasons": reasons,
    }


def register_catalog_routes(app: FastAPI, runtime: ApplicationRuntime) -> None:
    """Register capability discovery and policy-projection routes."""

    @app.get("/api/v1/tools")
    async def list_tools() -> dict[str, Any]:
        manifests = runtime.service.orchestrator.broker.registry.manifests()
        return {
            "schema_version": SCHEMA_VERSION,
            "tools": [manifest.model_dump(mode="json") for manifest in manifests],
        }

    @app.get("/api/v1/parsers")
    async def list_parsers() -> dict[str, Any]:
        manifests = runtime.service.orchestrator.parser_registry.manifests()
        return {
            "schema_version": SCHEMA_VERSION,
            "parsers": [manifest.model_dump(mode="json") for manifest in manifests],
        }

    @app.get("/api/v1/scenarios")
    async def list_scenarios() -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "scenarios": [manifest.model_dump(mode="json") for manifest in scenario_manifests()],
        }

    @app.get("/api/v1/skills")
    async def list_skills() -> dict[str, Any]:
        available, skills, error_type = _read_catalog(_component(runtime, "skill_registry"))
        external = _component(runtime, "external_skill_catalog")
        external_available = external is not None
        external_error: str | None = None
        external_summary: dict[str, Any] | None = None
        if external_available:
            try:
                external_summary = {
                    "catalog_digest": external.digest,
                    "selected_count": external.source.selected_count,
                    "source": jsonable_encoder(external.source),
                    "authority": "advisory_l5",
                    "executable": False,
                }
            except Exception as exc:
                external_available = False
                external_error = type(exc).__name__
        return {
            "schema_version": SCHEMA_VERSION,
            "available": available,
            "skills": skills,
            "count": len(skills),
            "error_type": error_type,
            "instructions_included": False,
            "external_available": external_available,
            "external_catalog": external_summary,
            "external_error_type": external_error,
        }

    @app.get("/api/v1/skills/external")
    async def list_external_skills(
        offset: Annotated[int, Query(ge=0)] = 0,
        limit: Annotated[int, Query(ge=1, le=100)] = 50,
    ) -> dict[str, Any]:
        catalog = _component(runtime, "external_skill_catalog")
        if catalog is None:
            raise HTTPException(503, "External skill catalog is unavailable")
        cards = catalog.catalog()
        page = cards[offset : offset + limit]
        return {
            "schema_version": SCHEMA_VERSION,
            "catalog_digest": catalog.digest,
            "source": jsonable_encoder(catalog.source),
            "cards": jsonable_encoder(page),
            "offset": offset,
            "limit": limit,
            "count": len(page),
            "total": len(cards),
            "has_more": offset + len(page) < len(cards),
            "bodies_included": False,
            "scripts_allowed": False,
        }

    @app.get("/api/v1/runs/{run_id}/skills")
    async def get_run_skills(run_id: str) -> dict[str, Any]:
        state = _run_state(runtime, run_id)
        context_by_id = {item.context_id: item for item in state.context_items}
        external_cards = {
            str(item.metadata["external_skill_id"]): item
            for item in state.context_items
            if item.metadata.get("external_skill_id")
        }
        steps: list[dict[str, Any]] = []
        for step in state.plan:
            packs = [item for item in state.context_packs if item.step_id == step.step_id]
            pack = packs[-1] if packs else None
            materialized_signed = []
            materialized_external = []
            if pack is not None:
                materialized_signed = sorted(
                    {
                        str(context_by_id[ref].metadata["skill_id"])
                        for ref in pack.selected_skill_refs
                        if ref in context_by_id and context_by_id[ref].metadata.get("skill_id")
                    }
                )
                materialized_external = sorted(
                    {
                        str(context_by_id[ref].metadata["external_skill_id"])
                        for ref in pack.knowledge_refs
                        if ref in context_by_id and context_by_id[ref].metadata.get("external_skill_id")
                    }
                )
            runtime_state = state.step_runtime.get(step.step_id)
            steps.append(
                {
                    "step_id": step.step_id,
                    "capability": step.capability,
                    "agent_profile": pack.agent_profile if pack is not None else None,
                    "signed_skill_ids": list(step.skill_ids),
                    "external_skill_card_ids": list(step.context_requirements.get("external_skill_card_ids", [])),
                    "tool_candidates": list(step.tool_candidates),
                    "materialized_signed_skill_ids": materialized_signed,
                    "materialized_external_skill_card_ids": materialized_external,
                    "runtime_status": runtime_state.status.value if runtime_state is not None else "pending",
                    "tool_invoked": bool(runtime_state and runtime_state.observation_indexes),
                }
            )
        return {
            "schema_version": SCHEMA_VERSION,
            "run_id": run_id,
            "selected_signed_skill_ids": sorted(state.selected_skill_ids),
            "selected_external_skill_card_ids": sorted(external_cards),
            "steps": steps,
            "tool_invoked_step_count": sum(bool(item["tool_invoked"]) for item in steps),
        }

    @app.get("/api/v1/capabilities")
    async def list_capabilities() -> dict[str, Any]:
        available, capabilities, error_type = _read_catalog(_component(runtime, "capability_resolver"))
        return {
            "schema_version": SCHEMA_VERSION,
            "available": available,
            "capabilities": capabilities,
            "count": len(capabilities),
            "error_type": error_type,
        }

    @app.get("/api/v1/policies/effective")
    async def get_effective_policies(
        run_id: Annotated[str | None, Query()] = None,
    ) -> dict[str, Any]:
        state = None
        autonomy_policy = "graded"
        if run_id is not None:
            state = _run_state(runtime, run_id)
            try:
                autonomy_policy = require_resolved_task_contract(state).autonomy_policy
            except ResolvedTaskContractRequired as exc:
                raise HTTPException(409, str(exc)) from exc
        orchestrator = getattr(runtime.service, "orchestrator", None)
        broker = getattr(orchestrator, "broker", None)
        registry = getattr(broker, "registry", None)
        manifests: list[Any] = []
        manifest_reader = getattr(registry, "manifests", None)
        registry_available = False
        registry_error: str | None = None
        if callable(manifest_reader):
            registry_available = True
            try:
                manifests = list(manifest_reader())
            except Exception as exc:
                registry_available = False
                registry_error = type(exc).__name__
        pdp = getattr(orchestrator, "policy_decision_point", None)
        policy_version = getattr(pdp, "policy_version", None)
        if registry_error is not None:
            component_error = registry_error
        elif not registry_available:
            component_error = "COMPONENT_NOT_CONFIGURED"
        elif policy_version is None:
            component_error = "POLICY_PDP_NOT_CONFIGURED"
        else:
            component_error = None
        pending_approvals: dict[str, dict[str, Any]] = {}
        if state is not None:
            contract = require_resolved_task_contract(state)
            pending = [*state.pending_approvals]
            if state.pending_approval is not None:
                pending.append(state.pending_approval)
            for approval in pending:
                pending_approvals[approval.request_id] = {
                    "request_id": approval.request_id,
                    "step_id": approval.step_id,
                    "tool_name": approval.tool_name,
                    "target": approval.target,
                    "risk_level": int(approval.risk_level),
                }
        return {
            "schema_version": SCHEMA_VERSION,
            "policy_version": policy_version,
            "available": policy_version is not None and registry_available,
            "error_type": component_error,
            "platform_rules": {
                "r0_r1": "allow",
                "r2": "require_approval",
                "r3": "deny",
                "model_may_lower_risk": False,
                "target_scope_is_immutable": True,
            },
            "run": (
                None
                if state is None
                else {
                    "run_id": state.run_id,
                    "resolved_contract_id": contract.contract_id,
                    "resolved_contract_digest": contract.contract_digest,
                    "autonomy_policy": contract.autonomy_policy,
                    "target_scope": contract.authorized_scope,
                    "constraints": contract.constraints,
                    "active_grants": [grant.model_dump(mode="json") for grant in state.active_grants],
                    "pending_approvals": list(pending_approvals.values()),
                    "policy_decisions": [
                        decision.model_dump(mode="json") for decision in state.decisions if decision.policy_ids
                    ],
                }
            ),
            "tools": [
                _effective_tool_policy(manifest, autonomy_policy)
                for manifest in sorted(manifests, key=lambda item: str(getattr(item, "name", "")))
            ],
        }
