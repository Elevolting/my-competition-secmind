from __future__ import annotations

from typing import Annotated, Any

from fastapi import Body, FastAPI, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from secmind.investigation.prompts import PromptRegistry, PromptRegistryError
from secmind.prompting.catalog import PromptCatalogError
from secmind.prompting.contracts import PromptContext, PromptMode
from secmind.runtime import ApplicationRuntime
from secmind.schemas import SCHEMA_VERSION


class LifecyclePromptPreviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: str = Field(min_length=1, max_length=80)
    signals: set[str] = Field(default_factory=set, max_length=40)
    top_k: int = Field(default=3, ge=1, le=10)


_LIFECYCLE_PROMPTS = PromptRegistry.builtin()


def _service(runtime: ApplicationRuntime) -> Any:
    return runtime.service.orchestrator.prompt_service


def _artifact_projection(artifact: Any) -> dict[str, Any]:
    payload = artifact.model_dump(mode="json", exclude={"system_prompt", "user_strategy_prefix"})
    payload["prompt_content_exposed"] = False
    return payload


def register_prompt_routes(app: FastAPI, runtime: ApplicationRuntime) -> None:
    @app.get("/api/v1/prompts/templates")
    async def list_prompt_templates(
        role: Annotated[str | None, Query(max_length=30)] = None,
        status: Annotated[str | None, Query(max_length=30)] = None,
    ) -> dict[str, Any]:
        prompt_service = _service(runtime)
        items = prompt_service.catalog.manifest()
        if role is not None:
            items = [item for item in items if item["role"] == role]
        if status is not None:
            items = [item for item in items if item["status"] == status]
        return {
            "schema_version": SCHEMA_VERSION,
            "catalog": prompt_service.catalog.readiness(),
            "items": items,
            "count": len(items),
        }

    @app.get("/api/v1/prompts/templates/{template_id}/versions/{version}")
    async def get_prompt_template(template_id: str, version: str) -> dict[str, Any]:
        try:
            seed = _service(runtime).catalog.get(template_id, version)
        except PromptCatalogError as exc:
            raise HTTPException(404, "Prompt template not found") from exc
        item = seed.model_dump(mode="json", exclude={"strategy_body"})
        item["digest"] = seed.seed_digest
        item["content_ready"] = seed.has_strategy_content
        return {"schema_version": SCHEMA_VERSION, "template": item}

    @app.get("/api/v1/runs/{run_id}/prompt-artifacts")
    async def list_prompt_artifacts(run_id: str) -> dict[str, Any]:
        artifacts = [_artifact_projection(item) for item in _service(runtime).artifacts(run_id)]
        return {
            "schema_version": SCHEMA_VERSION,
            "run_id": run_id,
            "items": artifacts,
            "count": len(artifacts),
        }

    @app.get("/api/v1/runs/{run_id}/prompt-artifacts/{artifact_id}")
    async def get_prompt_artifact(run_id: str, artifact_id: str) -> dict[str, Any]:
        prompt_service = _service(runtime)
        artifact = prompt_service.artifact(run_id, artifact_id)
        if artifact is None:
            raise HTTPException(404, "Prompt artifact not found")
        lineage = prompt_service.lineage(run_id, artifact_id)
        if lineage is None:  # pragma: no cover - artifact was resolved above
            raise HTTPException(404, "Prompt artifact not found")
        return {
            "schema_version": SCHEMA_VERSION,
            "run_id": run_id,
            "artifact": _artifact_projection(artifact),
            "lineage": lineage,
        }

    @app.post("/api/v1/prompts/preview")
    async def preview_prompt_selection(
        context: Annotated[PromptContext, Body()],
        mode: Annotated[PromptMode | None, Query()] = None,
    ) -> dict[str, Any]:
        preview = _service(runtime).preview(context, mode=mode)
        return {"schema_version": SCHEMA_VERSION, **preview}

    @app.get("/api/v1/prompts/metrics")
    async def prompt_metrics() -> dict[str, Any]:
        prompt_service = _service(runtime)
        model_policy = runtime.service.orchestrator.gateway.policy
        return {
            "schema_version": SCHEMA_VERSION,
            "catalog": prompt_service.catalog.readiness(),
            "mode": prompt_service.settings.mode.value,
            "optimizer_enabled": prompt_service.settings.optimizer_enabled,
            "optimizer_authoritative": prompt_service.optimizer_authoritative,
            "optimizer_authority_reason": prompt_service.optimizer_authority_reason,
            "adaptive_policy_approved": prompt_service.settings.adaptive_policy_approved,
            "model_mode": model_policy.mode.value,
            "live_model_allowed": model_policy.mode.value == "live",
        }

    @app.get("/api/v1/prompts/lifecycle")
    async def list_lifecycle_prompts(
        role: Annotated[str | None, Query(max_length=80)] = None,
    ) -> dict[str, Any]:
        items = _LIFECYCLE_PROMPTS.manifest()
        if role is not None:
            items = [item for item in items if item["role"] == role]
        return {
            "schema_version": SCHEMA_VERSION,
            "library_version": "2.0.0",
            "prompt_content_exposed": False,
            "items": items,
            "count": len(items),
        }

    @app.post("/api/v1/prompts/lifecycle/preview")
    async def preview_lifecycle_prompt_selection(
        request: Annotated[LifecyclePromptPreviewRequest, Body()],
    ) -> dict[str, Any]:
        try:
            selected = _LIFECYCLE_PROMPTS.select(
                role=request.role,
                signals=request.signals,
                top_k=request.top_k,
            )
        except PromptRegistryError as exc:
            raise HTTPException(422, str(exc)) from exc
        return {
            "schema_version": SCHEMA_VERSION,
            "role": request.role,
            "signals": sorted(request.signals),
            "executes_model": False,
            "selected": [
                {
                    "prompt_id": item.prompt_id,
                    "version": item.version,
                    "strategy_key": item.strategy_key,
                    "trigger_tags": sorted(item.trigger_tags),
                    "digest": item.digest,
                    "output_schema_ref": item.output_schema_ref,
                }
                for item in selected
            ],
        }


__all__ = ["LifecyclePromptPreviewRequest", "register_prompt_routes"]
