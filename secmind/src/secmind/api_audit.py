from __future__ import annotations

import hashlib
import json
from typing import Annotated, Any

from fastapi import Body, FastAPI, HTTPException

from secmind.audit_kernel.patch_release import PatchReleaseRecord, PatchReleaseStatus
from secmind.audit_kernel.persistence import AuditPersistenceConflict
from secmind.public_coverage import public_coverage_projection
from secmind.runtime import ApplicationRuntime
from secmind.schemas import SCHEMA_VERSION


def _state(runtime: ApplicationRuntime, run_id: str) -> Any:
    try:
        return runtime.service.state(run_id)
    except KeyError as exc:
        raise HTTPException(404, "Run not found") from exc


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def register_audit_routes(app: FastAPI, runtime: ApplicationRuntime) -> None:
    @app.get("/api/v1/runs/{run_id}/units")
    async def list_audit_units(run_id: str) -> dict[str, Any]:
        state = _state(runtime, run_id)
        units = [item.model_dump(mode="json") for item in state.audit_units]
        return {
            "schema_version": SCHEMA_VERSION,
            "run_id": run_id,
            "audit_kernel": state.audit_kernel,
            # ``audit_coverage`` is a replay/control-plane store and may
            # contain typed answers, deltas, and provider capsules.  Units is
            # a public API boundary, so expose the same minimal projection as
            # the report/admission routes instead of returning the raw state.
            "coverage": public_coverage_projection(state.audit_coverage),
            "units": units,
            "count": len(units),
        }

    @app.get("/api/v1/runs/{run_id}/comparative-result")
    async def comparative_result(run_id: str) -> dict[str, Any]:
        state = _state(runtime, run_id)
        if not state.audit_units:
            raise HTTPException(409, "Run has no Direct-anchored audit result")
        baseline = [
            {
                "unit_id": item.unit_id,
                "verdict": item.baseline_verdict,
                "cwe": item.baseline_cwe,
            }
            for item in sorted(state.audit_units, key=lambda value: value.unit_id)
        ]
        final = [
            {
                "unit_id": item.unit_id,
                "verdict": item.final_verdict,
                "cwe": item.cwe,
                "action": item.action,
            }
            for item in sorted(state.audit_units, key=lambda value: value.unit_id)
        ]
        changed = sum(item["action"] != "keep_baseline" for item in final)
        scoreable = sum(item["verdict"] != "inconclusive" for item in final)
        return {
            "schema_version": SCHEMA_VERSION,
            "run_id": run_id,
            "baseline_commitment": _digest(baseline),
            "final_commitment": _digest(final),
            "changed_units": changed,
            "decision_units": len(final),
            "scoreable_units": scoreable,
            "gold_accessed": False,
            "quality_claim": "not_evaluated_without_sealed_gold",
        }

    @app.get("/api/v1/patch-releases")
    async def list_patch_releases() -> dict[str, Any]:
        kernel = runtime.service.orchestrator.java_audit_kernel
        releases = [item.model_dump(mode="json") for item in kernel.patch_releases()]
        return {
            "schema_version": SCHEMA_VERSION,
            "items": releases,
            "count": len(releases),
        }

    @app.post("/api/v1/patch-releases")
    async def publish_patch_release(
        evaluation_run_id: Annotated[
            str,
            Body(min_length=1, max_length=36),
        ],
        release: Annotated[PatchReleaseRecord, Body()],
    ) -> dict[str, Any]:
        # Public API input is never a trusted evaluation authority.  A client
        # may register a SHADOW candidate for observation, but canary and
        # authoritative records must be constructed by the server-side sealed
        # evaluation import path.
        if release.status != PatchReleaseStatus.SHADOW:
            raise HTTPException(
                409,
                "Only shadow patch records may be client-submitted; authoritative release requires sealed evaluation",
            )
        kernel = runtime.service.orchestrator.java_audit_kernel
        try:
            published = kernel.publish_patch_release(evaluation_run_id, release)
        except (AuditPersistenceConflict, ValueError) as exc:
            raise HTTPException(409, str(exc)) from exc
        return {
            "schema_version": SCHEMA_VERSION,
            "patch_release": published.model_dump(mode="json"),
        }

    @app.post("/api/v1/patch-releases/{patch_release_id}/revoke")
    async def revoke_patch_release(
        patch_release_id: str,
        reason: Annotated[str, Body(embed=True, min_length=1, max_length=1024)],
    ) -> dict[str, Any]:
        kernel = runtime.service.orchestrator.java_audit_kernel
        try:
            release = kernel.revoke_patch_release(patch_release_id, reason)
        except KeyError as exc:
            raise HTTPException(404, "Patch release not found") from exc
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        return {
            "schema_version": SCHEMA_VERSION,
            "patch_release": release.model_dump(mode="json"),
        }


__all__ = ["register_audit_routes"]
