"""Operational HTTP endpoints.

This module owns process health, readiness, metrics, and upload lifecycle.
Keeping those concerns outside :mod:`secmind.api` makes the application
factory a wiring layer instead of a second service implementation.
"""

from __future__ import annotations

import asyncio
import os
import time
import unicodedata
from pathlib import Path
from typing import Annotated, Any
from uuid import uuid4

import httpx
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from sqlalchemy import text

from secmind.config import Settings
from secmind.log_parsers import binary_parser_dependency_status
from secmind.runtime import ApplicationRuntime
from secmind.schemas import SCHEMA_VERSION
from secmind.tool_assurance import tool_assurance_readiness

_WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}


def safe_upload_name(filename: str | None) -> str:
    """Return a portable filename or reject names that can escape storage."""

    candidate = unicodedata.normalize("NFC", filename or "")
    if not candidate or candidate in {".", ".."} or len(candidate.encode("utf-8")) > 255:
        raise HTTPException(400, "Invalid filename")
    if candidate != filename or any(ord(character) < 32 or ord(character) == 127 for character in candidate):
        raise HTTPException(400, "Invalid filename")
    if any(separator in candidate for separator in ("/", "\\")) or candidate.endswith((".", " ")):
        raise HTTPException(400, "Invalid filename")
    if Path(candidate).is_absolute() or candidate.split(".", 1)[0].upper() in _WINDOWS_RESERVED_NAMES:
        raise HTTPException(400, "Invalid filename")
    return candidate


def purge_expired_uploads(root: Path, *, ttl_seconds: int, now: float) -> int:
    """Delete expired regular files and return current retained byte usage."""

    total = 0
    for item in root.iterdir():
        if item.is_symlink() or not item.is_file():
            continue
        try:
            stat = item.stat()
            if now - stat.st_mtime > ttl_seconds:
                item.unlink(missing_ok=True)
            elif not item.name.startswith(".upload-"):
                total += stat.st_size
        except FileNotFoundError:
            # Another request may have completed the same cleanup pass.
            continue
    return total


def register_system_routes(app: FastAPI, runtime: ApplicationRuntime, settings: Settings) -> None:
    """Register operational routes on ``app`` without owning app startup."""

    upload_lock = asyncio.Lock()
    strict = settings.env.lower() in {"production", "competition"}
    execution_role = settings.runtime_role in {"worker", "embedded"}

    @app.get("/health")
    async def health() -> dict[str, Any]:
        runtime_profile = runtime.service.orchestrator.runtime_profile
        return {
            "status": "ok",
            "schema_version": SCHEMA_VERSION,
            "demo_mode": settings.demo_mode,
            "release_identity": runtime.service.orchestrator.release_identity,
            "runtime_profile": runtime_profile.model_dump(mode="json"),
        }

    @app.get("/health/live")
    async def live() -> dict[str, Any]:
        return {"status": "ok", "schema_version": SCHEMA_VERSION}

    @app.get("/health/ready")
    async def ready() -> dict[str, Any]:
        runtime_profile = runtime.service.orchestrator.runtime_profile
        checks: dict[str, Any] = {
            "database": False,
            "checkpointer": bool(settings.checkpoint_database_url) if strict else True,
            "projector": False,
            "tools": False,
            "runner": not strict and not settings.sandbox_runner_url,
            "prompt_catalog": False,
            "binary_log_parsers": not settings.binary_log_parsers_enabled,
        }
        # Development may deliberately run without scanner signing material,
        # but readiness must say so explicitly.  Strict execution roles are
        # fail-closed at runtime startup and are checked here as well.
        assurance = tool_assurance_readiness(required=strict and execution_role)
        checks["tool_assurance"] = assurance
        checks["tool_assurance_ready"] = assurance["status"] == "ready" if strict and execution_role else True
        try:
            with runtime.service.coordinator.engine.connect() as connection:
                checks["database"] = connection.execute(text("SELECT 1")).scalar_one() == 1
                failed_outbox = int(
                    connection.execute(
                        text("SELECT COUNT(*) FROM outbox_events WHERE status IN ('failed', 'retry_wait')")
                    ).scalar_one()
                )
                dead_letter_outbox = int(
                    connection.execute(
                        text("SELECT COUNT(*) FROM outbox_events WHERE status = 'dead_letter'")
                    ).scalar_one()
                )
                failure_class_rows = connection.execute(
                    text(
                        "SELECT COALESCE(failure_class, 'unknown') AS failure_class, COUNT(*) AS count "
                        "FROM outbox_events WHERE status IN ('failed', 'retry_wait', 'dead_letter') "
                        "GROUP BY failure_class"
                    )
                ).all()
                expired_projection_leases = int(
                    connection.execute(
                        text(
                            "SELECT COUNT(*) FROM outbox_events "
                            "WHERE status = 'projecting' AND lease_until < CURRENT_TIMESTAMP"
                        )
                    ).scalar_one()
                )
                checks["projector"] = failed_outbox == 0 and expired_projection_leases == 0
                checks["outbox_failed"] = failed_outbox
                checks["outbox_dead_letter"] = dead_letter_outbox
                checks["outbox_failure_classes"] = {
                    str(row._mapping["failure_class"]): int(row._mapping["count"]) for row in failure_class_rows
                }
                checks["outbox_expired_leases"] = expired_projection_leases

            manifests = runtime.service.orchestrator.broker.registry.manifests()
            tool_health = {manifest.name: manifest.health_status.value for manifest in manifests}
            healthy_tools = {name for name, health in tool_health.items() if health == "healthy"}
            required_tools = {
                "project_inventory",
                "bandit_python_audit",
                "secret_pattern_scan",
                "gitleaks_secret_scan",
                "syft_sbom",
                "osv_dependency_audit",
            }
            if settings.semgrep_candidate_rules_enabled:
                required_tools.add("semgrep_sast")
            checks["tools"] = required_tools <= healthy_tools if strict else bool(healthy_tools)
            checks["tool_health"] = tool_health

            prompt_readiness = runtime.service.orchestrator.prompt_service.catalog.readiness()
            prompt_total = int(prompt_readiness["total"])
            checks["prompt_catalog"] = (
                prompt_total > 0
                and int(prompt_readiness["content_ready"]) == prompt_total
                and (
                    settings.prompt_mode == "fixed"
                    or int(prompt_readiness["approved"]) > 0
                    or (
                        settings.prompt_reviewed_authoritative_enabled
                        and int(prompt_readiness["reviewed"]) == prompt_total
                    )
                )
            )
            checks["prompt_catalog_detail"] = prompt_readiness
            if settings.binary_log_parsers_enabled:
                parser_dependencies = binary_parser_dependency_status()
                checks["binary_log_parser_dependencies"] = parser_dependencies
                checks["binary_log_parsers"] = all(parser_dependencies.values())

            if settings.sandbox_runner_url:
                async with httpx.AsyncClient(timeout=3) as client:
                    response = await client.get(f"{settings.sandbox_runner_url.rstrip('/')}/health")
                checks["runner"] = response.status_code == 200
        except Exception as exc:
            # Readiness reports the failing component type without leaking its
            # connection string, runner token, or provider response.
            checks["error_type"] = type(exc).__name__

        required_checks = (
            "database",
            "checkpointer",
            "projector",
            "tools",
            "runner",
            "prompt_catalog",
            "binary_log_parsers",
            "tool_assurance_ready",
        )
        if not all(bool(checks[name]) for name in required_checks):
            raise HTTPException(503, detail={"status": "not_ready", "checks": checks})
        if int(checks.get("outbox_dead_letter", 0)) > 0:
            # A dead-letter event is an explicit, auditable degradation rather
            # than a healthy projector.  The process can serve diagnostics and
            # operator recovery, but the run-level quiet gate still blocks the
            # affected run until a resolution receipt exists.
            return {
                "status": "degraded",
                "schema_version": SCHEMA_VERSION,
                "checks": checks,
                "release_identity": runtime.service.orchestrator.release_identity,
                "runtime_profile": runtime_profile.model_dump(mode="json"),
            }
        return {
            "status": "ready",
            "schema_version": SCHEMA_VERSION,
            "checks": checks,
            "release_identity": runtime.service.orchestrator.release_identity,
            "runtime_profile": runtime_profile.model_dump(mode="json"),
        }

    @app.get("/metrics", include_in_schema=False)
    async def metrics() -> Response:
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    @app.post("/api/v1/uploads", status_code=201)
    async def upload(file: Annotated[UploadFile, File(...)]) -> dict[str, Any]:
        safe_name = safe_upload_name(file.filename)
        reference = f"{uuid4()}-{safe_name}"
        destination = settings.upload_root / reference
        temporary = settings.upload_root / f".upload-{uuid4().hex}"
        total = 0
        async with upload_lock:
            used = purge_expired_uploads(
                settings.upload_root,
                ttl_seconds=settings.upload_ttl_seconds,
                now=time.time(),
            )
            try:
                # Write-then-rename keeps partially uploaded files outside the
                # immutable attachment namespace seen by task ingestion.
                with temporary.open("xb") as stream:
                    while chunk := await file.read(1024 * 1024):
                        total += len(chunk)
                        if total > settings.max_upload_bytes:
                            raise HTTPException(413, "Upload exceeds per-file size limit")
                        if used + total > settings.max_upload_total_bytes:
                            raise HTTPException(413, "Upload exceeds total storage quota")
                        stream.write(chunk)
                    stream.flush()
                    os.fsync(stream.fileno())
                temporary.replace(destination)
            except Exception:
                temporary.unlink(missing_ok=True)
                destination.unlink(missing_ok=True)
                raise
        return {"schema_version": SCHEMA_VERSION, "ref": reference, "name": safe_name, "size_bytes": total}
