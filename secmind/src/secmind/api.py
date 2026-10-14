"""FastAPI application composition for SecMind.

Route behavior lives in the focused ``api_*`` modules. This facade owns only
application lifecycle, authentication, OpenAPI policy, and dependency wiring.
"""

from __future__ import annotations

import secrets
from contextlib import asynccontextmanager
from typing import Any

import httpx
import uvicorn
from fastapi import FastAPI, Request
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse, Response
from starlette.middleware.trustedhost import TrustedHostMiddleware

from secmind import PUBLIC_VERSION
from secmind.api_artifacts import register_artifact_routes
from secmind.api_audit import register_audit_routes
from secmind.api_catalogs import register_catalog_routes
from secmind.api_events import register_event_routes
from secmind.api_investigation import register_investigation_routes
from secmind.api_prompting import register_prompt_routes
from secmind.api_runs import register_run_routes  # noqa: F401
from secmind.api_system import purge_expired_uploads as _purge_expired_uploads  # noqa: F401
from secmind.api_system import register_system_routes
from secmind.api_system import safe_upload_name as _safe_upload_name  # noqa: F401
from secmind.config import Settings, get_settings
from secmind.runtime import ApplicationRuntime

__all__ = [
    "_purge_expired_uploads",
    "_safe_upload_name",
    "app",
    "create_app",
    "httpx",
    "run",
]


def _operator_token(headers: Any, expected: str) -> bool:
    """Compare bearer credentials without leaking timing information."""

    scheme, separator, credential = headers.get("authorization", "").partition(" ")
    return bool(
        separator and scheme.lower() == "bearer" and credential and secrets.compare_digest(credential, expected)
    )


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the HTTP adapter and wire it to one application runtime."""

    actual_settings = settings or get_settings()
    runtime = ApplicationRuntime(actual_settings)

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        # Startup owns durable clients and background workers; route modules
        # deliberately receive the runtime instead of constructing dependencies.
        await runtime.startup()
        application.state.service = runtime.service
        try:
            yield
        finally:
            await runtime.shutdown()

    app = FastAPI(
        title="SecMind Agent API",
        version=PUBLIC_VERSION,
        description="Governed multi-scenario beta built on the trusted SecMind cognitive kernel.",
        lifespan=lifespan,
    )
    app.state.runtime = runtime
    app.state.settings = actual_settings

    strict = actual_settings.env.lower() in {"production", "competition"}
    if strict and not actual_settings.operator_token:
        raise RuntimeError("production requires SECMIND_OPERATOR_TOKEN")

    @app.middleware("http")
    async def authenticate_operator(request: Request, call_next: Any) -> Response:
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            origin = request.headers.get("origin")
            allowed = {str(request.base_url).rstrip("/")}
            allowed.update(
                f"http://{host}:{port}"
                for host in ("127.0.0.1", "localhost")
                for port in (5173, actual_settings.api_port)
            )
            allowed.update(
                item.strip() for item in actual_settings.allowed_browser_origins.split(",") if item.strip()
            )
            if origin is not None and origin not in allowed:
                return JSONResponse(status_code=403, content={"detail": "Browser origin is not allowed"})
        if strict and request.url.path.startswith("/api/"):
            if not _operator_token(request.headers, actual_settings.operator_token):
                return JSONResponse(
                    status_code=401,
                    content={"detail": "operator authentication required"},
                    headers={"WWW-Authenticate": "Bearer"},
                )
        return await call_next(request)

    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["127.0.0.1", "localhost"] + [
            item.strip() for item in actual_settings.allowed_hosts.split(",") if item.strip()
        ],
    )

    def custom_openapi() -> dict[str, Any]:
        """Describe the same operator boundary enforced by the middleware."""

        if app.openapi_schema is None:
            schema = get_openapi(
                title=app.title,
                version=app.version,
                description=app.description,
                routes=app.routes,
            )
            components = schema.setdefault("components", {})
            components.setdefault("securitySchemes", {})["OperatorBearer"] = {
                "type": "http",
                "scheme": "bearer",
            }
            for path, operations in schema.get("paths", {}).items():
                if path.startswith("/api/"):
                    for operation in operations.values():
                        if isinstance(operation, dict):
                            operation["security"] = [{"OperatorBearer": []}]
            app.openapi_schema = schema
        return app.openapi_schema

    app.openapi = custom_openapi  # type: ignore[method-assign]

    # Registration order is stable because it affects OpenAPI snapshots and
    # therefore forms part of the B-group integration contract.
    register_system_routes(app, runtime, actual_settings)
    register_run_routes(app, runtime, actual_settings)
    register_catalog_routes(app, runtime)
    register_artifact_routes(app, runtime)
    register_audit_routes(app, runtime)
    register_prompt_routes(app, runtime)
    register_investigation_routes(app, runtime)
    register_event_routes(
        app,
        runtime,
        actual_settings,
        strict=strict,
        operator_token_valid=_operator_token,
    )
    return app


app = create_app()


def run() -> None:
    """Start the local ASGI server using environment-backed settings."""

    settings = get_settings()
    uvicorn.run(
        "secmind.api:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=False,
    )
