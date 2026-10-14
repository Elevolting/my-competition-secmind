from __future__ import annotations

import asyncio
import contextlib
import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from secmind.artifact_store import ContentAddressedArtifactStore
from secmind.capability import CapabilityError, CapabilityTicketVerifier, SqliteCapabilityReplayStore
from secmind.sandbox import (
    DockerSandboxBackend,
    SandboxError,
    SandboxInvocation,
    SandboxRunner,
    default_allowlist,
    invocation_input_sha256,
    token_matches,
)

logger = logging.getLogger(__name__)


class RequestBodyLimitMiddleware:
    """Reject oversized invocation bodies before FastAPI/Pydantic parse them."""

    def __init__(self, app: Any, *, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http" or scope.get("method") not in {"POST", "PUT", "PATCH"}:
            await self.app(scope, receive, send)
            return
        headers = dict(scope.get("headers", []))
        try:
            content_length = int(headers.get(b"content-length", b"0"))
        except ValueError:
            content_length = self.max_bytes + 1
        if content_length > self.max_bytes:
            await self._reject(send)
            return
        messages: list[dict[str, Any]] = []
        total = 0
        while True:
            message = await receive()
            messages.append(message)
            if message.get("type") != "http.request":
                break
            total += len(message.get("body", b""))
            if total > self.max_bytes:
                await self._reject(send)
                return
            if not message.get("more_body", False):
                break

        async def replay() -> dict[str, Any]:
            if messages:
                return messages.pop(0)
            return {"type": "http.request", "body": b"", "more_body": False}

        await self.app(scope, replay, send)

    @staticmethod
    async def _reject(send: Any) -> None:
        body = b'{"detail":"request body too large"}'
        await send(
            {
                "type": "http.response.start",
                "status": status.HTTP_413_CONTENT_TOO_LARGE,
                "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())],
            }
        )
        await send({"type": "http.response.body", "body": body})


def create_sandbox_app(
    runner: SandboxRunner,
    service_token: str | None = None,
    *,
    capability_verifier: CapabilityTicketVerifier | None = None,
    control_token: str | None = None,
    max_request_bytes: int = 96 * 1024 * 1024,
) -> FastAPI:
    bearer = HTTPBearer(auto_error=False)

    async def authenticate(  # noqa: B008
        credentials: HTTPAuthorizationCredentials | None = Depends(bearer),  # noqa: B008
    ) -> str:
        supplied = credentials.credentials if credentials and credentials.scheme.lower() == "bearer" else ""
        if capability_verifier is not None:
            if not supplied:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="capability ticket required")
            return supplied
        # Explicit test/development compatibility only; production construction below never enables it.
        if not service_token:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="runner capability verifier is not configured",
            )
        if not token_matches(service_token, supplied):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid runner token")
        return supplied

    async def authenticate_control(  # noqa: B008
        credentials: HTTPAuthorizationCredentials | None = Depends(bearer),  # noqa: B008
    ) -> None:
        supplied = credentials.credentials if credentials and credentials.scheme.lower() == "bearer" else ""
        if not control_token or not token_matches(control_token, supplied):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid runner control token")

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        await runner.cleanup_orphans()
        reaper_interval = max(10, int(os.getenv("SECMIND_SANDBOX_REAPER_INTERVAL_SECONDS", "60")))

        async def reap_periodically() -> None:
            while True:
                await asyncio.sleep(reaper_interval)
                try:
                    await runner.cleanup_orphans()
                except Exception:  # pragma: no cover - daemon failures are deployment-specific
                    # Keep the reaper alive and leave readiness/control-plane
                    # evidence to report the failure on the next explicit
                    # operation.  A transient Docker API error must not stop
                    # orphan cleanup forever.
                    logger.exception("sandbox orphan reaper failed")

        reaper = asyncio.create_task(reap_periodically(), name="sandbox-orphan-reaper")
        try:
            yield
        finally:
            reaper.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await reaper
            if capability_verifier is not None:
                capability_verifier.close()

    app = FastAPI(title="SecMind sandbox-runner", version="1.2", lifespan=lifespan)
    app.add_middleware(RequestBodyLimitMiddleware, max_bytes=max_request_bytes)

    @app.get("/health/live")
    async def live() -> dict[str, str]:
        return {"status": "ok", "schema_version": "1.2"}

    @app.get("/health")
    @app.get("/health/ready")
    async def health() -> dict[str, Any]:
        mode = "capability" if capability_verifier is not None else "development-token"
        try:
            execution_plane = await runner.readiness()
        except SandboxError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"status": "not_ready", "code": exc.code},
            ) from exc
        return {
            "status": "ready",
            "schema_version": "1.2",
            "authentication": mode,
            "execution_plane": execution_plane,
        }

    @app.post("/internal/v1/invocations")
    async def invoke(request: SandboxInvocation, credential: str = Depends(authenticate)):  # noqa: B008
        try:
            if capability_verifier is not None:
                capability_verifier.verify_and_consume(
                    credential,
                    invocation_id=request.invocation_id,
                    tool_name=request.tool_name,
                    input_sha256=invocation_input_sha256(request),
                    fence=request.lease_fence,
                    policy=runner.capability_policy(request.tool_name),
                )
            return await runner.execute(request)
        except CapabilityError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"code": exc.code, "message": str(exc)},
            ) from exc
        except SandboxError as exc:
            code = status.HTTP_429_TOO_MANY_REQUESTS if exc.code in {"RUNNER_BUSY", "TOOL_BUSY"} else 422
            raise HTTPException(status_code=code, detail={"code": exc.code, "message": str(exc)}) from exc

    @app.delete("/internal/v1/invocations/{invocation_id}")
    async def cancel_invocation(
        invocation_id: str,
        _: None = Depends(authenticate_control),  # noqa: B008
    ) -> dict[str, Any]:
        if not invocation_id or len(invocation_id) > 128:
            raise HTTPException(status_code=422, detail="invalid invocation id")
        try:
            cancelled = await runner.cancel(invocation_id)
        except SandboxError as exc:
            # A cancellation acknowledgement is only meaningful once the
            # Runner has observed an empty resource inventory.  Surface an
            # explicit retryable control-plane failure instead of returning a
            # misleading 200 or an untyped 500.
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": exc.code, "message": str(exc)},
            ) from exc
        return {"schema_version": "1.2", "invocation_id": invocation_id, "cancelled": cancelled}

    @app.get("/internal/v1/resources")
    async def list_resources(
        run_id: str,
        _: None = Depends(authenticate_control),  # noqa: B008
    ) -> dict[str, Any]:
        try:
            resources = await runner.list_resources(run_id)
        except SandboxError as exc:
            raise HTTPException(status_code=422, detail={"code": exc.code, "message": str(exc)}) from exc
        return {
            "schema_version": "1.2",
            "run_id": run_id,
            "resources": [item.model_dump(mode="json") for item in resources],
        }

    return app


def _load_public_key() -> CapabilityTicketVerifier | None:
    key_file = os.getenv("SECMIND_SANDBOX_TICKET_PUBLIC_KEY_FILE", "")
    if not key_file:
        return None
    replay_path = Path(os.getenv("SECMIND_SANDBOX_REPLAY_DB", "/var/lib/secmind/state/capability-replay.db"))
    return CapabilityTicketVerifier.from_pem(
        Path(key_file).read_bytes(),
        replay_store=SqliteCapabilityReplayStore(replay_path),
    )


def create_production_app() -> FastAPI:
    environment = os.getenv("SECMIND_ENV", "development").lower()
    strict = environment in {"production", "competition"}
    if strict and not os.getenv("SECMIND_SANDBOX_TICKET_PUBLIC_KEY_FILE", ""):
        raise RuntimeError("production sandbox requires an Ed25519 capability public key")
    if strict and not os.getenv("SECMIND_SANDBOX_STAGING_IMAGE", ""):
        raise RuntimeError("production sandbox requires a pinned staging helper image")
    if strict and not os.getenv("SECMIND_SANDBOX_BANDIT_IMAGE", ""):
        raise RuntimeError("production sandbox requires pinned tool images")
    control_token = os.getenv("SECMIND_SANDBOX_CONTROL_TOKEN", "")
    if strict and not control_token:
        raise RuntimeError("production sandbox requires a dedicated control token")
    docker_host = os.getenv("SECMIND_SANDBOX_DOCKER_HOST", "")
    if strict and (not docker_host or "var/run/docker.sock" in docker_host.replace("\\", "/")):
        raise RuntimeError("production sandbox requires a separate rootless Docker daemon")
    normalized_docker_host = docker_host.replace("\\", "/").lower()
    if strict and not (
        normalized_docker_host.startswith("unix://")
        and ("/run/user/" in normalized_docker_host or "rootless" in normalized_docker_host)
    ):
        raise RuntimeError("production sandbox requires a rootless per-user Docker socket")
    # A socket path alone is not an auditable claim that the daemon is
    # dedicated.  Competition deployments must explicitly attest that the
    # mounted socket belongs to a separate rootless dockerd instance; the
    # backend still verifies SecurityOptions at readiness time.
    if strict and os.getenv("SECMIND_SANDBOX_DEDICATED_ROOTLESS", "").strip().lower() != "true":
        raise RuntimeError("production sandbox requires an explicitly attested dedicated rootless Docker daemon")
    default_artifact_root = "/var/lib/secmind/artifacts" if strict else "./data/sandbox-artifacts"
    artifact_root = Path(os.getenv("SECMIND_ARTIFACT_ROOT", default_artifact_root))
    runner = SandboxRunner(
        DockerSandboxBackend(base_url=docker_host or None, require_rootless=strict),
        default_allowlist(),
        artifact_store=ContentAddressedArtifactStore(artifact_root),
        max_parallelism=int(os.getenv("SECMIND_SANDBOX_MAX_PARALLELISM", "4")),
    )
    return create_sandbox_app(
        runner,
        service_token=None if strict else os.getenv("SECMIND_SANDBOX_TOKEN", "") or None,
        control_token=control_token or os.getenv("SECMIND_SANDBOX_TOKEN", "") or None,
        capability_verifier=_load_public_key(),
        max_request_bytes=int(os.getenv("SECMIND_SANDBOX_MAX_REQUEST_BYTES", str(96 * 1024 * 1024))),
    )


app = create_production_app()
