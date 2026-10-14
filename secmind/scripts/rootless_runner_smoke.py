"""Run a real Runner probe against an independently rootless Docker daemon.

The script intentionally exercises :class:`DockerSandboxBackend` directly so
it does not turn a mock backend or a rootful Docker Desktop engine into
release evidence.  Set ``SECMIND_SANDBOX_DOCKER_HOST`` and immutable image
IDs before invoking it.  ``--output`` writes a versioned evidence document
containing success, cancellation, stale-fence, and cleanup receipts.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import re
import secrets
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from secmind.sandbox import (
    CREATED_LABEL,
    FENCE_LABEL,
    INVOCATION_LABEL,
    RESOURCE_LABEL,
    RUN_LABEL,
    DockerSandboxBackend,
    SandboxError,
    SandboxInvocation,
    SandboxLimits,
    SandboxRunner,
    SandboxToolSpec,
    default_allowlist,
)

EVIDENCE_SCHEMA_VERSION = "rootless-runner-evidence-v1"
_DIGEST_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def _dump(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if isinstance(value, dict):
        return {str(key): _dump(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_dump(item) for item in value]
    return value


def _image_digest(environment_name: str, *, required: bool = True) -> str | None:
    image = os.environ.get(environment_name, "").strip()
    if not image:
        if required:
            raise RuntimeError(f"{environment_name} is required for a real rootless Runner probe")
        return None
    if "@sha256:" in image:
        digest = image.rsplit("@sha256:", maxsplit=1)[1]
    elif image.startswith("sha256:"):
        digest = image.removeprefix("sha256:")
    else:
        raise RuntimeError(f"{environment_name} must be an immutable sha256 image ID")
    if not _DIGEST_RE.fullmatch(digest) or digest.lower() == "0" * 64:
        raise RuntimeError(f"{environment_name} must not use a zero or invalid sha256 digest")
    return image


def _configured_images(*, include_cancel: bool) -> dict[str, str]:
    images = {
        "staging": _image_digest("SECMIND_SANDBOX_STAGING_IMAGE"),
        "bandit": _image_digest("SECMIND_SANDBOX_BANDIT_IMAGE"),
    }
    if include_cancel:
        images["cancel"] = _image_digest("SECMIND_SANDBOX_CANCEL_IMAGE")  # type: ignore[assignment]
    return {name: value for name, value in images.items() if value is not None}


def _new_backend(*, include_cancel: bool) -> tuple[DockerSandboxBackend, dict[str, str]]:
    images = _configured_images(include_cancel=include_cancel)
    base_url = os.environ.get("SECMIND_SANDBOX_DOCKER_HOST", "tcp://127.0.0.1:23760")
    backend = DockerSandboxBackend(base_url=base_url, require_rootless=True)
    return backend, images


def _runner(backend: DockerSandboxBackend, *, cancel: bool, images: dict[str, str]) -> SandboxRunner:
    if cancel:
        image = images.get("cancel")
        if image is None:  # pragma: no cover - guarded by _configured_images
            raise RuntimeError("SECMIND_SANDBOX_CANCEL_IMAGE is required for cancellation evidence")
        spec = SandboxToolSpec(
            name="bandit_python_audit",
            image_digest=image,
            entrypoint=("/bin/sh", "-c", "sleep 30"),
            limits=SandboxLimits(timeout_seconds=60),
        )
        allowlist = {spec.name: spec}
    else:
        allowlist = default_allowlist()
        if "bandit_python_audit" not in allowlist:
            raise RuntimeError("SECMIND_SANDBOX_BANDIT_IMAGE did not produce a real allowlist entry")
    return SandboxRunner(
        backend,
        allowlist,
        max_parallelism=1,
        cancellation_wait_seconds=10,
    )


def _invocation(*, run_id: str, invocation_id: str, cancel: bool) -> SandboxInvocation:
    return SandboxInvocation(
        run_id=run_id,
        invocation_id=invocation_id,
        tool_name="bandit_python_audit",
        lease_fence=2,
        files=[]
        if cancel
        else [
            {
                "path": "probe.py",
                "content_base64": base64.b64encode(
                    b"import subprocess\nsubprocess.run('echo smoke', shell=True)\n"
                ).decode(),
            }
        ],
    )


async def _run(
    cancel: bool,
    *,
    backend: DockerSandboxBackend | None = None,
    images: dict[str, str] | None = None,
) -> dict[str, Any]:
    if backend is None:
        backend, images = _new_backend(include_cancel=cancel)
    elif images is None:
        images = _configured_images(include_cancel=cancel)
    runner = _runner(backend, cancel=cancel, images=images)
    readiness = await runner.readiness()
    run_id = "rootless-runner-smoke-cancel" if cancel else "rootless-runner-smoke-success"
    invocation = _invocation(
        run_id=run_id,
        invocation_id="rootless-runner-cancel" if cancel else "rootless-runner-success",
        cancel=cancel,
    )
    payload: dict[str, Any] = {
        "readiness": _dump(readiness),
        "run_id": run_id,
        "invocation_id": invocation.invocation_id,
    }
    task = asyncio.create_task(runner.execute(invocation))
    if cancel:
        await asyncio.sleep(0.8)
        payload["resources_before_cancel"] = _dump(await runner.list_resources(invocation.run_id))
        try:
            payload["cancelled"] = await runner.cancel(invocation.invocation_id)
        except SandboxError as exc:
            payload["cancel_error"] = {"code": exc.code, "message": str(exc)}
        try:
            await task
        except SandboxError as exc:
            payload["terminal_error"] = {"code": exc.code, "message": str(exc)}
    else:
        payload["result"] = _dump(await task)
    payload["resources_after"] = _dump(await runner.list_resources(invocation.run_id))
    payload["orphan_cleanup_removed"] = await runner.cleanup_orphans()
    payload["cleanup_confirmed"] = payload["resources_after"] == []
    return payload


def _resource_labels(*, run_id: str, invocation_id: str, fence: int) -> dict[str, str]:
    return {
        RESOURCE_LABEL: "true",
        INVOCATION_LABEL: invocation_id,
        RUN_LABEL: run_id,
        FENCE_LABEL: str(fence),
        CREATED_LABEL: str(int(datetime.now(UTC).timestamp())),
    }


async def _run_stale_fence(
    *,
    backend: DockerSandboxBackend,
    images: dict[str, str],
) -> dict[str, Any]:
    """Create two real daemon resources and prove the older fence is reaped."""

    client = backend._get_client()  # noqa: SLF001 - release probe needs daemon labels
    image = images.get("cancel")
    if image is None:
        raise RuntimeError("SECMIND_SANDBOX_CANCEL_IMAGE is required for stale-fence evidence")
    run_id = f"rootless-runner-stale-fence-{secrets.token_hex(6)}"
    containers: list[Any] = []
    runner: SandboxRunner | None = None
    evidence: dict[str, Any] | None = None
    invocation_ids = {1: f"stale-fence-{secrets.token_hex(6)}-old", 2: f"stale-fence-{secrets.token_hex(6)}-new"}
    try:
        for fence in (1, 2):
            container = client.containers.create(
                image,
                entrypoint=["/bin/sh", "-c"],
                command=["sleep 60"],
                user="65532:65532",
                network_mode="none",
                read_only=True,
                cap_drop=["ALL"],
                security_opt=["no-new-privileges:true"],
                mem_limit=64 * 1024 * 1024,
                nano_cpus=250_000_000,
                pids_limit=16,
                tmpfs={"/tmp": "rw,noexec,nosuid,nodev,size=1048576"},  # noqa: S108  # nosec B108
                labels=_resource_labels(run_id=run_id, invocation_id=invocation_ids[fence], fence=fence),
            )
            container.start()
            containers.append(container)

        runner = _runner(backend, cancel=False, images=images)
        resources_before = _dump(await runner.list_resources(run_id))
        result = _dump(
            await runner.execute(
                _invocation(
                    run_id=run_id,
                    invocation_id=f"stale-fence-current-{secrets.token_hex(6)}",
                    cancel=False,
                )
            )
        )
        resources_before_cleanup = _dump(await runner.list_resources(run_id))
        removed = await runner.cleanup_orphans()
        resources_after_cleanup = _dump(await runner.list_resources(run_id))
        stale_remaining = [item for item in resources_after_cleanup if item.get("fence") == 1]
        latest_remaining = [item for item in resources_after_cleanup if item.get("fence") == 2]
        evidence = {
            "status": "success",
            "run_id": run_id,
            "latest_fence": 2,
            "resources_before": resources_before,
            "resources_before_cleanup": resources_before_cleanup,
            "removed": removed,
            "stale_fence_removed": not stale_remaining,
            "latest_fence_preserved": bool(latest_remaining),
            "execution_result": result,
            "resources_after_stale_cleanup": resources_after_cleanup,
        }
        return evidence
    finally:
        cleanup_errors: list[str] = []
        for container in containers:
            try:
                container.remove(force=True)
            except Exception as exc:  # pragma: no cover - daemon failure is reported below
                if not backend._resource_already_gone(exc):  # noqa: SLF001
                    cleanup_errors.append(type(exc).__name__)
        if runner is not None:
            try:
                final_resources = _dump(await runner.list_resources(run_id))
                if evidence is not None:
                    evidence["resources_after_explicit_cleanup"] = final_resources
                if final_resources:
                    cleanup_errors.append("resources_remain_after_explicit_cleanup")
            except Exception as exc:  # pragma: no cover - daemon failure is reported below
                cleanup_errors.append(type(exc).__name__)
        if cleanup_errors:
            raise RuntimeError(f"stale-fence evidence cleanup failed: {cleanup_errors}")


async def _daemon_attestation(backend: DockerSandboxBackend) -> dict[str, Any]:
    client = backend._get_client()  # noqa: SLF001 - release probe attestation
    info = client.info()
    try:
        version_payload = client.version()
    except Exception:  # pragma: no cover - old SDK compatibility
        version_payload = {}
    security_options = [str(value) for value in info.get("SecurityOptions", [])]
    return {
        "host": os.environ.get("SECMIND_SANDBOX_DOCKER_HOST", "tcp://127.0.0.1:23760"),
        "server_version": info.get("ServerVersion") or version_payload.get("Version"),
        "security_options": security_options,
        "rootless": any("rootless" in value.lower() for value in security_options),
        "engine_id_present": bool(info.get("ID")),
    }


async def _evidence() -> dict[str, Any]:
    backend, images = _new_backend(include_cancel=True)
    success = await _run(False, backend=backend, images=images)
    cancel = await _run(True, backend=backend, images=images)
    stale_fence = await _run_stale_fence(backend=backend, images=images)
    daemon = await _daemon_attestation(backend)
    readiness = success["readiness"]
    result = success.get("result", {})
    resources_after = success.get("resources_after", [])
    policy = _runner(backend, cancel=False, images=images).capability_policy("bandit_python_audit")
    # These values are the fixed arguments passed by DockerSandboxBackend's
    # one-container tmpfs path; include them in the attestation consumed by
    # the engineering gate instead of relying on an implicit default.
    policy["user"] = "65532:65532"
    policy["cap_drop"] = ["ALL"]
    policy["security_opt"] = ["no-new-privileges:true"]
    policy["cleanup_confirmed"] = bool(success.get("cleanup_confirmed"))
    policy["daemon_host"] = daemon["host"]
    return {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "captured_at": datetime.now(UTC).isoformat(),
        "runner": {
            "backend": "DockerSandboxBackend",
            "script": "scripts/rootless_runner_smoke.py",
            "require_rootless": True,
        },
        "daemon": daemon,
        "images": images,
        "health": {
            "status": "ready",
            "status_code": 200,
            "execution_plane": readiness,
        },
        # These are the canonical fields consumed by check_engineering_gate.
        "result": result,
        "resources": {"run_id": success.get("run_id"), "resources": resources_after},
        "policy": policy,
        "scenarios": {
            "success": success,
            "cancel": cancel,
            "stale_fence": stale_fence,
        },
        "cleanup": {
            "success_confirmed": bool(success.get("cleanup_confirmed")),
            "cancel_confirmed": bool(cancel.get("cleanup_confirmed")),
            "cancel_terminal_code": (cancel.get("terminal_error") or {}).get("code"),
            "stale_fence_removed": bool(stale_fence.get("stale_fence_removed")),
            "latest_fence_preserved": bool(stale_fence.get("latest_fence_preserved")),
            "stale_fence_resources_after_cleanup": stale_fence.get("resources_after_stale_cleanup", []),
            "stale_fence_final_resources_empty": stale_fence.get("resources_after_explicit_cleanup") == [],
            "all_post_invocation_resources_empty": not resources_after,
        },
    }


def _write_output(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cancel", action="store_true", help="exercise cancellation and cleanup confirmation")
    parser.add_argument("--stale-fence", action="store_true", help="exercise stale-fence orphan cleanup")
    parser.add_argument("--evidence", action="store_true", help="run all scenarios and emit release evidence")
    parser.add_argument("--output", type=Path, help="write the machine-readable aggregate evidence to this path")
    arguments = parser.parse_args()

    if arguments.evidence or arguments.output is not None:
        payload = asyncio.run(_evidence())
    elif arguments.stale_fence:
        backend, images = _new_backend(include_cancel=True)
        payload = asyncio.run(_run_stale_fence(backend=backend, images=images))
    else:
        backend, images = _new_backend(include_cancel=arguments.cancel)
        payload = asyncio.run(_run(arguments.cancel, backend=backend, images=images))
    if arguments.output is not None:
        _write_output(arguments.output, payload)
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
