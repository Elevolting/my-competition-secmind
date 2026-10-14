from __future__ import annotations

import asyncio
import base64
import hashlib
import importlib
import io
import json
import logging
import os
import posixpath
import secrets
import shlex
import stat
import tarfile
import threading
import time
import unicodedata
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field, model_validator

from secmind.artifact_store import ArtifactStoreError, ContentAddressedArtifactStore

SANDBOX_SCHEMA_VERSION = "1.1"
RESOURCE_LABEL = "io.secmind.sandbox"
INVOCATION_LABEL = "io.secmind.invocation"
RUN_LABEL = "io.secmind.run"
FENCE_LABEL = "io.secmind.fence"
CREATED_LABEL = "io.secmind.created_epoch"
MAX_PATH_DEPTH = 32
MAX_ARTIFACTS = 128
MAX_TIMEOUT_SECONDS = 3_600
MAX_CPU_CORES = 16.0
MAX_MEMORY_BYTES = 16 * 1024 * 1024 * 1024
MAX_PIDS = 4_096
MAX_TMPFS_BYTES = 16 * 1024 * 1024 * 1024
MAX_INPUT_BYTES = 512 * 1024 * 1024
MAX_OUTPUT_BYTES = 512 * 1024 * 1024
MAX_LOG_TAIL_BYTES = 16 * 1024 * 1024
MAX_PARALLELISM = 64
MAX_CANCELLATION_WAIT_SECONDS = 60
DEFAULT_CANCELLATION_WAIT_SECONDS = 15
MAX_TRACKED_INVOCATIONS = 16_384

logger = logging.getLogger(__name__)


def validate_relative_path(value: str, *, description: str) -> str:
    """Require canonical NFC POSIX paths without control characters or traversal."""

    if "\\" in value:
        raise ValueError(f"{description} must use POSIX separators")
    if unicodedata.normalize("NFC", value) != value:
        raise ValueError(f"{description} must use Unicode NFC normalization")
    if any(unicodedata.category(char).startswith("C") for char in value):
        raise ValueError(f"{description} must not contain control characters")
    normalized = posixpath.normpath(value.replace("\\", "/"))
    path = PurePosixPath(normalized)
    if normalized in {"", "."} or path.is_absolute() or ".." in path.parts:
        raise ValueError(f"{description} must be a safe relative POSIX path")
    if normalized != value.replace("\\", "/"):
        raise ValueError(f"{description} must already be normalized")
    if len(path.parts) > MAX_PATH_DEPTH:
        raise ValueError(f"{description} exceeds maximum path depth")
    return normalized


class SandboxError(RuntimeError):
    """A typed, safe-to-report sandbox failure."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class SandboxInputFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str = Field(min_length=1, max_length=1024)
    content_base64: str = Field(max_length=16 * 1024 * 1024)

    @model_validator(mode="after")
    def validate_path_and_content(self) -> SandboxInputFile:
        validate_relative_path(self.path, description="input file path")
        try:
            base64.b64decode(self.content_base64, validate=True)
        except ValueError as exc:
            raise ValueError("content_base64 is invalid") from exc
        return self

    def decoded(self) -> bytes:
        return base64.b64decode(self.content_base64, validate=True)


def collect_sandbox_input_files(
    target: Path,
    *,
    max_files: int = 2_000,
    max_file_bytes: int = 10 * 1024 * 1024,
    max_total_bytes: int = 64 * 1024 * 1024,
) -> list[SandboxInputFile]:
    """Build one deterministic, bounded runner payload for an approved target."""

    root = target if target.is_dir() else target.parent
    if target.is_file():
        paths = [target]
    else:
        paths = []
        for path in target.rglob("*"):
            if path.is_file():
                paths.append(path)
                if len(paths) > max_files:
                    raise ValueError("Sandbox input contains too many files")
        paths.sort()

    files: list[SandboxInputFile] = []
    total = 0
    for path in paths:
        if path.is_symlink():
            raise ValueError("Sandbox inputs cannot contain symbolic links")
        remaining = min(max_file_bytes, max_total_bytes - total)
        content = _read_bounded_regular_file(path, remaining)
        total += len(content)
        files.append(
            SandboxInputFile(
                path=path.relative_to(root).as_posix(),
                content_base64=base64.b64encode(content).decode(),
            )
        )
    return files


def _read_bounded_regular_file(path: Path, max_bytes: int) -> bytes:
    """Read at most max_bytes without trusting a racy path stat or allocating unbounded input."""

    if max_bytes < 0:
        raise ValueError("Sandbox input exceeds configured limits")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError("Sandbox input is not a readable regular file") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("Sandbox inputs must be regular files")
        if metadata.st_size > max_bytes:
            raise ValueError("Sandbox input exceeds configured limits")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            content = stream.read(max_bytes + 1)
        if len(content) > max_bytes:
            raise ValueError("Sandbox input exceeds configured limits")
        return content
    finally:
        os.close(descriptor)


class SandboxInvocation(BaseModel):
    """Runner input. It deliberately has no image, command, host path, or privilege fields."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = SANDBOX_SCHEMA_VERSION
    run_id: str = Field(default="unscoped", min_length=1, max_length=256)
    invocation_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
    tool_name: str = Field(pattern=r"^[a-z][a-z0-9_]{1,63}$")
    lease_fence: int = Field(default=0, ge=0)
    files: list[SandboxInputFile] = Field(default_factory=list, max_length=2_000)

    @model_validator(mode="after")
    def reject_duplicate_paths(self) -> SandboxInvocation:
        paths = [unicodedata.normalize("NFC", item.path) for item in self.files]
        if len(paths) != len(set(paths)):
            raise ValueError("duplicate input file path")
        return self


class SandboxLog(BaseModel):
    tail: str = ""
    sha256: str
    bytes_seen: int = 0
    truncated: bool = False


class SandboxArtifact(BaseModel):
    artifact_id: str
    relative_path: str
    sha256: str
    size_bytes: int = Field(ge=0, le=MAX_OUTPUT_BYTES)
    media_type: str = "application/octet-stream"
    content_base64: str | None = None


class SandboxResult(BaseModel):
    schema_version: str = SANDBOX_SCHEMA_VERSION
    invocation_id: str
    status: str
    exit_code: int | None = None
    data: dict[str, Any] = Field(default_factory=dict)
    summary: str = ""
    artifacts: list[SandboxArtifact] = Field(default_factory=list, max_length=MAX_ARTIFACTS)
    logs: SandboxLog
    duration_ms: int = 0
    error_code: str | None = None
    error_message: str | None = None
    # A Docker result is only released after every container and volume has
    # been removed successfully.  Other backends may leave this false when
    # they cannot provide an equivalent receipt.
    cleanup_confirmed: bool = False


class SandboxResourceView(BaseModel):
    """Safe control-plane view of one invocation-owned sandbox resource."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = SANDBOX_SCHEMA_VERSION
    run_id: str
    resource_id: str
    invocation_id: str
    fence: int = Field(ge=0)
    active: bool = True


@dataclass(frozen=True)
class SandboxLimits:
    timeout_seconds: int = 120
    cpu_cores: float = 1.0
    memory_bytes: int = 512 * 1024 * 1024
    pids_limit: int = 64
    tmpfs_bytes: int = 64 * 1024 * 1024
    max_input_bytes: int = 64 * 1024 * 1024
    max_output_bytes: int = 16 * 1024 * 1024
    max_log_tail_bytes: int = 16 * 1024
    max_parallelism: int = 2
    max_artifacts: int = MAX_ARTIFACTS

    def __post_init__(self) -> None:
        if not 1 <= self.timeout_seconds <= MAX_TIMEOUT_SECONDS:
            raise ValueError("sandbox timeout is outside the configured safety bounds")
        if not 0 < self.cpu_cores <= MAX_CPU_CORES:
            raise ValueError("sandbox CPU limit is outside the configured safety bounds")
        if not 1 <= self.memory_bytes <= MAX_MEMORY_BYTES:
            raise ValueError("sandbox memory limit is outside the configured safety bounds")
        if not 1 <= self.pids_limit <= MAX_PIDS:
            raise ValueError("sandbox PID limit is outside the configured safety bounds")
        if not 1 <= self.tmpfs_bytes <= MAX_TMPFS_BYTES:
            raise ValueError("sandbox tmpfs limit is outside the configured safety bounds")
        if not 1 <= self.max_input_bytes <= MAX_INPUT_BYTES:
            raise ValueError("sandbox input limit is outside the configured safety bounds")
        if not 1 <= self.max_output_bytes <= MAX_OUTPUT_BYTES:
            raise ValueError("sandbox output limit is outside the configured safety bounds")
        if not 1 <= self.max_log_tail_bytes <= MAX_LOG_TAIL_BYTES:
            raise ValueError("sandbox log limit is outside the configured safety bounds")
        if not 1 <= self.max_parallelism <= MAX_PARALLELISM:
            raise ValueError("sandbox parallelism is outside the configured safety bounds")
        if not 1 <= self.max_artifacts <= MAX_ARTIFACTS:
            raise ValueError("sandbox artifact count is outside the configured safety bounds")


@dataclass(frozen=True)
class SandboxToolSpec:
    name: str
    image_digest: str
    entrypoint: tuple[str, ...]
    limits: SandboxLimits = field(default_factory=SandboxLimits)

    def __post_init__(self) -> None:
        if "@sha256:" in self.image_digest:
            digest = self.image_digest.rsplit("@sha256:", maxsplit=1)[1]
        elif self.image_digest.startswith("sha256:"):
            digest = self.image_digest.removeprefix("sha256:")
        else:
            raise ValueError("sandbox tool image must be pinned by sha256 digest or immutable image ID")
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest.lower()):
            raise ValueError("invalid tool image sha256 digest")
        if not self.entrypoint or any(not item for item in self.entrypoint):
            raise ValueError("a fixed entrypoint is required")

    def capability_policy(self) -> dict[str, Any]:
        return {
            "cpu_cores": self.limits.cpu_cores,
            "image_digest": self.image_digest,
            "memory_bytes": self.limits.memory_bytes,
            "max_artifacts": self.limits.max_artifacts,
            "max_input_bytes": self.limits.max_input_bytes,
            "max_log_tail_bytes": self.limits.max_log_tail_bytes,
            "max_output_bytes": self.limits.max_output_bytes,
            "network": "none",
            "pids_limit": self.limits.pids_limit,
            "read_only": True,
            "tmpfs_bytes": self.limits.tmpfs_bytes,
            "timeout_seconds": self.limits.timeout_seconds,
            # The production backend uses per-container tmpfs mounts.  A
            # named local-tmpfs volume is not portable: several rootless
            # daemons create a fresh tmpfs for each container attachment.
            # Input is populated once by the runner and made read-only before
            # the fixed tool entrypoint is executed; output remains a bounded
            # writable tmpfs owned by that invocation only.
            "volume_limit_mode": "container-tmpfs",
            "input_volume_bytes": self.limits.max_input_bytes,
            "output_volume_bytes": self.limits.max_output_bytes,
            "input_mount_mode": "write-once-read-only",
            "output_mount_mode": "bounded-writable",
        }


@dataclass(frozen=True)
class SandboxStagingSpec:
    image_digest: str
    entrypoint: tuple[str, ...] = ("/opt/secmind-stage",)
    memory_bytes: int = 64 * 1024 * 1024
    cpu_cores: float = 0.25
    pids_limit: int = 16

    def __post_init__(self) -> None:
        SandboxToolSpec(name="staging_helper", image_digest=self.image_digest, entrypoint=self.entrypoint)
        SandboxLimits(cpu_cores=self.cpu_cores, memory_bytes=self.memory_bytes, pids_limit=self.pids_limit)


class SandboxBackend(Protocol):
    async def execute(self, spec: SandboxToolSpec, invocation: SandboxInvocation) -> SandboxResult: ...

    async def cancel(self, invocation_id: str) -> bool: ...

    async def cleanup_orphans(
        self,
        *,
        active_invocations: tuple[SandboxInvocation, ...] = (),
        latest_fences: dict[str, int] | None = None,
    ) -> int: ...

    async def list_resources(self, run_id: str) -> list[SandboxResourceView]: ...


class SandboxRunner:
    def __init__(
        self,
        backend: SandboxBackend,
        allowlist: dict[str, SandboxToolSpec],
        *,
        artifact_store: ContentAddressedArtifactStore | None = None,
        max_parallelism: int = 4,
        cancellation_wait_seconds: float = DEFAULT_CANCELLATION_WAIT_SECONDS,
    ) -> None:
        if not 1 <= max_parallelism <= MAX_PARALLELISM:
            raise ValueError("runner max_parallelism is outside the configured safety bounds")
        if not 0 < cancellation_wait_seconds <= MAX_CANCELLATION_WAIT_SECONDS:
            raise ValueError("runner cancellation wait is outside the configured safety bounds")
        self._backend = backend
        self._allowlist = dict(allowlist)
        self._artifact_store = artifact_store
        self._cancellation_wait_seconds = cancellation_wait_seconds
        self._global_slots = asyncio.Semaphore(max_parallelism)
        self._tool_slots = {
            name: asyncio.Semaphore(spec.limits.max_parallelism) for name, spec in self._allowlist.items()
        }
        self._active_invocations: dict[str, SandboxInvocation] = {}
        self._cleanup_unconfirmed: dict[str, SandboxInvocation] = {}
        self._cancel_requested: set[str] = set()
        # A completion event lets the control plane wait for the worker's
        # finally block.  Returning from DELETE immediately after asking the
        # backend to stop is not a cleanup receipt: the worker may still be
        # creating volumes or may still publish a late result.
        self._completion_events: dict[str, asyncio.Event] = {}
        self._run_fences: dict[str, int] = {}
        self._terminal_invocations: dict[str, tuple[str, int]] = {}
        self._invocation_lock = asyncio.Lock()

    async def execute(self, invocation: SandboxInvocation) -> SandboxResult:
        spec = self._allowlist.get(invocation.tool_name)
        if spec is None:
            raise SandboxError("TOOL_NOT_ALLOWLISTED", "tool is not registered in the runner allowlist")
        input_size = sum(len(item.decoded()) for item in invocation.files)
        if input_size > spec.limits.max_input_bytes:
            raise SandboxError("INPUT_TOO_LARGE", "sandbox input exceeds the configured limit")
        global_acquired = await self._try_acquire(self._global_slots)
        if not global_acquired:
            raise SandboxError("RUNNER_BUSY", "runner concurrency limit reached")
        tool_slot = self._tool_slots[invocation.tool_name]
        tool_acquired = await self._try_acquire(tool_slot)
        if not tool_acquired:
            self._global_slots.release()
            raise SandboxError("TOOL_BUSY", "tool concurrency limit reached")
        registered = False
        cleanup_confirmed = False
        completion_event: asyncio.Event | None = None
        try:
            async with self._invocation_lock:
                if invocation.invocation_id in self._cancel_requested:
                    raise SandboxError("SANDBOX_CANCELLED", "sandbox invocation was cancelled before start")
                if invocation.invocation_id in self._active_invocations:
                    raise SandboxError("INVOCATION_BUSY", "sandbox invocation is already running")
                terminal = self._terminal_invocations.get(invocation.invocation_id)
                if terminal is not None:
                    terminal_run, terminal_fence = terminal
                    if terminal_run != invocation.run_id or invocation.lease_fence <= terminal_fence:
                        raise SandboxError(
                            "INVOCATION_REPLAYED",
                            "sandbox invocation has already reached a terminal state",
                        )
                latest_fence = self._run_fences.get(invocation.run_id)
                if latest_fence is not None and invocation.lease_fence < latest_fence:
                    raise SandboxError("STALE_FENCE", "sandbox invocation lease fence is stale")
                self._run_fences[invocation.run_id] = max(invocation.lease_fence, latest_fence or 0)
                if len(self._run_fences) > MAX_TRACKED_INVOCATIONS:
                    active_runs = {item.run_id for item in self._active_invocations.values()}
                    for candidate in self._run_fences:
                        if candidate not in active_runs:
                            self._run_fences.pop(candidate)
                            break
                self._active_invocations[invocation.invocation_id] = invocation
                completion_event = asyncio.Event()
                self._completion_events[invocation.invocation_id] = completion_event
                registered = True
            try:
                result = await self._backend.execute(spec, invocation)
                if result.invocation_id != invocation.invocation_id:
                    raise SandboxError(
                        "RESULT_INVOCATION_MISMATCH",
                        "sandbox backend returned a result for a different invocation",
                    )
                cleanup_confirmed = result.cleanup_confirmed
                if not cleanup_confirmed:
                    raise SandboxError(
                        "RESOURCE_CLEANUP_FAILED",
                        "sandbox backend did not confirm resource cleanup",
                    )
                # Treat the backend receipt as provisional until the durable
                # inventory has been queried successfully and is empty.
                cleanup_confirmed = False
                remaining = await self._backend_resources(invocation.run_id)
                if any(item.invocation_id == invocation.invocation_id for item in remaining):
                    raise SandboxError(
                        "RESOURCE_CLEANUP_FAILED",
                        "sandbox backend still reports invocation resources after execution",
                    )
                cleanup_confirmed = True
            except SandboxError as exc:
                cleanup_confirmed = exc.code != "RESOURCE_CLEANUP_FAILED"
                raise
            async with self._invocation_lock:
                cancelled = invocation.invocation_id in self._cancel_requested
                stale = self._run_fences.get(invocation.run_id, invocation.lease_fence) != invocation.lease_fence
            if cancelled:
                raise SandboxError("SANDBOX_CANCELLED", "sandbox invocation was cancelled")
            if stale:
                raise SandboxError("STALE_FENCE", "sandbox result belongs to a superseded lease fence")
            persisted = self._persist_artifacts(result, limits=spec.limits)
            # A newer fence can be claimed while artifacts are being copied to
            # durable storage.  Re-check immediately before exposing the
            # result; a stale result must never become the current answer.
            async with self._invocation_lock:
                if invocation.invocation_id in self._cancel_requested:
                    raise SandboxError("SANDBOX_CANCELLED", "sandbox invocation was cancelled")
                if self._run_fences.get(invocation.run_id, invocation.lease_fence) != invocation.lease_fence:
                    raise SandboxError("STALE_FENCE", "sandbox result belongs to a superseded lease fence")
            return persisted
        finally:
            async with self._invocation_lock:
                self._active_invocations.pop(invocation.invocation_id, None)
                self._completion_events.pop(invocation.invocation_id, None)
                if registered:
                    self._terminal_invocations[invocation.invocation_id] = (
                        invocation.run_id,
                        invocation.lease_fence,
                    )
                    if len(self._terminal_invocations) > MAX_TRACKED_INVOCATIONS:
                        self._terminal_invocations.pop(next(iter(self._terminal_invocations)))
                if not registered or cleanup_confirmed:
                    self._cleanup_unconfirmed.pop(invocation.invocation_id, None)
                else:
                    self._cleanup_unconfirmed[invocation.invocation_id] = invocation
                if completion_event is not None:
                    completion_event.set()
            tool_slot.release()
            self._global_slots.release()

    @staticmethod
    async def _try_acquire(semaphore: asyncio.Semaphore) -> bool:
        try:
            await asyncio.wait_for(semaphore.acquire(), timeout=0.01)
        except TimeoutError:
            return False
        return True

    def _persist_artifacts(self, result: SandboxResult, *, limits: SandboxLimits | None = None) -> SandboxResult:
        limits = limits or SandboxLimits()
        if len(result.artifacts) > limits.max_artifacts:
            raise SandboxError("TOO_MANY_ARTIFACTS", "sandbox produced too many artifacts")
        declared_total = sum(max(0, artifact.size_bytes) for artifact in result.artifacts)
        if declared_total > limits.max_output_bytes:
            raise SandboxError("OUTPUT_TOO_LARGE", "sandbox artifacts exceed the configured total limit")
        if self._artifact_store is None or not result.artifacts:
            return result
        persisted: list[SandboxArtifact] = []
        observed_total = 0
        for artifact in result.artifacts:
            if artifact.content_base64 is None:
                raise SandboxError("ARTIFACT_CONTENT_MISSING", "runner artifact content is unavailable")
            try:
                content = base64.b64decode(artifact.content_base64, validate=True)
                observed_total += len(content)
                if observed_total > limits.max_output_bytes:
                    raise SandboxError("OUTPUT_TOO_LARGE", "sandbox artifacts exceed the configured total limit")
                if len(content) != artifact.size_bytes:
                    raise SandboxError("ARTIFACT_VERIFICATION_FAILED", "runner artifact size does not match content")
                stored = self._artifact_store.put(
                    content,
                    expected_sha256=artifact.sha256,
                    media_type=artifact.media_type,
                )
            except SandboxError:
                raise
            except (ValueError, ArtifactStoreError) as exc:
                raise SandboxError("ARTIFACT_VERIFICATION_FAILED", "runner artifact verification failed") from exc
            persisted.append(
                artifact.model_copy(
                    update={
                        "artifact_id": stored.artifact_id,
                        "relative_path": stored.storage_ref,
                        "sha256": stored.sha256,
                        "size_bytes": stored.size_bytes,
                        "content_base64": None,
                    }
                )
            )
        return result.model_copy(update={"artifacts": persisted})

    async def cleanup_orphans(self) -> int:
        async with self._invocation_lock:
            active = tuple(self._active_invocations.values())
            latest_fences = dict(self._run_fences)
        cleanup = self._backend.cleanup_orphans
        # New backends receive the in-process active/fence view so a long
        # running invocation is not reaped merely because it crossed the TTL,
        # while an older fenced resource is reaped immediately.  Keep the
        # no-argument fallback for contract-test backends.
        try:
            removed = await cleanup(active_invocations=active, latest_fences=latest_fences)
        except TypeError:
            removed = await cleanup()
        # Reconcile retained failure receipts with the durable backend registry.
        for run_id in {item.run_id for item in self._cleanup_unconfirmed.values()}:
            remaining = await self._backend_resources(run_id)
            remaining_ids = {item.invocation_id for item in remaining}
            async with self._invocation_lock:
                for invocation_id, invocation in list(self._cleanup_unconfirmed.items()):
                    if invocation.run_id == run_id and invocation_id not in remaining_ids:
                        self._cleanup_unconfirmed.pop(invocation_id, None)
        return removed

    async def list_resources(self, run_id: str) -> list[SandboxResourceView]:
        if not run_id or len(run_id) > 256:
            raise SandboxError("INVALID_RUN_ID", "sandbox run id is invalid")
        durable = await self._backend_resources(run_id)
        durable_invocations = {item.invocation_id for item in durable}
        async with self._invocation_lock:
            virtual = [
                SandboxResourceView(
                    run_id=item.run_id,
                    resource_id=f"invocation:{item.invocation_id}",
                    invocation_id=item.invocation_id,
                    fence=item.lease_fence,
                    active=True,
                )
                for item in (*self._active_invocations.values(), *self._cleanup_unconfirmed.values())
                if item.run_id == run_id and item.invocation_id not in durable_invocations
            ]
        return sorted(
            [*durable, *virtual],
            key=lambda item: (item.invocation_id, item.resource_id),
        )

    async def _backend_resources(self, run_id: str) -> list[SandboxResourceView]:
        listing = getattr(self._backend, "list_resources", None)
        if not callable(listing):
            return []
        resources = await listing(run_id)
        if len(resources) > 10_000:
            raise SandboxError("RESOURCE_LIST_TOO_LARGE", "runner resource registry exceeds its safety bound")
        validated = [SandboxResourceView.model_validate(item) for item in resources]
        if any(item.run_id != run_id for item in validated):
            raise SandboxError("RESOURCE_SCOPE_VIOLATION", "runner returned a resource outside the requested run")
        return validated

    async def cancel(self, invocation_id: str) -> bool:
        if not invocation_id or len(invocation_id) > 128:
            raise SandboxError("INVALID_INVOCATION_ID", "sandbox invocation id is invalid")
        async with self._invocation_lock:
            if len(self._cancel_requested) >= 4096:
                self._cancel_requested.pop()
            self._cancel_requested.add(invocation_id)
            active = invocation_id in self._active_invocations
            completion_event = self._completion_events.get(invocation_id)
            known_unconfirmed = invocation_id in self._cleanup_unconfirmed
        backend_error: SandboxError | None = None
        try:
            cancelled = await self._backend.cancel(invocation_id)
        except SandboxError as exc:
            cancelled = False
            backend_error = exc
        if completion_event is not None:
            try:
                await asyncio.wait_for(asyncio.shield(completion_event.wait()), self._cancellation_wait_seconds)
            except TimeoutError as exc:
                raise SandboxError(
                    "RESOURCE_CLEANUP_FAILED",
                    "sandbox cancellation did not finish resource cleanup before the deadline",
                ) from exc
        # A backend's positive delete response only means that its delete API
        # accepted the request.  Confirm the durable resource inventory is
        # empty before acknowledging cancellation to the caller.
        if active or known_unconfirmed or cancelled:
            try:
                deadline = time.monotonic() + self._cancellation_wait_seconds
                while True:
                    remaining = [item for item in await self._backend_resources_for_invocation(invocation_id)]
                    if not remaining:
                        break
                    if time.monotonic() >= deadline:
                        raise SandboxError(
                            "RESOURCE_CLEANUP_FAILED",
                            "sandbox cancellation left resources behind",
                        )
                    await asyncio.sleep(0.05)
            except SandboxError:
                raise
            except (AttributeError, NotImplementedError) as exc:
                raise SandboxError(
                    "RESOURCE_CLEANUP_UNCONFIRMED",
                    "sandbox backend cannot confirm cancellation cleanup",
                ) from exc
        if backend_error is not None:
            raise backend_error
        # A negative backend answer is still useful: if no resources existed,
        # the request remains recorded and a late execute is denied before it
        # can create a container or volume.
        return cancelled or active

    async def _backend_resources_for_invocation(self, invocation_id: str) -> list[SandboxResourceView]:
        listing = getattr(self._backend, "list_resources", None)
        if not callable(listing):
            raise NotImplementedError("backend does not expose a resource inventory")
        # Resource listing is scoped by run, but cancellation only carries an
        # invocation id.  Inspect the known invocation first, then use the
        # backend's broad inventory only when the invocation was active.
        async with self._invocation_lock:
            known = self._active_invocations.get(invocation_id) or self._cleanup_unconfirmed.get(invocation_id)
            terminal = self._terminal_invocations.get(invocation_id)
        if known is not None:
            resources = await self._backend_resources(known.run_id)
            return [item for item in resources if item.invocation_id == invocation_id]
        if terminal is not None:
            resources = await self._backend_resources(terminal[0])
            return [item for item in resources if item.invocation_id == invocation_id]
        # An unknown invocation has no safe run scope to query.
        return []

    async def readiness(self) -> dict[str, Any]:
        """Probe the execution plane without accepting a tool invocation.

        Backends used only by unit tests may omit the probe.  The production
        Docker backend implements it and verifies both the daemon security
        mode and every immutable image in the active allowlist.
        """

        probe = getattr(self._backend, "readiness", None)
        if not callable(probe):
            return {"backend": type(self._backend).__name__, "tools": len(self._allowlist)}
        status = await probe(tuple(self._allowlist.values()))
        if isinstance(self._backend, DockerSandboxBackend):
            # The Docker backend proves bounded per-container tmpfs mounts at
            # readiness.  Include that fact so a release gate cannot mistake
            # post-hoc output truncation for a disk quota.
            status = {
                **status,
                "volume_limit_mode": "container-tmpfs",
                "dedicated_rootless": bool(self._backend._require_rootless),  # noqa: SLF001
            }
        return status

    def capability_policy(self, tool_name: str) -> dict[str, Any]:
        spec = self._allowlist.get(tool_name)
        if spec is None:
            raise SandboxError("TOOL_NOT_ALLOWLISTED", "tool is not registered in the runner allowlist")
        return spec.capability_policy()


class MockSandboxBackend:
    """A Docker-free backend for contract tests and local development."""

    def __init__(self, result_data: dict[str, Any] | None = None) -> None:
        self.result_data = result_data or {"findings": []}
        self.calls: list[tuple[SandboxToolSpec, SandboxInvocation]] = []
        self.cleanup_calls = 0
        self.cancelled: list[str] = []

    async def execute(self, spec: SandboxToolSpec, invocation: SandboxInvocation) -> SandboxResult:
        self.calls.append((spec, invocation))
        log_bytes = b"mock sandbox execution"
        return SandboxResult(
            invocation_id=invocation.invocation_id,
            status="success",
            exit_code=0,
            data=self.result_data,
            summary=f"{spec.name} completed in mock sandbox",
            logs=SandboxLog(
                tail=log_bytes.decode(),
                sha256=hashlib.sha256(log_bytes).hexdigest(),
                bytes_seen=len(log_bytes),
            ),
            cleanup_confirmed=True,
        )

    async def cleanup_orphans(
        self,
        *,
        active_invocations: tuple[SandboxInvocation, ...] = (),
        latest_fences: dict[str, int] | None = None,
    ) -> int:
        del active_invocations, latest_fences
        self.cleanup_calls += 1
        return 0

    async def list_resources(self, run_id: str) -> list[SandboxResourceView]:
        del run_id
        return []

    async def cancel(self, invocation_id: str) -> bool:
        self.cancelled.append(invocation_id)
        return True

    async def readiness(self, specs: tuple[SandboxToolSpec, ...]) -> dict[str, Any]:
        return {"backend": "mock", "daemon": "not_required", "images": len(specs), "rootless": False}


class DockerSandboxBackend:
    """Docker SDK backend. The Docker module is imported lazily for non-Docker hosts."""

    def __init__(
        self,
        client: Any | None = None,
        orphan_ttl_seconds: int = 900,
        staging_spec: SandboxStagingSpec | None = None,
        *,
        base_url: str | None = None,
        require_rootless: bool = False,
    ) -> None:
        self._client = client
        self._orphan_ttl_seconds = orphan_ttl_seconds
        self._staging_spec = staging_spec or default_staging_spec()
        self._base_url = base_url
        self._require_rootless = require_rootless
        self._cancelled_invocations: dict[str, float] = {}
        self._cancellation_lock = threading.Lock()
        self._volume_preflight: bool | None = None
        self._volume_preflight_lock = threading.Lock()
        if client is not None and require_rootless:
            self._assert_rootless(client)

    def _get_client(self) -> Any:
        if self._client is None:
            try:
                docker = importlib.import_module("docker")
            except ImportError as exc:
                raise SandboxError("DOCKER_SDK_UNAVAILABLE", "Docker SDK is not installed") from exc
            try:
                self._client = docker.DockerClient(base_url=self._base_url) if self._base_url else docker.from_env()
                self._client.ping()
                if self._require_rootless:
                    self._assert_rootless(self._client)
            except Exception as exc:
                if isinstance(exc, SandboxError):
                    raise
                raise SandboxError("DOCKER_UNAVAILABLE", "Docker Engine is unavailable") from exc
        return self._client

    @staticmethod
    def _assert_rootless(client: Any) -> None:
        security_options = client.info().get("SecurityOptions", [])
        if not any("rootless" in str(option).lower() for option in security_options):
            raise SandboxError("ROOTLESS_REQUIRED", "sandbox Docker daemon is not rootless")

    async def execute(self, spec: SandboxToolSpec, invocation: SandboxInvocation) -> SandboxResult:
        return await asyncio.to_thread(self._execute_sync, spec, invocation)

    async def cleanup_orphans(
        self,
        *,
        active_invocations: tuple[SandboxInvocation, ...] = (),
        latest_fences: dict[str, int] | None = None,
    ) -> int:
        return await asyncio.to_thread(self._cleanup_orphans_sync, active_invocations, latest_fences or {})

    async def cancel(self, invocation_id: str) -> bool:
        return await asyncio.to_thread(self._cancel_sync, invocation_id)

    async def readiness(self, specs: tuple[SandboxToolSpec, ...]) -> dict[str, Any]:
        return await asyncio.to_thread(self._readiness_sync, specs)

    async def list_resources(self, run_id: str) -> list[SandboxResourceView]:
        return await asyncio.to_thread(self._list_resources_sync, run_id)

    def _readiness_sync(self, specs: tuple[SandboxToolSpec, ...]) -> dict[str, Any]:
        """Verify daemon reachability, rootless mode and pinned image presence."""

        client = self._get_client()
        try:
            client.ping()
            security_options = client.info().get("SecurityOptions", [])
            rootless = any("rootless" in str(option).lower() for option in security_options)
            if self._require_rootless and not rootless:
                raise SandboxError("ROOTLESS_REQUIRED", "sandbox Docker daemon is not rootless")
            images = {self._staging_spec.image_digest, *(spec.image_digest for spec in specs)}
            for image in images:
                client.images.get(image)
            self._ensure_bounded_volume_support(client)
        except SandboxError:
            raise
        except Exception as exc:
            raise SandboxError("RUNNER_NOT_READY", "sandbox execution plane is not ready") from exc
        return {
            "backend": "docker",
            "daemon": "ok",
            "images": len(images),
            "rootless": rootless,
        }

    def _ensure_bounded_volume_support(self, client: Any) -> None:
        """Prove the exact per-container bounded storage used for execution.

        A named ``local`` volume with ``type=tmpfs`` is not a portable shared
        filesystem: rootless Docker Desktop, for example, gives each
        container attachment a fresh tmpfs.  The production path therefore
        uses two bounded tmpfs mounts on one tool container and populates the
        input mount through a short-lived root exec before making it read-only.
        This probe checks that the daemon accepts the same mount type, that
        data survives in that mount, and that the requested quota is enforced.
        Unsupported test doubles intentionally skip the probe.
        """

        if not all(callable(getattr(client, attribute, None)) for attribute in ("ping", "info")) or not hasattr(
            client, "containers"
        ):
            return
        with self._volume_preflight_lock:
            if self._volume_preflight is True:
                return
            if self._volume_preflight is False:
                raise SandboxError(
                    "BOUNDED_STORAGE_UNAVAILABLE",
                    "Docker cannot provide bounded per-container tmpfs storage",
                )
            labels = {
                RESOURCE_LABEL: "true",
                INVOCATION_LABEL: f"preflight-{secrets.token_hex(8)}",
                RUN_LABEL: "preflight",
                FENCE_LABEL: "0",
                CREATED_LABEL: str(int(time.time())),
            }
            probe = None
            failure: SandboxError | None = None
            try:
                probe = client.containers.create(
                    self._staging_spec.image_digest,
                    entrypoint=["/bin/sh", "-c"],
                    command=[
                        "set -eu; printf secmind > /probe/secmind; "
                        'test "$(cat /probe/secmind)" = secmind; '
                        "! dd if=/dev/zero of=/probe/over bs=1048576 count=2 >/dev/null 2>&1",
                    ],
                    user="0:0",
                    network_mode="none",
                    read_only=True,
                    cap_drop=["ALL"],
                    security_opt=["no-new-privileges:true"],
                    mem_limit=self._staging_spec.memory_bytes,
                    nano_cpus=int(self._staging_spec.cpu_cores * 1_000_000_000),
                    pids_limit=self._staging_spec.pids_limit,
                    tmpfs={"/probe": "rw,noexec,nosuid,nodev,size=1048576,mode=1777"},
                    labels=labels,
                )
                probe.start()
                result = probe.wait(timeout=30)
                if int(result.get("StatusCode", 1)) != 0:
                    raise SandboxError(
                        "BOUNDED_STORAGE_UNAVAILABLE",
                        "Docker bounded per-container tmpfs preflight failed",
                    )
                self._volume_preflight = True
                return
            except SandboxError as exc:
                failure = exc
            except Exception as exc:
                failure = SandboxError(
                    "BOUNDED_STORAGE_UNAVAILABLE",
                    "Docker bounded per-container tmpfs preflight failed",
                )
                failure.__cause__ = exc
            finally:
                if probe is not None:
                    try:
                        probe.remove(force=True)
                    except Exception as exc:  # pragma: no cover - daemon-specific cleanup
                        logger.warning("failed to remove bounded-tmpfs probe container: %s", type(exc).__name__)
                        if failure is None:
                            failure = SandboxError(
                                "BOUNDED_STORAGE_UNAVAILABLE",
                                "Docker bounded-tmpfs preflight cleanup failed",
                            )
            self._volume_preflight = False
            if failure is None:  # pragma: no cover - defensive invariant
                failure = SandboxError(
                    "BOUNDED_STORAGE_UNAVAILABLE",
                    "Docker bounded-tmpfs preflight did not complete",
                )
            raise failure

    def _cancel_sync(self, invocation_id: str) -> bool:
        client = self._get_client()
        now = time.monotonic()
        with self._cancellation_lock:
            self._cancelled_invocations = {
                key: timestamp
                for key, timestamp in self._cancelled_invocations.items()
                if now - timestamp < MAX_TIMEOUT_SECONDS
            }
            self._cancelled_invocations[invocation_id] = now
        removed = False
        cleanup_failed = False
        label = f"{INVOCATION_LABEL}={invocation_id}"
        for container in client.containers.list(all=True, filters={"label": label}):
            try:
                container.remove(force=True)
                removed = True
            except Exception as exc:
                cleanup_failed = True
                logger.warning("failed to remove cancelled sandbox container: %s", type(exc).__name__)
        for volume in client.volumes.list(filters={"label": label}):
            try:
                volume.remove(force=True)
                removed = True
            except Exception as exc:
                cleanup_failed = True
                logger.warning("failed to remove cancelled sandbox volume: %s", type(exc).__name__)
        if cleanup_failed:
            raise SandboxError("RESOURCE_CLEANUP_FAILED", "cancelled sandbox resources could not be reaped")
        return removed

    @staticmethod
    def _bounded_volume_options(*, size_bytes: int) -> dict[str, Any]:
        """Return a finite local-volume quota understood by rootless Docker.

        A normal ``local`` named volume is backed by the daemon's host
        filesystem and has no quota.  Using the local driver's tmpfs option
        makes the input and output volumes bounded before an untrusted tool
        starts writing.  If the daemon cannot create this volume, execution
        fails closed instead of silently falling back to an unbounded volume.
        """

        if not 1 <= size_bytes <= MAX_OUTPUT_BYTES:
            raise SandboxError("RESOURCE_LIMIT_INVALID", "sandbox volume size is outside the configured limit")
        return {
            "driver": "local",
            "driver_opts": {
                "type": "tmpfs",
                "device": "tmpfs",
                "o": f"rw,nosuid,nodev,noexec,size={size_bytes}",
            },
        }

    @classmethod
    def _create_bounded_volume(cls, client: Any, *, labels: dict[str, str], size_bytes: int) -> Any:
        try:
            return client.volumes.create(
                labels=labels,
                **cls._bounded_volume_options(size_bytes=size_bytes),
            )
        except SandboxError:
            raise
        except Exception as exc:
            # Do not retry with a plain named volume: that would turn a
            # storage-quota failure into an unbounded execution.
            raise SandboxError(
                "SANDBOX_EXECUTION_FAILED",
                "Docker could not create the required bounded sandbox volume",
            ) from exc

    def _list_resources_sync(self, run_id: str) -> list[SandboxResourceView]:
        client = self._get_client()
        label = f"{RUN_LABEL}={run_id}"
        resources: list[SandboxResourceView] = []

        def append_resource(resource: Any, *, kind: str) -> None:
            attrs = getattr(resource, "attrs", {}) or {}
            labels = attrs.get("Config", {}).get("Labels", {}) if kind == "container" else attrs.get("Labels", {})
            labels = labels or {}
            invocation_id = str(labels.get(INVOCATION_LABEL, ""))
            if not invocation_id:
                return
            fence = self._label_fence(labels)
            identifier = str(getattr(resource, "id", None) or getattr(resource, "name", "unknown"))
            active = True
            if kind == "container":
                active = bool(attrs.get("State", {}).get("Running", True))
            resources.append(
                SandboxResourceView(
                    run_id=run_id,
                    resource_id=f"{kind}:{identifier}",
                    invocation_id=invocation_id,
                    fence=fence,
                    active=active,
                )
            )

        for container in client.containers.list(all=True, filters={"label": label}):
            append_resource(container, kind="container")
        for volume in client.volumes.list(filters={"label": label}):
            append_resource(volume, kind="volume")
        return resources

    def _is_cancelled(self, invocation_id: str) -> bool:
        with self._cancellation_lock:
            return invocation_id in self._cancelled_invocations

    def _execute_sync(self, spec: SandboxToolSpec, invocation: SandboxInvocation) -> SandboxResult:
        client = self._get_client()
        # Real Docker clients expose the Engine exec API.  Use one tool
        # container with per-container bounded tmpfs mounts there; named
        # local-tmpfs volumes are not reliably shared by rootless daemons.
        # Contract-test doubles intentionally retain the legacy two-container
        # path below so their failure/cleanup assertions remain meaningful.
        if callable(getattr(getattr(client, "api", None), "exec_create", None)):
            return self._execute_tmpfs_sync(client, spec, invocation)
        self._ensure_bounded_volume_support(client)
        if self._is_cancelled(invocation.invocation_id):
            raise SandboxError("SANDBOX_CANCELLED", "sandbox invocation was cancelled before start")
        input_size = sum(len(item.decoded()) for item in invocation.files)
        if input_size > spec.limits.max_input_bytes:
            raise SandboxError("INPUT_TOO_LARGE", "sandbox input exceeds the configured limit")
        started = time.monotonic()
        labels = {
            RESOURCE_LABEL: "true",
            INVOCATION_LABEL: invocation.invocation_id,
            RUN_LABEL: invocation.run_id,
            FENCE_LABEL: str(invocation.lease_fence),
            CREATED_LABEL: str(int(time.time())),
        }
        input_volume = None
        output_volume = None
        helper = None
        container = None
        timed_out = False
        result: SandboxResult | None = None
        operation_error: SandboxError | None = None
        cleanup_errors: list[str] = []
        try:
            if self._is_cancelled(invocation.invocation_id):
                raise SandboxError(
                    "SANDBOX_CANCELLED", "sandbox invocation was cancelled before resources were created"
                )
            input_volume = self._create_bounded_volume(
                client,
                labels=labels,
                size_bytes=spec.limits.max_input_bytes,
            )
            if self._is_cancelled(invocation.invocation_id):
                raise SandboxError("SANDBOX_CANCELLED", "sandbox invocation was cancelled")
            output_volume = self._create_bounded_volume(
                client,
                labels=labels,
                size_bytes=spec.limits.max_output_bytes,
            )
            helper = client.containers.create(
                self._staging_spec.image_digest,
                entrypoint=list(self._staging_spec.entrypoint),
                user="0:0",
                network_mode="none",
                read_only=True,
                cap_drop=["ALL"],
                security_opt=["no-new-privileges:true"],
                mem_limit=self._staging_spec.memory_bytes,
                nano_cpus=int(self._staging_spec.cpu_cores * 1_000_000_000),
                pids_limit=self._staging_spec.pids_limit,
                log_config={"type": "json-file", "config": {"max-size": "1m", "max-file": "1"}},
                volumes={
                    input_volume.name: {"bind": "/input", "mode": "rw"},
                    output_volume.name: {"bind": "/output", "mode": "rw"},
                },
                labels=labels,
            )
            helper.put_archive("/input", self._make_input_tar(invocation))
            helper.start()
            if self._is_cancelled(invocation.invocation_id):
                raise SandboxError("SANDBOX_CANCELLED", "sandbox invocation was cancelled")
            helper_result = helper.wait(timeout=30)
            if int(helper_result.get("StatusCode", 1)) != 0:
                raise SandboxError("STAGING_FAILED", "failed to prepare temporary sandbox volumes")

            container = client.containers.create(
                spec.image_digest,
                entrypoint=list(spec.entrypoint),
                user="65532:65532",
                network_mode="none",
                read_only=True,
                cap_drop=["ALL"],
                security_opt=["no-new-privileges:true"],
                mem_limit=spec.limits.memory_bytes,
                nano_cpus=int(spec.limits.cpu_cores * 1_000_000_000),
                pids_limit=spec.limits.pids_limit,
                log_config={"type": "json-file", "config": {"max-size": "1m", "max-file": "1"}},
                tmpfs={
                    # A per-invocation, bounded, noexec tmpfs is safer than the image filesystem.
                    "/tmp": f"rw,noexec,nosuid,nodev,size={spec.limits.tmpfs_bytes}",  # noqa: S108  # nosec B108
                },
                volumes={
                    input_volume.name: {"bind": "/input", "mode": "ro"},
                    output_volume.name: {"bind": "/output", "mode": "rw"},
                },
                labels=labels,
            )
            if self._is_cancelled(invocation.invocation_id):
                raise SandboxError("SANDBOX_CANCELLED", "sandbox invocation was cancelled")
            container.start()
            try:
                wait_result = container.wait(timeout=spec.limits.timeout_seconds)
                exit_code = int(wait_result.get("StatusCode", 1))
            except Exception as exc:
                if not self._is_timeout(exc):
                    raise
                timed_out = True
                container.kill()
                wait_result = container.wait(timeout=10)
                exit_code = int(wait_result.get("StatusCode", 137))

            log = self._collect_logs(container, spec.limits.max_log_tail_bytes)
            artifacts, result_body = self._read_outputs(
                container,
                spec.limits.max_output_bytes,
                spec.limits.max_artifacts,
            )
            duration_ms = int((time.monotonic() - started) * 1000)
            if timed_out:
                result = SandboxResult(
                    invocation_id=invocation.invocation_id,
                    status="timeout",
                    exit_code=exit_code,
                    artifacts=artifacts,
                    logs=log,
                    duration_ms=duration_ms,
                    error_code="SANDBOX_TIMEOUT",
                    error_message="tool exceeded its sandbox execution deadline",
                )
            elif exit_code != 0:
                result = SandboxResult(
                    invocation_id=invocation.invocation_id,
                    status="error",
                    exit_code=exit_code,
                    artifacts=artifacts,
                    logs=log,
                    duration_ms=duration_ms,
                    error_code="TOOL_EXIT_NONZERO",
                    error_message="sandboxed tool returned a non-zero exit code",
                )
            else:
                result = SandboxResult(
                    invocation_id=invocation.invocation_id,
                    status=str(result_body.get("status", "success")),
                    exit_code=exit_code,
                    data=result_body.get("data", {}),
                    summary=str(result_body.get("summary", "")),
                    artifacts=artifacts,
                    logs=log,
                    duration_ms=duration_ms,
                )
        except SandboxError as exc:
            operation_error = exc
        except Exception as exc:
            if self._is_cancelled(invocation.invocation_id):
                operation_error = SandboxError("SANDBOX_CANCELLED", "sandbox invocation was cancelled")
            else:
                operation_error = SandboxError("SANDBOX_EXECUTION_FAILED", "sandbox execution failed")
                operation_error.__cause__ = exc
        finally:
            for resource_name, resource in (("tool container", container), ("staging container", helper)):
                if resource is not None:
                    try:
                        resource.remove(force=True)
                    except Exception as exc:
                        cleanup_errors.append(resource_name)
                        logger.warning("failed to remove sandbox container: %s", type(exc).__name__)
            for resource_name, volume in (("output volume", output_volume), ("input volume", input_volume)):
                if volume is None:
                    continue
                try:
                    volume.remove(force=True)
                except Exception as exc:
                    cleanup_errors.append(resource_name)
                    logger.warning("failed to remove sandbox volume: %s", type(exc).__name__)

        if cleanup_errors:
            logger.error("sandbox resources were not fully reaped: %s", ", ".join(cleanup_errors))
            # Preserve the staging diagnosis used by callers, but never
            # report a timeout/cancel/success as settled when reaping failed.
            if operation_error is None or operation_error.code != "STAGING_FAILED":
                raise SandboxError(
                    "RESOURCE_CLEANUP_FAILED", "sandbox resources could not be reaped"
                ) from operation_error
        if operation_error is not None:
            raise operation_error
        if result is None:  # pragma: no cover - defensive invariant
            raise SandboxError("SANDBOX_EXECUTION_FAILED", "sandbox execution produced no result")
        return result.model_copy(update={"cleanup_confirmed": True})

    def _execute_tmpfs_sync(self, client: Any, spec: SandboxToolSpec, invocation: SandboxInvocation) -> SandboxResult:
        """Execute one fixed tool entrypoint inside bounded private tmpfs mounts.

        The container is started with a harmless shell supervisor so the
        runner can populate ``/input`` through a root exec while the rootfs is
        read-only.  The input directory is then chmod'ed read-only and the
        immutable allowlisted entrypoint is launched as uid 65532 through the
        Engine exec API.  ``/output`` is a bounded writable tmpfs owned solely
        by this container.  No host path, ordinary named volume, network, or
        privilege is exposed to the tool.
        """

        self._ensure_bounded_volume_support(client)
        if self._is_cancelled(invocation.invocation_id):
            raise SandboxError("SANDBOX_CANCELLED", "sandbox invocation was cancelled before start")
        input_size = sum(len(item.decoded()) for item in invocation.files)
        if input_size > spec.limits.max_input_bytes:
            raise SandboxError("INPUT_TOO_LARGE", "sandbox input exceeds the configured limit")
        started = time.monotonic()
        labels = {
            RESOURCE_LABEL: "true",
            INVOCATION_LABEL: invocation.invocation_id,
            RUN_LABEL: invocation.run_id,
            FENCE_LABEL: str(invocation.lease_fence),
            CREATED_LABEL: str(int(time.time())),
        }
        container = None
        operation_error: SandboxError | None = None
        result: SandboxResult | None = None
        cleanup_errors: list[str] = []
        try:
            # ``/bin/sh`` is only the runner-owned supervisor.  The tool
            # itself is always started by the fixed, image-owned entrypoint
            # argv below; no request field can replace it.
            container = client.containers.create(
                spec.image_digest,
                entrypoint=["/bin/sh", "-c"],
                command=["while :; do sleep 1; done"],
                user="65532:65532",
                network_mode="none",
                read_only=True,
                cap_drop=["ALL"],
                security_opt=["no-new-privileges:true"],
                mem_limit=spec.limits.memory_bytes,
                nano_cpus=int(spec.limits.cpu_cores * 1_000_000_000),
                pids_limit=spec.limits.pids_limit,
                log_config={"type": "json-file", "config": {"max-size": "1m", "max-file": "1"}},
                tmpfs={
                    "/input": (f"rw,noexec,nosuid,nodev,size={spec.limits.max_input_bytes},mode=0777"),
                    "/output": (f"rw,noexec,nosuid,nodev,size={spec.limits.max_output_bytes},mode=1777"),
                    "/tmp": f"rw,noexec,nosuid,nodev,size={spec.limits.tmpfs_bytes}",  # noqa: S108  # nosec B108
                },
                labels=labels,
            )
            container.start()
            if self._is_cancelled(invocation.invocation_id):
                raise SandboxError("SANDBOX_CANCELLED", "sandbox invocation was cancelled")
            self._populate_tmpfs_input(container, invocation)
            if self._is_cancelled(invocation.invocation_id):
                raise SandboxError("SANDBOX_CANCELLED", "sandbox invocation was cancelled")
            exit_code, timed_out, log = self._run_fixed_entrypoint(
                client,
                container,
                spec,
                timeout_seconds=spec.limits.timeout_seconds,
            )
            if self._is_cancelled(invocation.invocation_id):
                raise SandboxError("SANDBOX_CANCELLED", "sandbox invocation was cancelled")
            try:
                artifacts, result_body = self._read_outputs_tmpfs(
                    client,
                    container,
                    spec.limits.max_output_bytes,
                    spec.limits.max_artifacts,
                )
            except SandboxError:
                # A timed-out or non-zero tool may legitimately have no
                # result.json.  Successful tools still fail closed on a
                # malformed/missing result.
                if not timed_out and exit_code == 0:
                    raise
                artifacts, result_body = [], {}
            duration_ms = int((time.monotonic() - started) * 1000)
            if timed_out:
                result = SandboxResult(
                    invocation_id=invocation.invocation_id,
                    status="timeout",
                    exit_code=exit_code,
                    artifacts=artifacts,
                    logs=log,
                    duration_ms=duration_ms,
                    error_code="SANDBOX_TIMEOUT",
                    error_message="tool exceeded its sandbox execution deadline",
                )
            elif exit_code != 0:
                result = SandboxResult(
                    invocation_id=invocation.invocation_id,
                    status="error",
                    exit_code=exit_code,
                    artifacts=artifacts,
                    logs=log,
                    duration_ms=duration_ms,
                    error_code="TOOL_EXIT_NONZERO",
                    error_message="sandboxed tool returned a non-zero exit code",
                )
            else:
                result = SandboxResult(
                    invocation_id=invocation.invocation_id,
                    status=str(result_body.get("status", "success")),
                    exit_code=exit_code,
                    data=result_body.get("data", {}),
                    summary=str(result_body.get("summary", "")),
                    artifacts=artifacts,
                    logs=log,
                    duration_ms=duration_ms,
                )
        except SandboxError as exc:
            operation_error = exc
        except Exception as exc:
            if self._is_cancelled(invocation.invocation_id):
                operation_error = SandboxError("SANDBOX_CANCELLED", "sandbox execution was cancelled")
            else:
                operation_error = SandboxError("SANDBOX_EXECUTION_FAILED", "sandbox execution failed")
                operation_error.__cause__ = exc
        finally:
            if container is not None:
                try:
                    container.remove(force=True)
                except Exception as exc:
                    # The control-plane cancellation path may have removed
                    # the same container concurrently.  A confirmed 404 is
                    # already a successful cleanup receipt; transient/API
                    # failures remain fatal and keep CANCELLING visible.
                    if not self._resource_already_gone(exc):
                        cleanup_errors.append("tool container")
                        logger.warning("failed to remove sandbox tmpfs container: %s", type(exc).__name__)
        if cleanup_errors:
            raise SandboxError("RESOURCE_CLEANUP_FAILED", "sandbox resources could not be reaped") from operation_error
        if operation_error is not None:
            raise operation_error
        if result is None:  # pragma: no cover - defensive invariant
            raise SandboxError("SANDBOX_EXECUTION_FAILED", "sandbox execution produced no result")
        return result.model_copy(update={"cleanup_confirmed": True})

    @staticmethod
    def _resource_already_gone(exc: Exception) -> bool:
        text = str(exc).lower()
        return (
            type(exc).__name__.lower() == "notfound"
            or "404" in text
            or "not found" in text
            or "already in progress" in text
        )

    @staticmethod
    def _exec_exit_code(response: Any) -> int:
        if isinstance(response, tuple) and response:
            return int(response[0])
        return int(getattr(response, "exit_code", 1))

    def _populate_tmpfs_input(self, container: Any, invocation: SandboxInvocation) -> None:
        """Write bounded input through the daemon exec API, then seal it."""

        for item in invocation.files:
            target = shlex.quote(f"/input/{item.path}")
            encoded = item.content_base64
            if not encoded:
                command = f": > {target}"
                response = container.exec_run(["/bin/sh", "-c", command], user="0:0")
                if self._exec_exit_code(response) != 0:
                    raise SandboxError("STAGING_FAILED", "failed to prepare sandbox input")
            else:
                first = True
                # Keep each exec argv well below Windows/Linux command-line
                # limits even when the input envelope is near its hard cap.
                for offset in range(0, len(encoded), 48 * 1024):
                    chunk = shlex.quote(encoded[offset : offset + 48 * 1024])
                    redirect = ">" if first else ">>"
                    command = f"printf %s {chunk} | base64 -d {redirect} {target}"
                    response = container.exec_run(["/bin/sh", "-c", command], user="0:0")
                    if self._exec_exit_code(response) != 0:
                        raise SandboxError("STAGING_FAILED", "failed to prepare sandbox input")
                    first = False
            response = container.exec_run(["/bin/sh", "-c", f"chmod 0444 {target}"], user="0:0")
            if self._exec_exit_code(response) != 0:
                raise SandboxError("STAGING_FAILED", "failed to seal sandbox input file")
        response = container.exec_run(["/bin/sh", "-c", "chmod 0555 /input"], user="0:0")
        if self._exec_exit_code(response) != 0:
            raise SandboxError("STAGING_FAILED", "failed to seal sandbox input directory")

    @staticmethod
    def _run_fixed_entrypoint(
        client: Any,
        container: Any,
        spec: SandboxToolSpec,
        *,
        timeout_seconds: int,
    ) -> tuple[int, bool, SandboxLog]:
        """Run the fixed tool argv while retaining a bounded log tail."""

        api = client.api
        exec_id = api.exec_create(
            container.id,
            cmd=list(spec.entrypoint),
            user="65532:65532",
            stdout=True,
            stderr=True,
        )
        digest = hashlib.sha256()
        tail: deque[int] = deque(maxlen=spec.limits.max_log_tail_bytes)
        seen = 0
        holder: dict[str, Any] = {}

        def consume() -> None:
            nonlocal seen
            try:
                stream = api.exec_start(exec_id, stream=True, demux=False)
                for chunk in stream:
                    data = bytes(chunk[0] + chunk[1]) if isinstance(chunk, tuple) else bytes(chunk)
                    digest.update(data)
                    seen += len(data)
                    tail.extend(data)
            except BaseException as exc:  # surfaced after the bounded join below
                holder["error"] = exc

        worker = threading.Thread(target=consume, name="secmind-sandbox-exec", daemon=True)
        worker.start()
        worker.join(timeout_seconds)
        timed_out = worker.is_alive()
        if timed_out:
            try:
                container.kill()
            except Exception as exc:
                logger.debug(
                    "sandbox tool container was already stopped during timeout cleanup: %s", type(exc).__name__
                )
            worker.join(10)
        try:
            inspected = api.exec_inspect(exec_id)
            exit_code = int(inspected.get("ExitCode", 137 if timed_out else 1))
        except Exception:
            exit_code = 137 if timed_out else 1
        if holder.get("error") is not None and not timed_out:
            error = holder["error"]
            raise SandboxError("SANDBOX_EXECUTION_FAILED", "sandbox tool process failed") from error
        return (
            exit_code,
            timed_out,
            SandboxLog(
                tail=bytes(tail).decode(errors="replace"),
                sha256=digest.hexdigest(),
                bytes_seen=seen,
                truncated=seen > spec.limits.max_log_tail_bytes,
            ),
        )

    @staticmethod
    def _read_outputs_tmpfs(
        client: Any,
        container: Any,
        limit: int,
        max_artifacts: int = MAX_ARTIFACTS,
    ) -> tuple[list[SandboxArtifact], dict[str, Any]]:
        """Export a tmpfs tree through a bounded root exec.

        Docker Engine's archive endpoint can expose only the mountpoint
        directory (not its files) for a rootless tmpfs.  A fixed ``tar`` exec
        reads the same mount namespace, and demultiplexed streaming keeps the
        archive itself bounded before the normal path/digest parser runs.
        """

        api = client.api
        exec_id = api.exec_create(
            container.id,
            cmd=["/bin/sh", "-c", "tar -cf - -C /output ."],
            user="0:0",
            stdout=True,
            stderr=True,
        )
        archive_limit = limit + 1024 * 1024
        raw = bytearray()
        stderr = bytearray()
        for chunk in api.exec_start(exec_id, stream=True, demux=True):
            if isinstance(chunk, tuple):
                stdout, error = chunk
                if stdout:
                    raw.extend(stdout)
                if error:
                    stderr.extend(error)
            else:
                raw.extend(bytes(chunk))
            if len(raw) > archive_limit:
                raise SandboxError("OUTPUT_TOO_LARGE", "sandbox output exceeds the configured limit")
            if len(stderr) > 16 * 1024:
                del stderr[16 * 1024 :]
        inspected = api.exec_inspect(exec_id)
        if int(inspected.get("ExitCode", 1)) != 0:
            raise SandboxError("OUTPUT_READ_FAILED", "sandbox output could not be exported")

        class _ArchiveView:
            def get_archive(self, _path: str) -> tuple[Any, dict[str, Any]]:
                return iter((bytes(raw),)), {}

        return DockerSandboxBackend._read_outputs(_ArchiveView(), limit, max_artifacts)

    @staticmethod
    def _make_input_tar(invocation: SandboxInvocation) -> bytes:
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w") as archive:
            for item in invocation.files:
                content = item.decoded()
                info = tarfile.TarInfo(item.path)
                info.size = len(content)
                info.mode = 0o444
                info.mtime = 0
                archive.addfile(info, io.BytesIO(content))
        return stream.getvalue()

    @staticmethod
    def _is_timeout(exc: Exception) -> bool:
        name = type(exc).__name__.lower()
        return "timeout" in name or "readtimeout" in name

    @staticmethod
    def _collect_logs(container: Any, limit: int) -> SandboxLog:
        digest = hashlib.sha256()
        tail: deque[int] = deque(maxlen=limit)
        seen = 0
        for chunk in container.logs(stdout=True, stderr=True, stream=True):
            data = bytes(chunk)
            digest.update(data)
            seen += len(data)
            tail.extend(data)
        return SandboxLog(
            tail=bytes(tail).decode(errors="replace"),
            sha256=digest.hexdigest(),
            bytes_seen=seen,
            truncated=seen > limit,
        )

    @staticmethod
    def _read_outputs(
        container: Any,
        limit: int,
        max_artifacts: int = MAX_ARTIFACTS,
    ) -> tuple[list[SandboxArtifact], dict[str, Any]]:
        if not 1 <= max_artifacts <= MAX_ARTIFACTS:
            raise SandboxError("TOO_MANY_ARTIFACTS", "sandbox artifact count limit is invalid")
        chunks, _ = container.get_archive("/output")
        raw = bytearray()
        archive_limit = limit + 1024 * 1024  # Allow bounded tar headers/padding in addition to payload bytes.
        for chunk in chunks:
            raw.extend(chunk)
            if len(raw) > archive_limit:
                raise SandboxError("OUTPUT_TOO_LARGE", "sandbox output exceeds the configured limit")
        artifacts: list[SandboxArtifact] = []
        result_body: dict[str, Any] | None = None
        extracted_bytes = 0
        seen_paths: set[str] = set()
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:*") as archive:
            for member in archive.getmembers():
                if member.isdir():
                    continue
                # ``tar -C /output .`` uses a harmless ``./`` prefix while
                # named-volume archives use ``output/``.  Normalize only that
                # canonical archive prefix before applying the strict
                # relative-path validator.
                member_name = member.name.removeprefix("./")
                path = PurePosixPath(member_name)
                try:
                    canonical_path = validate_relative_path(member_name, description="artifact path")
                except ValueError as exc:
                    raise SandboxError("INVALID_ARTIFACT_PATH", "sandbox produced an unsafe artifact") from exc
                if canonical_path in seen_paths:
                    raise SandboxError("DUPLICATE_ARTIFACT_PATH", "sandbox produced duplicate artifact paths")
                seen_paths.add(canonical_path)
                if member.issym() or member.islnk() or path.is_absolute() or ".." in path.parts:
                    raise SandboxError("INVALID_ARTIFACT_PATH", "sandbox produced an unsafe artifact")
                extracted = archive.extractfile(member)
                if extracted is None:
                    continue
                content = extracted.read(limit + 1)
                extracted_bytes += len(content)
                if len(content) > limit or extracted_bytes > limit:
                    raise SandboxError("OUTPUT_TOO_LARGE", "sandbox artifact exceeds the configured limit")
                relative = str(path)
                if relative in {"output/result.json", "result.json"}:
                    try:
                        decoded = json.loads(content)
                    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                        raise SandboxError("INVALID_RESULT_JSON", "tool result.json is invalid") from exc
                    if not isinstance(decoded, dict):
                        raise SandboxError("INVALID_RESULT_JSON", "tool result.json must be an object")
                    result_body = decoded
                    continue
                sha256 = hashlib.sha256(content).hexdigest()
                if len(artifacts) >= max_artifacts:
                    raise SandboxError("TOO_MANY_ARTIFACTS", "sandbox produced too many artifacts")
                artifacts.append(
                    SandboxArtifact(
                        artifact_id=sha256[:24],
                        relative_path=relative.removeprefix("output/"),
                        sha256=sha256,
                        size_bytes=len(content),
                        content_base64=base64.b64encode(content).decode(),
                    )
                )
        if result_body is None:
            raise SandboxError("RESULT_MISSING", "tool did not produce result.json")
        return artifacts, result_body

    def _cleanup_orphans_sync(
        self,
        active_invocations: tuple[SandboxInvocation, ...] = (),
        latest_fences: dict[str, int] | None = None,
    ) -> int:
        client = self._get_client()
        cutoff = int(time.time()) - self._orphan_ttl_seconds
        latest_fences = latest_fences or {}
        protected = {(item.run_id, item.invocation_id, item.lease_fence) for item in active_invocations}
        removed = 0
        for container in client.containers.list(all=True, filters={"label": f"{RESOURCE_LABEL}=true"}):
            labels = container.attrs.get("Config", {}).get("Labels", {}) or {}
            created = self._label_epoch(labels)
            run_id = str(labels.get(RUN_LABEL, ""))
            invocation_id = str(labels.get(INVOCATION_LABEL, ""))
            fence = self._label_fence(labels)
            if (run_id, invocation_id, fence) in protected:
                continue
            state = container.attrs.get("State", {})
            is_running = bool(state.get("Running"))
            stale_fence = run_id in latest_fences and fence < latest_fences[run_id]
            if stale_fence or not is_running or created <= cutoff:
                try:
                    container.remove(force=True)
                    removed += 1
                except Exception as exc:
                    logger.warning("failed to remove orphan sandbox container: %s", type(exc).__name__)
        for volume in client.volumes.list(filters={"label": f"{RESOURCE_LABEL}=true"}):
            labels = volume.attrs.get("Labels", {}) or {}
            run_id = str(labels.get(RUN_LABEL, ""))
            invocation_id = str(labels.get(INVOCATION_LABEL, ""))
            fence = self._label_fence(labels)
            if (run_id, invocation_id, fence) in protected:
                continue
            stale_fence = run_id in latest_fences and fence < latest_fences[run_id]
            if not stale_fence and self._label_epoch(labels) > cutoff:
                continue
            try:
                volume.remove(force=True)
                removed += 1
            except Exception as exc:
                logger.warning("failed to remove orphan sandbox volume: %s", type(exc).__name__)
        return removed

    @staticmethod
    def _label_epoch(labels: dict[str, Any]) -> int:
        try:
            return int(labels.get(CREATED_LABEL, "0"))
        except (TypeError, ValueError):
            return 0

    @staticmethod
    def _label_fence(labels: dict[str, Any]) -> int:
        try:
            return max(0, int(labels.get(FENCE_LABEL, "0")))
        except (TypeError, ValueError):
            return 0


def default_allowlist() -> dict[str, SandboxToolSpec]:
    """Build the immutable tool map from operator-controlled deployment configuration."""

    def reject_zero_digest(image: str, environment_name: str) -> None:
        digest = image.rsplit("@sha256:", maxsplit=1)[1] if "@sha256:" in image else image.removeprefix("sha256:")
        if digest.lower() == "0" * 64:
            raise ValueError(f"{environment_name} must not use a zero sha256 digest")

    # An unset image is an unavailable capability, not a fake pinned image.
    # In particular, ``sha256:000...`` is not an image identity and must never
    # enter a readiness payload or an invocation ticket.  Strict deployments
    # reject the missing setting in ``create_production_app``; development and
    # registry callers simply receive an allowlist without this capability.
    allowlist: dict[str, SandboxToolSpec] = {}
    image = os.getenv("SECMIND_SANDBOX_BANDIT_IMAGE", "").strip()
    if image:
        reject_zero_digest(image, "SECMIND_SANDBOX_BANDIT_IMAGE")
        allowlist["bandit_python_audit"] = SandboxToolSpec(
            name="bandit_python_audit",
            image_digest=image,
            entrypoint=("python", "/opt/secmind-bandit/run.py"),
        )
    # External images are opt-in. No tag/default is accepted: an operator must
    # provide an immutable digest, otherwise the tool is absent from the runner
    # allowlist and is advertised as UNAVAILABLE by the API registry.
    configured = {
        "semgrep_sast": (
            "SECMIND_SANDBOX_SEMGREP_IMAGE",
            ("/opt/secmind-tools/run-semgrep",),
            SandboxLimits(timeout_seconds=180, max_parallelism=2),
        ),
        "gitleaks_secret_scan": (
            "SECMIND_SANDBOX_GITLEAKS_IMAGE",
            ("/opt/secmind-tools/run-gitleaks",),
            SandboxLimits(timeout_seconds=120, max_parallelism=2),
        ),
        "syft_sbom": (
            "SECMIND_SANDBOX_SYFT_IMAGE",
            ("/opt/secmind-tools/run-syft",),
            SandboxLimits(timeout_seconds=180, max_parallelism=2),
        ),
        "osv_dependency_audit": (
            "SECMIND_SANDBOX_OSV_IMAGE",
            ("/opt/secmind-tools/run-osv-offline",),
            SandboxLimits(timeout_seconds=300, max_parallelism=2),
        ),
    }
    for name, (environment_name, entrypoint, limits) in configured.items():
        configured_image = os.getenv(environment_name, "").strip()
        if not configured_image:
            continue
        reject_zero_digest(configured_image, environment_name)
        allowlist[name] = SandboxToolSpec(
            name=name,
            image_digest=configured_image,
            entrypoint=entrypoint,
            limits=limits,
        )
    return allowlist


def default_staging_spec() -> SandboxStagingSpec:
    return SandboxStagingSpec(
        image_digest=os.getenv("SECMIND_SANDBOX_STAGING_IMAGE", "sha256:" + ("0" * 64)),
    )


def invocation_input_sha256(invocation: SandboxInvocation) -> str:
    digest = hashlib.sha256()
    for item in sorted(invocation.files, key=lambda value: value.path):
        path = item.path.encode("utf-8")
        content = item.decoded()
        digest.update(len(path).to_bytes(4, "big"))
        digest.update(path)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def token_matches(expected: str, supplied: str | None) -> bool:
    return bool(expected and supplied and secrets.compare_digest(expected, supplied))
