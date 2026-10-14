"""Crash-safe host-local concurrency gate for model provider requests.

The evaluation bridge launches an independent SecMind process for every
parallel task.  An ``asyncio.Semaphore`` therefore cannot protect a provider
from synchronized request waves.  This module uses one advisory byte lock per
slot.  Kernel locks are released when a process exits, so no stale lease or
request data is left behind.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import BinaryIO


class ProviderGateTimeout(TimeoutError):
    """Raised before transport when no host slot fits inside the deadline."""


def _try_lock(handle: BinaryIO) -> bool:
    handle.seek(0)
    if os.name == "nt":  # pragma: win32 cover - exercised by release evaluation
        import msvcrt

        try:
            msvcrt.locking(  # type: ignore[attr-defined]
                handle.fileno(),
                msvcrt.LK_NBLCK,  # type: ignore[attr-defined]
                1,
            )
        except OSError:
            return False
        return True

    import fcntl  # pragma: posix cover - exercised by Linux CI

    try:
        fcntl.flock(  # type: ignore[attr-defined]
            handle.fileno(),
            fcntl.LOCK_EX | fcntl.LOCK_NB,  # type: ignore[attr-defined]
        )
    except (BlockingIOError, OSError):
        return False
    return True


def _unlock(handle: BinaryIO) -> None:
    handle.seek(0)
    if os.name == "nt":  # pragma: win32 cover - exercised by release evaluation
        import msvcrt

        msvcrt.locking(  # type: ignore[attr-defined]
            handle.fileno(),
            msvcrt.LK_UNLCK,  # type: ignore[attr-defined]
            1,
        )
        return

    import fcntl  # pragma: posix cover - exercised by Linux CI

    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)  # type: ignore[attr-defined]


@dataclass(slots=True)
class ProviderSlot:
    """One acquired provider slot and its safe diagnostic wait duration."""

    handle: BinaryIO
    slot: int
    waited_ms: int

    async def __aenter__(self) -> ProviderSlot:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.release()

    def release(self) -> None:
        """Release the kernel lock exactly once."""

        if self.handle.closed:
            return
        try:
            _unlock(self.handle)
        finally:
            self.handle.close()


class ProviderHostGate:
    """Acquire one of a bounded set of host-local advisory lock slots."""

    def __init__(self, *, root: Path | None, key: str, slots: int) -> None:
        if slots < 1:
            raise ValueError("provider host concurrency must be positive")
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:24]
        base = root or Path(tempfile.gettempdir()) / "secmind-provider-gates"
        self._directory = base / digest
        self._slots = slots

    async def acquire(self, *, deadline_at: float, request_digest: str) -> ProviderSlot:
        started = time.monotonic()
        self._directory.mkdir(parents=True, exist_ok=True)
        start_slot = int(hashlib.sha256(request_digest.encode("ascii")).hexdigest()[:8], 16) % self._slots

        while True:
            for offset in range(self._slots):
                slot = (start_slot + offset) % self._slots
                path = self._directory / f"slot-{slot:02d}.lock"
                handle = path.open("a+b")
                try:
                    if path.stat().st_size == 0:
                        handle.write(b"\0")
                        handle.flush()
                    if _try_lock(handle):
                        return ProviderSlot(
                            handle=handle,
                            slot=slot,
                            waited_ms=max(0, int((time.monotonic() - started) * 1000)),
                        )
                except BaseException:
                    handle.close()
                    raise
                handle.close()

            remaining = deadline_at - time.monotonic()
            if remaining <= 0:
                raise ProviderGateTimeout("provider host-concurrency deadline exceeded")
            await asyncio.sleep(min(0.1, remaining))


def build_provider_host_gate(gateway, *, model_id: str) -> ProviderHostGate:
    """Build a gate without including secrets in its identity or files."""

    return ProviderHostGate(
        root=gateway.settings.model_provider_gate_directory,
        key=f"{gateway.policy.base_url.rstrip('/')}|{model_id}",
        slots=gateway.settings.model_provider_host_concurrency,
    )
