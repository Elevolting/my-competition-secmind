from __future__ import annotations

import asyncio
import subprocess
import sys
import time
from pathlib import Path

import pytest

from secmind.config import Settings
from secmind.model_gateway.provider_gate import ProviderGateTimeout, ProviderHostGate


def test_empty_optional_provider_gate_path_uses_system_temp() -> None:
    settings = Settings(_env_file=None, model_provider_gate_directory="")

    assert settings.model_provider_gate_directory is None


@pytest.mark.asyncio
async def test_provider_host_gate_serializes_independent_instances(tmp_path: Path) -> None:
    first_gate = ProviderHostGate(root=tmp_path, key="provider|model", slots=1)
    second_gate = ProviderHostGate(root=tmp_path, key="provider|model", slots=1)
    first = await first_gate.acquire(deadline_at=time.monotonic() + 1, request_digest="first")
    waiting = asyncio.create_task(second_gate.acquire(deadline_at=time.monotonic() + 1, request_digest="second"))
    await asyncio.sleep(0.05)
    assert not waiting.done()

    first.release()
    second = await waiting
    try:
        assert second.waited_ms >= 40
        assert second.slot == 0
    finally:
        second.release()


@pytest.mark.asyncio
async def test_provider_host_gate_deadline_is_bounded_and_crash_safe(tmp_path: Path) -> None:
    gate = ProviderHostGate(root=tmp_path, key="provider|model", slots=1)
    held = await gate.acquire(deadline_at=time.monotonic() + 1, request_digest="held")
    try:
        with pytest.raises(ProviderGateTimeout):
            await gate.acquire(deadline_at=time.monotonic() + 0.03, request_digest="blocked")
    finally:
        held.release()

    reacquired = await gate.acquire(deadline_at=time.monotonic() + 1, request_digest="reacquired")
    reacquired.release()


def test_provider_host_gate_is_shared_by_spawned_processes(tmp_path: Path) -> None:
    ready = tmp_path / "ready"
    release = tmp_path / "release"
    acquired = tmp_path / "acquired"
    holder_code = """
import asyncio, sys, time
from pathlib import Path
from secmind.model_gateway.provider_gate import ProviderHostGate
async def main():
    root, ready, release = map(Path, sys.argv[1:4])
    slot = await ProviderHostGate(root=root, key='shared', slots=1).acquire(
        deadline_at=time.monotonic() + 10, request_digest='holder')
    ready.write_text('ready')
    while not release.exists():
        await asyncio.sleep(0.02)
    slot.release()
asyncio.run(main())
"""
    contender_code = """
import asyncio, sys, time
from pathlib import Path
from secmind.model_gateway.provider_gate import ProviderHostGate
async def main():
    root, acquired = map(Path, sys.argv[1:3])
    slot = await ProviderHostGate(root=root, key='shared', slots=1).acquire(
        deadline_at=time.monotonic() + 10, request_digest='contender')
    acquired.write_text('acquired')
    slot.release()
asyncio.run(main())
"""
    holder = subprocess.Popen(  # noqa: S603 - fixed interpreter and test-owned arguments
        [sys.executable, "-c", holder_code, str(tmp_path), str(ready), str(release)]
    )
    contender: subprocess.Popen[bytes] | None = None
    try:
        deadline = time.monotonic() + 5
        while not ready.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        assert ready.exists()
        contender = subprocess.Popen(  # noqa: S603 - fixed interpreter and test-owned arguments
            [sys.executable, "-c", contender_code, str(tmp_path), str(acquired)]
        )
        time.sleep(0.2)
        assert not acquired.exists()
        holder.kill()
        holder.wait(timeout=5)
        assert contender.wait(timeout=5) == 0
        assert acquired.exists()
    finally:
        release.touch(exist_ok=True)
        for process in (contender, holder):
            if process is not None and process.poll() is None:
                process.kill()
                process.wait(timeout=5)
