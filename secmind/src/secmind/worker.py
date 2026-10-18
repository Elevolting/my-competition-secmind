from __future__ import annotations

import asyncio
import signal

from secmind.config import get_settings
from secmind.runtime import ApplicationRuntime


async def serve() -> None:
    settings = get_settings()
    if settings.runtime_role not in {"worker", "embedded"}:
        raise RuntimeError("secmind-worker requires SECMIND_RUNTIME_ROLE=worker")
    runtime = ApplicationRuntime(settings)
    await runtime.startup()
    stopped = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signal_name in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(signal_name, stopped.set)
        except NotImplementedError:
            pass
    try:
        await stopped.wait()
    finally:
        await runtime.shutdown()


def run() -> None:
    asyncio.run(serve())


if __name__ == "__main__":
    run()
