from __future__ import annotations

import asyncio
import signal

from sqlalchemy import create_engine

from secmind.config import get_settings
from secmind.coordinator import CoordinatorStore
from secmind.ledger import LedgerStore
from secmind.migration_guard import verify_database_at_head
from secmind.outbox_projector import OutboxProjector, PostgresNotificationWakeup


def _notification_url(database_url: str) -> str:
    return database_url.replace("postgresql+psycopg://", "postgresql://", 1)


async def serve() -> None:
    settings = get_settings()
    if settings.runtime_role != "projector":
        raise RuntimeError("secmind-projector requires SECMIND_RUNTIME_ROLE=projector")
    strict = settings.env.lower() in {"production", "competition"}
    if strict:
        verify_database_at_head(settings.database_url, settings.alembic_config_path)
    engine = create_engine(settings.database_url, future=True, pool_pre_ping=True)
    if not strict:
        # Reuse the projector engine for development schema initialization;
        # creating disposable stores here used to allocate two extra pools.
        CoordinatorStore(engine=engine, initialize_schema=True)
        LedgerStore(engine=engine, initialize_schema=True)
    wakeup = (
        PostgresNotificationWakeup(_notification_url(settings.database_url))
        if engine.dialect.name == "postgresql"
        else None
    )
    projector = OutboxProjector(
        engine,
        owner_id=f"{settings.worker_id}-projector",
        poll_interval_seconds=max(0.1, settings.worker_poll_seconds),
        wakeup=wakeup,
    )
    stopped = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signal_name in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(signal_name, stopped.set)
        except NotImplementedError:  # pragma: no cover - Windows event loops
            pass
    try:
        await projector.serve(stopped)
    finally:
        engine.dispose()


def run() -> None:
    asyncio.run(serve())


if __name__ == "__main__":
    run()
