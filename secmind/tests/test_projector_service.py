from __future__ import annotations

from types import SimpleNamespace

import pytest

import secmind.projector as projector_module


def _settings(**updates):
    values = {
        "runtime_role": "projector",
        "env": "development",
        "database_url": "sqlite:///projector.db",
        "alembic_config_path": "alembic.ini",
        "worker_id": "worker-test",
        "worker_poll_seconds": 0.05,
    }
    values.update(updates)
    return SimpleNamespace(**values)


def test_notification_url_normalizes_sqlalchemy_psycopg_scheme() -> None:
    assert (
        projector_module._notification_url("postgresql+psycopg://user@database/secmind")
        == "postgresql://user@database/secmind"
    )
    assert projector_module._notification_url("sqlite:///local.db") == "sqlite:///local.db"


@pytest.mark.asyncio
async def test_projector_rejects_an_incorrect_runtime_role(monkeypatch) -> None:
    monkeypatch.setattr(projector_module, "get_settings", lambda: _settings(runtime_role="api"))
    with pytest.raises(RuntimeError, match="RUNTIME_ROLE=projector"):
        await projector_module.serve()


@pytest.mark.asyncio
async def test_development_projector_initializes_schema_projects_and_disposes(monkeypatch) -> None:
    closed: list[str] = []
    served: list[tuple[str, float, object | None]] = []

    class Store:
        def __init__(self, _database_url=None, *, engine=None, initialize_schema=True):
            self.name = type(self).__name__
            assert engine is not None
            assert initialize_schema is True

        def close(self):
            closed.append(self.name)

    engine = SimpleNamespace(
        dialect=SimpleNamespace(name="sqlite"),
        dispose=lambda: closed.append("engine"),
    )

    class Projector:
        def __init__(self, _engine, *, owner_id, poll_interval_seconds, wakeup):
            served.append((owner_id, poll_interval_seconds, wakeup))

        async def serve(self, stopped):
            stopped.set()

    monkeypatch.setattr(projector_module, "get_settings", lambda: _settings())
    monkeypatch.setattr(projector_module, "CoordinatorStore", Store)
    monkeypatch.setattr(projector_module, "LedgerStore", Store)
    monkeypatch.setattr(projector_module, "create_engine", lambda *_args, **_kwargs: engine)
    monkeypatch.setattr(projector_module, "OutboxProjector", Projector)

    await projector_module.serve()

    assert closed == ["engine"]
    assert served == [("worker-test-projector", 0.1, None)]


@pytest.mark.asyncio
async def test_strict_projector_checks_migration_and_uses_postgres_wakeup(monkeypatch) -> None:
    checked: list[tuple[str, str]] = []
    disposed: list[bool] = []
    wakeups: list[str] = []
    engine = SimpleNamespace(
        dialect=SimpleNamespace(name="postgresql"),
        dispose=lambda: disposed.append(True),
    )

    class Wakeup:
        def __init__(self, url):
            wakeups.append(url)

    class Projector:
        def __init__(self, _engine, **_kwargs):
            pass

        async def serve(self, stopped):
            stopped.set()

    monkeypatch.setattr(
        projector_module,
        "get_settings",
        lambda: _settings(
            env="competition",
            database_url="postgresql+psycopg://user@database/secmind",
        ),
    )
    monkeypatch.setattr(
        projector_module,
        "verify_database_at_head",
        lambda database_url, config: checked.append((database_url, config)),
    )
    monkeypatch.setattr(projector_module, "create_engine", lambda *_args, **_kwargs: engine)
    monkeypatch.setattr(projector_module, "PostgresNotificationWakeup", Wakeup)
    monkeypatch.setattr(projector_module, "OutboxProjector", Projector)

    await projector_module.serve()

    assert checked == [("postgresql+psycopg://user@database/secmind", "alembic.ini")]
    assert wakeups == ["postgresql://user@database/secmind"]
    assert disposed == [True]
