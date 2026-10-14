from __future__ import annotations

import os
import sys
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from sqlalchemy import engine_from_config, pool

# Alembic is also a supported source-tree entrypoint.  Do not rely on an
# editable-install .pth file: Windows may decode non-ASCII checkout paths with
# a legacy code page before this module is imported.
source_root = Path(__file__).resolve().parents[1] / "src"
if str(source_root) not in sys.path:
    sys.path.insert(0, str(source_root))

# Import v0.5 model declarations before exposing CognitiveBase metadata to Alembic.
import secmind.task_specs  # noqa: F401,E402
from secmind.coordinator import CoordinatorBase  # noqa: E402
from secmind.execution import ExecutionBase  # noqa: E402
from secmind.knowledge import KnowledgeBase  # noqa: E402
from secmind.ledger import Base  # noqa: E402
from secmind.unit_of_work import CognitiveBase  # noqa: E402

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = [
    Base.metadata,
    ExecutionBase.metadata,
    CoordinatorBase.metadata,
    KnowledgeBase.metadata,
    CognitiveBase.metadata,
]


def database_url() -> str:
    return os.getenv("SECMIND_DATABASE_URL", config.get_main_option("sqlalchemy.url"))


def run_migrations_offline() -> None:
    context.configure(
        url=database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    section = config.get_section(config.config_ini_section) or {}
    section["sqlalchemy.url"] = database_url()
    connectable = engine_from_config(section, prefix="sqlalchemy.", poolclass=pool.NullPool)
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
