from __future__ import annotations

from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, text


class MigrationHeadError(RuntimeError):
    """The business database is not at the schema revision required by this build."""


def verify_database_at_head(database_url: str, config_path: Path = Path("alembic.ini")) -> str:
    """Fail closed when a production database is missing or behind Alembic head."""
    if not config_path.is_file():
        raise MigrationHeadError(f"Alembic configuration was not found: {config_path}")
    config = Config(str(config_path))
    expected = ScriptDirectory.from_config(config).get_current_head()
    if expected is None:
        raise MigrationHeadError("Alembic does not define a migration head")
    engine = create_engine(database_url, future=True)
    try:
        with engine.connect() as connection:
            current = connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one_or_none()
    except Exception as exc:
        raise MigrationHeadError("Unable to read the database migration revision") from exc
    finally:
        engine.dispose()
    if current != expected:
        raise MigrationHeadError(f"Database migration is {current or 'missing'}; required head is {expected}")
    return expected
