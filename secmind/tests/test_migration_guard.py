from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config

from secmind.migration_guard import MigrationHeadError, verify_database_at_head


def _config(url: str) -> Config:
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", url)
    return config


def test_migration_guard_accepts_only_the_current_head(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    url = f"sqlite:///{(tmp_path / 'guard.db').as_posix()}"
    monkeypatch.setenv("SECMIND_DATABASE_URL", url)
    with pytest.raises(MigrationHeadError, match="Unable to read"):
        verify_database_at_head(url)

    command.upgrade(_config(url), "0002_v03_control_plane")
    with pytest.raises(MigrationHeadError, match="required head"):
        verify_database_at_head(url)

    command.upgrade(_config(url), "head")
    assert verify_database_at_head(url) == "0022_widen_prompt_versions"
