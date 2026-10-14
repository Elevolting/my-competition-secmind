from __future__ import annotations

from pathlib import Path

import pytest

from security_agent.config import Settings


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        _env_file=None,
        demo_mode=True,
        allowed_hosts="testserver,workbench.test",
        reverse_base_url="http://127.0.0.1:1",
        penetration_base_url="http://127.0.0.1:1",
        database_url=f"sqlite:///{(tmp_path / 'security_agent.db').as_posix()}",
        input_root=tmp_path / "inputs",
        upload_root=tmp_path / "uploads",
        run_root=tmp_path / "runs",
        evaluation_root=tmp_path / "evaluations",
        question_bank_root=tmp_path / "question-banks",
        max_upload_bytes=1024 * 1024,
        max_extracted_bytes=2 * 1024 * 1024,
    )
