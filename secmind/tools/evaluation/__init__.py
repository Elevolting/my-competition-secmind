"""CLI wrappers for the SecMind v0.8.2 evaluation contracts."""

from __future__ import annotations

import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parents[2] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from secmind_dev.v082_cli import main  # noqa: E402

__all__ = ["main"]
