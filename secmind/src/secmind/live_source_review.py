from __future__ import annotations

import hashlib
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class SourceUnit:
    """Immutable source input shared by the bounded audit kernel."""

    case_id: str
    path: str
    content: str

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.content.encode("utf-8")).hexdigest()


__all__ = ["SourceUnit"]
