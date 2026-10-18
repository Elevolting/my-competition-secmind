"""Small, dependency-free contracts shared by optional binary log parsers."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, fields
from typing import Any, Literal


@dataclass(frozen=True, slots=True)
class BinaryParseLimits:
    max_input_bytes: int = 8 * 1024 * 1024
    max_records: int = 10_000
    max_event_fields: int = 256
    max_string_chars: int = 4_096
    max_archive_members: int = 100
    max_archive_member_bytes: int = 2 * 1024 * 1024
    max_archive_total_bytes: int = 8 * 1024 * 1024
    max_archive_ratio: int = 100

    def __post_init__(self) -> None:
        if any(getattr(self, item.name) < 1 for item in fields(self)):
            raise ValueError("binary parse limits must be positive")


@dataclass(frozen=True, slots=True)
class BinaryEvent:
    event_id: str
    timestamp_utc: str | None
    event_type: str
    message: str
    attributes: Mapping[str, Any] = field(default_factory=dict)
    record_number: int = 0
    byte_offset: int = 0
    byte_length: int = 0
    locator_scope: Literal["record", "whole_file"] = "whole_file"


@dataclass(frozen=True, slots=True)
class BinaryDiagnostic:
    code: str
    message: str
    severity: Literal["info", "warning", "error"]
    record_number: int | None = None


@dataclass(frozen=True, slots=True)
class BinaryParseResult:
    source_ref: str
    format_detected: str
    records_seen: int
    records_emitted: int
    truncated: bool
    events: tuple[BinaryEvent, ...]
    diagnostics: tuple[BinaryDiagnostic, ...]


@dataclass(frozen=True, slots=True)
class SafeArchiveMember:
    path: str
    content: bytes


@dataclass(frozen=True, slots=True)
class SafeArchiveResult:
    members: tuple[SafeArchiveMember, ...]
    skipped_member_paths: tuple[str, ...]


__all__ = [
    "BinaryDiagnostic",
    "BinaryEvent",
    "BinaryParseLimits",
    "BinaryParseResult",
    "SafeArchiveMember",
    "SafeArchiveResult",
]
