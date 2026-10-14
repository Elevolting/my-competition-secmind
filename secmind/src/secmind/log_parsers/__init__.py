"""Public boundary for optional bounded binary-log parsing."""

from importlib.util import find_spec

from secmind.log_parsers.archive import ArchiveSafetyError, extract_safe_zip
from secmind.log_parsers.binary import detect_binary_format, parse_binary_log
from secmind.log_parsers.contracts import (
    BinaryDiagnostic,
    BinaryEvent,
    BinaryParseLimits,
    BinaryParseResult,
    SafeArchiveMember,
    SafeArchiveResult,
)


def binary_parser_dependency_status() -> dict[str, bool]:
    """Report optional parser availability without importing parser libraries."""

    return {
        "defusedxml": find_spec("defusedxml") is not None,
        "dpkt": find_spec("dpkt") is not None,
        "python_evtx": find_spec("Evtx") is not None,
    }


__all__ = [
    "ArchiveSafetyError",
    "BinaryDiagnostic",
    "BinaryEvent",
    "BinaryParseLimits",
    "BinaryParseResult",
    "SafeArchiveMember",
    "SafeArchiveResult",
    "binary_parser_dependency_status",
    "detect_binary_format",
    "extract_safe_zip",
    "parse_binary_log",
]
