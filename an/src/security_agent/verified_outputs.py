from __future__ import annotations

import re
from collections.abc import Iterable

_FLAG_PATTERN = re.compile(r"(?i)(?:flag|ctf[a-z0-9_-]*)\{[^}\r\n]{1,256}\}")
# A real flag body is an opaque token.  Reports and tool output frequently
# quote the extraction pattern itself (for example ``grep 'flag{[^}]*}'``),
# and a regex/shell fragment satisfies the brace pattern without being a
# flag.  A genuine body starts with an alphanumeric character and contains
# no regular-expression metacharacters, which keeps the uuid, hex, dotted
# and underscore forms the platform actually issues.
_FLAG_BODY_LEAD = re.compile(r"[A-Za-z0-9]")
_FLAG_BODY_PATTERN_CHARS = frozenset("[](){}\\*+?|^$")


def _is_placeholder(value: str) -> bool:
    content = value[value.index("{") + 1:-1].strip()
    return not content.strip(".…。*? ") or content.casefold() in {
        "flag", "your_flag", "your_flag_here", "example", "placeholder",
    }


def _is_plausible_flag(value: str) -> bool:
    """Reject regex/shell literals that merely look brace-delimited."""
    body = value[value.index("{") + 1:-1]
    if not body or not _FLAG_BODY_LEAD.match(body):
        return False
    return not (_FLAG_BODY_PATTERN_CHARS & set(body))


def extract_verified_flags(values: Iterable[str]) -> list[str]:
    """Extract flag-shaped values from evidence already classified as verified."""
    return list(dict.fromkeys(
        match.group(0)
        for value in values
        for match in _FLAG_PATTERN.finditer(value)
        if not _is_placeholder(match.group(0)) and _is_plausible_flag(match.group(0))
    ))


def include_verified_outputs(summary: str, outputs: list[str]) -> str:
    if not outputs:
        return summary
    missing = [value for value in outputs if value not in summary]
    if not missing:
        return summary
    return f"{summary.rstrip()} 已验证目标输出：{', '.join(missing)}。"
