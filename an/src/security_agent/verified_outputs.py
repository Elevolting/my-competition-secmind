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

# A flag recovered from the server's own process environment is a runtime
# artifact of the hosting platform, not the challenge's answer: the deployment
# injects ``FLAG=<per-instance token>`` into every container, so the value
# changes per instance and says nothing about the vulnerability the task asked
# to demonstrate.  Reading ``/proc/self/environ`` is a legitimate finding, but
# the bracket-delimited value inside it must not be promoted to the task's
# target output while the challenge's own flag path is still reachable.
#
# The signal is deliberately narrow.  A configuration file that merely happens
# to contain ``KEY=VALUE`` lines (``.env``, ``settings.php``) is a normal CTF
# flag path, so newlines do not count: an environment dump is NUL-separated.
_PROC_ENV_PATH = re.compile(r"(?i)/proc/(?:\d+|self|thread-self)/(?:environ|cmdline)\b")
# Serialized receipts escape the separators, so both the raw and the JSON form
# have to count as a field separator and terminate an entry.
_NUL_SEPARATORS = ("\x00", "\\u0000", "\\x00")
_ENV_DUMP_ENTRY = re.compile(
    r"[A-Za-z_][A-Za-z0-9_]*=(?:(?!\x00|\\u0000|\\x00)[^\r\n])*"
)
_ENV_DUMP_NULS = 2
_ENV_DUMP_ENTRIES = 3


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


def is_runtime_metadata_source(value: str) -> bool:
    """Whether a value is a process/container metadata dump rather than the target.

    Reading ``/proc/self/environ`` (or an equivalent environment or machine
    identity file) is a real finding, but the brace-delimited token inside it is
    the hosting platform's per-instance ``FLAG`` variable, not the challenge's
    answer.  Preferring it over the application's own flag path made the
    workbench report a value that changes on every rebuild.
    """
    if not isinstance(value, str) or not value:
        return False
    if _PROC_ENV_PATH.search(value):
        return True
    # A run of NUL-separated ``KEY=VALUE`` entries is an environment dump; the
    # same lines joined by newlines are an ordinary config file.
    separators = sum(value.count(token) for token in _NUL_SEPARATORS)
    return separators >= _ENV_DUMP_NULS and len(_ENV_DUMP_ENTRY.findall(value)) >= _ENV_DUMP_ENTRIES


def without_runtime_metadata(candidates: Iterable[tuple[str, str]]) -> list[str]:
    """Keep declared outputs that a real target response produced.

    ``candidates`` pairs a declared output with the serialized receipt text it
    was found in.  A value is dropped only when *every* receipt that contains it
    is a process/container metadata dump; if the application itself also emitted
    it, the value stands as the evidenced target output.
    """
    sources: dict[str, list[str]] = {}
    order: list[str] = []
    for value, context in candidates:
        if value not in sources:
            sources[value] = []
            order.append(value)
        sources[value].append(context)
    return [value for value in order
            if any(not is_runtime_metadata_source(context) for context in sources[value])]


def include_verified_outputs(summary: str, outputs: list[str]) -> str:
    if not outputs:
        return summary
    missing = [value for value in outputs if value not in summary]
    if not missing:
        return summary
    return f"{summary.rstrip()} 已验证目标输出：{', '.join(missing)}。"
