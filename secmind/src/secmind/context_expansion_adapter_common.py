"""Shared conservative heuristics for language adapters."""

from __future__ import annotations

import re


def _looks_untrusted_name(value: str) -> bool:
    tokens = set(re.findall(r"[A-Za-z0-9]+", value.casefold()))
    return bool(
        tokens
        & {
            "user",
            "input",
            "request",
            "req",
            "query",
            "param",
            "params",
            "body",
            "payload",
            "untrusted",
            "value",
            "cmd",
            "command",
            "arg",
            "argument",
            "data",
        }
    )


__all__ = ["_looks_untrusted_name"]
