"""Deterministic query matching and stable semantic node identifiers."""

from __future__ import annotations

import re
from collections.abc import Iterable

from secmind.context_expansion_contracts import _MAX_QUERY_TOKENS, SemanticSliceError, SemanticSliceQuery
from secmind.context_expansion_indexer import _normalise_input_path


def _query_tokens(value: str) -> tuple[str, ...]:
    tokens = re.findall(r"[A-Za-z0-9_$]{2,}", value.casefold())
    return tuple(dict.fromkeys(tokens))[:_MAX_QUERY_TOKENS]


def _query_match(
    query: SemanticSliceQuery,
    *,
    kind: str,
    name: str,
    path: str,
    tags: Iterable[str],
) -> bool:
    if query.path is not None:
        try:
            wanted_path = _normalise_input_path(query.path)
        except SemanticSliceError:
            return False
        if path != wanted_path:
            return False
    lowered_name = name.casefold()
    lowered_path = path.casefold()
    lowered_tags = {item.casefold() for item in tags}
    wanted = query.value.strip().casefold()
    if query.kind == "symbol":
        return kind == "symbol" and (
            lowered_name == wanted or lowered_name.endswith("." + wanted) or lowered_name.endswith("::" + wanted)
        )
    if query.kind == "sink":
        if kind != "sink":
            return False
        return (
            wanted in lowered_name
            or wanted in lowered_tags
            or any(token in lowered_name for token in _query_tokens(wanted))
        )
    if query.kind == "call":
        if kind != "call":
            return False
        return (
            wanted in lowered_name
            or wanted in lowered_tags
            or any(token in lowered_name for token in _query_tokens(wanted))
        )
    if query.kind == "dataflow":
        if kind not in {"data", "source", "sink", "call"}:
            return False
        return bool(set(_query_tokens(wanted)) & (set(re.findall(r"[a-z0-9_$]+", lowered_name)) | lowered_tags))
    tokens = _query_tokens(query.value)
    if kind in {"source", "sink", "symbol", "call"}:
        return bool(set(tokens) & (set(re.findall(r"[a-z0-9_$]+", lowered_name)) | lowered_tags))
    return bool(set(tokens) & set(re.findall(r"[a-z0-9_$]+", lowered_path)))


def _node_id(path: str, kind: str, name: str, line: int, ordinal: int) -> str:
    safe_name = re.sub(r"[^A-Za-z0-9_$.-]+", "_", name)[:160] or "unit"
    return f"{path}::{kind}:{safe_name}:{line}:{ordinal}"


__all__ = ["_query_tokens", "_query_match", "_node_id"]
