"""Compatibility facade for bounded semantic context expansion.

The contracts, immutable input resolver, language adapters, and graph slicer
live in small sibling modules.  This module intentionally keeps the original
import surface used by Canonical Context and gap planning.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from secmind.context_expansion_contracts import (
    MAX_ANCHORS,
    MAX_CONTEXT_EDGES,
    MAX_DISTANCE,
    SEMANTIC_SLICE_VERSION,
    SemanticContextPlan,
    SemanticEdge,
    SemanticExpansionBudget,
    SemanticInputRef,
    SemanticNode,
    SemanticQuery,
    SemanticSlice,
    SemanticSliceBudget,
    SemanticSliceCoverage,
    SemanticSliceError,
    SemanticSliceQuery,
    SemanticSourceRef,
    SemanticUnresolved,
    _path_aliases,
    _resolve_import,
    build_semantic_context_plan,
)
from secmind.context_expansion_slicer import expand_semantic_slice
from secmind.repository_index import RepositoryIndexDocument


@dataclass(frozen=True, slots=True)
class SemanticSliceFrame:
    content: str
    line_start: int
    line_end: int


def semantic_slice_budget(max_context_bytes: int) -> SemanticSliceBudget:
    """Derive a fixed second-pass reserve from the canonical context cap."""

    context_limit = max(1, int(max_context_bytes))
    reserved_bytes = max(1, min(64 * 1024, context_limit // 4))
    return SemanticSliceBudget(
        max_files=32,
        max_bytes=reserved_bytes,
        max_nodes=256,
        max_edges=512,
        max_depth=4,
        max_lines_per_file=160,
        max_snippet_chars=2_400,
    )


def semantic_slice_query(objective: str, document: RepositoryIndexDocument) -> SemanticSliceQuery:
    """Choose one stable query anchor; calls/data-flow stay graph edges."""

    dangerous_apis = sorted(
        {api.strip() for entry in document.files for api in entry.dangerous_apis if api.strip()},
        key=lambda value: (value.casefold(), value),
    )
    if dangerous_apis:
        return SemanticSliceQuery.sink(dangerous_apis[0][:4_000])
    objective_terms = {value.casefold() for value in re.findall(r"[A-Za-z0-9_$]{3,}", objective)}
    symbols = sorted(
        {symbol.strip() for entry in document.files for symbol in entry.symbols if symbol.strip()},
        key=lambda value: (value.casefold(), value),
    )
    for symbol in symbols:
        if symbol.casefold() in objective_terms:
            return SemanticSliceQuery.symbol(symbol[:4_000])
    return SemanticSliceQuery.task(objective[:4_000])


def semantic_slice_frames(
    semantic_slice: SemanticSlice,
    *,
    display_paths: dict[str, str],
    max_bytes: int,
) -> tuple[dict[str, list[SemanticSliceFrame]], int]:
    """Render typed nodes as bounded, explicitly untrusted source frames."""

    grouped: dict[str, list[SemanticSliceFrame]] = {}
    seen: set[tuple[str, int, int, str]] = set()
    remaining = max(0, max_bytes)
    ordered_nodes = sorted(
        semantic_slice.nodes,
        key=lambda item: (
            item.path.casefold(),
            item.path,
            item.line,
            item.end_line,
            item.kind,
            item.name.casefold(),
            item.node_id,
        ),
    )
    for node in ordered_nodes:
        display_path = display_paths.get(node.path)
        snippet = node.snippet.strip("\r\n")
        if display_path is None or not snippet or remaining <= 0:
            continue
        dedupe_key = (node.path, node.line, node.end_line, snippet)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        metadata = json.dumps(
            {
                "cas_ref": node.cas_ref,
                "kind": node.kind,
                "line_end": node.end_line,
                "line_start": node.line,
                "name": node.name,
                "node_id": node.node_id,
                "path": display_path,
                "tags": list(node.tags),
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        prefix = "\n<SEMANTIC_NODE_JSON>\n" + metadata + "\n</SEMANTIC_NODE_JSON>\n<SEMANTIC_SNIPPET>\n"
        suffix = "\n</SEMANTIC_SNIPPET>\n"
        fixed_bytes = len((prefix + suffix).encode("utf-8"))
        if fixed_bytes >= remaining:
            break
        snippet_limit = min(len(snippet.encode("utf-8")), remaining - fixed_bytes)
        bounded_snippet = snippet.encode("utf-8")[:snippet_limit].decode("utf-8", errors="ignore")
        frame = prefix + bounded_snippet + suffix
        encoded_size = len(frame.encode("utf-8"))
        if encoded_size > remaining:
            break
        grouped.setdefault(display_path, []).append(SemanticSliceFrame(frame, node.line, node.end_line))
        remaining -= encoded_size
    return grouped, max(0, max_bytes - remaining)


def build_semantic_slice(*args: Any, **kwargs: Any) -> SemanticSlice:
    """Compatibility constructor for callers using the design vocabulary."""

    return expand_semantic_slice(*args, **kwargs)


query_semantic_slice = expand_semantic_slice
build_semantic_context_slice = expand_semantic_slice


__all__ = [
    "MAX_CONTEXT_EDGES",
    "MAX_ANCHORS",
    "MAX_DISTANCE",
    "SEMANTIC_SLICE_VERSION",
    "SemanticContextPlan",
    "SemanticSliceError",
    "SemanticSliceBudget",
    "SemanticExpansionBudget",
    "SemanticSliceQuery",
    "SemanticQuery",
    "SemanticInputRef",
    "SemanticSourceRef",
    "SemanticNode",
    "SemanticEdge",
    "SemanticUnresolved",
    "SemanticSliceCoverage",
    "SemanticSlice",
    "SemanticSliceFrame",
    "build_semantic_context_plan",
    "semantic_slice_budget",
    "semantic_slice_query",
    "semantic_slice_frames",
    "expand_semantic_slice",
    "build_semantic_slice",
    "query_semantic_slice",
    "build_semantic_context_slice",
    "_path_aliases",
    "_resolve_import",
]
