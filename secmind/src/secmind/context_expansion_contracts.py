"""Deterministic semantic-neighbour expansion for immutable repository context."""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from secmind.repository_index import RepositoryFileEntry, RepositoryIndexDocument
from secmind.source_triage import source_triage_sort_key

MAX_CONTEXT_EDGES = 256
MAX_ANCHORS = 12
MAX_DISTANCE = 2
_TOKEN = re.compile(r"[^a-z0-9_./@-]+")


@dataclass(frozen=True, slots=True)
class SemanticContextPlan:
    ordered_paths: tuple[str, ...]
    edges: tuple[dict[str, str | int], ...]
    anchor_paths: tuple[str, ...]


def build_semantic_context_plan(
    document: RepositoryIndexDocument | SemanticSlice,
    *,
    available_paths: set[str] | None = None,
) -> SemanticContextPlan:
    if isinstance(document, SemanticSlice):
        return document.to_context_plan()
    if available_paths is None:
        available_paths = {item.path for item in document.files}
    entries = {item.path: item for item in document.files if item.path in available_paths}
    ranked = sorted(
        entries.values(),
        key=lambda item: source_triage_sort_key(
            score=item.security_score,
            size_bytes=item.size_bytes,
            path=item.path,
        ),
    )
    if not ranked:
        return SemanticContextPlan((), (), ())
    anchors = [
        item.path
        for item in ranked
        if item.security_score > 0 or item.dangerous_apis or item.security_signals or item.risk_hints
    ][:MAX_ANCHORS]
    if not anchors:
        anchors = [item.path for item in ranked[: min(3, len(ranked))]]

    aliases: dict[str, set[str]] = {}
    for entry in ranked:
        for alias in _path_aliases(entry):
            aliases.setdefault(alias, set()).add(entry.path)

    raw_edges: set[tuple[str, str, str]] = set()
    for entry in ranked:
        for imported in entry.imports[:256]:
            for target in _resolve_import(imported, aliases):
                if target != entry.path:
                    raw_edges.add((entry.path, target, "imports"))

    adjacency: dict[str, set[str]] = {path: set() for path in entries}
    for source, target, _kind in raw_edges:
        adjacency[source].add(target)
        adjacency[target].add(source)
    distance = {path: 0 for path in anchors}
    queue: deque[str] = deque(anchors)
    while queue:
        current = queue.popleft()
        if distance[current] >= MAX_DISTANCE:
            continue
        for neighbour in sorted(adjacency.get(current, ())):
            proposed = distance[current] + 1
            if neighbour in distance and distance[neighbour] <= proposed:
                continue
            distance[neighbour] = proposed
            queue.append(neighbour)

    base_rank = {item.path: index for index, item in enumerate(ranked)}
    ordered = sorted(
        entries,
        key=lambda path: (distance.get(path, MAX_DISTANCE + 1), base_rank[path], path.casefold()),
    )
    retained: list[dict[str, str | int]] = []
    for source, target, kind in sorted(raw_edges):
        if source not in distance and target not in distance:
            continue
        retained.append(
            {
                "source": source,
                "target": target,
                "relation": kind,
                "distance": min(distance.get(source, 99), distance.get(target, 99)),
            }
        )
        if len(retained) >= MAX_CONTEXT_EDGES:
            break
    return SemanticContextPlan(tuple(ordered), tuple(retained), tuple(anchors))


def _path_aliases(entry: RepositoryFileEntry) -> set[str]:
    path = PurePosixPath(entry.path)
    without_suffix = path.with_suffix("").as_posix().casefold()
    aliases = {
        path.stem.casefold(),
        without_suffix,
        without_suffix.replace("/", "."),
        path.name.casefold(),
    }
    if path.name.casefold() in {"__init__.py", "index.js", "index.ts", "index.tsx"}:
        parent = path.parent.as_posix().casefold()
        aliases.update({parent, parent.replace("/", "."), path.parent.name.casefold()})
    return {item for item in aliases if item and item != "."}


def _resolve_import(value: str, aliases: dict[str, set[str]]) -> set[str]:
    token = _TOKEN.sub("", value.casefold().strip()).lstrip("./")
    if not token:
        return set()
    candidates = {
        token,
        token.replace(".", "/"),
        token.replace("/", "."),
        PurePosixPath(token).name,
        PurePosixPath(token).stem,
    }
    resolved: set[str] = set()
    for candidate in candidates:
        resolved.update(aliases.get(candidate, ()))
        parts = candidate.replace(".", "/").split("/")
        for end in range(len(parts) - 1, 0, -1):
            prefix = "/".join(parts[:end])
            resolved.update(aliases.get(prefix, ()))
            resolved.update(aliases.get(prefix.replace("/", "."), ()))
            if resolved:
                break
    return resolved


SEMANTIC_SLICE_VERSION = "secmind.semantic-slice.v1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_LANGUAGE_SUFFIXES: dict[str, tuple[str, ...]] = {
    "python": (".py", ".pyi"),
    "javascript": (".js", ".jsx", ".mjs", ".cjs"),
    "typescript": (".ts", ".tsx", ".mts", ".cts"),
    "java": (".java",),
}
_TEXT_LANGUAGES = frozenset(_LANGUAGE_SUFFIXES)
_UNSUPPORTED_SOURCE_SUFFIXES = frozenset({".go", ".rs", ".c", ".cpp", ".h", ".cs", ".php", ".rb"})
_MAX_QUERY_TOKENS = 32
_MAX_SNIPPET_CHARS = 1_500


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


class SemanticSliceError(ValueError):
    """The immutable manifest or CAS input cannot be used for slicing."""


class SemanticSliceBudget(BaseModel):
    """Server-owned, deterministic limits for one semantic expansion.

    The limits apply before a parser is called.  In particular, a caller may
    never make a semantic query read an unbounded workspace or materialize all
    source bytes merely because a repository index exists.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_files: int = Field(default=32, ge=1, le=512)
    max_bytes: int = Field(default=512_000, ge=1, le=16 * 1024 * 1024)
    max_nodes: int = Field(default=512, ge=1, le=10_000)
    max_edges: int = Field(default=1_024, ge=1, le=20_000)
    max_depth: int = Field(default=4, ge=0, le=32)
    max_lines_per_file: int = Field(default=240, ge=1, le=10_000)
    max_snippet_chars: int = Field(default=_MAX_SNIPPET_CHARS, ge=80, le=20_000)


# Naming used by a few older integrations and by the gap planner prototype.
SemanticExpansionBudget = SemanticSliceBudget


class SemanticSliceQuery(BaseModel):
    """A small query language for task-, gap-, symbol-, call-, and flow-led slices."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal["task", "gap", "symbol", "sink", "call", "dataflow"]
    value: str = Field(min_length=1, max_length=4_000)
    path: str | None = Field(default=None, max_length=1_024)

    @classmethod
    def task(cls, value: str) -> SemanticSliceQuery:
        return cls(kind="task", value=value)

    @classmethod
    def gap(cls, value: str) -> SemanticSliceQuery:
        return cls(kind="gap", value=value)

    @classmethod
    def symbol(cls, value: str, *, path: str | None = None) -> SemanticSliceQuery:
        return cls(kind="symbol", value=value, path=path)

    @classmethod
    def sink(cls, value: str, *, path: str | None = None) -> SemanticSliceQuery:
        return cls(kind="sink", value=value, path=path)

    @classmethod
    def call(cls, value: str, *, path: str | None = None) -> SemanticSliceQuery:
        return cls(kind="call", value=value, path=path)

    @classmethod
    def dataflow(cls, value: str, *, path: str | None = None) -> SemanticSliceQuery:
        return cls(kind="dataflow", value=value, path=path)

    @classmethod
    def data_flow(cls, value: str, *, path: str | None = None) -> SemanticSliceQuery:
        """Compatibility spelling matching the emitted ``data_flow`` edge."""

        return cls.dataflow(value, path=path)


# Short alias for consumers that adopted the design name before the concrete
# module landed.
SemanticQuery = SemanticSliceQuery


class SemanticInputRef(BaseModel):
    """A path/hash pair from the invocation's immutable input manifest."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str = Field(min_length=1, max_length=4_096)
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    size_bytes: int = Field(ge=0)
    media_type: str = Field(default="application/octet-stream", min_length=1, max_length=200)
    artifact_id: str | None = Field(default=None, max_length=256)
    language: str | None = Field(default=None, max_length=64)

    @property
    def cas_ref(self) -> str:
        return f"cas://sha256/{self.sha256}"


class SemanticSourceRef(BaseModel):
    """A source locator whose bytes can be re-read from CAS."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    cas_ref: str
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)
    byte_start: int | None = Field(default=None, ge=0)
    byte_end: int | None = Field(default=None, ge=0)
    role: Literal["file", "symbol", "call", "source", "sink", "data", "import"] = "file"


class SemanticNode(BaseModel):
    """One bounded semantic unit; snippets are evidence, never instructions."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    node_id: str = Field(min_length=1, max_length=2_000)
    kind: Literal["file", "symbol", "call", "source", "sink", "data", "import"]
    name: str = Field(min_length=1, max_length=512)
    path: str = Field(min_length=1, max_length=4_096)
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    cas_ref: str = Field(min_length=1, max_length=256)
    line: int = Field(default=1, ge=1)
    end_line: int = Field(default=1, ge=1)
    snippet: str = Field(default="", max_length=20_000)
    tags: tuple[str, ...] = ()


class SemanticEdge(BaseModel):
    """A typed call/import/data-flow relationship."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source: str
    target: str
    relation: Literal["imports", "calls", "data_flow", "defines", "contains", "sanitized"]
    source_path: str
    target_path: str
    source_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    target_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    evidence: tuple[SemanticSourceRef, ...] = ()


class SemanticUnresolved(BaseModel):
    """A typed limitation retained instead of being converted to a clean result."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: Literal[
        "manifest_invalid",
        "cas_missing",
        "cas_hash_mismatch",
        "cas_size_mismatch",
        "budget_files",
        "budget_bytes",
        "budget_nodes",
        "budget_edges",
        "unsupported_language",
        "parse_error",
        "import_unresolved",
        "import_ambiguous",
        "call_unresolved",
        "query_unmatched",
        "query_ambiguous",
        "source_truncated",
    ]
    path: str | None = None
    detail: str = Field(min_length=1, max_length=1_000)
    line: int | None = Field(default=None, ge=1)


class SemanticSliceCoverage(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    manifest_files: int = Field(ge=0)
    considered_files: int = Field(ge=0)
    parsed_files: int = Field(ge=0)
    selected_files: int = Field(ge=0)
    loaded_bytes: int = Field(ge=0)
    node_count: int = Field(ge=0)
    edge_count: int = Field(ge=0)
    source_count: int = Field(ge=0)
    sink_count: int = Field(ge=0)


class SemanticSlice(BaseModel):
    """Immutable, CAS-bound semantic evidence returned by a query."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = SEMANTIC_SLICE_VERSION
    query: SemanticSliceQuery
    manifest_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    manifest: tuple[SemanticInputRef, ...] = ()
    files: tuple[str, ...] = ()
    anchor_paths: tuple[str, ...] = ()
    nodes: tuple[SemanticNode, ...] = ()
    edges: tuple[SemanticEdge, ...] = ()
    source_refs: tuple[SemanticSourceRef, ...] = ()
    truncated: bool = False
    truncation_reasons: tuple[str, ...] = ()
    unresolved: tuple[SemanticUnresolved, ...] = ()
    coverage: SemanticSliceCoverage
    slice_digest: str = Field(default="", pattern=r"^[a-f0-9]{64}$|^$")

    @model_validator(mode="after")
    def seal_digest(self) -> SemanticSlice:
        payload = self.model_dump(mode="json", exclude={"slice_digest"})
        digest = hashlib.sha256(_canonical_json(payload)).hexdigest()
        if self.slice_digest and self.slice_digest != digest:
            raise SemanticSliceError("semantic slice digest does not match its typed payload")
        object.__setattr__(self, "slice_digest", digest)
        return self

    @property
    def digest(self) -> str:
        return self.slice_digest

    @property
    def semantic_context_edges(self) -> tuple[dict[str, str | int], ...]:
        """Compatibility view consumed by Canonical Context."""

        return tuple(self._context_edges())

    def _context_edges(self) -> list[dict[str, str | int]]:
        rows: set[tuple[str, str, str]] = set()
        for edge in self.edges:
            if edge.relation not in {"imports", "calls", "data_flow", "sanitized"}:
                continue
            if edge.source_path == edge.target_path and edge.relation == "data_flow":
                continue
            rows.add((edge.source_path, edge.target_path, edge.relation))
        distance: dict[str, int] = {path: 0 for path in self.anchor_paths}
        adjacency: dict[str, set[str]] = defaultdict(set)
        for source, target, _relation in rows:
            adjacency[source].add(target)
            adjacency[target].add(source)
        queue: deque[str] = deque(self.anchor_paths)
        while queue:
            path = queue.popleft()
            for neighbour in sorted(adjacency.get(path, ())):
                if neighbour in distance:
                    continue
                distance[neighbour] = distance[path] + 1
                queue.append(neighbour)
        result: list[dict[str, str | int]] = []
        for source, target, relation in sorted(rows):
            if source not in self.files or target not in self.files:
                continue
            result.append(
                {
                    "source": source,
                    "target": target,
                    "relation": relation,
                    "distance": min(
                        distance.get(source, MAX_DISTANCE + 1),
                        distance.get(target, MAX_DISTANCE + 1),
                    ),
                }
            )
            if len(result) >= MAX_CONTEXT_EDGES:
                break
        return result

    def to_context_plan(self) -> SemanticContextPlan:
        """Project a semantic slice to the old path/edge-only API."""

        context_edges = self._context_edges()
        distance: dict[str, int] = {path: 0 for path in self.anchor_paths}
        adjacency: dict[str, set[str]] = defaultdict(set)
        for edge in context_edges:
            adjacency[str(edge["source"])].add(str(edge["target"]))
            adjacency[str(edge["target"])].add(str(edge["source"]))
        queue: deque[str] = deque(self.anchor_paths)
        while queue:
            current = queue.popleft()
            for neighbour in sorted(adjacency.get(current, ())):
                if neighbour in distance:
                    continue
                distance[neighbour] = distance[current] + 1
                queue.append(neighbour)
        ordered = tuple(
            sorted(
                self.files,
                key=lambda path: (distance.get(path, MAX_DISTANCE + 1), path.casefold(), path),
            )
        )
        return SemanticContextPlan(ordered, tuple(context_edges), tuple(self.anchor_paths))

    # This name is convenient for Gap planner adapters and does not alter the
    # existing planner contract.
    compatibility_plan = to_context_plan


__all__ = [
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
    "build_semantic_context_plan",
]
