"""Bounded deterministic semantic graph expansion and compatibility builders."""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Callable, Iterable, Mapping, Sequence
from typing import Any, Literal

from secmind.artifact_store import ContentAddressedArtifactStore
from secmind.context_expansion_contracts import (
    SemanticEdge,
    SemanticInputRef,
    SemanticNode,
    SemanticSlice,
    SemanticSliceBudget,
    SemanticSliceCoverage,
    SemanticSliceError,
    SemanticSliceQuery,
    SemanticSourceRef,
    SemanticUnresolved,
)
from secmind.context_expansion_indexer import (
    _canonical_manifest,
    _coerce_query,
    _Event,
    _manifest_from_document,
    _normalise_input_path,
    _RawEdge,
    _snippet,
    _source_ref,
)
from secmind.context_expansion_loader import _load_semantic_facts
from secmind.context_expansion_query import _node_id, _query_match, _query_tokens
from secmind.repository_index import RepositoryIndexDocument
from secmind.schemas import InputArtifact


def expand_semantic_slice(
    document: RepositoryIndexDocument | None = None,
    *,
    input_manifest: Sequence[SemanticInputRef | InputArtifact | Mapping[str, Any]] | None = None,
    manifest: Sequence[SemanticInputRef | InputArtifact | Mapping[str, Any]] | None = None,
    cas_store: ContentAddressedArtifactStore | None = None,
    content_loader: Callable[[str], bytes] | Mapping[str, bytes] | None = None,
    source_bytes: Mapping[str, bytes] | None = None,
    query: SemanticSliceQuery | Mapping[str, Any] | str | None = None,
    task: str | None = None,
    gap: str | None = None,
    symbol: str | None = None,
    sink: str | None = None,
    call: str | None = None,
    dataflow: str | None = None,
    data_flow: str | None = None,
    budget: SemanticSliceBudget | Mapping[str, Any] | None = None,
    available_paths: set[str] | None = None,
) -> SemanticSlice:
    """Build a deterministic cross-file semantic slice from immutable CAS bytes.

    The function accepts a repository index for ranking and import metadata,
    but source bytes are read exclusively through ``cas_store``,
    ``content_loader`` or the explicit ``source_bytes`` mapping.  There is no
    workspace fallback: this prevents a second read from observing a changed
    file after ingestion.
    """

    if input_manifest is not None and manifest is not None:
        raise SemanticSliceError("provide only one of input_manifest or manifest")
    refs = _manifest_from_document(document, input_manifest if input_manifest is not None else manifest)
    if available_paths is not None:
        normalized_available = {_normalise_input_path(item) for item in available_paths}
        refs = tuple(item for item in refs if item.path in normalized_available)
    if not refs:
        raise SemanticSliceError("semantic expansion manifest is empty")
    selected_query = _coerce_query(
        query,
        task=task,
        gap=gap,
        symbol=symbol,
        sink=sink,
        call=call,
        dataflow=dataflow,
        data_flow=data_flow,
    )
    limits = budget if isinstance(budget, SemanticSliceBudget) else SemanticSliceBudget.model_validate(budget or {})
    manifest_digest = _canonical_manifest(refs)

    loaded = _load_semantic_facts(
        refs,
        document=document,
        query=selected_query,
        limits=limits,
        cas_store=cas_store,
        content_loader=content_loader,
        source_bytes=source_bytes,
    )
    facts_by_path = loaded.facts_by_path
    import_targets = loaded.import_targets
    unresolved = list(loaded.unresolved)
    loaded_bytes = loaded.loaded_bytes
    considered = loaded.considered

    node_rows: dict[str, tuple[str, str, str, SemanticInputRef, int, int, tuple[str, ...]]] = {}
    ids_by_event: dict[tuple[str, str, int, str], str] = {}
    file_ids: dict[str, str] = {}
    events_by_path: dict[str, list[tuple[_Event, str]]] = defaultdict(list)

    for path, facts in sorted(facts_by_path.items()):
        ref = facts.ref
        file_id = f"{path}::file"
        file_ids[path] = file_id
        node_rows[file_id] = ("file", path, path, ref, 1, max(1, len(facts.text.splitlines())), ())
        all_events = [*facts.symbols, *facts.calls, *facts.sources, *facts.sinks, *facts.data]
        kind_counts: dict[str, int] = defaultdict(int)
        for event in sorted(all_events, key=lambda item: (item.line, item.kind, item.name, item.end_line)):
            key = (path, event.kind, event.line, event.name)
            ordinal = kind_counts[event.kind]
            kind_counts[event.kind] += 1
            node = _node_id(path, event.kind, event.name, event.line, ordinal)
            ids_by_event[key] = node
            node_rows[node] = (
                event.kind,
                event.name,
                path,
                ref,
                event.line,
                event.end_line,
                event.tags,
            )
            events_by_path[path].append((event, node))

    raw_edges: set[_RawEdge] = set()

    def add_edge(
        source: str,
        target: str,
        relation: Literal["imports", "calls", "data_flow", "defines", "contains", "sanitized"],
        *,
        line: int | None = None,
    ) -> None:
        if source == target or source not in node_rows or target not in node_rows:
            return
        source_info = node_rows[source]
        target_info = node_rows[target]
        evidence: tuple[SemanticSourceRef, ...] = ()
        if line is not None:
            evidence = (_source_ref(source_info[3], line=line, end_line=line, role="call"),)
        raw_edges.add(
            _RawEdge(
                source=source,
                target=target,
                relation=relation,
                source_path=source_info[2],
                target_path=target_info[2],
                evidence=evidence,
            )
        )

    # File imports and file containment are always useful context edges.
    for path, facts in sorted(facts_by_path.items()):
        for imported in facts.imports:
            targets = import_targets.get(f"{path}\x00{imported}", ())
            if len(targets) == 1 and targets[0] in file_ids:
                add_edge(file_ids[path], file_ids[targets[0]], "imports")
        for event, node in events_by_path[path]:
            add_edge(file_ids[path], node, "contains", line=event.line)
            if event.kind == "symbol":
                add_edge(file_ids[path], node, "defines", line=event.line)

    symbol_ids: dict[tuple[str, str], list[str]] = defaultdict(list)
    for path, facts in facts_by_path.items():
        for event in facts.symbols:
            symbol_node = ids_by_event.get((path, "symbol", event.line, event.name))
            if symbol_node is not None:
                symbol_ids[(path, event.name.casefold())].append(symbol_node)

    def resolve_symbol(path: str, name: str) -> tuple[str, ...]:
        facts = facts_by_path[path]
        clean = name.rsplit(".", 1)[-1].casefold()
        first = name.split(".", 1)[0]
        binding = facts.import_bindings.get(first)
        if binding and ":" in binding:
            module, imported_symbol = binding.rsplit(":", 1)
            targets = import_targets.get(f"{path}\x00{module}", ())
            if len(targets) == 1:
                return tuple(symbol_ids.get((targets[0], imported_symbol.casefold()), ()))
        local = tuple(symbol_ids.get((path, clean), ()))
        if local:
            return local
        candidates = [
            node
            for (_candidate_path, candidate_name), nodes in symbol_ids.items()
            if candidate_name == clean
            for node in nodes
        ]
        return tuple(sorted(candidates))

    # Build call and cross-file data-flow edges.  Incoming origins are keyed
    # by target symbols so conservative function parameters can carry taint
    # across a bounded call edge without reading another file.
    incoming_origins: dict[str, set[str]] = defaultdict(set)
    for path, facts in sorted(facts_by_path.items()):
        tainted: dict[str, set[str]] = defaultdict(set)
        for function_symbol in facts.symbols:
            symbol_node = ids_by_event.get((path, "symbol", function_symbol.line, function_symbol.name))
            if symbol_node is not None:
                for name in function_symbol.defines:
                    tainted[name].update(incoming_origins.get(symbol_node, ()))
        for source in facts.sources:
            source_node = ids_by_event.get((path, "source", source.line, source.name))
            if source_node is not None:
                for name in source.defines:
                    tainted[name].add(source_node)
        source_by_line: dict[int, set[str]] = defaultdict(set)
        for source in facts.sources:
            source_node = ids_by_event.get((path, "source", source.line, source.name))
            if source_node is not None:
                source_by_line[source.line].add(source_node)
        for event in sorted(facts.data, key=lambda item: (item.line, item.name)):
            value_node = ids_by_event.get((path, "data", event.line, event.name))
            if value_node is None:
                continue
            origins: set[str] = set(source_by_line.get(event.line, ())) if event.source_hint else set()
            for used in event.uses:
                origins.update(tainted.get(used, ()))
            if event.sanitizer:
                for origin in sorted(origins):
                    add_edge(origin, value_node, "sanitized", line=event.line)
            else:
                for origin in sorted(origins):
                    add_edge(origin, value_node, "data_flow", line=event.line)
                for name in event.defines:
                    tainted[name].update(origins)
        for event in facts.calls:
            call_node = ids_by_event.get((path, "call", event.line, event.name))
            if call_node is None:
                continue
            targets = resolve_symbol(path, event.name)
            if not targets:
                # Unknown calls are retained as unresolved only when they look
                # local; standard library and framework calls are not gaps.
                first_name = event.name.split(".", 1)[0]
                if (
                    "." not in event.name
                    and first_name not in facts.import_bindings
                    and event.name.casefold()
                    not in {
                        "print",
                        "len",
                        "str",
                        "int",
                        "bool",
                        "string",
                        "exec",
                        "execute",
                        "get",
                        "read",
                        "write",
                        "exchange",
                        "deserialize",
                    }
                ):
                    unresolved.append(
                        SemanticUnresolved(
                            code="call_unresolved",
                            path=path,
                            detail=f"no manifest symbol for call {event.name}",
                            line=event.line,
                        )
                    )
            origins = {origin for used in event.uses for origin in tainted.get(used, ())}
            for target in targets[:4]:
                add_edge(call_node, target, "calls", line=event.line)
                for origin in sorted(origins):
                    add_edge(origin, target, "data_flow", line=event.line)
                incoming_origins[target].update(origins)
        for event in facts.sinks:
            sink_node = ids_by_event.get((path, "sink", event.line, event.name))
            if sink_node is None:
                continue
            origins = set(source_by_line.get(event.line, ())) if event.source_hint else set()
            for used in event.uses:
                origins.update(tainted.get(used, ()))
            for origin in sorted(origins):
                add_edge(origin, sink_node, "data_flow", line=event.line)

    # Select the bounded neighbourhood around query matches.  File nodes and
    # evidence nodes share the same graph, so an import/call/data-flow path can
    # cross languages without a second traversal implementation.
    seed_ids: list[str] = []
    for node, (kind, name, path, _ref, _line, _end, tags) in node_rows.items():
        if _query_match(selected_query, kind=kind, name=name, path=path, tags=tags):
            seed_ids.append(node)
    seed_ids = sorted(set(seed_ids))
    if selected_query.kind in {"symbol", "sink", "call", "dataflow"} and not seed_ids:
        unresolved.append(
            SemanticUnresolved(
                code="query_unmatched",
                detail=f"query did not match {selected_query.kind}:{selected_query.value}",
            )
        )
    if not seed_ids:
        seed_ids = sorted(
            node
            for node, (kind, _name, _path, _ref, _line, _end, tags) in node_rows.items()
            if kind in {"source", "sink"} or "dangerous" in {tag.casefold() for tag in tags}
        )
    if not seed_ids:
        seed_ids = sorted(file_ids.values())[:1]

    adjacency: dict[str, set[str]] = defaultdict(set)
    for edge in raw_edges:
        adjacency[edge.source].add(edge.target)
        adjacency[edge.target].add(edge.source)
    distance: dict[str, int] = {}
    queue: deque[str] = deque()
    for seed in seed_ids:
        if seed not in distance:
            distance[seed] = 0
            queue.append(seed)
    while queue:
        current = queue.popleft()
        if distance[current] >= limits.max_depth:
            continue
        for neighbour in sorted(adjacency.get(current, ())):
            proposed = distance[current] + 1
            if neighbour in distance and distance[neighbour] <= proposed:
                continue
            if len(distance) >= limits.max_nodes:
                break
            distance[neighbour] = proposed
            queue.append(neighbour)
    truncation_reasons: set[str] = set()
    if len(distance) >= limits.max_nodes and len(distance) < len(node_rows):
        truncation_reasons.add("node_budget")
        unresolved.append(SemanticUnresolved(code="budget_nodes", detail="semantic node budget reached"))

    selected_nodes = set(distance)
    selected_edges = [
        edge
        for edge in sorted(raw_edges, key=lambda item: (item.source, item.target, item.relation))
        if edge.source in selected_nodes and edge.target in selected_nodes
    ]
    if len(selected_edges) > limits.max_edges:
        truncation_reasons.add("edge_budget")
        unresolved.append(SemanticUnresolved(code="budget_edges", detail="semantic edge budget reached"))
        selected_edges = selected_edges[: limits.max_edges]
    if any(item.code in {"budget_files", "budget_bytes"} for item in unresolved):
        truncation_reasons.update(
            item.code.removeprefix("budget_") for item in unresolved if item.code in {"budget_files", "budget_bytes"}
        )
    if any(item.code == "source_truncated" for item in unresolved):
        truncation_reasons.add("lines")

    node_models: list[SemanticNode] = []
    for node in sorted(
        selected_nodes,
        key=lambda item: (
            node_rows[item][2].casefold(),
            node_rows[item][4],
            node_rows[item][0],
            node_rows[item][1],
            item,
        ),
    ):
        kind, name, path, ref, line, end_line, tags = node_rows[node]
        node_models.append(
            SemanticNode(
                node_id=node,
                kind=kind,  # type: ignore[arg-type]
                name=name,
                path=path,
                sha256=ref.sha256,
                cas_ref=ref.cas_ref,
                line=line,
                end_line=end_line,
                snippet=_snippet(
                    facts_by_path[path].text,
                    line,
                    max_lines=limits.max_lines_per_file,
                    max_chars=limits.max_snippet_chars,
                ),
                tags=tuple(sorted(tags)),
            )
        )
    edge_models: list[SemanticEdge] = []
    for edge in selected_edges:
        source_ref = node_rows[edge.source][3]
        target_ref = node_rows[edge.target][3]
        edge_models.append(
            SemanticEdge(
                source=edge.source,
                target=edge.target,
                relation=edge.relation,
                source_path=edge.source_path,
                target_path=edge.target_path,
                source_sha256=source_ref.sha256,
                target_sha256=target_ref.sha256,
                evidence=edge.evidence,
            )
        )
    source_models: list[SemanticSourceRef] = []
    seen_refs: set[tuple[str, int, str]] = set()
    for semantic_node in node_models:
        if semantic_node.kind == "file":
            continue
        role = semantic_node.kind
        source_key = (semantic_node.path, semantic_node.line, role)
        if source_key in seen_refs:
            continue
        seen_refs.add(source_key)
        source_models.append(
            _source_ref(
                node_rows[semantic_node.node_id][3],
                line=semantic_node.line,
                end_line=semantic_node.end_line,
                role=role,
            )
        )
    selected_files = sorted(
        {node_rows[node][2] for node in selected_nodes},
        key=lambda path: (
            min(
                (distance[node] for node in selected_nodes if node_rows[node][2] == path),
                default=999,
            ),
            path.casefold(),
            path,
        ),
    )
    anchors = tuple(
        sorted(
            {node_rows[node][2] for node in seed_ids if node in node_rows},
            key=lambda path: (path.casefold(), path),
        )
    )
    final_unresolved = _dedupe_unresolved(unresolved)[:256]
    coverage = SemanticSliceCoverage(
        manifest_files=len(refs),
        considered_files=considered,
        parsed_files=len(facts_by_path),
        selected_files=len(selected_files),
        loaded_bytes=loaded_bytes,
        node_count=len(node_models),
        edge_count=len(edge_models),
        source_count=sum(1 for node in node_models if node.kind == "source"),
        sink_count=sum(1 for node in node_models if node.kind == "sink"),
    )
    return SemanticSlice(
        query=selected_query,
        manifest_digest=manifest_digest,
        manifest=refs,
        files=tuple(selected_files),
        anchor_paths=anchors,
        nodes=tuple(node_models),
        edges=tuple(edge_models),
        source_refs=tuple(source_models),
        truncated=bool(truncation_reasons),
        truncation_reasons=tuple(sorted(truncation_reasons)),
        unresolved=tuple(final_unresolved),
        coverage=coverage,
    )


def _dedupe_unresolved(items: Iterable[SemanticUnresolved]) -> list[SemanticUnresolved]:
    unique: dict[tuple[str, str | None, str, int | None], SemanticUnresolved] = {}
    for item in items:
        key = (item.code, item.path, item.detail, item.line)
        unique[key] = item
    return sorted(unique.values(), key=lambda item: (item.code, item.path or "", item.line or 0, item.detail))


__all__ = ["expand_semantic_slice", "_query_tokens", "_query_match", "_node_id", "_dedupe_unresolved"]
