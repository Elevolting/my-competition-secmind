"""Bounded manifest loading and import resolution for semantic slices."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass

from secmind.artifact_store import ContentAddressedArtifactStore
from secmind.context_expansion_contracts import (
    SemanticInputRef,
    SemanticSliceBudget,
    SemanticSliceQuery,
    SemanticUnresolved,
)
from secmind.context_expansion_indexer import (
    _candidate_paths,
    _decode_source,
    _FileFacts,
    _is_probably_local_import,
    _load_cas_bytes,
    _manifest_rank,
    _normalise_input_path,
    _path_aliases_for_ref,
)
from secmind.context_expansion_languages import _parse_facts
from secmind.context_expansion_query import _query_tokens
from secmind.repository_index import RepositoryFileEntry, RepositoryIndexDocument


@dataclass(frozen=True, slots=True)
class _LoadedSemanticFacts:
    indexed: Mapping[str, RepositoryFileEntry]
    refs_by_path: Mapping[str, SemanticInputRef]
    aliases: Mapping[str, set[str]]
    facts_by_path: Mapping[str, _FileFacts]
    import_targets: Mapping[str, tuple[str, ...]]
    unresolved: tuple[SemanticUnresolved, ...]
    loaded_bytes: int
    considered: int


def _load_semantic_facts(
    refs: Sequence[SemanticInputRef],
    *,
    document: RepositoryIndexDocument | None,
    query: SemanticSliceQuery,
    limits: SemanticSliceBudget,
    cas_store: ContentAddressedArtifactStore | None,
    content_loader: Callable[[str], bytes] | Mapping[str, bytes] | None,
    source_bytes: Mapping[str, bytes] | None,
) -> _LoadedSemanticFacts:
    """Load only manifest-listed CAS bytes and resolve local imports."""

    indexed = {_normalise_input_path(entry.path): entry for entry in (document.files if document is not None else ())}
    refs_by_path = {item.path: item for item in refs}
    aliases: dict[str, set[str]] = defaultdict(set)
    for ref in refs:
        for alias in _path_aliases_for_ref(ref):
            aliases[alias].add(ref.path)

    query_terms = set(_query_tokens(query.value))
    ranked_refs = sorted(
        refs,
        key=lambda ref: (
            -_manifest_rank(ref, indexed.get(ref.path), query, query_terms),
            ref.path.casefold(),
            ref.path,
        ),
    )
    facts_by_path: dict[str, _FileFacts] = {}
    unresolved: list[SemanticUnresolved] = []
    loaded_bytes = 0
    considered = 0
    for ref in ranked_refs:
        considered += 1
        if len(facts_by_path) >= limits.max_files:
            unresolved.append(
                SemanticUnresolved(
                    code="budget_files",
                    path=ref.path,
                    detail="semantic file budget reached",
                )
            )
            continue
        if loaded_bytes + ref.size_bytes > limits.max_bytes:
            unresolved.append(
                SemanticUnresolved(
                    code="budget_bytes",
                    path=ref.path,
                    detail=(f"byte budget={limits.max_bytes}, required={ref.size_bytes}, used={loaded_bytes}"),
                )
            )
            continue
        payload, issue = _load_cas_bytes(
            ref,
            cas_store=cas_store,
            content_loader=content_loader,
            source_bytes=source_bytes,
        )
        if issue is not None:
            unresolved.append(issue)
            continue
        if payload is None:  # pragma: no cover - loader returns an issue
            unresolved.append(
                SemanticUnresolved(
                    code="cas_missing",
                    path=ref.path,
                    detail="CAS bytes are unavailable",
                )
            )
            continue
        loaded_bytes += len(payload)
        text = _decode_source(payload)
        if text is None:
            unresolved.append(
                SemanticUnresolved(
                    code="unsupported_language",
                    path=ref.path,
                    detail="source bytes are binary or not UTF-8",
                )
            )
            continue
        facts = _parse_facts(ref, text)
        facts_by_path[ref.path] = facts
        unresolved.extend(facts.unresolved)
        if len(text.splitlines()) > limits.max_lines_per_file:
            unresolved.append(
                SemanticUnresolved(
                    code="source_truncated",
                    path=ref.path,
                    detail=(f"line budget={limits.max_lines_per_file}, observed={len(text.splitlines())}"),
                )
            )

    import_targets: dict[str, tuple[str, ...]] = {}
    for path, facts in sorted(facts_by_path.items()):
        for imported in facts.imports:
            targets = _candidate_paths(facts, imported, refs_by_path, aliases)
            import_targets[f"{path}\x00{imported}"] = targets
            if not targets and _is_probably_local_import(
                imported,
                current_path=path,
                aliases=aliases,
            ):
                unresolved.append(
                    SemanticUnresolved(
                        code="import_unresolved",
                        path=path,
                        detail=f"no unique manifest target for import {imported}",
                    )
                )
            elif len(targets) > 1:
                unresolved.append(
                    SemanticUnresolved(
                        code="import_ambiguous",
                        path=path,
                        detail=(f"multiple manifest targets for import {imported}: {', '.join(targets[:8])}"),
                    )
                )
    for path in sorted(facts_by_path):
        facts = facts_by_path[path]
        for imported in facts.imports:
            targets = import_targets.get(f"{path}\x00{imported}", ())
            if targets and targets[0] not in facts_by_path:
                unresolved.append(
                    SemanticUnresolved(
                        code=("budget_files" if len(facts_by_path) >= limits.max_files else "cas_missing"),
                        path=path,
                        detail=f"import target is not materialized: {targets[0]}",
                    )
                )

    return _LoadedSemanticFacts(
        indexed=indexed,
        refs_by_path=refs_by_path,
        aliases=aliases,
        facts_by_path=facts_by_path,
        import_targets=import_targets,
        unresolved=tuple(unresolved),
        loaded_bytes=loaded_bytes,
        considered=considered,
    )


__all__ = ["_LoadedSemanticFacts", "_load_semantic_facts"]
