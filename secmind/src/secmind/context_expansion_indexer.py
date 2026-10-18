"""Immutable manifest, CAS, and deterministic resolver helpers for semantic slicing."""

from __future__ import annotations

import hashlib
import re
import unicodedata
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any, Literal, cast

from secmind.artifact_store import ContentAddressedArtifactStore
from secmind.context_expansion_contracts import (
    _LANGUAGE_SUFFIXES,
    _SHA256,
    _TEXT_LANGUAGES,
    SemanticInputRef,
    SemanticSliceError,
    SemanticSliceQuery,
    SemanticSourceRef,
    SemanticUnresolved,
    _canonical_json,
)
from secmind.repository_index import RepositoryFileEntry, RepositoryIndexDocument
from secmind.schemas import InputArtifact


@dataclass(frozen=True, slots=True)
class _Event:
    kind: Literal["symbol", "call", "source", "sink", "data", "import"]
    name: str
    line: int
    end_line: int
    uses: tuple[str, ...] = ()
    defines: tuple[str, ...] = ()
    source_hint: bool = False
    sanitizer: bool = False
    tags: tuple[str, ...] = ()


@dataclass(slots=True)
class _FileFacts:
    ref: SemanticInputRef
    language: str
    text: str
    symbols: list[_Event] = field(default_factory=list)
    calls: list[_Event] = field(default_factory=list)
    sources: list[_Event] = field(default_factory=list)
    sinks: list[_Event] = field(default_factory=list)
    data: list[_Event] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    import_bindings: dict[str, str] = field(default_factory=dict)
    unresolved: list[SemanticUnresolved] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class _RawEdge:
    source: str
    target: str
    relation: Literal["imports", "calls", "data_flow", "defines", "contains", "sanitized"]
    source_path: str
    target_path: str
    evidence: tuple[SemanticSourceRef, ...] = ()


def _normalise_input_path(value: object) -> str:
    if not isinstance(value, str):
        raise SemanticSliceError("input manifest path must be a string")
    raw = unicodedata.normalize("NFC", value.replace("\\", "/"))
    if not raw or raw.startswith("/") or re.match(r"^[A-Za-z]:/", raw) or ".." in PurePosixPath(raw).parts:
        raise SemanticSliceError("input manifest contains an unsafe path")
    if any(ord(char) < 32 or ord(char) == 127 for char in raw):
        raise SemanticSliceError("input manifest path contains control characters")
    normalized = PurePosixPath(raw).as_posix()
    if normalized in {"", "."} or any(part in {"", "."} for part in PurePosixPath(normalized).parts):
        raise SemanticSliceError("input manifest contains a non-canonical path")
    return normalized


def _canonical_manifest(refs: Sequence[SemanticInputRef]) -> str:
    payload = [
        {
            "path": item.path,
            "sha256": item.sha256,
            "size_bytes": item.size_bytes,
            "media_type": item.media_type,
            "artifact_id": item.artifact_id,
            "language": item.language,
        }
        for item in sorted(refs, key=lambda value: value.path.casefold())
    ]
    return hashlib.sha256(_canonical_json(payload)).hexdigest()


def _coerce_manifest_item(value: SemanticInputRef | InputArtifact | Mapping[str, Any]) -> SemanticInputRef:
    if isinstance(value, SemanticInputRef):
        return value
    if isinstance(value, InputArtifact):
        payload: Mapping[str, Any] = {
            "path": value.relative_path,
            "sha256": value.sha256,
            "size_bytes": value.size_bytes,
            "media_type": value.media_type,
            "artifact_id": value.artifact_id,
        }
    elif isinstance(value, Mapping):
        payload = value
    else:
        raise SemanticSliceError("input manifest entries must be typed mappings")
    path = _normalise_input_path(payload.get("path", payload.get("relative_path", "")))
    digest = str(payload.get("sha256", "")).strip().casefold()
    if not _SHA256.fullmatch(digest):
        raise SemanticSliceError(f"input manifest has an invalid SHA-256 for {path}")
    try:
        size = int(payload.get("size_bytes", -1))
    except (TypeError, ValueError) as exc:
        raise SemanticSliceError(f"input manifest has an invalid size for {path}") from exc
    if size < 0:
        raise SemanticSliceError(f"input manifest has an invalid size for {path}")
    media_type = str(payload.get("media_type") or "application/octet-stream")
    language_value = payload.get("language")
    language = str(language_value).casefold() if language_value else None
    return SemanticInputRef(
        path=path,
        sha256=digest,
        size_bytes=size,
        media_type=media_type,
        artifact_id=str(payload["artifact_id"]) if payload.get("artifact_id") is not None else None,
        language=language,
    )


def _manifest_from_document(
    document: RepositoryIndexDocument | None,
    input_manifest: Sequence[SemanticInputRef | InputArtifact | Mapping[str, Any]] | None,
) -> tuple[SemanticInputRef, ...]:
    if input_manifest is not None:
        raw_refs = [_coerce_manifest_item(item) for item in input_manifest]
    elif document is not None:
        raw_refs = [
            SemanticInputRef(
                path=_normalise_input_path(entry.path),
                sha256=entry.sha256.casefold(),
                size_bytes=entry.size_bytes,
                media_type=entry.media_type,
                language=(entry.language.casefold() if entry.language else None),
            )
            for entry in document.files
        ]
    else:
        raise SemanticSliceError("semantic expansion requires an immutable input manifest")
    refs: dict[str, SemanticInputRef] = {}
    for ref in raw_refs:
        key = ref.path.casefold()
        if key in refs:
            raise SemanticSliceError("input manifest contains a cross-platform path collision")
        refs[key] = ref
    normalized = tuple(sorted(refs.values(), key=lambda item: (item.path.casefold(), item.path)))
    if document is not None:
        indexed = {_normalise_input_path(entry.path).casefold(): entry for entry in document.files}
        for ref in normalized:
            entry = indexed.get(ref.path.casefold())
            if entry is None:
                raise SemanticSliceError(f"semantic manifest path is absent from repository index: {ref.path}")
            if entry.sha256.casefold() != ref.sha256 or entry.size_bytes != ref.size_bytes:
                raise SemanticSliceError(f"semantic manifest hash/size disagrees with repository index: {ref.path}")
    return normalized


def _coerce_query(
    query: SemanticSliceQuery | Mapping[str, Any] | str | None,
    *,
    task: str | None,
    gap: str | None,
    symbol: str | None,
    sink: str | None,
    call: str | None = None,
    dataflow: str | None = None,
    data_flow: str | None = None,
) -> SemanticSliceQuery:
    if query is not None:
        if isinstance(query, SemanticSliceQuery):
            return query
        if isinstance(query, Mapping):
            return SemanticSliceQuery.model_validate(query)
        return SemanticSliceQuery.task(str(query))
    selected = [
        ("task", task),
        ("gap", gap),
        ("symbol", symbol),
        ("sink", sink),
        ("call", call),
        ("dataflow", dataflow),
        ("dataflow", data_flow),
    ]
    provided = [(kind, value) for kind, value in selected if value is not None and str(value).strip()]
    if len(provided) > 1:
        raise SemanticSliceError("semantic query must choose exactly one of task, gap, symbol, or sink")
    kind, value = provided[0] if provided else ("task", "security-sensitive source and sink paths")
    return SemanticSliceQuery(
        kind=cast(Literal["task", "gap", "symbol", "sink", "call", "dataflow"], kind),
        value=str(value),
    )


def _language(path: str, declared: str | None) -> str | None:
    value = (declared or "").casefold()
    if value in {"js", "jsx", "mjs", "cjs"}:
        return "javascript"
    if value in {"ts", "tsx", "mts", "cts"}:
        return "typescript"
    if value in {"py", "pyi"}:
        return "python"
    if value in {"java"}:
        return "java"
    if value in _TEXT_LANGUAGES:
        return value
    suffix = PurePosixPath(path).suffix.casefold()
    for language, suffixes in _LANGUAGE_SUFFIXES.items():
        if suffix in suffixes:
            return language
    return None


def _load_cas_bytes(
    ref: SemanticInputRef,
    *,
    cas_store: ContentAddressedArtifactStore | None,
    content_loader: Callable[[str], bytes] | Mapping[str, bytes] | None,
    source_bytes: Mapping[str, bytes] | None,
) -> tuple[bytes | None, SemanticUnresolved | None]:
    payload: bytes | None = None
    if source_bytes is not None:
        for key in (ref.sha256, ref.cas_ref, ref.path):
            if key in source_bytes:
                payload = source_bytes[key]
                break
    if payload is None and isinstance(content_loader, Mapping):
        for key in (ref.sha256, ref.cas_ref, ref.path):
            if key in content_loader:
                payload = content_loader[key]
                break
    if payload is None and callable(content_loader):
        try:
            candidate = content_loader(ref.sha256)
        except (KeyError, FileNotFoundError, OSError, ValueError):
            candidate = None
        if candidate is not None:
            payload = candidate
    if payload is None and cas_store is not None:
        try:
            payload = cas_store.read(ref.sha256)
        except (KeyError, FileNotFoundError, OSError, ValueError):
            payload = None
    if payload is None:
        return None, SemanticUnresolved(code="cas_missing", path=ref.path, detail="CAS bytes are unavailable")
    if not isinstance(payload, bytes):
        return None, SemanticUnresolved(code="cas_hash_mismatch", path=ref.path, detail="CAS loader returned non-bytes")
    if len(payload) != ref.size_bytes:
        return None, SemanticUnresolved(
            code="cas_size_mismatch",
            path=ref.path,
            detail=f"manifest size={ref.size_bytes}, observed size={len(payload)}",
        )
    observed = hashlib.sha256(payload).hexdigest()
    if observed != ref.sha256:
        return None, SemanticUnresolved(
            code="cas_hash_mismatch",
            path=ref.path,
            detail=f"manifest sha256={ref.sha256}, observed sha256={observed}",
        )
    return payload, None


def _decode_source(payload: bytes) -> str | None:
    if b"\x00" in payload:
        return None
    try:
        return payload.decode("utf-8-sig")
    except UnicodeDecodeError:
        return None


def _snippet(text: str, line: int, *, max_lines: int, max_chars: int) -> str:
    lines = text.splitlines()
    if not lines:
        return ""
    start = max(1, min(line, len(lines)))
    end = min(len(lines), start + max(0, max_lines - 1))
    result = "\n".join(f"{index}: {lines[index - 1]}" for index in range(start, end + 1))
    return result[:max_chars]


def _source_ref(ref: SemanticInputRef, *, line: int, end_line: int, role: str) -> SemanticSourceRef:
    return SemanticSourceRef(
        path=ref.path,
        sha256=ref.sha256,
        cas_ref=ref.cas_ref,
        line_start=max(1, line),
        line_end=max(max(1, line), end_line),
        role=role,  # type: ignore[arg-type]
    )


def _path_aliases_for_ref(ref: SemanticInputRef) -> set[str]:
    path = PurePosixPath(ref.path)
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


def _candidate_paths(
    current: _FileFacts,
    import_name: str,
    refs_by_path: Mapping[str, SemanticInputRef],
    aliases: Mapping[str, set[str]],
) -> tuple[str, ...]:
    """Resolve one import without touching the workspace.

    Resolution is intentionally conservative: a unique local candidate is
    accepted, while zero or multiple candidates are preserved as typed gaps.
    External packages never become source nodes.
    """

    raw = import_name.strip().replace("\\", "/")
    if not raw:
        return ()
    current_path = PurePosixPath(current.ref.path)
    candidates: set[str] = set()
    if raw.startswith("."):
        # Python uses ``.module`` while JS/TS uses ``./module``.  Normalize
        # both spellings before applying package-relative parent traversal.
        if "/" in raw:
            parts = raw.split("/")
            level = 0
            for part in parts:
                if part == ".":
                    level += 1
                else:
                    break
            module = "/".join(parts[level:])
        else:
            level = len(raw) - len(raw.lstrip("."))
            module = raw[level:]
        parent = current_path.parent
        for _ in range(max(0, level - 1)):
            parent = parent.parent
        base = (parent / module).as_posix()
        candidates.update(_path_variants(base, refs_by_path))
    else:
        normalized = raw.replace(".", "/")
        candidates.update(_path_variants(normalized, refs_by_path))
        # A Java/Python qualified module may be represented by a basename in
        # a small fixture.  Only accept a unique alias to avoid false binding.
        lowered = raw.casefold().lstrip("./")
        candidates.update(aliases.get(lowered, ()))
        candidates.update(aliases.get(normalized.casefold(), ()))
        last = PurePosixPath(normalized).name.casefold()
        if len(aliases.get(last, ())) == 1:
            candidates.update(aliases[last])
    return tuple(sorted(path for path in candidates if path in refs_by_path))


def _is_probably_local_import(import_name: str, *, current_path: str, aliases: Mapping[str, set[str]]) -> bool:
    """Tell local resolution gaps apart from ordinary third-party imports."""

    value = import_name.strip().replace("\\", "/").casefold()
    if value.startswith("."):
        return True
    if value in aliases or value.replace(".", "/") in aliases:
        return True
    top = value.split(".", 1)[0].split("/", 1)[0]
    local_parts = set(PurePosixPath(current_path).parts[:-1])
    return top in {part.casefold() for part in local_parts} or top in {"src", "app", "lib", "server", "pkg"}


def _path_variants(base: str, refs_by_path: Mapping[str, SemanticInputRef]) -> set[str]:
    normalized = PurePosixPath(base).as_posix().lstrip("./")
    if not normalized or normalized == ".":
        return set()
    direct = {normalized, normalized.casefold()}
    suffixes = (".py", ".pyi", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts", ".java")
    candidates = set(direct)
    candidates.update(normalized + suffix for suffix in suffixes)
    candidates.update(f"{normalized}/index{suffix}" for suffix in suffixes if suffix != ".java")
    actual = {path for path in refs_by_path if path in candidates or path.casefold() in candidates}
    return actual


def _manifest_rank(
    ref: SemanticInputRef,
    entry: RepositoryFileEntry | None,
    query: SemanticSliceQuery,
    terms: set[str],
) -> int:
    """Rank immutable manifest entries before bounded source loading."""

    score = 0
    if entry is not None:
        score += entry.security_score
        score += 20 * len(entry.dangerous_apis)
        score += 8 * len(entry.security_signals)
        fields = [*entry.symbols, *entry.dangerous_apis, *entry.imports, *entry.risk_hints]
        score += 40 * len(set(item.casefold() for item in fields) & terms)
    path_terms = set(re.findall(r"[a-z0-9_$]+", ref.path.casefold()))
    score += 25 * len(path_terms & terms)
    if (
        query.kind == "sink"
        and entry is not None
        and any(query.value.casefold() in item.casefold() for item in entry.dangerous_apis)
    ):
        score += 1000
    if (
        query.kind == "symbol"
        and entry is not None
        and any(query.value.casefold() in item.casefold() for item in entry.symbols)
    ):
        score += 1000
    return score


__all__ = [
    "_Event",
    "_FileFacts",
    "_RawEdge",
    "_normalise_input_path",
    "_canonical_manifest",
    "_coerce_manifest_item",
    "_manifest_from_document",
    "_coerce_query",
    "_language",
    "_load_cas_bytes",
    "_decode_source",
    "_snippet",
    "_source_ref",
    "_path_aliases_for_ref",
    "_candidate_paths",
    "_is_probably_local_import",
    "_path_variants",
    "_manifest_rank",
]
