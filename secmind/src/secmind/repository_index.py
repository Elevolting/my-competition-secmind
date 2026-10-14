from __future__ import annotations

import ast
import hashlib
import hmac
import json
import mimetypes
import re
import unicodedata
from pathlib import Path
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from pydantic import BaseModel, ConfigDict, Field

from secmind.artifact_store import ContentAddressedArtifactStore
from secmind.language_registry import (
    LANGUAGE_REGISTRY_VERSION,
    LANGUAGE_SUFFIXES,
    language_for_path,
)
from secmind.schemas import InputArtifact, RepositoryIndexRef
from secmind.source_triage import (
    MAX_SECURITY_SIGNALS,
    triage_javascript_typescript,
    triage_source,
)

INDEX_FORMAT_VERSION = "secmind.repository-index.v2"
LEGACY_INDEX_FORMAT_VERSION = "secmind.repository-index.v1"
_SUPPORTED_INDEX_FORMATS = frozenset({LEGACY_INDEX_FORMAT_VERSION, INDEX_FORMAT_VERSION})
_FILE_CHUNK_BYTES = 1024 * 1024


class RepositoryIndexError(ValueError):
    """The workspace cannot be represented as a safe deterministic index."""


class RepositoryFileEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str
    size_bytes: int = Field(ge=0)
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    media_type: str
    language: str | None = None
    encoding: str | None = None
    line_count: int = Field(default=0, ge=0)
    binary: bool = False
    generated: bool = False
    test_file: bool = False
    vendor: bool = False
    dependency_manifest: bool = False
    imports: list[str] = Field(default_factory=list)
    symbols: list[str] = Field(default_factory=list)
    dangerous_apis: list[str] = Field(default_factory=list)
    risk_hints: list[str] = Field(default_factory=list)
    security_score: int = Field(default=0, ge=0, le=1_000)
    security_signals: list[str] = Field(default_factory=list, max_length=MAX_SECURITY_SIGNALS)


class RepositoryIndexDocument(BaseModel):
    """Content-addressed payload; deliberately excludes run IDs and timestamps."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    format_version: str = INDEX_FORMAT_VERSION
    language_registry_version: str | None = None
    files: list[RepositoryFileEntry]
    file_count: int = Field(ge=0)
    total_bytes: int = Field(ge=0)
    languages: dict[str, int] = Field(default_factory=dict)
    dependency_files: list[str] = Field(default_factory=list)

    def canonical_bytes(self) -> bytes:
        payload = self.model_dump(mode="json")
        if self.language_registry_version is None:
            payload.pop("language_registry_version", None)
        if self.format_version == LEGACY_INDEX_FORMAT_VERSION:
            for entry in payload["files"]:
                entry.pop("security_score", None)
                entry.pop("security_signals", None)
        return json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")


# Compatibility export for older integrations.  New consumers should import the
# registry from ``secmind.language_registry`` so index and tool routing cannot
# silently drift apart.
_LANGUAGES = LANGUAGE_SUFFIXES

_DEPENDENCY_FILES = {
    "cargo.lock",
    "cargo.toml",
    "composer.json",
    "composer.lock",
    "go.mod",
    "go.sum",
    "gradle.lockfile",
    "package-lock.json",
    "package.json",
    "pipfile",
    "pipfile.lock",
    "poetry.lock",
    "pom.xml",
    "pyproject.toml",
    "requirements.txt",
    "uv.lock",
    "yarn.lock",
}

_VENDOR_PARTS = {".git", ".venv", "dist", "node_modules", "site-packages", "vendor"}
_GENERATED_PARTS = {"build", "dist", "generated", "node_modules", "vendor"}
_TEST_PARTS = {"test", "tests", "spec", "specs", "__tests__"}
_CREDENTIAL_HINT = re.compile(r"(?i)\b(api[_-]?key|access[_-]?token|secret|password|passwd|private[_-]?key)\b\s*[:=]")
_BASE64_BLOB = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{256,}={0,2}(?![A-Za-z0-9+/])")
_GENERIC_IMPORT = re.compile(r"(?m)^\s*(?:import\s+([\w./@-]+)|from\s+([\w./@-]+)\s+import|.*?require\(['\"]([^'\"]+))")
_GENERIC_SYMBOL = re.compile(r"(?m)^\s*(?:export\s+)?(?:async\s+)?(?:function|class)\s+([A-Za-z_$][\w$]*)")
_GENERIC_DANGEROUS = {
    "child_process.exec": re.compile(r"\b(?:child_process\.)?exec\s*\("),
    "eval": re.compile(r"\beval\s*\("),
    "innerHTML": re.compile(r"\.innerHTML\s*="),
    "Runtime.exec": re.compile(r"\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\("),
    "os/exec.Command": re.compile(r"\bexec\s*\.\s*Command\s*\("),
}


class RepositoryIndexer:
    def __init__(
        self,
        artifact_store: ContentAddressedArtifactStore,
        *,
        max_files: int = 20_000,
        max_inspected_file_bytes: int = 2 * 1024 * 1024,
    ) -> None:
        if max_files < 1 or max_inspected_file_bytes < 1:
            raise ValueError("repository index limits must be positive")
        self.artifact_store = artifact_store
        self.max_files = max_files
        self.max_inspected_file_bytes = max_inspected_file_bytes

    def build(
        self,
        run_id: str,
        workspace: Path,
        input_manifest: list[InputArtifact] | None = None,
    ) -> RepositoryIndexRef:
        root = workspace.resolve()
        if not root.is_dir() or root.is_symlink():
            raise RepositoryIndexError("repository workspace must be a real directory")
        manifest = self._manifest_by_path(input_manifest or [])
        paths = (
            []
            if manifest
            else sorted(
                (path for path in root.rglob("*") if path.is_file() or path.is_symlink()),
                key=lambda path: self._normalized_path(path, root),
            )
        )
        if max(len(paths), len(manifest)) > self.max_files:
            raise RepositoryIndexError("repository contains too many files")

        found_paths: set[str] = set()
        collision_keys: set[str] = set()
        entries: list[RepositoryFileEntry] = []
        language_counts: dict[str, int] = {}
        total_bytes = 0
        source_rows: list[tuple[str, Path, bytes | None, str, int]] = []
        if manifest:
            for relative, expected in sorted(manifest.items()):
                path = (root / relative).resolve()
                try:
                    payload = self.artifact_store.read(expected.sha256)
                    digest = hashlib.sha256(payload).hexdigest()
                    size_bytes = len(payload)
                    content = payload if size_bytes <= self.max_inspected_file_bytes else None
                except (OSError, ValueError):
                    if not path.is_relative_to(root) or not path.is_file() or path.is_symlink():
                        raise RepositoryIndexError(f"input manifest references missing file: {relative}") from None
                    content, digest, size_bytes = self._read_file(path)
                if digest != expected.sha256.lower() or size_bytes != expected.size_bytes:
                    raise RepositoryIndexError(f"input hash changed after ingestion: {relative}")
                source_rows.append((relative, path, content, digest, size_bytes))
        else:
            for path in paths:
                relative = self._normalized_path(path, root)
                if path.is_symlink():
                    raise RepositoryIndexError(f"repository contains a symbolic link: {relative}")
                content, digest, size_bytes = self._read_file(path)
                source_rows.append((relative, path, content, digest, size_bytes))

        for relative, path, content, digest, size_bytes in source_rows:
            collision_key = relative.casefold()
            if collision_key in collision_keys:
                raise RepositoryIndexError("repository contains a cross-platform path collision")
            collision_keys.add(collision_key)
            found_paths.add(relative)
            manifest_entry = manifest.get(relative)
            if manifest_entry is not None and not hmac.compare_digest(digest, manifest_entry.sha256.lower()):
                raise RepositoryIndexError(f"input hash changed after ingestion: {relative}")
            entry = self._entry(relative, path, content, digest, size_bytes)
            entries.append(entry)
            total_bytes += size_bytes
            if entry.language:
                language_counts[entry.language] = language_counts.get(entry.language, 0) + 1

        missing = sorted(set(manifest) - found_paths)
        if missing:
            raise RepositoryIndexError(f"input manifest references missing file: {missing[0]}")

        document = RepositoryIndexDocument(
            language_registry_version=LANGUAGE_REGISTRY_VERSION,
            files=entries,
            file_count=len(entries),
            total_bytes=total_bytes,
            languages=dict(sorted(language_counts.items())),
            dependency_files=sorted(item.path for item in entries if item.dependency_manifest),
        )
        stored = self.artifact_store.put(
            document.canonical_bytes(),
            media_type="application/vnd.secmind.repository-index+json",
            run_id=run_id,
        )
        return RepositoryIndexRef(
            index_id=str(uuid5(NAMESPACE_URL, f"secmind:repository-index:{run_id}:{stored.sha256}")),
            run_id=run_id,
            artifact_id=stored.artifact_id,
            digest=stored.sha256,
            file_count=document.file_count,
            total_bytes=document.total_bytes,
            languages=sorted(document.languages),
            dependency_files=document.dependency_files,
        )

    def load(self, reference: RepositoryIndexRef, *, run_id: str | None = None) -> RepositoryIndexDocument:
        if run_id is not None and reference.run_id != run_id:
            raise RepositoryIndexError("repository index belongs to a different run")
        if not hmac.compare_digest(reference.artifact_id.lower(), reference.digest.lower()):
            raise RepositoryIndexError("repository index reference digest is inconsistent")
        try:
            document = RepositoryIndexDocument.model_validate_json(self.artifact_store.read(reference.artifact_id))
        except (OSError, ValueError) as exc:
            raise RepositoryIndexError("repository index artifact is invalid") from exc
        if document.format_version not in _SUPPORTED_INDEX_FORMATS:
            raise RepositoryIndexError("repository index format is unsupported")
        if hashlib.sha256(document.canonical_bytes()).hexdigest() != reference.digest.lower():
            raise RepositoryIndexError("repository index canonical digest does not match its reference")
        return document

    def _entry(
        self,
        relative: str,
        path: Path,
        content: bytes | None,
        digest: str,
        size_bytes: int,
    ) -> RepositoryFileEntry:
        language = language_for_path(relative)
        dependency = path.name.casefold() in _DEPENDENCY_FILES or path.name.casefold().startswith("requirements-")
        parts = {part.casefold() for part in Path(relative).parts[:-1]}
        vendor = bool(parts & _VENDOR_PARTS)
        generated = bool(parts & _GENERATED_PARTS) or ".min." in path.name.casefold()
        test_file = bool(parts & _TEST_PARTS) or path.stem.casefold().startswith("test_")
        risk_hints: list[str] = []
        imports: list[str] = []
        symbols: list[str] = []
        dangerous: list[str] = []
        text: str | None = None
        encoding: str | None = None
        if content is None:
            risk_hints.append("oversized")
        else:
            text, encoding = self._decode_text(content)
        if text is not None:
            if _CREDENTIAL_HINT.search(text):
                risk_hints.append("credential_candidate")
            if _BASE64_BLOB.search(text):
                risk_hints.append("obfuscated_or_encoded_blob")
            if language == "python":
                imports, symbols, dangerous = self._python_metadata(text)
            else:
                imports, symbols, dangerous = self._generic_metadata(text)
                if language in {"javascript", "typescript"}:
                    analysis = triage_javascript_typescript(text)
                    imports = sorted(set(imports).union(analysis.imports))
                    symbols = sorted(
                        set(symbols).union(analysis.symbols).union(f"alias:{item}" for item in analysis.aliases)
                    )
                    dangerous = sorted(set(dangerous).union(analysis.dangerous_apis))
                    risk_hints.extend(
                        signal for signal in analysis.signals if signal.startswith(("source:", "flow:", "sink:"))
                    )
        else:
            risk_hints.append("binary")
        media_type, _ = mimetypes.guess_type(path.name)
        triage = triage_source(
            relative,
            text=text,
            language=language,
            dependency_manifest=dependency,
            generated=generated,
            test_file=test_file,
            vendor=vendor,
            dangerous_apis=dangerous,
            risk_hints=risk_hints,
        )
        return RepositoryFileEntry(
            path=relative,
            size_bytes=size_bytes,
            sha256=digest,
            media_type=media_type or "application/octet-stream",
            language=language,
            encoding=encoding,
            line_count=0 if text is None else len(text.splitlines()),
            binary=text is None,
            generated=generated,
            test_file=test_file,
            vendor=vendor,
            dependency_manifest=dependency,
            imports=imports,
            symbols=symbols,
            dangerous_apis=dangerous,
            risk_hints=sorted(set(risk_hints)),
            security_score=triage.score,
            security_signals=list(triage.signals),
        )

    def _read_file(self, path: Path) -> tuple[bytes | None, str, int]:
        """Hash the full file while retaining only a bounded inspection buffer."""

        hasher = hashlib.sha256()
        size_bytes = 0
        inspected: bytearray | None = bytearray()
        with path.open("rb") as handle:
            while chunk := handle.read(_FILE_CHUNK_BYTES):
                size_bytes += len(chunk)
                hasher.update(chunk)
                if inspected is not None:
                    if size_bytes <= self.max_inspected_file_bytes:
                        inspected.extend(chunk)
                    else:
                        inspected = None
        return (bytes(inspected) if inspected is not None else None, hasher.hexdigest(), size_bytes)

    @staticmethod
    def _decode_text(content: bytes) -> tuple[str | None, str | None]:
        if b"\x00" in content:
            return None, None
        try:
            return content.decode("utf-8-sig"), "utf-8"
        except UnicodeDecodeError:
            return None, None

    @staticmethod
    def _python_metadata(text: str) -> tuple[list[str], list[str], list[str]]:
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError):
            return [], [], []
        imports: set[str] = set()
        symbols: set[str] = set()
        dangerous: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.add(node.module or "")
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                symbols.add(f"function:{node.name}")
                if any(
                    RepositoryIndexer._call_name(item.func).rsplit(".", 1)[-1]
                    in {"route", "get", "post", "put", "delete"}
                    for item in node.decorator_list
                    if isinstance(item, ast.Call)
                ):
                    symbols.add(f"route:{node.name}")
            elif isinstance(node, ast.ClassDef):
                symbols.add(f"class:{node.name}")
            elif isinstance(node, ast.Call):
                name = RepositoryIndexer._call_name(node.func)
                if name in {
                    "eval",
                    "exec",
                    "os.system",
                    "pickle.load",
                    "pickle.loads",
                    "subprocess.call",
                    "subprocess.Popen",
                    "subprocess.run",
                    "yaml.load",
                }:
                    dangerous.add(name)
        imports.discard("")
        return sorted(imports), sorted(symbols), sorted(dangerous)

    @staticmethod
    def _call_name(node: ast.expr) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            prefix = RepositoryIndexer._call_name(node.value)
            return f"{prefix}.{node.attr}" if prefix else node.attr
        return ""

    @staticmethod
    def _generic_metadata(text: str) -> tuple[list[str], list[str], list[str]]:
        imports = {
            next(value for value in match.groups() if value)
            for match in _GENERIC_IMPORT.finditer(text)
            if any(match.groups())
        }
        symbols = {match.group(1) for match in _GENERIC_SYMBOL.finditer(text)}
        dangerous = {name for name, pattern in _GENERIC_DANGEROUS.items() if pattern.search(text)}
        return sorted(imports), sorted(f"symbol:{name}" for name in symbols), sorted(dangerous)

    @staticmethod
    def _normalized_path(path: Path, root: Path) -> str:
        try:
            relative = path.relative_to(root).as_posix()
        except ValueError as exc:
            raise RepositoryIndexError("repository file escapes the workspace") from exc
        normalized = unicodedata.normalize("NFC", relative)
        if not normalized or normalized.startswith("/") or ".." in Path(normalized).parts:
            raise RepositoryIndexError("repository contains an unsafe path")
        if any(ord(char) < 32 or ord(char) == 127 for char in normalized):
            raise RepositoryIndexError("repository path contains control characters")
        return normalized

    @classmethod
    def _manifest_by_path(cls, artifacts: list[InputArtifact]) -> dict[str, InputArtifact]:
        manifest: dict[str, InputArtifact] = {}
        collision_keys: set[str] = set()
        for artifact in artifacts:
            normalized = unicodedata.normalize("NFC", artifact.relative_path.replace("\\", "/"))
            if not normalized or normalized.startswith("/") or ".." in Path(normalized).parts:
                raise RepositoryIndexError("input manifest contains an unsafe path")
            key = normalized.casefold()
            if key in collision_keys:
                raise RepositoryIndexError("input manifest contains a cross-platform path collision")
            collision_keys.add(key)
            manifest[normalized] = artifact
        return manifest


def repository_index_metadata(document: RepositoryIndexDocument) -> dict[str, Any]:
    """Small, prompt-safe repository map; never includes source text."""

    return {
        "format_version": document.format_version,
        "language_registry_version": document.language_registry_version or LANGUAGE_REGISTRY_VERSION,
        "file_count": document.file_count,
        "total_bytes": document.total_bytes,
        "languages": document.languages,
        "dependency_files": document.dependency_files,
        "files": [
            {
                "path": item.path,
                "language": item.language,
                "generated": item.generated,
                "test_file": item.test_file,
                "vendor": item.vendor,
                "risk_hints": item.risk_hints,
            }
            for item in document.files
        ],
    }


def repository_planning_view(document: RepositoryIndexDocument) -> dict[str, Any]:
    """Return the complete source-free planning view of an indexed repository.

    ``repository_index_metadata`` intentionally remains a small compatibility
    view used by prompt builders.  Planner, affinity, and evidence components
    need stronger identity and routing facts, however.  This view exposes those
    facts without copying source bytes: content is represented by its SHA and
    all high-cardinality fields remain bounded by the indexer's limits.
    """

    files = [
        {
            "path": item.path,
            "sha256": item.sha256,
            "size_bytes": item.size_bytes,
            "line_count": item.line_count,
            "language": item.language,
            "generated": item.generated,
            "test_file": item.test_file,
            "vendor": item.vendor,
            "dependency_manifest": item.dependency_manifest,
            "imports": list(item.imports),
            "symbols": list(item.symbols),
            "dangerous_apis": list(item.dangerous_apis),
            "risk_hints": list(item.risk_hints),
            "security_score": item.security_score,
            "security_signals": list(item.security_signals),
        }
        for item in document.files
    ]
    payload: dict[str, Any] = {
        "format_version": document.format_version,
        "language_registry_version": document.language_registry_version or LANGUAGE_REGISTRY_VERSION,
        "file_count": document.file_count,
        "total_bytes": document.total_bytes,
        "languages": dict(document.languages),
        "dependency_files": list(document.dependency_files),
        "files": files,
    }
    payload["planning_digest"] = hashlib.sha256(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return payload
