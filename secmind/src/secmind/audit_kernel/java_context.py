from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from pathlib import Path, PurePosixPath, PureWindowsPath

from secmind.live_source_review import SourceUnit
from secmind.schemas import InputArtifact

_PACKAGE = re.compile(r"(?m)^\s*package\s+([\w.]+)\s*;")
_IMPORT = re.compile(r"(?m)^\s*import\s+(?:static\s+)?([\w.*]+)\s*;")
_IDENTIFIER = re.compile(r"\b[A-Z][A-Za-z0-9_$]{1,127}\b")
JAVA_AUDIT_SUFFIXES = frozenset({".java"})
JAVA_SUPPORT_SUFFIXES = frozenset(
    {
        ".properties",
        ".xml",
        ".yaml",
        ".yml",
        ".json",
        ".gradle",
        ".kts",
        ".jsp",
        ".tag",
        ".html",
        ".vm",
    }
)


def load_java_source_units(
    workspace_value: str,
    artifacts: list[InputArtifact],
    target_scope: list[str] | None = None,
) -> tuple[list[SourceUnit], list[SourceUnit]]:
    """Load bounded Java audit and dependency/configuration context safely."""

    workspace = Path(workspace_value).resolve()
    normalized_scope = tuple(
        sorted({raw.replace("\\", "/").strip().rstrip("/") or "." for raw in (target_scope or ["."])})
    )
    for scope in normalized_scope:
        posix_scope = PurePosixPath(scope)
        windows_scope = PureWindowsPath(scope)
        if (
            "\x00" in scope
            or any(ord(character) < 32 for character in scope)
            or posix_scope.is_absolute()
            or windows_scope.is_absolute()
            or bool(windows_scope.drive)
            or ".." in posix_scope.parts
        ):
            raise ValueError("target_scope contains an unsafe path")

    def in_scope(relative_path: str) -> bool:
        return any(
            scope == "." or relative_path == scope or relative_path.startswith(f"{scope}/")
            for scope in normalized_scope
        )

    cases: list[SourceUnit] = []
    support: list[SourceUnit] = []
    accepted_suffixes = JAVA_AUDIT_SUFFIXES | JAVA_SUPPORT_SUFFIXES
    for artifact in sorted(artifacts, key=lambda item: item.relative_path):
        relative = Path(artifact.relative_path)
        relative_posix = relative.as_posix()
        suffix = relative.suffix.lower()
        if not in_scope(relative_posix) or suffix not in accepted_suffixes:
            continue
        max_bytes = 512 * 1024 if suffix in JAVA_AUDIT_SUFFIXES else 128 * 1024
        if artifact.size_bytes > max_bytes:
            continue
        source = (workspace / relative).resolve()
        if not source.is_relative_to(workspace) or not source.is_file() or source.is_symlink():
            continue
        try:
            content = source.read_bytes().decode("utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        identity = hashlib.sha256(f"{relative_posix}:{artifact.sha256}".encode()).hexdigest()[:32]
        unit = SourceUnit(case_id=identity, path=relative_posix, content=content)
        (cases if suffix in JAVA_AUDIT_SUFFIXES else support).append(unit)
    return cases, support


def dependency_closed_support(
    case_files: list[SourceUnit],
    support_files: list[SourceUnit],
    *,
    max_related_java: int = 12,
) -> dict[str, tuple[str, ...]]:
    """Build a deterministic, bounded Java dependency context per source.

    This is deliberately a lightweight index, not a Java parser.  It closes
    the common package/import/type-reference gap without making prompt size or
    runtime quadratic in the repository size.
    """

    by_type: dict[str, list[SourceUnit]] = defaultdict(list)
    by_fqcn: dict[str, SourceUnit] = {}
    package_by_path: dict[str, str] = {}
    identifiers_by_path: dict[str, frozenset[str]] = {}
    for source in case_files:
        type_name = PurePosixPath(source.path).stem
        package_match = _PACKAGE.search(source.content)
        package_name = package_match.group(1) if package_match else ""
        package_by_path[source.path] = package_name
        identifiers_by_path[source.path] = frozenset(_IDENTIFIER.findall(source.content))
        by_type[type_name].append(source)
        if package_name:
            by_fqcn[f"{package_name}.{type_name}"] = source

    configuration_paths = tuple(sorted(item.path for item in support_files))
    result: dict[str, tuple[str, ...]] = {}
    for source in sorted(case_files, key=lambda item: item.path):
        scored: dict[str, int] = {}
        imports = set(_IMPORT.findall(source.content))
        for imported in imports:
            if imported.endswith(".*"):
                imported_package = imported[:-2]
                for candidate in case_files:
                    if candidate.path != source.path and package_by_path.get(candidate.path) == imported_package:
                        scored[candidate.path] = max(scored.get(candidate.path, 0), 4)
                continue
            imported_source = by_fqcn.get(imported)
            if imported_source is not None and imported_source.path != source.path:
                scored[imported_source.path] = max(scored.get(imported_source.path, 0), 6)

        for identifier in identifiers_by_path[source.path]:
            for candidate in by_type.get(identifier, ()):
                if candidate.path != source.path:
                    scored[candidate.path] = max(scored.get(candidate.path, 0), 3)

        package_name = package_by_path[source.path]
        if package_name:
            for candidate in case_files:
                if candidate.path != source.path and package_by_path.get(candidate.path) == package_name:
                    scored[candidate.path] = max(scored.get(candidate.path, 0), 1)

        related = [path for path, _ in sorted(scored.items(), key=lambda item: (-item[1], item[0]))]
        result[source.path] = tuple([*related[:max_related_java], *configuration_paths])
    return result


__all__ = [
    "JAVA_AUDIT_SUFFIXES",
    "JAVA_SUPPORT_SUFFIXES",
    "dependency_closed_support",
    "load_java_source_units",
]
