"""The single language vocabulary shared by indexing, routing, and scanners.

Language detection is security-relevant metadata: if the repository index calls a
file TypeScript while the tool planner calls it unknown, a language-specific
scanner can disappear before it gets a chance to run.  Keep the registry small,
versioned, and free of source content so it can safely be included in manifests
and replay bundles.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath

LANGUAGE_REGISTRY_VERSION = "secmind.language-registry.v1"


@dataclass(frozen=True, slots=True)
class LanguageSpec:
    language: str
    extensions: tuple[str, ...]
    aliases: tuple[str, ...] = ()


_SPECS: tuple[LanguageSpec, ...] = (
    LanguageSpec("python", (".py", ".pyi"), ("py",)),
    LanguageSpec("javascript", (".js", ".jsx", ".mjs", ".cjs"), ("js", "jsx", "node")),
    LanguageSpec("typescript", (".ts", ".tsx"), ("ts", "tsx")),
    LanguageSpec("java", (".java",), ()),
    LanguageSpec("go", (".go",), ("golang",)),
    LanguageSpec("rust", (".rs",), ("rs",)),
    LanguageSpec("c", (".c", ".h"), ()),
    LanguageSpec("cpp", (".cc", ".cpp", ".hpp"), ("c++",)),
    LanguageSpec("csharp", (".cs",), ("c#", "cs")),
    LanguageSpec("kotlin", (".kt", ".kts"), ("kt",)),
    LanguageSpec("php", (".php",), ()),
    LanguageSpec("ruby", (".rb",), ("rb",)),
    LanguageSpec("shell", (".sh", ".bash", ".zsh"), ("bash", "zsh", "shellscript")),
    LanguageSpec("sql", (".sql",), ()),
    LanguageSpec("yaml", (".yaml", ".yml"), ("yml",)),
    LanguageSpec("json", (".json",), ()),
    LanguageSpec("toml", (".toml",), ()),
    LanguageSpec("xml", (".xml",), ()),
)

LANGUAGE_SPECS = {spec.language: spec for spec in _SPECS}
LANGUAGE_SUFFIXES = {extension: spec.language for spec in _SPECS for extension in spec.extensions}
LANGUAGE_ALIASES = {alias.casefold(): spec.language for spec in _SPECS for alias in spec.aliases}
LANGUAGE_ALIASES.update({language.casefold(): language for language in LANGUAGE_SPECS})

# A tuple is used for public catalogues so callers cannot mutate the registry by
# accident.  The suffix map remains a regular dict for compatibility with the
# old ``tools.LANGUAGE_SUFFIXES`` import.
KNOWN_LANGUAGES = tuple(sorted(LANGUAGE_SPECS))


def normalize_language(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip().casefold()
    if not normalized:
        return None
    if normalized.startswith("."):
        return LANGUAGE_SUFFIXES.get(normalized)
    return LANGUAGE_ALIASES.get(normalized)


def language_for_path(path: str) -> str | None:
    suffix = PurePosixPath(path.replace("\\", "/")).suffix.casefold()
    return LANGUAGE_SUFFIXES.get(suffix)


def normalize_languages(values: object) -> set[str]:
    if isinstance(values, str):
        values = (values,)
    if not isinstance(values, (list, tuple, set, frozenset)):
        return set()
    return {language for item in values if (language := normalize_language(str(item))) is not None}


def extensions_for_languages(values: object) -> tuple[str, ...]:
    languages = normalize_languages(values)
    return tuple(sorted(extension for extension, language in LANGUAGE_SUFFIXES.items() if language in languages))


__all__ = [
    "KNOWN_LANGUAGES",
    "LANGUAGE_ALIASES",
    "LANGUAGE_REGISTRY_VERSION",
    "LANGUAGE_SPECS",
    "LANGUAGE_SUFFIXES",
    "LanguageSpec",
    "extensions_for_languages",
    "language_for_path",
    "normalize_language",
    "normalize_languages",
]
