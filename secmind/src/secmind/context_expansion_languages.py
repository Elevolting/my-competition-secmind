"""Dispatch conservative language adapters without workspace access."""

from __future__ import annotations

from pathlib import PurePosixPath

from secmind.context_expansion_contracts import SemanticInputRef, SemanticUnresolved
from secmind.context_expansion_indexer import _FileFacts, _language
from secmind.context_expansion_java import _parse_java
from secmind.context_expansion_javascript import _parse_javascript
from secmind.context_expansion_python import _parse_python


def _parse_facts(ref: SemanticInputRef, text: str) -> _FileFacts:
    language = _language(ref.path, ref.language)
    facts = _FileFacts(ref=ref, language=language or "unknown", text=text)
    if language == "python":
        _parse_python(facts)
    elif language in {"javascript", "typescript"}:
        _parse_javascript(facts)
    elif language == "java":
        _parse_java(facts)
    else:
        facts.unresolved.append(
            SemanticUnresolved(
                code="unsupported_language",
                path=ref.path,
                detail=f"no conservative semantic parser for {language or PurePosixPath(ref.path).suffix or 'unknown'}",
            )
        )
    return facts


__all__ = ["_parse_facts"]
