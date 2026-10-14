"""Conservative Java event extraction for semantic slices."""

from __future__ import annotations

import re

from secmind.context_expansion_adapter_common import _looks_untrusted_name
from secmind.context_expansion_indexer import _Event, _FileFacts
from secmind.context_expansion_javascript import _identifier_names, _line_for_offset, _mask_javascript

_JAVA_IMPORT_RE = re.compile(r"\bimport\s+(?:static\s+)?(?P<module>[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*;")
_JAVA_TYPE_RE = re.compile(
    r"\b(?:public\s+|private\s+|protected\s+|abstract\s+|final\s+)?class\s+(?P<name>[A-Za-z_$][\w$]*)"
)
# Keep this declaration matcher deliberately regular and bounded.  The former
# expression nested an unbounded ``+`` around an alternative containing an
# unbounded ``*``.  A normal servlet declaration could therefore trigger
# catastrophic backtracking for minutes, monopolise the GIL in the semantic
# expansion thread, and make the co-located API appear dead.  Modifiers, the
# return type, generic suffix and parameter list now have disjoint boundaries
# and explicit ceilings; method bodies and arbitrary expressions are never
# consumed by this matcher.
_JAVA_METHOD_RE = re.compile(
    r"(?<![\w$])"
    r"(?:(?:public|private|protected|static|final|synchronized|abstract|native|strictfp|default)"
    r"\b[ \t]+){0,16}"
    r"(?:<[^<>{};()\r\n]{1,256}>[ \t]+)?"
    r"[A-Za-z_$][\w$]*(?:[ \t]*\.[ \t]*[A-Za-z_$][\w$]*)*"
    r"(?:[ \t]*<[^<>{};()\r\n]{0,512}>)?"
    r"(?:[ \t]*\[[ \t]*\])*[ \t]+"
    r"(?P<name>[A-Za-z_$][\w$]*)[ \t]*"
    r"\((?P<params>[^(){};]{0,4000})\)"
)
_JAVA_CALL_RE = re.compile(r"(?P<callee>[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*\(")
_JAVA_SINKS = {
    "exec": "command",
    "execute": "sql",
    "executequery": "sql",
    "executewrite": "sql",
    "read": "path",
    "write": "path",
    "get": "http",
    "exchange": "http",
    "deserialize": "deserialize",
}


def _parse_java(facts: _FileFacts) -> None:
    text = facts.text
    # Java comments and strings are masked only for matching; line locations
    # remain identical to the source text.
    masked = _mask_java(text)
    for match in _JAVA_IMPORT_RE.finditer(masked):
        module = match.group("module")
        facts.imports.append(module)
        facts.import_bindings[module.rsplit(".", 1)[-1]] = module
    for pattern in (_JAVA_TYPE_RE, _JAVA_METHOD_RE):
        for match in pattern.finditer(masked):
            name = match.group("name")
            line = _line_for_offset(masked, match.start())
            params = _identifier_names(match.groupdict().get("params") or "")
            facts.symbols.append(_Event("symbol", name, line, line, defines=params))
            for param in params:
                if _looks_untrusted_name(param):
                    facts.sources.append(
                        _Event(
                            "source",
                            f"parameter:{param}",
                            line,
                            line,
                            defines=(param,),
                            source_hint=True,
                        )
                    )
    for match in _JAVA_CALL_RE.finditer(masked):
        callee = re.sub(r"\s+", "", match.group("callee"))
        method = callee.rsplit(".", 1)[-1].casefold()
        line = _line_for_offset(masked, match.start())
        end = masked.find(")", match.end())
        arguments = masked[match.end() : end if end >= 0 else min(len(masked), match.end() + 800)]
        uses = _identifier_names(arguments)
        facts.calls.append(_Event("call", callee, line, line, uses=uses))
        if method not in _JAVA_SINKS and not callee.endswith("Runtime.getRuntime.exec"):
            continue
        source_hint = any(_looks_untrusted_name(item) for item in uses)
        facts.sinks.append(
            _Event(
                "sink",
                callee,
                line,
                line,
                uses=uses,
                source_hint=source_hint,
                tags=(_JAVA_SINKS.get(method, "command"),),
            )
        )
    assignment = re.compile(r"\b(?P<name>[A-Za-z_$][\w$]*)\s*=\s*(?P<rhs>[^;\n]{1,1000})")
    for match in assignment.finditer(masked):
        name, rhs = match.group("name"), match.group("rhs")
        line = _line_for_offset(masked, match.start())
        uses = _identifier_names(rhs)
        sanitized = bool(re.search(r"\b(?:escape|sanitize|quote|encode|clean)\w*\s*\(", rhs, re.I))
        source_hint = any(_looks_untrusted_name(item) for item in uses)
        facts.data.append(
            _Event(
                "data",
                name,
                line,
                line,
                uses=uses,
                defines=(name,),
                source_hint=source_hint,
                sanitizer=sanitized,
                tags=("sanitizer",) if sanitized else (),
            )
        )
    facts.imports = sorted(set(item for item in facts.imports if item))
    facts.symbols = sorted(set(facts.symbols), key=lambda item: (item.line, item.name))
    facts.calls = sorted(set(facts.calls), key=lambda item: (item.line, item.name))
    facts.sources = sorted(set(facts.sources), key=lambda item: (item.line, item.name))
    facts.sinks = sorted(set(facts.sinks), key=lambda item: (item.line, item.name))
    facts.data = sorted(set(facts.data), key=lambda item: (item.line, item.name))


def _mask_java(text: str) -> str:
    # Java's lexical subset needed here matches the JS comment/string masker.
    return _mask_javascript(text)


__all__ = ["_parse_java"]
