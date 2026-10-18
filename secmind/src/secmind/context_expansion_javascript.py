"""Conservative JavaScript/TypeScript event extraction for semantic slices."""

from __future__ import annotations

import re

from secmind.context_expansion_adapter_common import _looks_untrusted_name
from secmind.context_expansion_indexer import _Event, _FileFacts


def _mask_javascript(text: str) -> str:
    output = list(text)
    state = "normal"
    escaped = False
    index = 0
    while index < len(text):
        char = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""
        if state == "normal":
            if char == "/" and following == "/":
                output[index] = output[index + 1] = " "
                state = "line_comment"
                index += 2
                continue
            if char == "/" and following == "*":
                output[index] = output[index + 1] = " "
                state = "block_comment"
                index += 2
                continue
            if char in {'"', "'", "`"}:
                output[index] = " "
                state = char
        elif state == "line_comment":
            if char == "\n":
                state = "normal"
            else:
                output[index] = " "
        elif state == "block_comment":
            if char == "*" and following == "/":
                output[index] = output[index + 1] = " "
                state = "normal"
                index += 2
                continue
            if char != "\n":
                output[index] = " "
        else:
            if char == "\n":
                escaped = False
            elif escaped:
                output[index] = " "
                escaped = False
            elif char == "\\":
                output[index] = " "
                escaped = True
            elif char == state:
                output[index] = " "
                state = "normal"
            else:
                output[index] = " "
        index += 1
    return "".join(output)


_JS_IMPORT_RE = re.compile(
    r"\bimport\s+(?:(?:\{(?P<brace>[^}]+)\})|(?:\*\s+as\s+(?P<star>[A-Za-z_$][\w$]*))|(?P<default>[A-Za-z_$][\w$]*))"
    r"\s+from\s+[\"'](?P<module>[^\"']+)[\"']"
)
_JS_REQUIRE_RE = re.compile(
    r"\b(?:const|let|var)\s+(?P<binding>\{[^}]+\}|[A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*[\"'](?P<module>[^\"']+)[\"']\s*\)"
)
_JS_DECL_RE = re.compile(r"\b(?:export\s+)?(?:async\s+)?(?:function|class)\s+(?P<name>[A-Za-z_$][\w$]*)")
_JS_FUNC_PARAMS_RE = re.compile(
    r"\bfunction\s+(?P<name>[A-Za-z_$][\w$]*)\s*\((?P<params>[^)]*)\)"
    r"|\b(?:const|let|var)\s+(?P<arrow_name>[A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\((?P<arrow_params>[^)]*)\)\s*=>"
)
_JS_ASSIGN_RE = re.compile(r"\b(?:const|let|var)\s+(?P<name>[A-Za-z_$][\w$]*)\s*=\s*(?P<rhs>[^;\n]{1,1000})")
_JS_CALL_RE = re.compile(r"(?P<callee>[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*\(")
_JS_SINK_METHODS = {
    "exec": "command",
    "execfile": "command",
    "spawn": "command",
    "readfile": "path",
    "readfilesync": "path",
    "createreadstream": "path",
    "sendfile": "path",
    "join": "path",
    "resolve": "path",
    "query": "sql",
    "execute": "sql",
    "fetch": "http",
    "request": "http",
    "get": "http",
    "post": "http",
}
_JS_SINK_MODULES = {"child_process", "fs", "path", "mysql", "pg", "axios", "node-fetch"}


def _line_for_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, max(0, offset)) + 1


def _identifier_names(value: str) -> tuple[str, ...]:
    return tuple(sorted(set(re.findall(r"\b[A-Za-z_$][\w$]*\b", value))))


def _parse_javascript(facts: _FileFacts) -> None:
    bounded = facts.text
    masked = _mask_javascript(bounded)
    for match in _JS_IMPORT_RE.finditer(bounded):
        module = match.group("module")
        facts.imports.append(module)
        brace = match.group("brace")
        if brace:
            for item in brace.split(","):
                parts = [part.strip() for part in item.split(" as ", 1)]
                if parts and parts[-1]:
                    facts.import_bindings[parts[-1]] = f"{module}:{parts[0]}"
        alias = match.group("star") or match.group("default")
        if alias:
            facts.import_bindings[alias] = module
    for match in _JS_REQUIRE_RE.finditer(bounded):
        module = match.group("module")
        binding = match.group("binding").strip()
        facts.imports.append(module)
        if binding.startswith("{"):
            for item in binding[1:-1].split(","):
                parts = [part.strip() for part in item.split(":", 1)]
                if parts:
                    facts.import_bindings[parts[-1]] = f"{module}:{parts[0]}"
        else:
            facts.import_bindings[binding] = module
    function_params: dict[tuple[str, int], tuple[str, ...]] = {}
    parameter_matches = list(_JS_FUNC_PARAMS_RE.finditer(masked))
    for match in parameter_matches:
        name = match.group("name") or match.group("arrow_name")
        if name:
            function_params[(name, _line_for_offset(masked, match.start()))] = _identifier_names(
                match.group("params") or match.group("arrow_params") or ""
            )
    for match in _JS_DECL_RE.finditer(masked):
        name = match.group("name")
        line = _line_for_offset(masked, match.start())
        facts.symbols.append(
            _Event(
                "symbol",
                name,
                line,
                line,
                defines=function_params.get((name, line), ()),
            )
        )
    for match in parameter_matches:
        name = match.group("name") or match.group("arrow_name")
        line = _line_for_offset(masked, match.start())
        if match.group("arrow_name") and name:
            facts.symbols.append(
                _Event(
                    "symbol",
                    name,
                    line,
                    line,
                    defines=function_params.get((name, line), ()),
                )
            )
        params = _identifier_names(match.group("params") or match.group("arrow_params") or "")
        if any(_looks_untrusted_name(item) for item in params):
            line = _line_for_offset(masked, match.start())
            for item in params:
                if _looks_untrusted_name(item):
                    facts.sources.append(
                        _Event(
                            "source",
                            f"parameter:{item}",
                            line,
                            line,
                            defines=(item,),
                            source_hint=True,
                        )
                    )
    for match in _JS_ASSIGN_RE.finditer(masked):
        name, rhs = match.group("name"), match.group("rhs")
        uses = _identifier_names(rhs)
        sanitized = bool(re.search(r"\b(?:escape|sanitize|quote|encode|clean)\w*\s*\(", rhs, re.I))
        source_hint = bool(
            re.search(r"\b(?:req|request|ctx|context)\s*\.\s*(?:params|query|body|headers|cookies|files?)\b", rhs)
            or re.search(r"\b(?:process\.env|input)\b", rhs)
            or any(_looks_untrusted_name(item) for item in uses)
        )
        line = _line_for_offset(masked, match.start())
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
        if source_hint:
            facts.sources.append(_Event("source", f"source:{name}", line, line, defines=(name,), source_hint=True))
    for match in _JS_CALL_RE.finditer(masked):
        callee = re.sub(r"\s+", "", match.group("callee"))
        parts = callee.split(".")
        method = parts[-1].casefold()
        if parts[0].casefold() in {"app", "router", "server", "express"} and method in {
            "get",
            "post",
            "put",
            "patch",
            "delete",
            "route",
            "use",
        }:
            continue
        module = facts.import_bindings.get(parts[0], "").split(":", 1)[0].casefold()
        category = _JS_SINK_METHODS.get(method) if method in _JS_SINK_METHODS else None
        if module in _JS_SINK_MODULES:
            category = _JS_SINK_METHODS.get(method, "path")
        line = _line_for_offset(masked, match.start())
        end = masked.find(")", match.end())
        arguments = masked[match.end() : end if end >= 0 else min(len(masked), match.end() + 800)]
        uses = _identifier_names(arguments)
        # Keep ordinary local calls so cross-file call binding can connect a
        # handler to its imported helper.  Only sink classification is gated
        # by the conservative category table.
        facts.calls.append(_Event("call", callee, line, line, uses=uses))
        if category is None:
            continue
        source_hint = bool(
            re.search(r"\b(?:req|request|ctx|context)\s*\.\s*(?:params|query|body|headers|cookies|files?)\b", arguments)
            or any(_looks_untrusted_name(item) for item in uses)
        )
        facts.sinks.append(_Event("sink", callee, line, line, uses=uses, source_hint=source_hint, tags=(category,)))
    facts.imports = sorted(set(item for item in facts.imports if item))
    facts.symbols = sorted(set(facts.symbols), key=lambda item: (item.line, item.name))
    facts.calls = sorted(set(facts.calls), key=lambda item: (item.line, item.name))
    facts.sources = sorted(set(facts.sources), key=lambda item: (item.line, item.name))
    facts.sinks = sorted(set(facts.sinks), key=lambda item: (item.line, item.name))
    facts.data = sorted(set(facts.data), key=lambda item: (item.line, item.name))


__all__ = ["_parse_javascript", "_mask_javascript"]
