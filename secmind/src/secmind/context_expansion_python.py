"""Conservative Python event extraction for semantic slices."""

from __future__ import annotations

import ast

from secmind.context_expansion_adapter_common import _looks_untrusted_name
from secmind.context_expansion_contracts import SemanticUnresolved
from secmind.context_expansion_indexer import _Event, _FileFacts


def _ast_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _ast_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _ast_names(node: ast.AST) -> tuple[str, ...]:
    return tuple(sorted({item.id for item in ast.walk(node) if isinstance(item, ast.Name)}))


_PYTHON_SOURCES = frozenset(
    {
        "input",
        "request.args.get",
        "request.form.get",
        "request.values.get",
        "request.json.get",
        "request.GET.get",
        "request.POST.get",
    }
)
_PYTHON_SANITIZERS = frozenset(
    {
        "shlex.quote",
        "html.escape",
        "escape",
        "quote",
        "urlencode",
        "urllib.parse.quote",
        "bleach.clean",
        "markupsafe.escape",
    }
)
_PYTHON_SINK_CATEGORIES: dict[str, str] = {
    "eval": "code",
    "exec": "code",
    "os.system": "command",
    "os.popen": "command",
    "subprocess.run": "command",
    "subprocess.call": "command",
    "subprocess.check_call": "command",
    "subprocess.check_output": "command",
    "subprocess.Popen": "command",
    "open": "path",
    "requests.get": "http",
    "requests.post": "http",
    "requests.put": "http",
    "requests.patch": "http",
    "requests.delete": "http",
    "requests.request": "http",
    "httpx.get": "http",
    "httpx.post": "http",
    "httpx.request": "http",
}


def _python_sink(name: str) -> str | None:
    if name in _PYTHON_SINK_CATEGORIES:
        return _PYTHON_SINK_CATEGORIES[name]
    if name.endswith((".execute", ".executemany", ".objects.raw", ".query", ".raw")):
        return "sql"
    if name.endswith((".fromstring", ".parse", ".parseString")) and any(
        token in name for token in ("xml", "etree", "minidom", "sax", "pulldom")
    ):
        return "deserialize"
    return None


def _python_call_names(call: ast.Call, name: str) -> tuple[str, ...]:
    """Select only the security-relevant argument for common sinks."""

    if name.endswith((".execute", ".executemany", ".objects.raw", ".query", ".raw")):
        # Parameterized SQL keeps values out of the query expression.  A
        # non-literal query is still tracked through the first argument.
        selected: list[ast.AST] = list(call.args[:1])
    elif name in {"requests.request", "httpx.request"}:
        selected = list(call.args[1:2])
    else:
        selected = list(call.args[:1])
    selected.extend(keyword.value for keyword in call.keywords if keyword.arg in {"url", "uri", "query", "cmd"})
    names: set[str] = set()
    for item in selected:
        names.update(_ast_names(item))
    return tuple(sorted(names))


def _parse_python(facts: _FileFacts) -> None:
    try:
        tree = ast.parse(facts.text, filename=facts.ref.path)
    except (SyntaxError, ValueError) as exc:
        facts.unresolved.append(SemanticUnresolved(code="parse_error", path=facts.ref.path, detail=str(exc)[:1000]))
        return
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                facts.imports.append(alias.name)
                facts.import_bindings[alias.asname or alias.name.split(".", 1)[0]] = alias.name
        elif isinstance(node, ast.ImportFrom):
            module = ("." * node.level) + (node.module or "")
            facts.imports.append(module)
            for alias in node.names:
                local = alias.asname or alias.name
                facts.import_bindings[local] = f"{module}:{alias.name}"
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            facts.symbols.append(
                _Event(
                    kind="symbol",
                    name=node.name,
                    line=int(node.lineno),
                    end_line=int(getattr(node, "end_lineno", node.lineno)),
                    defines=tuple(
                        argument.arg for argument in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
                    ),
                )
            )
            for argument in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]:
                if _looks_untrusted_name(argument.arg):
                    facts.sources.append(
                        _Event(
                            kind="source",
                            name=f"parameter:{argument.arg}",
                            line=int(node.lineno),
                            end_line=int(node.lineno),
                            defines=(argument.arg,),
                            source_hint=True,
                        )
                    )
        elif isinstance(node, ast.ClassDef):
            facts.symbols.append(
                _Event(
                    kind="symbol",
                    name=node.name,
                    line=int(node.lineno),
                    end_line=int(getattr(node, "end_lineno", node.lineno)),
                )
            )
        elif isinstance(node, ast.Call):
            name = _ast_name(node.func)
            if not name:
                continue
            names = _python_call_names(node, name)
            is_source = name in _PYTHON_SOURCES
            sink_category = _python_sink(name)
            if is_source:
                facts.sources.append(
                    _Event(
                        kind="source",
                        name=f"source:{name}",
                        line=int(node.lineno),
                        end_line=int(getattr(node, "end_lineno", node.lineno)),
                        source_hint=True,
                    )
                )
            if sink_category is not None:
                facts.sinks.append(
                    _Event(
                        kind="sink",
                        name=name,
                        line=int(node.lineno),
                        end_line=int(getattr(node, "end_lineno", node.lineno)),
                        uses=names,
                        source_hint=any(_looks_untrusted_name(item) for item in names) or is_source,
                        tags=(sink_category,),
                    )
                )
            if isinstance(node.func, (ast.Name, ast.Attribute)):
                facts.calls.append(
                    _Event(
                        kind="call",
                        name=name,
                        line=int(node.lineno),
                        end_line=int(getattr(node, "end_lineno", node.lineno)),
                        uses=names,
                    )
                )
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            value = node.value
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            names = tuple(
                sorted({item.id for target in targets for item in ast.walk(target) if isinstance(item, ast.Name)})
            )
            if not names or value is None:
                continue
            value_names = _ast_names(value)
            call = value.func if isinstance(value, ast.Call) else None
            call_name = _ast_name(call) if isinstance(call, ast.AST) else ""
            sanitized = call_name in _PYTHON_SANITIZERS or any(
                token in call_name.casefold() for token in ("sanitize", "escape", "quote", "clean")
            )
            facts.data.append(
                _Event(
                    kind="data",
                    name=names[0],
                    line=int(node.lineno),
                    end_line=int(getattr(node, "end_lineno", node.lineno)),
                    uses=value_names,
                    defines=names,
                    source_hint=any(_looks_untrusted_name(item) for item in value_names)
                    or (isinstance(value, ast.Call) and _ast_name(value.func) in _PYTHON_SOURCES),
                    sanitizer=sanitized,
                    tags=("sanitizer",) if sanitized else (),
                )
            )
        elif isinstance(node, ast.Return):
            values = _ast_names(node.value) if node.value is not None else ()
            if values:
                facts.data.append(
                    _Event(
                        kind="data",
                        name="return",
                        line=int(node.lineno),
                        end_line=int(getattr(node, "end_lineno", node.lineno)),
                        uses=values,
                    )
                )
    facts.imports = sorted(set(item for item in facts.imports if item))
    facts.symbols = sorted(set(facts.symbols), key=lambda item: (item.line, item.name))
    facts.calls = sorted(set(facts.calls), key=lambda item: (item.line, item.name))
    facts.sources = sorted(set(facts.sources), key=lambda item: (item.line, item.name))
    facts.sinks = sorted(set(facts.sinks), key=lambda item: (item.line, item.name))
    facts.data = sorted(set(facts.data), key=lambda item: (item.line, item.name))


__all__ = ["_parse_python"]
