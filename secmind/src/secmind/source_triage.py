from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import PurePosixPath

MAX_TRIAGE_CONTENT_CHARS = 64 * 1024
MAX_SECURITY_SIGNALS = 16
MAX_ROUTING_SIGNALS = 32

_RUNTIME_LANGUAGES = frozenset(
    {
        "c",
        "cpp",
        "csharp",
        "go",
        "java",
        "javascript",
        "php",
        "python",
        "ruby",
        "rust",
        "shell",
        "typescript",
    }
)
_RUNTIME_PATH_PARTS = frozenset(
    {
        "api",
        "app",
        "cmd",
        "controller",
        "controllers",
        "handler",
        "handlers",
        "middleware",
        "route",
        "routes",
        "server",
        "service",
        "services",
        "src",
        "views",
    }
)
_SECURITY_PATH_TERMS = frozenset(
    {
        "admin",
        "auth",
        "crypto",
        "download",
        "jwt",
        "login",
        "oauth",
        "permission",
        "redirect",
        "secret",
        "security",
        "session",
        "token",
        "upload",
        "webhook",
    }
)


def _rx(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE | re.MULTILINE)


_CONTENT_SIGNALS: tuple[tuple[str, re.Pattern[str], int], ...] = (
    (
        "source:http-input",
        _rx(r"\b(?:request|req|ctx|context)\.(?:args|body|data|form|json|params|query|headers|cookies|files)\b"),
        12,
    ),
    (
        "source:route",
        _rx(r"@(?:app|router|bp)\.(?:route|get|post|put|delete|patch)\b|router\.(?:get|post|put|delete|patch)\s*\("),
        12,
    ),
    ("sink:sql", _rx(r"\b(?:execute|executemany|query|raw|text)\s*\("), 18),
    (
        "sink:command",
        _rx(r"\b(?:os\.system|subprocess\.(?:run|call|Popen)|child_process\.(?:exec|spawn)|Runtime\.getRuntime)\b"),
        20,
    ),
    (
        "sink:file",
        _rx(r"\b(?:open|readFile|writeFile|send_file|FileInputStream|Files\.(?:read|write)|path\.join)\s*\("),
        12,
    ),
    ("sink:http", _rx(r"\b(?:requests\.(?:get|post|put)|httpx\.(?:get|post|put)|fetch|axios\.)\b"), 12),
    (
        "sink:xss",
        _rx(r"\b(?:innerHTML|dangerouslySetInnerHTML|v-html|render_template_string|document\.write)\b"),
        14,
    ),
    (
        "sink:deserialize",
        _rx(r"\b(?:pickle\.loads?|yaml\.load|marshal\.loads?|ObjectInputStream|deserialize)\b"),
        14,
    ),
    (
        "authz:check",
        _rx(r"\b(?:is_admin|has_perm|permission|authorize|requireAuth|require_auth|login_required|current_user)\b"),
        10,
    ),
    (
        "secret:candidate",
        _rx(r"\b(?:password|passwd|secret|token|api[_-]?key|credential|private[_-]?key)\b"),
        12,
    ),
    ("crypto:weak", _rx(r"\b(?:md5|sha1|des|rc4|random\.random|Math\.random|java\.util\.Random)\b"), 12),
)

_SIGNAL_ROUTING_TERMS: dict[str, frozenset[str]] = {
    "authz:check": frozenset({"authentication", "authorization", "session"}),
    "crypto:weak": frozenset({"dangerous api", "sast"}),
    "dependency:manifest": frozenset({"dependency", "sbom", "osv", "supply chain"}),
    "secret:candidate": frozenset({"credential", "password", "secret", "token"}),
    "sink:command": frozenset({"command injection", "dataflow", "injection"}),
    "sink:deserialize": frozenset({"dangerous api", "sast"}),
    "sink:file": frozenset({"dangerous api", "sast"}),
    "sink:http": frozenset({"dangerous api", "sast"}),
    "sink:sql": frozenset({"dataflow", "injection", "sql injection"}),
    "sink:xss": frozenset({"dataflow", "injection", "sast"}),
    "source:http-input": frozenset({"dataflow", "route", "sast"}),
    "source:route": frozenset({"authentication", "authorization", "route", "session"}),
}


@dataclass(frozen=True, slots=True)
class SourceFlow:
    """A bounded source-to-sink routing observation, not a Finding."""

    kind: str
    source: str
    sink: str
    line: int
    aliases: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class JavascriptSourceAnalysis:
    signals: tuple[str, ...]
    flows: tuple[SourceFlow, ...] = ()
    imports: tuple[str, ...] = ()
    aliases: tuple[str, ...] = ()
    symbols: tuple[str, ...] = ()
    dangerous_apis: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class SourceTriageResult:
    score: int
    signals: tuple[str, ...]
    flows: tuple[SourceFlow, ...] = ()
    imports: tuple[str, ...] = ()
    aliases: tuple[str, ...] = ()
    symbols: tuple[str, ...] = ()
    dangerous_apis: tuple[str, ...] = ()


_JS_IMPORT = re.compile(
    r"\bimport\s+(?:(?:\{(?P<brace>[^}]+)\})|(?:\*\s+as\s+(?P<star>[A-Za-z_$][\w$]*))|(?P<default>[A-Za-z_$][\w$]*))"
    r"\s+from\s+[\"'](?P<module>[^\"']+)[\"']",
    re.IGNORECASE,
)
_JS_REQUIRE = re.compile(
    r"\b(?:const|let|var)\s+(?P<binding>\{[^}]+\}|[A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*[\"'](?P<module>[^\"']+)[\"']\s*\)",
    re.IGNORECASE,
)
_JS_DECL = re.compile(r"\b(?:export\s+)?(?:async\s+)?(?:function|class)\s+(?P<name>[A-Za-z_$][\w$]*)")
_JS_ASSIGNMENT = re.compile(r"\b(?:const|let|var)\s+(?P<name>[A-Za-z_$][\w$]*)\s*=\s*(?P<rhs>[^;\n]{0,800})")
_JS_SIMPLE_ASSIGNMENT = re.compile(r"\b(?P<name>[A-Za-z_$][\w$]*)\s*=\s*(?P<rhs>[^;\n]{0,800})")
_JS_DESTRUCTURED = re.compile(r"\b(?:const|let|var)\s+\{(?P<body>[^{}]{1,500})\}\s*=\s*(?P<rhs>[^;\n]{1,500})")
_JS_NESTED_DESTRUCTURED = re.compile(
    r"\b(?:const|let|var)\s+\{\s*(?P<outer>[A-Za-z_$][\w$]*)\s*:\s*\{(?P<body>[^{}]{1,500})\}\s*\}\s*=\s*(?P<rhs>[^;\n]{1,500})"
)
_JS_CALL = re.compile(r"(?P<callee>[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*\(")
_JS_REQUEST_FIELDS = frozenset({"params", "query", "body", "headers", "cookies", "files", "file", "data"})
_JS_SINK_METHODS: dict[str, str] = {
    "exec": "command",
    "execfile": "command",
    "spawn": "command",
    "spawnsync": "command",
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
_JS_MODULE_SINKS = {
    "child_process": "command",
    "fs": "path",
    "path": "path",
    "mysql": "sql",
    "pg": "sql",
    "axios": "http",
    "node-fetch": "http",
}


def _mask_javascript(text: str) -> str:
    """Mask comments and literals while preserving line/column boundaries."""

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
                state = "normal" if state == "`" else state
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


def _js_line(text: str, offset: int) -> int:
    return text.count("\n", 0, max(0, offset)) + 1


def _js_call_arguments(masked: str, opening: int) -> tuple[str, int] | None:
    depth = 0
    for index in range(opening, len(masked)):
        char = masked[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return masked[opening + 1 : index], index
    return None


def _binding_parts(value: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in value.split(","):
        pieces = [part.strip() for part in item.split(":", 1)]
        if not pieces or not pieces[0]:
            continue
        source_name = pieces[0].strip()
        local_name = pieces[-1].strip()
        if re.fullmatch(r"[A-Za-z_$][\w$]*", local_name):
            result[local_name] = source_name
    return result


def triage_javascript_typescript(text: str) -> JavascriptSourceAnalysis:
    """Extract alias-aware JS/TS source-to-sink hints using bounded tokens.

    This deliberately stops short of claiming a vulnerability.  It tracks
    request destructuring, import/require aliases, and local assignments so a
    Scout can prioritize the right file and semantic scanner without putting
    untrusted source text into a prompt or a Finding.
    """

    bounded = text[:MAX_TRIAGE_CONTENT_CHARS]
    masked = _mask_javascript(bounded)
    imports: set[str] = set()
    source_vars: dict[str, str] = {"req": "request", "request": "request", "ctx": "request", "context": "request"}
    sink_aliases: dict[str, str] = {}
    module_aliases: dict[str, str] = {}
    aliases: set[str] = set()
    dangerous: set[str] = set()

    for match in _JS_IMPORT.finditer(bounded):
        module = match.group("module").casefold()
        imports.add(module)
        brace = match.group("brace")
        if brace:
            for item in brace.split(","):
                parts = [part.strip() for part in item.split(" as ", 1)]
                imported = parts[0]
                local = parts[-1]
                if module in _JS_MODULE_SINKS and imported.casefold() in _JS_SINK_METHODS:
                    sink_aliases[local] = _JS_SINK_METHODS[imported.casefold()]
                    aliases.add(f"{local}={module}.{imported}")
        star = match.group("star") or match.group("default")
        if star and module in _JS_MODULE_SINKS:
            module_aliases[star] = module
            aliases.add(f"{star}={module}")

    for match in _JS_REQUIRE.finditer(bounded):
        module = match.group("module").casefold()
        binding = match.group("binding").strip()
        imports.add(module)
        if binding.startswith("{"):
            for local, imported in _binding_parts(binding[1:-1]).items():
                if module in _JS_MODULE_SINKS and imported.casefold() in _JS_SINK_METHODS:
                    sink_aliases[local] = _JS_SINK_METHODS[imported.casefold()]
                    aliases.add(f"{local}={module}.{imported}")
        elif module in _JS_MODULE_SINKS:
            module_aliases[binding] = module
            aliases.add(f"{binding}={module}")

    # Destructured request fields are common in Express/Koa handlers.  Handle
    # both ``{ params: p } = req`` and nested ``{ params: { file } } = req``.
    for match in _JS_DESTRUCTURED.finditer(masked):
        body = match.group("body")
        rhs = match.group("rhs")
        if (
            re.search(r"\b(?:req|request|ctx|context)\b", rhs)
            or any(re.search(rf"\b{re.escape(item)}\b", rhs) for item in source_vars)
            or re.search(r"\b(?:req|request|ctx|context)\s*\.\s*(?:params|query|body|files?)\b", rhs)
        ):
            for local, field in _binding_parts(body).items():
                if field.casefold() in _JS_REQUEST_FIELDS:
                    source_vars[local] = f"request.{field.casefold()}"
                    aliases.add(f"{local}=request.{field.casefold()}")
                elif re.search(r"\b(?:params|query|body|files?|headers)\b", body, re.IGNORECASE):
                    source_vars[local] = "request.field"
                    aliases.add(f"{local}=request.field")

    for match in _JS_NESTED_DESTRUCTURED.finditer(masked):
        outer = match.group("outer").casefold()
        rhs = match.group("rhs")
        if not (
            re.search(r"\b(?:req|request|ctx|context)\b", rhs)
            or any(re.search(rf"\b{re.escape(item)}\b", rhs) for item in source_vars)
        ):
            continue
        for local, field in _binding_parts(match.group("body")).items():
            source_vars[local] = f"request.{outer}.{field}"
            aliases.add(f"{local}=request.{outer}.{field}")

    # Alias propagation is intentionally bounded and monotonic.  It catches
    # ``const wanted = routeParams.file`` and one further wrapper assignment.
    for _ in range(4):
        changed = False
        for match in _JS_ASSIGNMENT.finditer(masked):
            name, rhs = match.group("name"), match.group("rhs")
            if name in source_vars:
                continue
            source = next(
                (source_vars[item] for item in source_vars if re.search(rf"\b{re.escape(item)}\b", rhs)),
                None,
            )
            if source is None and re.search(
                r"\b(?:req|request|ctx|context)\s*\.\s*(?:params|query|body|files?|headers|cookies)\b",
                rhs,
                re.IGNORECASE,
            ):
                source = "request.field"
            if source is not None:
                source_vars[name] = source
                aliases.add(f"{name}={source}")
                changed = True
        if not changed:
            break

    functions = tuple(sorted(f"function:{match.group('name')}" for match in _JS_DECL.finditer(masked)))
    signals: set[str] = set()
    if imports:
        signals.add("js:imports")
    if source_vars.keys() - {"req", "request", "ctx", "context"}:
        signals.add("source:http-input")
    if re.search(r"\b(?:req|request|ctx|context)\s*\.\s*(?:params|query|body|files?|headers|cookies)\b", masked):
        signals.add("source:http-input")

    flows: list[SourceFlow] = []
    for match in _JS_CALL.finditer(masked):
        callee = re.sub(r"\s+", "", match.group("callee"))
        parts = callee.split(".")
        method = parts[-1].casefold()
        if parts[0].casefold() in {"app", "router", "bp", "server", "express"} and method in {
            "route",
            "get",
            "post",
            "put",
            "patch",
            "delete",
            "use",
        }:
            continue
        module = module_aliases.get(parts[0])
        kind = sink_aliases.get(parts[0]) if len(parts) == 1 else None
        if kind is None and module is not None:
            kind = _JS_SINK_METHODS.get(method) if method in _JS_SINK_METHODS else _JS_MODULE_SINKS.get(module)
        if kind is None:
            kind = _JS_SINK_METHODS.get(method)
        if kind is None:
            continue
        dangerous.add(callee)
        args = _js_call_arguments(masked, match.end() - 1)
        if args is None:
            continue
        base_request_aliases = {"req", "request", "ctx", "context"}
        source_names = [
            name
            for name in sorted(source_vars)
            if (
                re.search(rf"\b{re.escape(name)}\s*\.\s*(?:params|query|body|files?|headers|cookies)\b", args[0])
                if name in base_request_aliases
                else re.search(rf"\b{re.escape(name)}\b", args[0])
            )
        ]
        if not source_names:
            continue
        source_label = source_vars[source_names[0]]
        flows.append(
            SourceFlow(
                kind=kind,
                source=source_label,
                sink=callee,
                line=_js_line(bounded, match.start()),
                aliases=tuple(source_names),
            )
        )

    unique_flows = sorted(
        {(flow.kind, flow.source, flow.sink, flow.line, flow.aliases): flow for flow in flows}.values(),
        key=lambda flow: (flow.line, flow.kind, flow.sink, flow.source),
    )
    for flow in unique_flows:
        signals.add(f"flow:{flow.kind}")
        signals.add(f"sink:{flow.kind}")
    return JavascriptSourceAnalysis(
        signals=tuple(sorted(signals)),
        flows=tuple(unique_flows[:MAX_SECURITY_SIGNALS]),
        imports=tuple(sorted(imports)),
        aliases=tuple(sorted(aliases))[:MAX_ROUTING_SIGNALS],
        symbols=functions[:MAX_ROUTING_SIGNALS],
        dangerous_apis=tuple(sorted(dangerous))[:MAX_SECURITY_SIGNALS],
    )


def triage_source(
    path: str,
    *,
    text: str | None,
    language: str | None,
    dependency_manifest: bool,
    generated: bool,
    test_file: bool,
    vendor: bool,
    dangerous_apis: Iterable[str] = (),
    risk_hints: Iterable[str] = (),
) -> SourceTriageResult:
    """Return bounded, benchmark-blind routing metadata for immutable source bytes.

    Signals describe file shape only. They are never findings, evidence, or
    instructions and must only be consumed as deterministic routing hints.
    """

    normalized = _safe_source_path(path)
    lowered = normalized.casefold()
    posix = PurePosixPath(lowered)
    parts = frozenset(posix.parts[:-1])
    score = 0
    signals: list[str] = []

    def add(signal: str, weight: int) -> None:
        nonlocal score
        score += weight
        if signal not in signals and len(signals) < MAX_SECURITY_SIGNALS:
            signals.append(signal)

    if language and language.casefold() in _RUNTIME_LANGUAGES:
        score += 30
    if dependency_manifest:
        add("dependency:manifest", 12)
    if parts.intersection(_RUNTIME_PATH_PARTS):
        score += 10
    if any(term in lowered for term in _SECURITY_PATH_TERMS):
        add("path:security-sensitive", 8)
    if dangerous := tuple(sorted(set(dangerous_apis))):
        add("api:dangerous", min(24, 8 * len(dangerous)))
    if "credential_candidate" in set(risk_hints):
        add("secret:candidate", 12)

    if text is not None:
        window = text[:MAX_TRIAGE_CONTENT_CHARS]
        content_window = (
            _mask_javascript(window)
            if language and language.casefold() in {"javascript", "typescript", "js", "ts", "jsx", "tsx"}
            else window
        )
        for label, pattern, weight in _CONTENT_SIGNALS:
            if pattern.search(content_window):
                add(label, weight)
        analysis = (
            triage_javascript_typescript(window)
            if language and language.casefold() in {"javascript", "typescript", "js", "ts", "jsx", "tsx"}
            else None
        )
        if analysis is not None:
            for signal in analysis.signals:
                add(signal, 24 if signal.startswith("flow:") else 10)
            imports = analysis.imports
            aliases = analysis.aliases
            symbols = analysis.symbols
            dangerous = analysis.dangerous_apis
            flows = analysis.flows
        else:
            imports = aliases = symbols = dangerous = ()
            flows = ()
    else:
        imports = aliases = symbols = dangerous = ()
        flows = ()

    if generated:
        score -= 40
    if vendor:
        score -= 45
    if test_file:
        score -= 20
    return SourceTriageResult(
        score=max(0, min(1_000, score)),
        signals=tuple(signals),
        flows=tuple(flows),
        imports=tuple(imports),
        aliases=tuple(aliases),
        symbols=tuple(symbols),
        dangerous_apis=tuple(dangerous),
    )


def source_triage_sort_key(*, score: int, size_bytes: int, path: str) -> tuple[int, int, str]:
    return (-max(0, min(1_000, score)), size_bytes, _safe_source_path(path).casefold())


def collect_source_signals(entries: Iterable[object], *, limit: int = MAX_ROUTING_SIGNALS) -> tuple[str, ...]:
    """Collect a bounded stable signal set from already-indexed entries."""

    if limit < 1:
        return ()
    ranked = sorted(
        entries,
        key=lambda item: source_triage_sort_key(
            score=int(getattr(item, "security_score", 0)),
            size_bytes=int(getattr(item, "size_bytes", 0)),
            path=str(getattr(item, "path", "")),
        ),
    )
    selected: list[str] = []
    for entry in ranked:
        for signal in tuple(getattr(entry, "security_signals", ())):
            if signal not in selected:
                selected.append(signal)
                if len(selected) >= min(limit, MAX_ROUTING_SIGNALS):
                    return tuple(selected)
    return tuple(selected)


def routing_terms_for_signals(signals: Iterable[str]) -> frozenset[str]:
    terms: set[str] = set()
    for signal in tuple(signals)[:MAX_ROUTING_SIGNALS]:
        terms.update(_SIGNAL_ROUTING_TERMS.get(signal, ()))
    return frozenset(terms)


def _safe_source_path(path: str) -> str:
    normalized = PurePosixPath(path.replace("\\", "/")).as_posix()
    if normalized in {"", "."} or normalized.startswith("/") or ".." in PurePosixPath(normalized).parts:
        raise ValueError("source triage path must be a safe relative path")
    if any(ord(char) < 32 or ord(char) == 127 for char in normalized):
        raise ValueError("source triage path contains control characters")
    return normalized


__all__ = [
    "MAX_ROUTING_SIGNALS",
    "MAX_SECURITY_SIGNALS",
    "MAX_TRIAGE_CONTENT_CHARS",
    "JavascriptSourceAnalysis",
    "SourceFlow",
    "SourceTriageResult",
    "collect_source_signals",
    "routing_terms_for_signals",
    "source_triage_sort_key",
    "triage_source",
    "triage_javascript_typescript",
]
