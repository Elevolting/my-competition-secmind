"""Small, deterministic Python source-to-sink analysis.

This is deliberately not a general taint engine.  It proves only direct,
intra-procedural flows from function parameters or common request/input
sources into a short allowlist of security-sensitive sinks.  Narrow proofs are
more useful to SecMind than a large collection of uncorroborated pattern hits.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from typing import Final, Literal


@dataclass(frozen=True)
class PythonFlowFinding:
    rule_id: str
    native_rule_id: str
    title: str
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"]
    confidence: Literal["LOW", "MEDIUM", "HIGH", "UNKNOWN"]
    line: int
    description: str
    impact: str
    remediation: str
    source_names: tuple[str, ...]
    sink: str


_NETWORK_SINK_ARGUMENT: Final = {
    "requests.get": 0,
    "requests.post": 0,
    "requests.put": 0,
    "requests.patch": 0,
    "requests.delete": 0,
    # The generic request APIs take ``method`` before ``url``.
    "requests.request": 1,
    "httpx.get": 0,
    "httpx.post": 0,
    "httpx.put": 0,
    "httpx.patch": 0,
    "httpx.delete": 0,
    "httpx.request": 1,
    "urllib.request.urlopen": 0,
    "urlopen": 0,
    # Common local aliases/wrappers. They remain high-specificity only when a
    # tainted argument reaches the callable; the identifier alone is never a
    # finding.
    "urlopen_func": 0,
    # Bound ``HTTPConnection.request``-style callables take method, then URL.
    "request_method": 1,
}
_COMMAND_SINKS: Final = {
    "os.system",
    "os.popen",
    "subprocess.run",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.Popen",
}
_XML_SINK_SUFFIXES: Final = {
    "etree.fromstring",
    "etree.parse",
    "pulldom.parse",
    "pulldom.parseString",
    "sax.parse",
    "sax.parseString",
    "minidom.parse",
    "minidom.parseString",
}
_EXPLICITLY_UNTRUSTED_PARAMETER_TOKENS: Final = frozenset({"user", "untrusted", "external", "input", "request"})
_CAMEL_CASE_BOUNDARY: Final = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_IDENTIFIER_SEPARATOR: Final = re.compile(r"[^A-Za-z0-9]+")


def analyze_python_source(source: str) -> tuple[PythonFlowFinding, ...]:
    """Return stable, high-specificity findings for parseable Python source."""

    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return ()
    findings: list[PythonFlowFinding] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            findings.extend(_analyze_function(node))
    findings.extend(_predictable_prng_findings(tree))
    unique = {(item.rule_id, item.line, item.sink, item.source_names): item for item in findings}
    return tuple(unique[key] for key in sorted(unique))


def _predictable_prng_findings(tree: ast.Module) -> list[PythonFlowFinding]:
    """Prove a caller-controlled seed reaches an exposed generator result.

    This deliberately does not flag every use of ``random``.  A finding needs
    all three facts in one bounded source unit: an explicitly untrusted
    parameter, a seed operation (possibly through a tiny local helper), and a
    subsequent result from the same receiver returned to the caller.
    """

    functions = [node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
    seed_helpers: dict[str, dict[str, frozenset[str]]] = {}
    for function in functions:
        tainted = _parameter_origins(function)
        receivers: dict[str, frozenset[str]] = {}
        for call in _ordered_calls(function):
            name = _qualified_name(call.func)
            receiver, _, method = name.rpartition(".")
            if method.casefold() != "seed" or not receiver:
                continue
            origins = _call_argument_origins(call, 0, tainted)
            if origins and _has_explicitly_untrusted_network_origin(origins):
                receivers[receiver] = origins
        if receivers:
            seed_helpers[function.name] = receivers

    findings: list[PythonFlowFinding] = []
    reported_receivers: set[str] = set()
    for function in functions:
        tainted = _parameter_origins(function)
        seeded: dict[str, frozenset[str]] = {}
        returned_call_ids = {
            id(call)
            for item in ast.walk(function)
            if isinstance(item, ast.Return) and item.value is not None
            for call in ast.walk(item.value)
            if isinstance(call, ast.Call)
        }
        for call in _ordered_calls(function):
            name = _qualified_name(call.func)
            receiver, _, method = name.rpartition(".")
            if method.casefold() == "seed" and receiver:
                seed_origins = _call_argument_origins(call, 0, tainted)
                if seed_origins and _has_explicitly_untrusted_network_origin(seed_origins):
                    seeded[receiver] = seed_origins
                continue
            helper_receivers = seed_helpers.get(name)
            if helper_receivers:
                helper_origins = frozenset(origin for argument in call.args for origin in _origins(argument, tainted))
                if helper_origins and _has_explicitly_untrusted_network_origin(helper_origins):
                    for helper_receiver in helper_receivers:
                        seeded[helper_receiver] = helper_origins
                continue
            generator_origins = seeded.get(receiver)
            if (
                generator_origins is None
                or receiver in reported_receivers
                or id(call) not in returned_call_ids
                or method.casefold() in {"seed", "getstate", "setstate"}
            ):
                continue
            findings.append(
                PythonFlowFinding(
                    rule_id="CWE-330",
                    native_rule_id="PYFLOW-PREDICTABLE-PRNG-001",
                    title="Caller-controlled seed makes returned pseudo-random output predictable",
                    severity="MEDIUM",
                    confidence="HIGH",
                    line=int(call.lineno),
                    description=(
                        "An explicitly untrusted function parameter controls the generator seed before a value "
                        "from the same generator is returned to the caller."
                    ),
                    impact=(
                        "A caller can reproduce the generated sequence; using the returned value as a token, "
                        "nonce, identifier, or other security value would make it predictable."
                    ),
                    remediation=(
                        "Use a cryptographically secure generator for security-sensitive values and never seed it "
                        "with caller-controlled data."
                    ),
                    source_names=tuple(sorted(generator_origins)),
                    sink=name,
                )
            )
            reported_receivers.add(receiver)
    return findings


def _parameter_origins(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> dict[str, frozenset[str]]:
    parameters = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
    origins = {item.arg: frozenset({f"parameter:{item.arg}"}) for item in parameters}
    if node.args.vararg is not None:
        origins[node.args.vararg.arg] = frozenset({f"parameter:{node.args.vararg.arg}"})
    if node.args.kwarg is not None:
        origins[node.args.kwarg.arg] = frozenset({f"parameter:{node.args.kwarg.arg}"})
    return origins


def _ordered_calls(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.Call]:
    return sorted(
        (item for item in ast.walk(node) if isinstance(item, ast.Call)),
        key=lambda item: (int(item.lineno), int(item.col_offset)),
    )


def _analyze_function(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[PythonFlowFinding]:
    tainted = {
        argument.arg: frozenset({f"parameter:{argument.arg}"})
        for argument in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
    }
    if node.args.vararg is not None:
        tainted[node.args.vararg.arg] = frozenset({f"parameter:{node.args.vararg.arg}"})
    if node.args.kwarg is not None:
        tainted[node.args.kwarg.arg] = frozenset({f"parameter:{node.args.kwarg.arg}"})
    findings: list[PythonFlowFinding] = []
    _scan_statements(node.body, tainted, findings)
    return findings


def _scan_statements(
    statements: list[ast.stmt],
    tainted: dict[str, frozenset[str]],
    findings: list[PythonFlowFinding],
) -> None:
    for statement in statements:
        for call in (item for item in ast.walk(statement) if isinstance(item, ast.Call)):
            findings.extend(_classify_call(call, tainted))
        if isinstance(statement, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            value = statement.value
            if value is None:
                continue
            origins = _origins(value, tainted)
            targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
            for target in targets:
                for name in _assigned_names(target):
                    if origins:
                        tainted[name] = origins
                    else:
                        tainted.pop(name, None)
        elif isinstance(statement, (ast.For, ast.AsyncFor)):
            origins = _origins(statement.iter, tainted)
            nested = dict(tainted)
            for name in _assigned_names(statement.target):
                if origins:
                    nested[name] = origins
            _scan_statements(statement.body, nested, findings)
            _scan_statements(statement.orelse, dict(nested), findings)
        elif isinstance(statement, ast.If):
            _scan_statements(statement.body, dict(tainted), findings)
            _scan_statements(statement.orelse, dict(tainted), findings)
        elif isinstance(statement, (ast.With, ast.AsyncWith)):
            _scan_statements(statement.body, dict(tainted), findings)
        elif isinstance(statement, ast.Try):
            _scan_statements(statement.body, dict(tainted), findings)
            for handler in statement.handlers:
                _scan_statements(handler.body, dict(tainted), findings)
            _scan_statements(statement.orelse, dict(tainted), findings)
            _scan_statements(statement.finalbody, dict(tainted), findings)
        elif isinstance(statement, ast.Match):
            for case in statement.cases:
                _scan_statements(case.body, dict(tainted), findings)


def _classify_call(call: ast.Call, tainted: dict[str, frozenset[str]]) -> list[PythonFlowFinding]:
    name = _qualified_name(call.func)
    argument_index = _NETWORK_SINK_ARGUMENT.get(name, 0)
    origins = _call_argument_origins(call, argument_index, tainted)
    if not origins:
        return []
    line = int(call.lineno)
    source_names = tuple(sorted(origins))
    if name in _NETWORK_SINK_ARGUMENT:
        # A parameter is not evidence of attacker control merely because it is
        # named ``url``.  Publishing every generic URL wrapper as authoritative
        # SSRF made a bounded flow proof overstate its source boundary.  Keep
        # the broader parameter-taint model for the other sinks, but require a
        # real request/input source or an explicitly untrusted parameter name
        # before emitting CWE-918.
        if not _has_explicitly_untrusted_network_origin(origins):
            return []
        return [
            PythonFlowFinding(
                rule_id="CWE-918",
                native_rule_id="PYFLOW-SSRF-001",
                title="User-controlled URL reaches an outbound request",
                severity="HIGH",
                description="An untrusted value flows into a network request target without an allowlist proof.",
                impact="An attacker may make the server access internal services, cloud metadata, or unintended hosts.",
                remediation=(
                    "Allowlist schemes and destinations, resolve and validate every IP, "
                    "and block redirects to private ranges."
                ),
                confidence="HIGH",
                line=line,
                source_names=source_names,
                sink=name,
            )
        ]
    if name in _COMMAND_SINKS:
        return [
            PythonFlowFinding(
                rule_id="CWE-78",
                native_rule_id="PYFLOW-CMD-001",
                title="User-controlled data reaches an operating-system command",
                severity="CRITICAL",
                description="An untrusted value flows into a process or shell execution API.",
                impact="An attacker may execute commands with the privileges of the application process.",
                remediation=(
                    "Use a fixed executable and argument vector; validate every user-controlled argument "
                    "and avoid a shell."
                ),
                confidence="HIGH",
                line=line,
                source_names=source_names,
                sink=name,
            )
        ]
    if name in {"eval", "exec"}:
        return [
            PythonFlowFinding(
                rule_id="CWE-95",
                native_rule_id="PYFLOW-EVAL-001",
                title="User-controlled data reaches dynamic code evaluation",
                severity="CRITICAL",
                description="An untrusted value flows directly into eval or exec.",
                impact="An attacker may execute arbitrary Python code in the application process.",
                remediation="Remove dynamic evaluation and parse input with a fixed schema and allowlisted operations.",
                confidence="HIGH",
                line=line,
                source_names=source_names,
                sink=name,
            )
        ]
    if name == "open" or name.endswith(".open"):
        return [
            PythonFlowFinding(
                rule_id="CWE-22",
                native_rule_id="PYFLOW-PATH-001",
                title="User-controlled path reaches a filesystem open operation",
                severity="HIGH",
                description="An untrusted path reaches a file-open sink without a demonstrated containment check.",
                impact="An attacker may read or overwrite files outside the intended application directory.",
                remediation=(
                    "Resolve the path against a fixed root and reject any result outside that root; "
                    "prefer opaque file identifiers."
                ),
                confidence="HIGH",
                line=line,
                source_names=source_names,
                sink=name,
            )
        ]
    if name.endswith((".execute", ".executemany", ".objects.raw")):
        django_raw = name.endswith(".objects.raw")
        return [
            PythonFlowFinding(
                rule_id="CWE-89",
                native_rule_id=("PYFLOW-DJANGO-RAW-SQL-001" if django_raw else "PYFLOW-SQL-001"),
                title="User-controlled SQL reaches a database execution sink",
                severity="CRITICAL",
                description=(
                    "An untrusted expression flows into Django's raw-query API."
                    if django_raw
                    else "An untrusted expression flows into a SQL execution method."
                ),
                impact="An attacker may read or modify database data and bypass application authorization.",
                remediation="Use a constant query with driver-supported parameter binding for every untrusted value.",
                confidence="HIGH",
                line=line,
                source_names=source_names,
                sink=name,
            )
        ]
    if any(name.endswith(suffix) for suffix in _XML_SINK_SUFFIXES):
        return [
            PythonFlowFinding(
                rule_id="CWE-611",
                native_rule_id="PYFLOW-XXE-001",
                title="User-controlled XML reaches a parser with unsafe entity defaults",
                severity="HIGH",
                description=(
                    "Untrusted XML reaches a parser API without evidence that external entities and DTDs are disabled."
                ),
                impact="An attacker may read local files, trigger server-side requests, or exhaust parser resources.",
                remediation=(
                    "Use a hardened parser such as defusedxml or explicitly disable DTD and external-entity resolution."
                ),
                confidence="HIGH",
                line=line,
                source_names=source_names,
                sink=name,
            )
        ]
    return []


def _call_argument_origins(
    call: ast.Call,
    argument_index: int,
    tainted: dict[str, frozenset[str]],
) -> frozenset[str]:
    """Resolve the security-relevant argument, including an explicit URL keyword.

    Treating every sink's first positional argument as the target produced false
    SSRF findings for APIs such as ``requests.request(method, url)`` and bound
    ``HTTPConnection.request(method, url)`` callables.
    """

    origins: set[str] = set()
    if len(call.args) > argument_index:
        origins.update(_origins(call.args[argument_index], tainted))
    for keyword in call.keywords:
        if keyword.arg in {"url", "uri"}:
            origins.update(_origins(keyword.value, tainted))
    return frozenset(origins)


def _origins(node: ast.AST, tainted: dict[str, frozenset[str]]) -> frozenset[str]:
    if isinstance(node, ast.Name):
        return tainted.get(node.id, frozenset())
    if isinstance(node, ast.Call) and _is_untrusted_source(node):
        return frozenset({f"source:{_qualified_name(node.func)}"})
    values: set[str] = set()
    for child in ast.iter_child_nodes(node):
        values.update(_origins(child, tainted))
    return frozenset(values)


def _is_untrusted_source(call: ast.Call) -> bool:
    name = _qualified_name(call.func)
    return name == "input" or name in {
        "request.args.get",
        "request.form.get",
        "request.values.get",
        "request.json.get",
        "request.GET.get",
        "request.POST.get",
    }


def _has_explicitly_untrusted_network_origin(origins: frozenset[str]) -> bool:
    return any(
        origin.startswith("source:")
        or (
            origin.startswith("parameter:")
            and bool(_identifier_tokens(origin.removeprefix("parameter:")) & _EXPLICITLY_UNTRUSTED_PARAMETER_TOKENS)
        )
        for origin in origins
    )


def _identifier_tokens(name: str) -> set[str]:
    separated = _CAMEL_CASE_BOUNDARY.sub("_", name)
    return {item.casefold() for item in _IDENTIFIER_SEPARATOR.split(separated) if item}


def _assigned_names(node: ast.AST) -> tuple[str, ...]:
    return tuple(item.id for item in ast.walk(node) if isinstance(item, ast.Name))


def _qualified_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Call):
        # Preserve the callable part of a chained expression such as
        # ``connection.cursor().execute``.  The previous empty name caused a
        # tainted SQL expression passed through a cursor factory to disappear
        # before the ``.execute`` sink classifier saw it.
        return _qualified_name(node.func)
    if isinstance(node, ast.Attribute):
        parent = _qualified_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


__all__ = ["PythonFlowFinding", "analyze_python_source"]
