from __future__ import annotations

import hashlib
import re
from collections import defaultdict, deque
from dataclasses import dataclass

from secmind.audit_kernel.contracts import (
    AuditUnit,
    CandidateFlow,
    CodeSite,
    FlowEdge,
    FlowEdgeKind,
    FlowVerdict,
    SemanticCheck,
    StructuralConsistencyCertificate,
    content_digest,
)


class JavaEvidenceError(ValueError):
    """The immutable Java input cannot be safely inspected."""


@dataclass(frozen=True, slots=True)
class _Pattern:
    family: str
    expression: re.Pattern[str]
    cwe: int | None = None


@dataclass(frozen=True, slots=True)
class _Taint:
    source: CodeSite
    terminal_node_id: str
    edges: tuple[FlowEdge, ...]
    sanitizers: tuple[CodeSite, ...]


@dataclass(frozen=True, slots=True)
class _DetectedSink:
    pattern: _Pattern
    start: int
    relevant_text: str
    bound_taint: _Taint | None = None
    uses_bound_taint: bool = False
    symbol: str | None = None


_IDENTIFIER = r"[A-Za-z_$][A-Za-z0-9_$]*"
_ASSIGNMENT = re.compile(rf"\b({_IDENTIFIER})\s*=\s*(.+)$", re.DOTALL)
_CONDITION = re.compile(r"\bif\s*\((.*?)\)", re.DOTALL)
_RUNTIME_FACTORY = re.compile(r"\bRuntime\s*\.\s*getRuntime\s*\(\s*\)")
_VARIABLE_EXEC = re.compile(rf"\b(?P<receiver>{_IDENTIFIER})\s*\.\s*exec\s*\(")
_PROCESS_BUILDER_CONSTRUCTOR = re.compile(r"\bnew\s+ProcessBuilder\s*\(")
_PROCESS_BUILDER_COMMAND = re.compile(
    rf"\b(?P<receiver>{_IDENTIFIER})\s*\.\s*command\s*\((?P<arguments>.*?)\)",
    re.DOTALL,
)
_PROCESS_BUILDER_ADD = re.compile(
    rf"\b(?P<receiver>{_IDENTIFIER})\s*\.\s*command\s*\(\s*\)\s*\.\s*"
    r"(?:add|addAll)\s*\((?P<arguments>.*?)\)",
    re.DOTALL,
)
_PROCESS_BUILDER_START = re.compile(rf"\b(?P<receiver>{_IDENTIFIER})\s*\.\s*start\s*\(\s*\)")
_INLINE_PROCESS_BUILDER_START = re.compile(
    r"\bnew\s+ProcessBuilder\s*\((?P<arguments>.*?)\)\s*\.\s*start\s*\(\s*\)",
    re.DOTALL,
)
_COMMAND_EXECUTION = _Pattern("command_execution", re.compile(r"(?!)"), 78)

SOURCE_PATTERNS = (
    _Pattern("http_parameter", re.compile(r"\bgetParameter(?:Values|Map|Names)?\s*\(")),
    _Pattern("http_header", re.compile(r"\bgetHeader(?:s|Names)?\s*\(")),
    _Pattern("http_cookie", re.compile(r"\bgetCookies\s*\(")),
    _Pattern("http_body", re.compile(r"\b(?:getInputStream|getReader|getQueryString)\s*\(")),
    _Pattern("environment", re.compile(r"\bSystem\s*\.\s*getenv\s*\(")),
    _Pattern("console_input", re.compile(r"\b(?:readLine|nextLine|next)\s*\(")),
)

SINK_PATTERNS = (
    _Pattern(
        "sql_execution",
        re.compile(r"\.\s*execute(?:Query|Update|LargeUpdate|Batch)?\s*\("),
        89,
    ),
    _Pattern(
        "command_execution",
        re.compile(r"\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\("),
        78,
    ),
    _Pattern(
        "file_path",
        re.compile(r"\bnew\s+(?:File|FileInputStream|FileOutputStream|FileReader|FileWriter)\s*\("),
        22,
    ),
    _Pattern("file_path", re.compile(r"\b(?:Paths\s*\.\s*get|Path\s*\.\s*of)\s*\("), 22),
    _Pattern(
        "file_path",
        re.compile(r"\bFiles\s*\.\s*(?:read|write|copy|move|delete|newInputStream|newOutputStream)\w*\s*\("),
        22,
    ),
    _Pattern("html_output", re.compile(r"\.\s*(?:print|println|write|append)\s*\("), 79),
    _Pattern("ldap_filter", re.compile(r"\.\s*search\s*\("), 90),
    _Pattern(
        "session_storage",
        re.compile(
            r"\.\s*(?:setAttribute|putValue)\s*\(\s*[^,]+,",
            re.DOTALL,
        ),
        501,
    ),
    _Pattern("xpath_expression", re.compile(r"\.\s*(?:evaluate|compile)\s*\("), 643),
)

SANITIZER_PATTERNS = (
    _Pattern(
        "html_encoding",
        re.compile(
            r"\b(?:encodeForHTML|escapeHtml\w*|htmlEscape|forHtml|sanitizeHtml|HtmlUtils\s*\.\s*htmlEscape)\s*\("
        ),
    ),
    _Pattern(
        "path_normalization",
        re.compile(r"\b(?:normalize|getCanonicalPath|getCanonicalFile|toRealPath)\s*\("),
    ),
    _Pattern(
        "input_validation",
        re.compile(r"\b(?:matches|Pattern\s*\.\s*matches|isValid|validate|allowlist)\s*\("),
    ),
    _Pattern(
        "sql_parameterization",
        re.compile(r"\.\s*set(?:String|Int|Long|Object|Boolean|Date)\s*\("),
    ),
    _Pattern(
        "shell_escaping",
        re.compile(r"\b(?:escapeShell|quoteArgument|sanitizeCommand)\s*\("),
    ),
)

CWE_SINK_FAMILIES: dict[int, frozenset[str]] = {
    22: frozenset({"file_path"}),
    78: frozenset({"command_execution"}),
    79: frozenset({"html_output"}),
    89: frozenset({"sql_execution"}),
    90: frozenset({"ldap_filter"}),
    327: frozenset({"crypto_operation"}),
    328: frozenset({"digest_operation"}),
    330: frozenset({"security_random_value"}),
    501: frozenset({"session_storage"}),
    614: frozenset({"cookie_transport"}),
    643: frozenset({"xpath_expression"}),
}


def _stable_id(prefix: str, payload: dict[str, object]) -> str:
    return f"{prefix}-{content_digest(payload)}"


def _site(
    unit: AuditUnit,
    *,
    line: int,
    column: int,
    family: str,
    symbol: str | None,
    kind: str,
) -> CodeSite:
    node_id = _stable_id(
        "node",
        {
            "unit_id": unit.unit_id,
            "path": unit.primary_path,
            "line": line,
            "column": column,
            "family": family,
            "symbol": symbol,
            "kind": kind,
        },
    )
    return CodeSite(
        node_id=node_id,
        path=unit.primary_path,
        line=line,
        column=column,
        family=family,
        symbol=symbol,
        file_sha256=unit.source_sha256,
    )


def _edge(from_node_id: str, to_node_id: str, kind: FlowEdgeKind, symbol: str | None = None) -> FlowEdge:
    return FlowEdge(
        edge_id=_stable_id(
            "edge",
            {
                "from": from_node_id,
                "to": to_node_id,
                "kind": kind.value,
                "symbol": symbol,
            },
        ),
        from_node_id=from_node_id,
        to_node_id=to_node_id,
        kind=kind,
        symbol=symbol,
    )


def _mask_comments_and_literals(source: str) -> str:
    """Mask comments and literal bodies while preserving byte positions and lines."""

    result = list(source)
    state = "normal"
    escaped = False
    index = 0
    while index < len(source):
        character = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if state == "normal":
            if character == "/" and following == "/":
                result[index] = result[index + 1] = " "
                state = "line_comment"
                index += 2
                continue
            if character == "/" and following == "*":
                result[index] = result[index + 1] = " "
                state = "block_comment"
                index += 2
                continue
            if character == '"':
                result[index] = " "
                state = "string"
            elif character == "'":
                result[index] = " "
                state = "character"
        elif state == "line_comment":
            if character == "\n":
                state = "normal"
            else:
                result[index] = " "
        elif state == "block_comment":
            if character == "*" and following == "/":
                result[index] = result[index + 1] = " "
                state = "normal"
                index += 2
                continue
            if character != "\n":
                result[index] = " "
        else:
            if character == "\n":
                # Invalid multiline literals are left structurally visible to
                # avoid collapsing all following source into one false string.
                state = "normal"
                escaped = False
            else:
                result[index] = " "
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif (state == "string" and character == '"') or (state == "character" and character == "'"):
                    state = "normal"
        index += 1
    return "".join(result)


def _statements(masked_source: str) -> list[tuple[str, int, int]]:
    statements: list[tuple[str, int, int]] = []
    start = 0
    for match in re.finditer(r";", masked_source):
        end = match.end()
        text = masked_source[start:end]
        if text.strip():
            statements.append((text, start, masked_source.count("\n", 0, start) + 1))
        start = end
    tail = masked_source[start:]
    if tail.strip():
        statements.append((tail, start, masked_source.count("\n", 0, start) + 1))
    return statements


def _location(statement: str, statement_line: int, offset: int) -> tuple[int, int]:
    prefix = statement[:offset]
    line = statement_line + prefix.count("\n")
    column = len(prefix.rsplit("\n", 1)[-1]) + 1
    return line, column


def _first_match(patterns: tuple[_Pattern, ...], text: str) -> tuple[_Pattern, re.Match[str]] | None:
    matches = ((pattern, match) for pattern in patterns if (match := pattern.expression.search(text)) is not None)
    return min(matches, key=lambda item: item[1].start(), default=None)


def _referenced_taints(text: str, taints: dict[str, _Taint]) -> list[tuple[str, _Taint]]:
    referenced: list[tuple[int, str, _Taint]] = []
    for symbol, taint in taints.items():
        match = re.search(rf"(?<![A-Za-z0-9_$]){re.escape(symbol)}(?![A-Za-z0-9_$])", text)
        if match is not None:
            referenced.append((match.start(), symbol, taint))
    return [(symbol, taint) for _offset, symbol, taint in sorted(referenced)]


def _derive_taint(
    unit: AuditUnit,
    *,
    statement: str,
    statement_line: int,
    expression: str,
    expression_offset: int,
    target_offset: int,
    target_symbol: str,
    target_family: str,
    edge_kind: FlowEdgeKind,
    taints: dict[str, _Taint],
) -> _Taint | None:
    source_match = _first_match(SOURCE_PATTERNS, expression)
    referenced = _referenced_taints(expression, taints)
    inherited = referenced[0][1] if referenced else None
    source_site = inherited.source if inherited is not None else None
    edges = list(inherited.edges if inherited is not None else ())
    sanitizers = list(inherited.sanitizers if inherited is not None else ())
    terminal = inherited.terminal_node_id if inherited is not None else None

    if source_match is not None:
        pattern, match = source_match
        line, column = _location(statement, statement_line, expression_offset + match.start())
        source_site = _site(
            unit,
            line=line,
            column=column,
            family=pattern.family,
            symbol=target_symbol,
            kind="source",
        )
        terminal = source_site.node_id
    if source_site is None or terminal is None:
        return None

    sanitizer_match = _first_match(SANITIZER_PATTERNS, expression)
    if sanitizer_match is not None:
        pattern, match = sanitizer_match
        line, column = _location(statement, statement_line, expression_offset + match.start())
        sanitizer = _site(
            unit,
            line=line,
            column=column,
            family=pattern.family,
            symbol=target_symbol,
            kind="sanitizer",
        )
        edges.append(
            _edge(
                terminal,
                sanitizer.node_id,
                FlowEdgeKind.SANITIZATION,
                target_symbol,
            )
        )
        sanitizers.append(sanitizer)
        terminal = sanitizer.node_id
    else:
        line, column = _location(statement, statement_line, target_offset)
        target = _site(
            unit,
            line=line,
            column=column,
            family=target_family,
            symbol=target_symbol,
            kind="assignment" if target_family == "local_value" else "configuration",
        )
        edges.append(_edge(terminal, target.node_id, edge_kind, target_symbol))
        terminal = target.node_id
    return _Taint(source_site, terminal, tuple(edges), tuple(sanitizers))


class JavaEvidenceExtractor:
    """Conservative Java candidate generator; it never emits final findings."""

    def __init__(self, *, tool_name: str, tool_version: str, rule_bundle_digest: str) -> None:
        if not tool_name or not tool_version:
            raise JavaEvidenceError("tool identity is required")
        if len(rule_bundle_digest) != 64 or any(
            character not in "0123456789abcdef" for character in rule_bundle_digest
        ):
            raise JavaEvidenceError("a pinned lowercase rule bundle digest is required")
        self.tool_name = tool_name
        self.tool_version = tool_version
        self.rule_bundle_digest = rule_bundle_digest

    def extract(self, unit: AuditUnit, source: str) -> tuple[CandidateFlow, ...]:
        source_digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
        if source_digest != unit.source_sha256:
            raise JavaEvidenceError("Java source does not match the immutable AuditUnit digest")
        masked = _mask_comments_and_literals(source)
        taints: dict[str, _Taint] = {}
        runtime_variables: set[str] = set()
        process_builders: dict[str, _Taint | None] = {}
        flows: list[CandidateFlow] = []

        for statement, _absolute_offset, statement_line in _statements(masked):
            assignment = _ASSIGNMENT.search(statement.rstrip(";\n\r\t "))
            if assignment is not None:
                symbol = assignment.group(1)
                expression = assignment.group(2)
                derived = _derive_taint(
                    unit,
                    statement=statement,
                    statement_line=statement_line,
                    expression=expression,
                    expression_offset=assignment.start(2),
                    target_offset=assignment.start(1),
                    target_symbol=symbol,
                    target_family="local_value",
                    edge_kind=(FlowEdgeKind.CONCATENATION if "+" in expression else FlowEdgeKind.ASSIGNMENT),
                    taints=taints,
                )
                if derived is None:
                    taints.pop(symbol, None)
                else:
                    taints[symbol] = derived

                expression_value = expression.strip()
                runtime_alias = next(
                    (
                        value
                        for value in runtime_variables
                        if re.fullmatch(rf"\(?\s*{re.escape(value)}\s*\)?", expression_value)
                    ),
                    None,
                )
                if _RUNTIME_FACTORY.search(expression) is not None or runtime_alias is not None:
                    runtime_variables.add(symbol)
                else:
                    runtime_variables.discard(symbol)

                builder_alias = next(
                    (
                        value
                        for value in process_builders
                        if re.fullmatch(rf"\(?\s*{re.escape(value)}\s*\)?", expression_value)
                    ),
                    None,
                )
                if _PROCESS_BUILDER_CONSTRUCTOR.search(expression) is not None:
                    process_builders[symbol] = taints.get(symbol)
                elif builder_alias is not None:
                    process_builders[symbol] = process_builders[builder_alias]
                else:
                    process_builders.pop(symbol, None)

            add_spans: set[tuple[int, int]] = set()
            for command_match in _PROCESS_BUILDER_ADD.finditer(statement):
                receiver = command_match.group("receiver")
                if receiver not in process_builders:
                    continue
                add_spans.add(command_match.span())
                arguments = command_match.group("arguments")
                command_taint = _derive_taint(
                    unit,
                    statement=statement,
                    statement_line=statement_line,
                    expression=arguments,
                    expression_offset=command_match.start("arguments"),
                    target_offset=command_match.start(),
                    target_symbol=receiver,
                    target_family="process_builder_command",
                    edge_kind=FlowEdgeKind.ARGUMENT,
                    taints=taints,
                )
                if command_taint is not None:
                    process_builders[receiver] = command_taint

            for command_match in _PROCESS_BUILDER_COMMAND.finditer(statement):
                receiver = command_match.group("receiver")
                if receiver not in process_builders or any(
                    start <= command_match.start() < end for start, end in add_spans
                ):
                    continue
                arguments = command_match.group("arguments")
                process_builders[receiver] = _derive_taint(
                    unit,
                    statement=statement,
                    statement_line=statement_line,
                    expression=arguments,
                    expression_offset=command_match.start("arguments"),
                    target_offset=command_match.start(),
                    target_symbol=receiver,
                    target_family="process_builder_command",
                    edge_kind=FlowEdgeKind.ARGUMENT,
                    taints=taints,
                )

            detected_sinks: list[_DetectedSink] = []
            for sink_pattern in SINK_PATTERNS:
                if sink_pattern.cwe not in unit.target_cwes:
                    continue
                detected_sinks.extend(
                    _DetectedSink(
                        pattern=sink_pattern,
                        start=sink_match.start(),
                        relevant_text=statement[sink_match.start() :],
                    )
                    for sink_match in sink_pattern.expression.finditer(statement)
                )
            if 78 in unit.target_cwes:
                detected_sinks.extend(
                    _DetectedSink(
                        pattern=_COMMAND_EXECUTION,
                        start=match.start(),
                        relevant_text=statement[match.start() :],
                        symbol=match.group("receiver"),
                    )
                    for match in _VARIABLE_EXEC.finditer(statement)
                    if match.group("receiver") in runtime_variables
                )
                detected_sinks.extend(
                    _DetectedSink(
                        pattern=_COMMAND_EXECUTION,
                        start=match.start(),
                        relevant_text=statement[match.start() :],
                        bound_taint=process_builders[match.group("receiver")],
                        uses_bound_taint=True,
                        symbol=match.group("receiver"),
                    )
                    for match in _PROCESS_BUILDER_START.finditer(statement)
                    if match.group("receiver") in process_builders
                )
                detected_sinks.extend(
                    _DetectedSink(
                        pattern=_COMMAND_EXECUTION,
                        start=match.start(),
                        relevant_text=statement[match.start() :],
                    )
                    for match in _INLINE_PROCESS_BUILDER_START.finditer(statement)
                )

            unique_sinks = {
                (
                    sink.pattern.cwe,
                    sink.start,
                    sink.symbol,
                    sink.uses_bound_taint,
                ): sink
                for sink in detected_sinks
            }
            for sink in sorted(
                unique_sinks.values(),
                key=lambda value: (
                    value.start,
                    value.pattern.cwe or 0,
                    value.symbol or "",
                ),
            ):
                sink_pattern = sink.pattern
                sink_start = sink.start
                if sink_pattern.cwe is None:
                    continue
                sink_line, sink_column = _location(statement, statement_line, sink_start)
                sink_site = _site(
                    unit,
                    line=sink_line,
                    column=sink_column,
                    family=sink_pattern.family,
                    symbol=sink.symbol,
                    kind="sink",
                )
                relevant_text = sink.relevant_text
                referenced = _referenced_taints(relevant_text, taints)
                taint = sink.bound_taint if sink.uses_bound_taint else (referenced[0][1] if referenced else None)
                source_site = taint.source if taint is not None else None
                edges = list(taint.edges if taint is not None else ())
                sanitizers = list(taint.sanitizers if taint is not None else ())

                if source_site is None:
                    direct_source = _first_match(SOURCE_PATTERNS, relevant_text)
                    if direct_source is not None:
                        pattern, match = direct_source
                        line, column = _location(
                            statement,
                            statement_line,
                            sink_start + match.start(),
                        )
                        source_site = _site(
                            unit,
                            line=line,
                            column=column,
                            family=pattern.family,
                            symbol=None,
                            kind="source",
                        )
                        edges.append(
                            _edge(
                                source_site.node_id,
                                sink_site.node_id,
                                FlowEdgeKind.ARGUMENT,
                            )
                        )
                elif taint is not None:
                    edge_symbol = sink.symbol or (referenced[0][0] if referenced else None)
                    edges.append(
                        _edge(
                            taint.terminal_node_id,
                            sink_site.node_id,
                            FlowEdgeKind.CALL,
                            edge_symbol,
                        )
                    )

                if source_site is None:
                    verdict = FlowVerdict.UNKNOWN
                    confidence = 0.25
                elif sanitizers:
                    verdict = FlowVerdict.CANDIDATE_NEGATIVE
                    confidence = 0.8
                else:
                    verdict = FlowVerdict.CANDIDATE_POSITIVE
                    confidence = 0.9
                conditions = tuple(
                    " ".join(match.group(1).split())[:256]
                    for match in _CONDITION.finditer(statement)
                    if match.group(1).strip()
                )
                evidence_id = _stable_id(
                    "java",
                    {
                        "unit_id": unit.unit_id,
                        "cwe": sink_pattern.cwe,
                        "source_node_id": None if source_site is None else source_site.node_id,
                        "sink_node_id": sink_site.node_id,
                        "tool_name": self.tool_name,
                        "tool_version": self.tool_version,
                        "rule_bundle_digest": self.rule_bundle_digest,
                    },
                )
                flows.append(
                    CandidateFlow.create(
                        unit_id=unit.unit_id,
                        cwe=sink_pattern.cwe,
                        source_site=source_site,
                        sink_site=sink_site,
                        propagation_edges=edges,
                        sanitizer_sites=sanitizers,
                        branch_conditions=conditions,
                        tool_name=self.tool_name,
                        tool_version=self.tool_version,
                        rule_bundle_digest=self.rule_bundle_digest,
                        verdict=verdict,
                        confidence=confidence,
                        evidence_ids=[evidence_id],
                    )
                )
        return tuple(
            sorted(
                {flow.flow_id: flow for flow in flows}.values(),
                key=lambda flow: flow.flow_id,
            )
        )


def extract_java_candidate_flows(
    unit: AuditUnit,
    source: str,
    *,
    tool_name: str,
    tool_version: str,
    rule_bundle_digest: str,
) -> tuple[CandidateFlow, ...]:
    return JavaEvidenceExtractor(
        tool_name=tool_name,
        tool_version=tool_version,
        rule_bundle_digest=rule_bundle_digest,
    ).extract(unit, source)


def _reachable(adjacency: dict[str, set[str]], start: str) -> set[str]:
    visited: set[str] = set()
    queue: deque[str] = deque([start])
    while queue:
        node = queue.popleft()
        if node in visited:
            continue
        visited.add(node)
        queue.extend(sorted(adjacency.get(node, set()) - visited))
    return visited


def validate_structural_flow(
    unit: AuditUnit,
    flow: CandidateFlow,
) -> StructuralConsistencyCertificate:
    allowed_paths = {unit.primary_path, *unit.support_paths}
    checks: list[SemanticCheck] = []

    def add(check_id: str, passed: bool, detail: str) -> None:
        checks.append(SemanticCheck(check_id=check_id, passed=passed, detail=detail))

    add(
        "unit-binding",
        flow.unit_id == unit.unit_id,
        "Candidate flow must belong to the reviewed unit.",
    )
    add(
        "target-cwe",
        flow.cwe in unit.target_cwes,
        "Candidate CWE must be inside the immutable audit profile.",
    )
    add(
        "positive-candidate",
        flow.verdict == FlowVerdict.CANDIDATE_POSITIVE,
        "Only positive tool candidates may support a positive enhancement.",
    )
    add(
        "source-present",
        flow.source_site is not None,
        "A positive candidate requires a bound taint source or insecure configuration site.",
    )
    add(
        "tool-evidence",
        bool(flow.evidence_ids),
        "A candidate must carry immutable tool evidence.",
    )
    add(
        "sink-family",
        flow.sink_site.family in CWE_SINK_FAMILIES.get(flow.cwe, frozenset()),
        "The sink family must agree with the claimed CWE.",
    )
    add(
        "sink-scope",
        flow.sink_site.path == unit.primary_path and flow.sink_site.file_sha256 == unit.source_sha256,
        "The sink must bind to the immutable primary source.",
    )
    source_in_scope = flow.source_site is not None and flow.source_site.path in allowed_paths
    source_hash_valid = flow.source_site is not None and (
        flow.source_site.path != unit.primary_path or flow.source_site.file_sha256 == unit.source_sha256
    )
    add(
        "source-scope",
        source_in_scope and source_hash_valid,
        "The source must bind to the immutable unit scope.",
    )

    edge_ids = [edge.edge_id for edge in flow.propagation_edges]
    add(
        "unique-edges",
        len(edge_ids) == len(set(edge_ids)),
        "Propagation edges must be unique.",
    )
    adjacency: dict[str, set[str]] = defaultdict(set)
    reverse: dict[str, set[str]] = defaultdict(set)
    for edge in flow.propagation_edges:
        adjacency[edge.from_node_id].add(edge.to_node_id)
        reverse[edge.to_node_id].add(edge.from_node_id)
    source_node = None if flow.source_site is None else flow.source_site.node_id
    forward = set() if source_node is None else _reachable(adjacency, source_node)
    connected = source_node is not None and flow.sink_site.node_id in forward
    add(
        "source-sink-path",
        connected,
        "The normalized edge graph must connect source to sink.",
    )
    backward = _reachable(reverse, flow.sink_site.node_id)
    path_nodes = forward & backward
    sanitizer_on_path = any(site.node_id in path_nodes for site in flow.sanitizer_sites)
    add(
        "no-effective-sanitizer",
        not sanitizer_on_path,
        "A sanitizer on the claimed path blocks automatic promotion.",
    )

    return StructuralConsistencyCertificate.create(
        unit_id=unit.unit_id,
        flow_id=flow.flow_id,
        checks=checks,
        evidence_ids=flow.evidence_ids,
    )


def validate_structural_correction(
    unit: AuditUnit,
    flow: CandidateFlow,
) -> StructuralConsistencyCertificate:
    """Check a bounded sanitizer-backed correction candidate structurally."""

    allowed_paths = {unit.primary_path, *unit.support_paths}
    checks: list[SemanticCheck] = []

    def add(check_id: str, passed: bool, detail: str) -> None:
        checks.append(SemanticCheck(check_id=check_id, passed=passed, detail=detail))

    add("unit-binding", flow.unit_id == unit.unit_id, "Candidate flow must belong to the reviewed unit.")
    add("target-cwe", flow.cwe in unit.target_cwes, "Candidate CWE must be in the immutable profile.")
    add(
        "negative-candidate",
        flow.verdict == FlowVerdict.CANDIDATE_NEGATIVE,
        "Only a negative semantic candidate may correct a positive baseline.",
    )
    add("tool-evidence", bool(flow.evidence_ids), "Correction requires immutable tool evidence.")
    add(
        "sink-family",
        flow.sink_site.family in CWE_SINK_FAMILIES.get(flow.cwe, frozenset()),
        "The sink family must agree with the baseline CWE.",
    )
    add(
        "sink-scope",
        flow.sink_site.path == unit.primary_path and flow.sink_site.file_sha256 == unit.source_sha256,
        "The sink must bind to the immutable primary source.",
    )
    source = flow.source_site
    add(
        "source-scope",
        source is not None
        and source.path in allowed_paths
        and (source.path != unit.primary_path or source.file_sha256 == unit.source_sha256),
        "The source must bind to the immutable unit scope.",
    )
    adjacency: dict[str, set[str]] = defaultdict(set)
    reverse: dict[str, set[str]] = defaultdict(set)
    for edge in flow.propagation_edges:
        adjacency[edge.from_node_id].add(edge.to_node_id)
        reverse[edge.to_node_id].add(edge.from_node_id)
    source_node = None if source is None else source.node_id
    forward = set() if source_node is None else _reachable(adjacency, source_node)
    backward = _reachable(reverse, flow.sink_site.node_id)
    connected = source_node is not None and flow.sink_site.node_id in forward
    add("source-sink-path", connected, "The normalized graph must connect source and sink.")
    path_nodes = forward & backward
    sanitizer_on_path = any(site.node_id in path_nodes for site in flow.sanitizer_sites)
    add(
        "effective-sanitizer",
        sanitizer_on_path,
        "A negative correction requires a sanitizer on the exact source-to-sink path.",
    )
    return StructuralConsistencyCertificate.create(
        unit_id=unit.unit_id,
        flow_id=flow.flow_id,
        checks=checks,
        evidence_ids=flow.evidence_ids,
    )


# Compatibility aliases. These functions perform structural consistency
# checks and intentionally carry no independent semantic-authority claim.
validate_semantic_flow = validate_structural_flow
validate_semantic_correction = validate_structural_correction
