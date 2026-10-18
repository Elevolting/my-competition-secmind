"""High-precision deterministic Java weak-digest analysis.

This module deliberately implements one narrow rule. It starts with the
hash-bound candidates emitted by :class:`JavaConfigurationEvidenceExtractor`
and promotes only calls backed by a bounded intraprocedural def-use proof.
Incidental security vocabulary, documentation, checksums and ETags are not
evidence by themselves.
"""

from __future__ import annotations

import hashlib
import json
import re
from bisect import bisect_right
from dataclasses import dataclass
from typing import Final

from secmind.audit_kernel.contracts import AuditUnit, CandidateFlow
from secmind.audit_kernel.java_configuration import JavaConfigurationEvidenceExtractor
from secmind.java_security_flows import JavaSecurityFlow, analyze_java_security_flows
from secmind.schemas import Evidence, Finding

TOOL_NAME: Final = "java_semantic_sast"
TOOL_VERSION: Final = "2"
NATIVE_RULE_ID: Final = "JAVA-WEAK-DIGEST-SENSITIVE-001"
SEMANTIC_SIGNAL: Final = "java_sensitive_weak_digest"
RULE_BUNDLE_DIGEST: Final = hashlib.sha256(
    b"secmind-java-semantic-sast-v3-weak-digest-ldap-filter-sensitive-log"
).hexdigest()
PROFILE_DIGEST: Final = hashlib.sha256(b"secmind-java-semantic-sast-profile-v3").hexdigest()

_WEAK_DIGEST_CALL = re.compile(
    r"\b(?:java\s*\.\s*security\s*\.\s*)?MessageDigest\s*\.\s*getInstance\s*"
    r"\(\s*\"(?P<algorithm>MD2|MD4|MD5|SHA|SHA[-_ ]?1)\"",
    re.IGNORECASE,
)
_METHOD = re.compile(
    r"(?P<header>(?:(?:public|protected|private|static|final|synchronized|native|abstract|strictfp)\s+)*"
    r"[A-Za-z_$][\w$<>,.?\[\] ]*\s+(?P<name>[A-Za-z_$][\w$]*)\s*"
    r"\((?P<parameters>[^;{}]{0,800})\)\s*(?:throws\s+[^{}]{1,500})?)\s*\{",
    re.IGNORECASE,
)
_IDENTIFIER = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")
_FIELD_DECLARATION = re.compile(
    r"(?m)^[ \t]*(?:(?:public|protected|private|static|final|transient|volatile)\s+)*"
    r"(?:[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*(?:\s*<[^;\n={}]{1,500}>)?"
    r"(?:\s*\[\s*\])?)\s+(?P<name>[A-Za-z_$][\w$]*)\s*(?:=[^;\n]*)?;"
)
_RECEIVER_DIGEST_CALL = re.compile(
    r"\b(?P<receiver>[A-Za-z_$][\w$]*)\s*\.\s*(?P<operation>update|digest)\s*\(",
    re.IGNORECASE,
)
_CALL = re.compile(
    r"(?:(?P<receiver>\b[A-Za-z_$][\w$]*)\s*\.\s*)?"
    r"(?P<method>[A-Za-z_$][\w$]*)\s*\(",
)
_WRITER_CONSTRUCTOR = re.compile(
    r"\bnew\s+(?:java\s*\.\s*io\s*\.\s*)?"
    r"(?:FileWriter|FileOutputStream|PrintWriter|BufferedWriter|OutputStreamWriter)\s*\(",
    re.IGNORECASE,
)

_SENSITIVE_ATOMS: Final = frozenset(
    {"password", "passwd", "pwd", "credential", "credentials", "secret", "authentication", "auth", "pin"}
)
_SENSITIVE_PAIRS: Final = frozenset({("access", "token"), ("refresh", "token"), ("api", "key")})
_NON_DATA_SUFFIXES: Final = frozenset(
    {
        "cache",
        "checksum",
        "dedup",
        "dedupe",
        "deduplicate",
        "deduplication",
        "doc",
        "docs",
        "documentation",
        "etag",
        "hint",
        "label",
        "length",
        "name",
        "pattern",
        "policies",
        "policy",
        "regex",
        "rule",
        "rules",
        "validation",
        "validator",
    }
)
_PERSISTENCE_METHODS: Final = frozenset({"append", "insert", "persist", "put", "save", "store", "update", "write"})
_WRITER_METHODS: Final = frozenset({"append", "format", "print", "printf", "println", "write"})
_SECURITY_OPERATION_TOKENS: Final = frozenset(
    {"authenticate", "authentication", "authorize", "integrity", "mac", "sign", "signature", "verify"}
)
_NON_SECURITY_SINK_TOKENS: Final = frozenset(
    {"cache", "checksum", "dedup", "dedupe", "deduplicate", "deduplication", "etag"}
)


@dataclass(frozen=True, slots=True)
class JavaSource:
    path: str
    source: str
    sha256: str


@dataclass(frozen=True, slots=True)
class WeakDigestContext:
    line: int
    algorithm: str
    sensitive_identifier: str
    method_name: str
    proof_kind: str
    sink: str


@dataclass(frozen=True, slots=True)
class _MethodSpan:
    start: int
    body_start: int
    end: int
    name: str
    parameters: str
    synthetic: bool


@dataclass(frozen=True, slots=True)
class _WeakOrigin:
    offset: int
    line: int
    algorithm: str


@dataclass(frozen=True, slots=True)
class _Proof:
    origin: _WeakOrigin
    sensitive_identifier: str
    proof_kind: str
    sink: str


def _canonical_digest(value: object) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _mask_comments(source: str) -> str:
    """Mask comments while preserving Java offsets and string literals."""

    output = list(source)
    state = "normal"
    escaped = False
    index = 0
    while index < len(source):
        character = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if state == "normal":
            if character == "/" and following == "/":
                output[index] = output[index + 1] = " "
                state = "line_comment"
                index += 2
                continue
            if character == "/" and following == "*":
                output[index] = output[index + 1] = " "
                state = "block_comment"
                index += 2
                continue
            if character == '"':
                state = "string"
            elif character == "'":
                state = "character"
        elif state == "line_comment":
            if character == "\n":
                state = "normal"
            else:
                output[index] = " "
        elif state == "block_comment":
            if character == "*" and following == "/":
                output[index] = output[index + 1] = " "
                state = "normal"
                index += 2
                continue
            if character != "\n":
                output[index] = " "
        elif character == "\n":
            state = "normal"
            escaped = False
        elif escaped:
            escaped = False
        elif character == "\\":
            escaped = True
        elif (state == "string" and character == '"') or (state == "character" and character == "'"):
            state = "normal"
        index += 1
    return "".join(output)


def _brace_pairs(source: str) -> dict[int, int]:
    """Index brace pairs once; callers never rescan a method body per digest."""

    stack: list[int] = []
    pairs: dict[int, int] = {}
    state = "normal"
    escaped = False
    for index, character in enumerate(source):
        if state == "normal":
            if character == '"':
                state = "string"
                continue
            if character == "'":
                state = "character"
                continue
            if character == "{":
                stack.append(index)
            elif character == "}":
                if stack:
                    pairs[stack.pop()] = index
        elif escaped:
            escaped = False
        elif character == "\\":
            escaped = True
        elif (state == "string" and character == '"') or (state == "character" and character == "'"):
            state = "normal"
    return pairs


def _method_spans(code: str) -> tuple[_MethodSpan, ...]:
    pairs = _brace_pairs(code)
    spans: list[_MethodSpan] = []
    for match in _METHOD.finditer(code):
        opening = match.end() - 1
        closing = pairs.get(opening)
        if closing is None:
            continue
        spans.append(
            _MethodSpan(
                start=match.start(),
                body_start=opening + 1,
                end=closing,
                name=match.group("name"),
                parameters=match.group("parameters"),
                synthetic=match.group("header").strip().casefold().startswith("new "),
            )
        )
    return tuple(sorted(spans, key=lambda item: (item.start, item.end)))


def _name_tokens(value: str) -> tuple[str, ...]:
    chunks = re.sub(r"[^A-Za-z0-9]+", " ", value).split()
    tokens: list[str] = []
    for chunk in chunks:
        tokens.extend(token.casefold() for token in re.findall(r"[A-Z]+(?=[A-Z][a-z]|\d|$)|[A-Z]?[a-z]+|\d+", chunk))
    return tuple(tokens)


def _sensitive_identifier(value: str) -> str | None:
    """Classify an identifier, never an incidental substring or prose literal."""

    tokens = _name_tokens(value)
    if not tokens or any(token in _NON_DATA_SUFFIXES for token in tokens):
        return None
    if any(token in _SENSITIVE_ATOMS for token in tokens):
        return value.casefold()
    if any(pair[0] in tokens and pair[1] in tokens for pair in _SENSITIVE_PAIRS):
        return value.casefold()
    return None


def _parameter_names(parameters: str) -> tuple[str, ...]:
    names: list[str] = []
    for declaration in parameters.split(","):
        identifiers = _IDENTIFIER.findall(declaration)
        if identifiers:
            names.append(identifiers[-1])
    return tuple(names)


def _field_names(code: str, spans: tuple[_MethodSpan, ...]) -> tuple[str, ...]:
    outside = list(code)
    merged: list[tuple[int, int]] = []
    for span in spans:
        if merged and span.start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], span.end))
        else:
            merged.append((span.start, span.end))
    for start, end in merged:
        for index in range(start, end + 1):
            if outside[index] != "\n":
                outside[index] = " "
    return tuple(match.group("name") for match in _FIELD_DECLARATION.finditer("".join(outside)))


def _child_spans(spans: tuple[_MethodSpan, ...]) -> dict[int, tuple[_MethodSpan, ...]]:
    """Map each span to its direct nested spans in one stack pass."""

    children: dict[int, list[_MethodSpan]] = {id(span): [] for span in spans}
    stack: list[_MethodSpan] = []
    for span in spans:
        while stack and span.start > stack[-1].end:
            stack.pop()
        while stack and span.end > stack[-1].end:
            stack.pop()
        if stack:
            children[id(stack[-1])].append(span)
        stack.append(span)
    return {key: tuple(value) for key, value in children.items()}


def _mask_literals(value: str) -> str:
    output = list(value)
    state = "normal"
    escaped = False
    for index, character in enumerate(value):
        if state == "normal":
            if character == '"':
                output[index] = " "
                state = "string"
            elif character == "'":
                output[index] = " "
                state = "character"
        else:
            if character != "\n":
                output[index] = " "
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif (state == "string" and character == '"') or (state == "character" and character == "'"):
                state = "normal"
    return "".join(output)


def _identifier_references(value: str) -> set[str]:
    return set(_IDENTIFIER.findall(_mask_literals(value)))


def _assignment(statement: str) -> tuple[str, str] | None:
    masked = _mask_literals(statement)
    for match in re.finditer(r"(?<![=!<>])=(?!=)", masked):
        left = masked[: match.start()]
        identifiers = _IDENTIFIER.findall(left)
        if identifiers:
            return identifiers[-1], statement[match.end() :]
    return None


def _call_arguments(value: str, opening: int) -> tuple[str, int] | None:
    depth = 0
    state = "normal"
    escaped = False
    for index in range(opening, len(value)):
        character = value[index]
        if state == "normal":
            if character == '"':
                state = "string"
            elif character == "'":
                state = "character"
            elif character == "(":
                depth += 1
            elif character == ")":
                depth -= 1
                if depth == 0:
                    return value[opening + 1 : index], index
        elif escaped:
            escaped = False
        elif character == "\\":
            escaped = True
        elif (state == "string" and character == '"') or (state == "character" and character == "'"):
            state = "normal"
    return None


def _statements(
    code: str,
    start: int,
    end: int,
    excluded: tuple[_MethodSpan, ...] = (),
) -> tuple[tuple[int, str], ...]:
    statements: list[tuple[int, str]] = []
    statement_start = start
    state = "normal"
    escaped = False
    parentheses = 0
    exclusion_index = 0
    index = start
    while index < end:
        if exclusion_index < len(excluded) and index >= excluded[exclusion_index].start:
            index = excluded[exclusion_index].end + 1
            exclusion_index += 1
            statement_start = index
            state = "normal"
            escaped = False
            parentheses = 0
            continue
        character = code[index]
        if state == "normal":
            if character == '"':
                state = "string"
            elif character == "'":
                state = "character"
            elif character == "(":
                parentheses += 1
            elif character == ")":
                parentheses = max(0, parentheses - 1)
            elif character == ";" and parentheses == 0:
                statements.append((statement_start, code[statement_start : index + 1]))
                statement_start = index + 1
            elif character in "{}" and parentheses == 0:
                statement_start = index + 1
        elif escaped:
            escaped = False
        elif character == "\\":
            escaped = True
        elif (state == "string" and character == '"') or (state == "character" and character == "'"):
            state = "normal"
        index += 1
    return tuple(statements)


def _source_label(expression: str, labels: dict[str, str]) -> str | None:
    references = _identifier_references(expression)
    matches = sorted(labels[name] for name in references if name in labels)
    return matches[0] if matches else None


def _origin_refs(expression: str, outputs: dict[str, frozenset[_WeakOrigin]]) -> frozenset[_WeakOrigin]:
    origins: set[_WeakOrigin] = set()
    for name in _identifier_references(expression):
        origins.update(outputs.get(name, ()))
    return frozenset(origins)


def _is_sensitive_target(
    expression: str,
    labels: dict[str, str],
    target_aliases: dict[str, str] | None = None,
) -> str | None:
    references = _identifier_references(expression)
    if target_aliases:
        aliases = sorted(target_aliases[name] for name in references if name in target_aliases)
        if aliases:
            return aliases[0]
    label = _source_label(expression, labels)
    if label is not None:
        return label
    for identifier in sorted(references):
        sensitive = _sensitive_identifier(identifier)
        if sensitive is not None:
            return sensitive
    for literal in re.findall(r'"((?:\\.|[^"\\])*)"', expression):
        sensitive = _sensitive_identifier(literal)
        if sensitive is not None:
            return sensitive
    return None


def _security_sink(
    receiver: str | None,
    method: str,
    *,
    sensitive_writers: dict[str, str],
) -> tuple[str, str] | None:
    method_tokens = _name_tokens(method)
    receiver_tokens = _name_tokens(receiver or "")
    method_folded = method.casefold()
    combined_tokens = (*receiver_tokens, *method_tokens)
    compact_name = re.sub(r"[^a-z0-9]", "", f"{receiver or ''}{method}".casefold())
    if any(token in _NON_SECURITY_SINK_TOKENS for token in combined_tokens) or any(
        marker in compact_name for marker in ("checksum", "etag", "dedup")
    ):
        return None
    if receiver in sensitive_writers and method_folded in _WRITER_METHODS:
        return sensitive_writers[receiver], f"{receiver}.{method}"
    if any(token in _SECURITY_OPERATION_TOKENS for token in combined_tokens):
        return (receiver or method).casefold(), f"{receiver + '.' if receiver else ''}{method}"
    sensitive = _sensitive_identifier(receiver or method)
    if sensitive is not None and any(token in _PERSISTENCE_METHODS for token in method_tokens):
        return sensitive, f"{receiver + '.' if receiver else ''}{method}"
    return None


def _analyze_method(
    code: str,
    span: _MethodSpan,
    *,
    field_labels: dict[str, str],
    line_starts: tuple[int, ...],
    excluded: tuple[_MethodSpan, ...] = (),
) -> tuple[_Proof, ...]:
    labels = dict(field_labels)
    for parameter in _parameter_names(span.parameters):
        sensitive = _sensitive_identifier(parameter)
        if sensitive is not None:
            labels[parameter] = sensitive

    weak_receivers: dict[str, _WeakOrigin] = {}
    updated_from: dict[_WeakOrigin, str] = {}
    digest_outputs: dict[str, frozenset[_WeakOrigin]] = {}
    sensitive_targets: dict[str, str] = {}
    sensitive_writers: dict[str, str] = {}
    proofs: dict[_WeakOrigin, _Proof] = {}

    def record(origin: _WeakOrigin, identifier: str, proof_kind: str, sink: str) -> None:
        candidate = _Proof(origin, identifier, proof_kind, sink)
        existing = proofs.get(origin)
        if existing is None or (candidate.proof_kind, candidate.sink, candidate.sensitive_identifier) < (
            existing.proof_kind,
            existing.sink,
            existing.sensitive_identifier,
        ):
            proofs[origin] = candidate

    for statement_offset, statement in _statements(code, span.body_start, span.end, excluded):
        assignment = _assignment(statement)
        lhs = assignment[0] if assignment else None
        rhs = assignment[1] if assignment else ""

        # Evaluate RHS aliases against the pre-assignment environment, then
        # kill every fact previously attached to the assigned symbol. This is
        # the minimum SSA-like discipline needed to prove a real def-use path:
        # stale secret taint, digest output, writer targets and digest receiver
        # state must not survive ``value = cleanValue``.
        assigned_source = _source_label(rhs, labels) if assignment is not None else None
        assigned_origins = set(_origin_refs(rhs, digest_outputs)) if assignment is not None else set()
        receiver_aliases = (
            sorted(
                (weak_receivers[name] for name in _identifier_references(rhs) if name in weak_receivers),
                key=lambda item: item.offset,
            )
            if assignment is not None
            else []
        )
        writer_aliases = (
            sorted(sensitive_writers[name] for name in _identifier_references(rhs) if name in sensitive_writers)
            if assignment is not None
            else []
        )
        assigned_target = _is_sensitive_target(rhs, labels, sensitive_targets) if assignment is not None else None
        constructor_targets: list[str] = []
        if assignment is not None:
            for constructor in _WRITER_CONSTRUCTOR.finditer(rhs):
                arguments = _call_arguments(rhs, constructor.end() - 1)
                target = None if arguments is None else _is_sensitive_target(arguments[0], labels, sensitive_targets)
                if target is not None:
                    constructor_targets.append(target)
        if lhs is not None:
            labels.pop(lhs, None)
            digest_outputs.pop(lhs, None)
            weak_receivers.pop(lhs, None)
            sensitive_targets.pop(lhs, None)
            sensitive_writers.pop(lhs, None)

        statement_origins: set[_WeakOrigin] = set()
        for factory in _WEAK_DIGEST_CALL.finditer(statement):
            origin = _WeakOrigin(
                offset=statement_offset + factory.start(),
                line=bisect_right(line_starts, statement_offset + factory.start()) + 1,
                algorithm=re.sub(r"[^A-Z0-9]", "", factory.group("algorithm").upper()),
            )
            if lhs is not None and factory.start() >= statement.find("="):
                weak_receivers[lhs] = origin
            tail = statement[factory.end() :]
            direct_digest = re.match(r"\s*\)\s*\.\s*digest\s*\(", tail, re.IGNORECASE)
            if direct_digest is not None:
                opening = factory.end() + direct_digest.end() - 1
                arguments = _call_arguments(statement, opening)
                if arguments is not None:
                    label = _source_label(arguments[0], labels)
                    if label is not None:
                        record(origin, label, "sensitive_input", "MessageDigest.digest")
                    statement_origins.add(origin)

        for call in _RECEIVER_DIGEST_CALL.finditer(statement):
            receiver_origin = weak_receivers.get(call.group("receiver"))
            if receiver_origin is None:
                continue
            arguments = _call_arguments(statement, call.end() - 1)
            if arguments is None:
                continue
            label = _source_label(arguments[0], labels)
            if call.group("operation").casefold() == "update":
                if label is not None:
                    updated_from[receiver_origin] = label
                continue
            if label is None:
                label = updated_from.get(receiver_origin)
            if label is not None:
                record(receiver_origin, label, "sensitive_input", f"{call.group('receiver')}.digest")
            statement_origins.add(receiver_origin)

        if assignment is not None:
            if assigned_source is not None and lhs is not None:
                labels[lhs] = assigned_source
            if assigned_target is not None and lhs is not None:
                sensitive_targets[lhs] = assigned_target
            referenced_origins = assigned_origins
            referenced_origins.update(statement_origins)
            if lhs is not None and referenced_origins:
                digest_outputs[lhs] = frozenset(referenced_origins)
                if lhs in field_labels:
                    for origin in referenced_origins:
                        record(origin, field_labels[lhs], "sensitive_sink", f"field:{lhs}")
            if lhs is not None and not statement_origins:
                if receiver_aliases:
                    weak_receivers[lhs] = receiver_aliases[0]

            if lhs is not None and constructor_targets:
                sensitive_writers[lhs] = sorted(constructor_targets)[0]
            elif lhs is not None and writer_aliases:
                sensitive_writers[lhs] = writer_aliases[0]

        for call in _CALL.finditer(statement):
            arguments = _call_arguments(statement, call.end() - 1)
            if arguments is None:
                continue
            output_origins = set(_origin_refs(arguments[0], digest_outputs))
            if not output_origins and statement_origins and ".digest" in arguments[0].replace(" ", ""):
                output_origins.update(statement_origins)
            if not output_origins:
                continue
            sink = _security_sink(call.group("receiver"), call.group("method"), sensitive_writers=sensitive_writers)
            if sink is not None:
                for origin in output_origins:
                    record(origin, sink[0], "sensitive_sink", sink[1])

    return tuple(proofs[key] for key in sorted(proofs, key=lambda item: item.offset))


def security_relevant_weak_digest_contexts(source: str) -> tuple[WeakDigestContext, ...]:
    """Return weak digests backed by a bounded intraprocedural def-use proof."""

    code = _mask_comments(source)
    spans = _method_spans(code)
    field_labels = {
        name: sensitive for name in _field_names(code, spans) if (sensitive := _sensitive_identifier(name)) is not None
    }
    line_starts = tuple(index for index, character in enumerate(code) if character == "\n")
    children = _child_spans(spans)
    contexts: dict[tuple[int, str, str], WeakDigestContext] = {}
    for span in spans:
        if span.synthetic:
            continue
        for proof in _analyze_method(
            code,
            span,
            field_labels=field_labels,
            line_starts=line_starts,
            excluded=children[id(span)],
        ):
            context = WeakDigestContext(
                line=proof.origin.line,
                algorithm=proof.origin.algorithm,
                sensitive_identifier=proof.sensitive_identifier,
                method_name=span.name,
                proof_kind=proof.proof_kind,
                sink=proof.sink,
            )
            contexts[(context.line, context.algorithm, context.method_name)] = context
    return tuple(contexts[key] for key in sorted(contexts))


def has_security_relevant_weak_digest(source: str) -> bool:
    """Cheap, deterministic signal shared by routing and execution."""

    return bool(security_relevant_weak_digest_contexts(source))


def _materialize_security_flow(
    *,
    source: JavaSource,
    flow: JavaSecurityFlow,
    input_manifest_digest: str,
) -> tuple[Evidence, dict[str, object]]:
    material = {
        "tool_name": TOOL_NAME,
        "tool_version": TOOL_VERSION,
        "native_rule_id": flow.native_rule_id,
        "normalized_rule_id": flow.rule_id,
        "path": source.path,
        "line": flow.line,
        "file_sha256": source.sha256,
        "input_manifest_digest": input_manifest_digest,
        "rule_bundle_digest": RULE_BUNDLE_DIGEST,
        "sink": flow.sink,
        "data_flow": list(flow.data_flow),
    }
    evidence_digest = _canonical_digest(material)
    evidence_id = f"java-semantic-{evidence_digest[:24]}"
    finding_digest = _canonical_digest(
        {
            "rule_id": flow.rule_id,
            "path": source.path,
            "line": flow.line,
            "evidence_id": evidence_id,
            "file_sha256": source.sha256,
        }
    )
    evidence = Evidence(
        evidence_id=evidence_id,
        source=f"{TOOL_NAME}:{TOOL_VERSION}",
        summary=f"{flow.rule_id} deterministic Java flow at {source.path}:{flow.line}",
        sha256=evidence_digest,
        metadata={
            **material,
            "evidence_type": "sast_flow",
            "assurance_level": "semantically_corroborated",
            "semantic_corroboration": True,
        },
    )
    finding = Finding(
        finding_id=f"java-semantic-finding-{finding_digest}",
        rule_id=flow.rule_id,
        severity=flow.severity,
        confidence=flow.confidence,
        path=source.path,
        line=flow.line,
        title=flow.title,
        description=flow.description,
        remediation=flow.remediation,
        evidence_ids=[evidence_id],
        raw={
            "native_rule_id": flow.native_rule_id,
            "normalized_rule_id": flow.rule_id,
            "data_flow": list(flow.data_flow),
            "root_cause": flow.description,
            "impact": flow.impact,
            "semantic_corroboration": True,
            "assurance_level": "semantically_corroborated",
            "tool_name": TOOL_NAME,
            "tool_version": TOOL_VERSION,
            "rule_bundle_digest": RULE_BUNDLE_DIGEST,
            "file_sha256": source.sha256,
            "input_manifest_digest": input_manifest_digest,
            "sink": flow.sink,
        },
    )
    return evidence, finding.model_dump(mode="json")


def analyze_java_sources(
    *,
    run_id: str,
    sources: tuple[JavaSource, ...],
) -> tuple[list[Evidence], list[dict[str, object]]]:
    """Return bounded, immutable high-specificity Java findings."""

    manifest_digest = _canonical_digest(
        [{"path": item.path, "sha256": item.sha256} for item in sorted(sources, key=lambda item: item.path)]
    )
    extractor = JavaConfigurationEvidenceExtractor(
        tool_name=TOOL_NAME,
        tool_version=TOOL_VERSION,
        rule_bundle_digest=RULE_BUNDLE_DIGEST,
    )
    candidates: list[tuple[str, int, CandidateFlow, WeakDigestContext]] = []
    semantic_flows: list[tuple[JavaSource, JavaSecurityFlow]] = []
    for item in sorted(sources, key=lambda value: value.path):
        if hashlib.sha256(item.source.encode("utf-8")).hexdigest() != item.sha256:
            continue
        semantic_flows.extend((item, flow) for flow in analyze_java_security_flows(item.source))
        contexts = {context.line: context for context in security_relevant_weak_digest_contexts(item.source)}
        if not contexts:
            continue
        unit = AuditUnit.create(
            run_id=run_id,
            input_manifest_digest=manifest_digest,
            profile_digest=PROFILE_DIGEST,
            primary_path=item.path,
            source_sha256=item.sha256,
            target_cwes=(328,),
        )
        for flow in extractor.extract(unit, item.source):
            context = contexts.get(flow.sink_site.line)
            if context is not None and flow.cwe == 328:
                candidates.append((item.path, flow.sink_site.line, flow, context))

    result_evidence: list[Evidence] = []
    result_findings: list[dict[str, object]] = []
    for source, semantic_flow in sorted(
        semantic_flows,
        key=lambda item: (item[0].path, item[1].line, item[1].native_rule_id),
    )[:8]:
        general_evidence, general_finding = _materialize_security_flow(
            source=source,
            flow=semantic_flow,
            input_manifest_digest=manifest_digest,
        )
        result_evidence.append(general_evidence)
        result_findings.append(general_finding)
    if not candidates:
        return result_evidence, result_findings
    path, line, flow, context = min(candidates, key=lambda item: (item[0], item[1], item[2].flow_id))
    source_sha256 = flow.sink_site.file_sha256
    if source_sha256 is None:
        # AuditUnit-backed sites should always carry this digest. Keep the
        # publication boundary fail-closed if an incompatible extractor ever
        # violates that contract; production correctness must not rely on an
        # assertion that disappears under ``python -O``.
        return result_evidence, result_findings
    trace = (
        [
            f"sensitive_source:{context.sensitive_identifier}",
            f"weak_digest:{context.algorithm}",
            f"digest_input:{context.sink}",
        ]
        if context.proof_kind == "sensitive_input"
        else [
            f"weak_digest:{context.algorithm}",
            "digest_output",
            f"security_sensitive_sink:{context.sink}",
        ]
    )
    material = {
        "tool_name": TOOL_NAME,
        "tool_version": TOOL_VERSION,
        "native_rule_id": NATIVE_RULE_ID,
        "normalized_rule_id": "CWE-328",
        "path": path,
        "line": line,
        "file_sha256": source_sha256,
        "input_manifest_digest": manifest_digest,
        "rule_bundle_digest": RULE_BUNDLE_DIGEST,
        "flow_id": flow.flow_id,
        "unit_id": flow.unit_id,
        "algorithm": context.algorithm,
        "sensitive_identifier": context.sensitive_identifier,
        "method_name": context.method_name,
        "proof_kind": context.proof_kind,
        "sink": context.sink,
        "data_flow": trace,
    }
    evidence_digest = _canonical_digest(material)
    evidence_id = f"java-semantic-{evidence_digest[:24]}"
    finding_digest = _canonical_digest(
        {
            "rule_id": "CWE-328",
            "path": path,
            "line": line,
            "evidence_id": evidence_id,
            "file_sha256": source_sha256,
        }
    )
    evidence = Evidence(
        evidence_id=evidence_id,
        source=f"{TOOL_NAME}:{TOOL_VERSION}",
        summary=f"CWE-328 security-sensitive weak digest at {path}:{line}",
        sha256=evidence_digest,
        metadata={
            **material,
            "evidence_type": "sast_flow",
            "assurance_level": "semantically_corroborated",
            "semantic_corroboration": True,
            "semantic_signal": SEMANTIC_SIGNAL,
        },
    )
    weak_finding = Finding(
        finding_id=f"java-semantic-finding-{finding_digest}",
        rule_id="CWE-328",
        severity="HIGH",
        confidence="HIGH",
        path=path,
        line=line,
        title="Weak digest used for security-sensitive data",
        description=(
            f"{context.algorithm} in {context.method_name} has a proven {context.proof_kind} flow "
            f"through {context.sink}; "
            "fast collision-prone digests are unsuitable for password or authentication-secret storage."
        ),
        remediation=(
            "Use Argon2id, scrypt, bcrypt, or PBKDF2 with a unique salt and an approved work factor; "
            "migrate existing stored digests after successful authentication."
        ),
        evidence_ids=[evidence_id],
        raw={
            "native_rule_id": NATIVE_RULE_ID,
            "normalized_rule_id": "CWE-328",
            "data_flow": trace,
            "root_cause": f"{context.algorithm} participates in a proven {context.proof_kind} flow.",
            "impact": "Offline guessing and digest collisions can weaken stored credential protection.",
            "semantic_corroboration": True,
            "assurance_level": "semantically_corroborated",
            "semantic_signal": SEMANTIC_SIGNAL,
            "tool_name": TOOL_NAME,
            "tool_version": TOOL_VERSION,
            "rule_bundle_digest": RULE_BUNDLE_DIGEST,
            "file_sha256": source_sha256,
            "flow_id": flow.flow_id,
        },
    )
    result_evidence.append(evidence)
    result_findings.append(weak_finding.model_dump(mode="json"))
    return result_evidence, result_findings


__all__ = [
    "NATIVE_RULE_ID",
    "RULE_BUNDLE_DIGEST",
    "SEMANTIC_SIGNAL",
    "TOOL_NAME",
    "TOOL_VERSION",
    "JavaSource",
    "WeakDigestContext",
    "analyze_java_sources",
    "has_security_relevant_weak_digest",
    "security_relevant_weak_digest_contexts",
]
