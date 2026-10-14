"""Deterministic precision policy for model-proposed Primary claims.

The provider response is immutable evidence.  This module never rewrites it;
it returns a projection decision that callers may apply when publishing the
Primary baseline.  The rules intentionally cover only a small closed set of
recurring precision failures and otherwise admit the provider claim unchanged.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from pathlib import PurePosixPath
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field

PRIMARY_CLAIM_GATE_VERSION = "primary-claim-precision-v6"


class PrimaryClaimLike(Protocol):
    """Small structural surface consumed from a Primary finding."""

    @property
    def title(self) -> str: ...

    @property
    def cwe(self) -> str | int | None: ...

    @property
    def severity(self) -> str: ...

    @property
    def path(self) -> str | None: ...

    @property
    def file(self) -> str | None: ...

    @property
    def line(self) -> int | None: ...

    @property
    def evidence(self) -> str: ...

    @property
    def evidence_excerpt(self) -> str: ...

    @property
    def data_flow(self) -> str: ...

    @property
    def root_cause(self) -> str: ...

    @property
    def preconditions(self) -> str: ...

    @property
    def impact(self) -> str: ...


class PrimaryClaimRef(BaseModel):
    """Stable reference to one entry in the immutable provider response."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    claim_index: int = Field(ge=0)
    claim_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    rule_id: str
    path: str
    line: int | None = Field(default=None, ge=1)
    reason_code: str


class FoldedPrimaryClaim(PrimaryClaimRef):
    """A downstream symptom represented by an admitted causal root."""

    folded_into_index: int = Field(ge=0)
    folded_into_digest: str = Field(pattern=r"^[a-f0-9]{64}$")


class PrimaryClaimGateResult(BaseModel):
    """Explicit publication disposition without mutating provider output."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    policy_version: str = PRIMARY_CLAIM_GATE_VERSION
    admitted: tuple[PrimaryClaimRef, ...] = ()
    rejected: tuple[PrimaryClaimRef, ...] = ()
    folded: tuple[FoldedPrimaryClaim, ...] = ()

    @property
    def admitted_indices(self) -> frozenset[int]:
        return frozenset(item.claim_index for item in self.admitted)


_AVAILABILITY_TERMS = (
    "availability",
    "unavailable",
    "unavailability",
    "denial of service",
    "dos",
    "crash",
    "terminate",
    "unhandled exception",
    "request failure",
    "service disruption",
    "resource exhaustion",
    "拒绝服务",
    "可用性",
    "崩溃",
)
_NON_AVAILABILITY_TERMS = (
    "sensitive",
    "secret",
    "credential",
    "password",
    "token",
    "stack trace",
    "internal path",
    "information disclosure",
    "error leakage",
    "data leak",
    "敏感",
    "泄露",
    "凭据",
    "堆栈",
)
_REMOTE_BODY_TERMS = (
    "remote response",
    "fetched response",
    "fetched content",
    "upstream response",
    "upstream body",
    "http response body",
    "remote content",
    "body returned by the http client",
    "entityutils",
    "getentity",
    "response.text",
    "远程响应",
    "上游响应",
    "远程内容",
)

_MATERIAL_SCOPE_TERMS = (
    "process",
    "application",
    "runtime",
    "server",
    "worker",
    "all requests",
    "subsequent requests",
    "later requests",
    "persistent",
    "process-wide",
    "global state",
    "shared state",
    "进程",
    "服务整体",
    "后续请求",
    "持久",
    "全局状态",
    "共享状态",
)

_PROCESS_WIDE_DOS = re.compile(
    r"(?:system\s*\.\s*exit|runtime\s*\.\s*getruntime\s*\(\s*\)\s*\.\s*halt|"
    r"environment\s*\.\s*(?:exit|failfast)|process\s*\.\s*(?:exit|abort)|"
    r"os\s*\.\s*_exit|raise\s+systemexit|kill\s*\(\s*(?:0|getpid\s*\(\s*\))|"
    r"abort\s*\(\s*\))",
    re.IGNORECASE,
)
_SENSITIVE_ERROR_LEAK = re.compile(
    r"(?:send|write|print|json|render|body|content)\s*\([^\n;]{0,240}"
    r"(?:getmessage\s*\(|stack(?:trace)?|traceback|format_exc|"
    r"str\s*\(\s*(?:e|ex|err|error|exc|exception)\b|"
    r"\b(?:e|ex|err|error|exc|exception)\s*\.\s*(?:message|stack|tostring|getmessage))|"
    r"return\b[^\n;]{0,240}(?:getmessage\s*\(|stack(?:trace)?|traceback|format_exc|"
    r"str\s*\(\s*(?:e|ex|err|error|exc|exception)\b|"
    r"\b(?:e|ex|err|error|exc|exception)\s*\.\s*(?:message|stack|tostring|getmessage))",
    re.IGNORECASE,
)
_FAILURE_MUTATION = re.compile(
    r"\b(?P<symbol>disabled|unavailable|poisoned|failed|broken|shutdown|circuit_open)\b\s*"
    r"(?:=\s*(?:true|1)|\.\s*set\s*\(\s*(?:true|1)\s*\)|\.\s*open\s*\()",
    re.IGNORECASE,
)
_EXCEPTION_HANDLER = re.compile(r"\b(?:catch\s*\(|except\b)", re.IGNORECASE)
_FETCH_PRIMITIVE = re.compile(
    r"(?:requests?\s*\.\s*(?:get|post|request)|urlopen\s*\(|fetch\s*\(|"
    r"needle\s*\.\s*(?:get|post|request)\s*\(|axios\s*\.\s*(?:get|post|request)\s*\(|"
    r"got\s*\(|"
    r"httpclient|httpurlconnection|openconnection\s*\(|new\s+httpget|"
    r"resttemplate|webclient|client\s*\.\s*do\s*\(|http\s*\.\s*get\s*\()",
    re.IGNORECASE,
)
_ASSIGNMENT = re.compile(
    r"\b(?P<target>[A-Za-z_$][\w$]*)\s*=\s*(?P<value>[^;\n]+)",
    re.IGNORECASE,
)
_REMOTE_BODY_SOURCE = re.compile(
    r"(?:entityutils\s*\.\s*tostring\s*\(\s*)?"
    r"(?P<source>[A-Za-z_$][\w$]*)\s*\.\s*(?:getentity|body|text|content)\b",
    re.IGNORECASE,
)
_CALLBACK_PARAMETERS = re.compile(
    r"(?:function\s*)?\((?P<parameters>[^()\n]{1,240})\)\s*(?:=>|\{)",
    re.IGNORECASE,
)
_OUTPUT_CALL = re.compile(
    r"\b(?:response\s*\.\s*getwriter\s*\(\s*\)|response|res|writer|out)\s*\.\s*"
    r"(?:write|send|json|render|end)\s*\(\s*(?P<symbol>[A-Za-z_$][\w$]*)\b",
    re.IGNORECASE,
)
_OUTPUT_ASSIGNMENT = re.compile(
    r"\.\s*(?:innerhtml|dangerouslysetinnerhtml)\s*=\s*(?P<symbol>[A-Za-z_$][\w$]*)\b",
    re.IGNORECASE,
)
_CONTROL_HEADERS = frozenset({"catch", "do", "else", "finally", "for", "if", "switch", "try", "while"})
_RUNTIME_SUBJECT = re.compile(r"\b(?:container|runtime|framework|server|version)\b", re.IGNORECASE)
_RUNTIME_BEHAVIOR = re.compile(
    r"\b(?:reject(?:s|ed|ing)?|allow(?:s|ed|ing)?|permit(?:s|ted|ting)?|"
    r"saniti[sz](?:e|es|ed|ing)|encode(?:s|d|ing)?|validate(?:s|d|ing)?|"
    r"seriali[sz](?:e|es|ed|ing))\b",
    re.IGNORECASE,
)
_RUNTIME_CONDITION = re.compile(
    r"\b(?:if|unless|depend(?:s|ed|ing)?\s+on|provided\s+that|must|may|might|"
    r"only\s+(?:if|when)|without|implementation[- ]dependent|runtime[- ]dependent)\b",
    re.IGNORECASE,
)
_COOKIE_RESPONSE_API = re.compile(r"\bnew\s+Cookie\s*\(|\.\s*addCookie\s*\(", re.IGNORECASE)
_DIRECT_HEADER_API = re.compile(r"\.\s*(?:setHeader|addHeader)\s*\(", re.IGNORECASE)
_CSRF_CONTROL = re.compile(r"\b(?:csrf|cross[- ]site\s+request\s+forgery|anti[- ]csrf)\b", re.IGNORECASE)
_EXTERNAL_REQUEST_CONTROL = re.compile(
    r"\b(?:framework|middleware|router|routing|gateway|proxy|platform|filter|interceptor)\b",
    re.IGNORECASE,
)
_EXPLICITLY_UNAVAILABLE = re.compile(
    r"\b(?:not|isn't|isnt|wasn't|wasnt|aren't|arent|weren't|werent)\s+"
    r"(?:provided|supplied|available|shown|included|visible)|"
    r"\b(?:unseen|outside\s+(?:the\s+)?supplied|not\s+in\s+(?:the\s+)?supplied)\b",
    re.IGNORECASE,
)
_REQUEST_CONTROLLED_INPUT = re.compile(
    r"(?:\$_(?:POST|GET|REQUEST)\s*\[|\b(?:req|request)\s*\.\s*(?:body|form|query|params)\b|"
    r"\b(?:request\.getParameter|@(?:Post|Put|Patch|Delete)Mapping)\b)",
    re.IGNORECASE,
)
_STATE_CHANGING_OPERATION = re.compile(
    r"(?:\b(?:UPDATE|INSERT|DELETE)\b|\b(?:change|set|update|reset|save|delete|remove|transfer|"
    r"enable|disable)[A-Za-z0-9_]*(?:password|account|user|role|permission|setting|record)?\s*\(|"
    r"\.\s*(?:save|delete|remove|update|executeUpdate)\s*\()",
    re.IGNORECASE,
)
_UI_SECRET_PRESENTATION = re.compile(
    r"\b(?:unmasked|password[- ]?mask(?:ed|ing)?|secret[- ]aware|"
    r"plain[- ]?text|editable\s+fields?|dynamiclist|password\s*=\s*true)\b",
    re.IGNORECASE,
)
_EXTERNAL_PRESENTATION_OR_ACCESS = re.compile(
    r"\b(?:renderer|rendering|template|user\s+interface|ui|framework|"
    r"access\s+controls?|authori[sz](?:e|ed|ation)|principal|runtime)\b",
    re.IGNORECASE,
)
_DISCLOSURE_NOT_ESTABLISHED = re.compile(
    r"\b(?:not|isn't|isnt|wasn't|wasnt)\s+(?:established|shown|demonstrated|proven)|"
    r"\b(?:cannot|can't|cant)\s+(?:establish|show|demonstrate|prove)\b",
    re.IGNORECASE,
)


def _text(item: PrimaryClaimLike) -> str:
    return " ".join(
        str(value or "")
        for value in (
            item.title,
            item.evidence,
            item.evidence_excerpt,
            item.data_flow,
            item.root_cause,
            item.preconditions,
            item.impact,
        )
    ).casefold()


def _depends_on_unsupplied_runtime_behavior(semantic: str) -> bool:
    """Recognize an explicitly conditional runtime claim independent of word order."""

    return all(
        pattern.search(semantic) is not None for pattern in (_RUNTIME_SUBJECT, _RUNTIME_BEHAVIOR, _RUNTIME_CONDITION)
    )


def _csrf_depends_on_unavailable_external_control(item: PrimaryClaimLike) -> bool:
    """Reject a *self-declared* conditional CSRF hypothesis.

    Absence of a token in one handler is not proof that a framework, router, or
    middleware layer provides no request-forgery protection.  The gate is
    deliberately narrower than a generic "no token found" heuristic: the
    provider must itself name CSRF, identify an external control boundary, and
    state that the boundary was not supplied.  The immutable provider receipt
    remains available for audit; only the verified publication view changes.
    """

    semantic = _text(item)
    return all(
        pattern.search(semantic) is not None
        for pattern in (_CSRF_CONTROL, _EXTERNAL_REQUEST_CONTROL, _EXPLICITLY_UNAVAILABLE)
    )


def _source_supports_local_request_state_change(source: str) -> bool:
    """Return whether supplied bytes contain both sides of a CSRF hypothesis.

    A missing router or middleware is a real uncertainty, but it does not erase
    a source-local request-to-state-change flow.  Such a finding remains
    conditional and auditable.  Conversely, a provider claim with neither a
    request-controlled entry nor a mutation in the supplied bytes is only an
    unsupported external-control hypothesis and stays out of publication.
    """

    return _REQUEST_CONTROLLED_INPUT.search(source) is not None and _STATE_CHANGING_OPERATION.search(source) is not None


def _credential_ui_exposure_is_unproven(item: PrimaryClaimLike) -> bool:
    """Recognize a provider-admitted UI-only credential exposure hypothesis.

    A missing password-mask flag can justify a hardening recommendation, but it
    is not by itself proof that an unauthorized principal can observe a secret.
    This narrow gate applies only when the provider explicitly says disclosure
    was not established and makes exploitability depend on a renderer or access
    boundary absent from the immutable input.  Proven storage, logging,
    transport, or authorization failures do not match all three predicates.
    """

    semantic = _text(item)
    return all(
        pattern.search(semantic) is not None
        for pattern in (_UI_SECRET_PRESENTATION, _EXTERNAL_PRESENTATION_OR_ACCESS, _DISCLOSURE_NOT_ESTABLISHED)
    )


def _rule_id(item: PrimaryClaimLike) -> str:
    value = item.cwe
    if isinstance(value, int) or (isinstance(value, str) and value.strip().isdigit()):
        return f"CWE-{str(value).strip()}"
    normalized = str(value or "MODEL-SECURITY-FINDING").strip().upper().replace("_", "-")
    cwe_match = re.fullmatch(r"CWE[\s:-]*(\d+)", normalized)
    if cwe_match:
        return f"CWE-{cwe_match.group(1)}"
    return normalized if normalized.startswith("CWE-") else normalized


def _path(item: PrimaryClaimLike) -> str:
    return str(item.path or item.file or ".").replace("\\", "/")


def _claim_digest(index: int, item: PrimaryClaimLike) -> str:
    payload = {
        "index": index,
        "rule_id": _rule_id(item),
        "severity": str(item.severity),
        "path": _path(item),
        "line": item.line,
        "title": item.title,
        "evidence": item.evidence,
        "evidence_excerpt": item.evidence_excerpt,
        "data_flow": item.data_flow,
        "root_cause": item.root_cause,
        "preconditions": item.preconditions,
        "impact": item.impact,
    }
    return hashlib.sha256(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _source_for(path: str, sources: Mapping[str, str]) -> str:
    normalized = path.replace("\\", "/")
    if normalized in sources:
        return sources[normalized]
    suffix_matches = [value for key, value in sources.items() if key.replace("\\", "/").endswith("/" + normalized)]
    if len(suffix_matches) == 1:
        return suffix_matches[0]
    basename = PurePosixPath(normalized).name
    basename_matches = [value for key, value in sources.items() if PurePosixPath(key).name == basename]
    return basename_matches[0] if len(basename_matches) == 1 else ""


def _mask_non_code(source: str) -> str:
    """Mask comments and literal bodies while preserving offsets and line numbers."""

    output = list(source)
    state = "code"
    delimiter = ""
    escaped = False
    index = 0
    while index < len(source):
        character = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if state == "code":
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
            if character == "#":
                output[index] = " "
                state = "line_comment"
            elif character in {'"', "'", "`"}:
                delimiter = character * 3 if source.startswith(character * 3, index) else character
                for offset in range(len(delimiter)):
                    output[index + offset] = " "
                state = "literal"
                index += len(delimiter)
                continue
        elif state == "line_comment":
            if character == "\n":
                state = "code"
            else:
                output[index] = " "
        elif state == "block_comment":
            if character == "*" and following == "/":
                output[index] = output[index + 1] = " "
                state = "code"
                index += 2
                continue
            if character != "\n":
                output[index] = " "
        else:
            if source.startswith(delimiter, index) and not escaped:
                for offset in range(len(delimiter)):
                    output[index + offset] = " "
                state = "code"
                index += len(delimiter)
                continue
            if character == "\n" and len(delimiter) == 1 and delimiter != "`":
                state = "code"
                escaped = False
            else:
                if character != "\n":
                    output[index] = " "
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
        index += 1
    return "".join(output)


def _line_text(source: str, line: int | None) -> str:
    if line is None:
        return ""
    lines = source.splitlines()
    return lines[line - 1] if 1 <= line <= len(lines) else ""


def _claim_effects(item: PrimaryClaimLike) -> tuple[bool, bool]:
    """Return whether the claim itself asserts leakage and/or cross-request impact."""

    semantic = _text(item)
    leakage = any(term in semantic for term in _NON_AVAILABILITY_TERMS)
    material_scope = any(term in semantic for term in _MATERIAL_SCOPE_TERMS)
    availability = any(term in semantic for term in _AVAILABILITY_TERMS)
    return leakage, material_scope and availability


def _shared_failure_proof(masked_source: str, claim_line: int | None, claim_code: str) -> bool:
    mutation = _FAILURE_MUTATION.search(claim_code)
    if mutation is None or claim_line is None:
        return False
    lines = masked_source.splitlines()
    handler_context = "\n".join(lines[max(0, claim_line - 8) : claim_line])
    if _EXCEPTION_HANDLER.search(handler_context) is None:
        return False
    symbol = re.escape(mutation.group("symbol"))
    declaration = re.compile(
        rf"\b(?:static|global|volatile|singleton|shared)\b[^\n;]{{0,160}}\b{symbol}\b|"
        rf"\b{symbol}\b[^\n;]{{0,160}}\b(?:static|global|volatile|singleton|shared)\b",
        re.IGNORECASE,
    )
    return declaration.search(masked_source) is not None


def _material_cwe248_proof(item: PrimaryClaimLike, source: str) -> bool:
    """Require claim-declared impact and matching executable code at its evidence line."""

    masked = _mask_non_code(source)
    claim_code = _line_text(masked, item.line)
    if not claim_code.strip():
        return False
    claims_leakage, claims_material_scope = _claim_effects(item)
    if claims_leakage and _SENSITIVE_ERROR_LEAK.search(claim_code):
        return True
    if claims_material_scope and _PROCESS_WIDE_DOS.search(claim_code):
        return True
    return claims_material_scope and _shared_failure_proof(masked, item.line, claim_code)


def _is_low_or_availability_only(item: PrimaryClaimLike) -> bool:
    semantic = _text(item)
    low = str(item.severity).upper() == "LOW"
    availability_only = any(term in semantic for term in _AVAILABILITY_TERMS) and not any(
        term in semantic for term in _NON_AVAILABILITY_TERMS
    )
    return low or availability_only


def _matching_brace(source: str, opening: int) -> int:
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    return len(source)


def _callable_scope(source: str, line: int) -> tuple[int, int]:
    """Return the nearest callable/callback scope containing ``line``."""

    lines = source.splitlines(keepends=True)
    if not 1 <= line <= len(lines):
        return 0, 0
    offset = sum(len(value) for value in lines[: line - 1])
    stack: list[int] = []
    for index, character in enumerate(source[: offset + len(lines[line - 1])]):
        if character == "{":
            stack.append(index)
        elif character == "}" and stack:
            stack.pop()
    for opening in reversed(stack):
        boundaries = (
            source.rfind(";", 0, opening),
            source.rfind("}", 0, opening),
            source.rfind("{", 0, opening),
        )
        header_start = max(boundaries) + 1
        header = source[header_start:opening].strip()
        if "=>" in header or re.search(r"\bfunction\b", header, re.IGNORECASE):
            return header_start, _matching_brace(source, opening)
        call = re.search(r"\b(?P<name>[A-Za-z_$][\w$]*)\s*\([^;{}]*\)\s*$", header)
        if call is not None and call.group("name").casefold() not in _CONTROL_HEADERS:
            return header_start, _matching_brace(source, opening)
    return 0, len(source)


def _sink_symbols(source_line: str) -> frozenset[str]:
    calls = {match.group("symbol") for match in _OUTPUT_CALL.finditer(source_line)}
    assignments = {match.group("symbol") for match in _OUTPUT_ASSIGNMENT.finditer(source_line)}
    return frozenset(calls | assignments)


def _claim_sink_symbol(item: PrimaryClaimLike, source_line: str) -> str | None:
    source_symbols = _sink_symbols(source_line)
    if not source_symbols:
        return None
    claimed_symbols = _sink_symbols(f"{item.evidence_excerpt}\n{item.evidence}")
    if claimed_symbols:
        overlap = source_symbols.intersection(claimed_symbols)
        return next(iter(overlap)) if len(overlap) == 1 else None
    return next(iter(source_symbols)) if len(source_symbols) == 1 else None


def _assigned_match(source: str, symbol: str) -> re.Match[str] | None:
    matches = [match for match in _ASSIGNMENT.finditer(source) if match.group("target") == symbol]
    return matches[-1] if matches else None


def _fetch_identity(value: str) -> tuple[int, str] | None:
    matches = list(_FETCH_PRIMITIVE.finditer(value))
    if not matches:
        return None
    match = matches[-1]
    argument_start = match.end()
    if not value[:argument_start].rstrip().endswith("("):
        opening = value.find("(", argument_start, argument_start + 40)
        if opening < 0:
            return None
        argument_start = opening + 1
    source = re.match(r"\s*(?P<source>[A-Za-z_$][\w$]*)\b", value[argument_start:])
    return None if source is None else (match.start(), source.group("source"))


def _callback_body_fetch(scope_prefix: str, symbol: str) -> tuple[int, str] | None:
    for match in _CALLBACK_PARAMETERS.finditer(scope_prefix):
        parameters = {value.strip() for value in match.group("parameters").split(",")}
        if symbol not in parameters:
            continue
        nearby_start = max(0, match.start() - 300)
        identity = _fetch_identity(scope_prefix[nearby_start : match.start()])
        if identity is not None:
            return nearby_start + identity[0], identity[1]
    return None


def _direct_remote_body_flow(item: PrimaryClaimLike, source: str) -> tuple[int, str] | None:
    """Prove an exact remote-body symbol reaches the claim's annotated sink line."""

    if item.line is None or not any(term in _text(item) for term in _REMOTE_BODY_TERMS):
        return None
    masked = _mask_non_code(source)
    source_line = _line_text(masked, item.line)
    sink_symbol = _claim_sink_symbol(item, source_line)
    if sink_symbol is None:
        return None
    scope_start, scope_end = _callable_scope(masked, item.line)
    if scope_end <= scope_start:
        return None
    lines = masked.splitlines(keepends=True)
    sink_offset = sum(len(value) for value in lines[: item.line - 1]) + len(lines[item.line - 1])
    scope_prefix = masked[scope_start : min(sink_offset, scope_end)]
    fetch = _callback_body_fetch(scope_prefix, sink_symbol)
    if fetch is None:
        body_assignment = _assigned_match(scope_prefix, sink_symbol)
        if body_assignment is None:
            return None
        body_value = body_assignment.group("value")
        direct_fetch = _fetch_identity(body_value)
        if direct_fetch is not None and _REMOTE_BODY_SOURCE.search(body_value) is not None:
            fetch = body_assignment.start("value") + direct_fetch[0], direct_fetch[1]
        else:
            remote_source = _REMOTE_BODY_SOURCE.search(body_value)
            if remote_source is None:
                return None
            upstream = _assigned_match(scope_prefix, remote_source.group("source"))
            if upstream is None or (upstream_fetch := _fetch_identity(upstream.group("value"))) is None:
                return None
            fetch = upstream.start("value") + upstream_fetch[0], upstream_fetch[1]
    fetch_offset = scope_start + fetch[0]
    return masked.count("\n", 0, fetch_offset) + 1, fetch[1]


def _ssrf_matches_flow(item: PrimaryClaimLike, fetch_line: int, fetch_source: str) -> bool:
    if item.line != fetch_line:
        return False
    return (
        re.search(
            rf"(?<![A-Za-z0-9_$]){re.escape(fetch_source)}(?![A-Za-z0-9_$])",
            _text(item),
            re.IGNORECASE,
        )
        is not None
    )


def _reference(index: int, item: PrimaryClaimLike, reason_code: str) -> PrimaryClaimRef:
    return PrimaryClaimRef(
        claim_index=index,
        claim_digest=_claim_digest(index, item),
        rule_id=_rule_id(item),
        path=_path(item),
        line=item.line,
        reason_code=reason_code,
    )


def gate_primary_claims(
    claims: Sequence[PrimaryClaimLike],
    source_text_by_path: Mapping[str, str],
) -> PrimaryClaimGateResult:
    """Return a deterministic admitted/rejected/folded publication view.

    The sequence and every claim object are read-only.  Candidate indices bind
    the decision back to the exact provider JSON array without modifying it.
    """

    rejected: dict[int, PrimaryClaimRef] = {}
    for index, item in enumerate(claims):
        if _rule_id(item) == "CWE-522" and _credential_ui_exposure_is_unproven(item):
            rejected[index] = _reference(
                index,
                item,
                "cwe_522_ui_exposure_depends_on_unprovided_renderer_or_authorization",
            )
            continue
        if (
            _rule_id(item) == "CWE-352"
            and _csrf_depends_on_unavailable_external_control(item)
            and not _source_supports_local_request_state_change(
                _source_for(_path(item), source_text_by_path),
            )
        ):
            rejected[index] = _reference(
                index,
                item,
                "cwe_352_depends_on_unavailable_external_request_control",
            )
            continue
        if _rule_id(item) == "CWE-113":
            source = _source_for(_path(item), source_text_by_path)
            semantic = _text(item)
            if (
                _depends_on_unsupplied_runtime_behavior(semantic)
                and _COOKIE_RESPONSE_API.search(source)
                and _DIRECT_HEADER_API.search(source) is None
            ):
                rejected[index] = _reference(
                    index,
                    item,
                    "cwe_113_depends_on_unsupplied_runtime_behavior",
                )
                continue
        if _rule_id(item) != "CWE-248" or not _is_low_or_availability_only(item):
            continue
        source = _source_for(_path(item), source_text_by_path)
        if not _material_cwe248_proof(item, source):
            rejected[index] = _reference(index, item, "cwe_248_lacks_material_scope_or_leakage")

    ssrf_indices = [index for index, item in enumerate(claims) if index not in rejected and _rule_id(item) == "CWE-918"]
    folded: dict[int, FoldedPrimaryClaim] = {}
    for index, item in enumerate(claims):
        if index in rejected or _rule_id(item) != "CWE-79":
            continue
        path = _path(item)
        source = _source_for(path, source_text_by_path)
        flow = _direct_remote_body_flow(item, source)
        if flow is None:
            continue
        fetch_line, fetch_source = flow
        same_path_roots = [
            root
            for root in ssrf_indices
            if _path(claims[root]) == path and _ssrf_matches_flow(claims[root], fetch_line, fetch_source)
        ]
        if not same_path_roots:
            continue
        target = min(same_path_roots)
        reference = _reference(index, item, "downstream_xss_folded_into_ssrf_root")
        folded[index] = FoldedPrimaryClaim(
            **reference.model_dump(),
            folded_into_index=target,
            folded_into_digest=_claim_digest(target, claims[target]),
        )

    admitted = tuple(
        _reference(index, item, "claim_preserved")
        for index, item in enumerate(claims)
        if index not in rejected and index not in folded
    )
    return PrimaryClaimGateResult(
        admitted=admitted,
        rejected=tuple(rejected[index] for index in sorted(rejected)),
        folded=tuple(folded[index] for index in sorted(folded)),
    )


__all__ = [
    "PRIMARY_CLAIM_GATE_VERSION",
    "FoldedPrimaryClaim",
    "PrimaryClaimGateResult",
    "PrimaryClaimRef",
    "gate_primary_claims",
]
