"""High-precision, bounded static checks for server-side web workflows.

The analyzer intentionally implements a small closed rule set.  It never
executes repository code and it only emits a finding when a complete local
control-flow proof is available.  Missing middleware or framework context is
therefore not treated as proof of a vulnerability.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Final

TOOL_NAME: Final = "web_workflow_audit"
TOOL_VERSION: Final = "3"
CAPTCHA_STAGE_BYPASS_RULE: Final = "WEBFLOW-PHP-CAPTCHA-STAGE-BYPASS-001"
PASSWORD_CHANGE_WITHOUT_REAUTH_RULE: Final = "WEBFLOW-PHP-PASSWORD-CHANGE-REAUTH-001"  # noqa: S105
WEAK_PASSWORD_HASH_RULE: Final = "WEBFLOW-PHP-WEAK-PASSWORD-HASH-001"  # noqa: S105
RULE_BUNDLE_DIGEST: Final = hashlib.sha256(
    b"secmind-web-workflow-static-rules-v3:php-captcha-stage-bypass:php-password-change-reauth:php-weak-password-hash"
).hexdigest()

_MAX_CONDITION_CHARS: Final = 1_200
_MAX_BRANCHES: Final = 64
_MAX_FINDINGS: Final = 32
_STAGE_ACCESS = re.compile(
    r"\$_(?P<method>POST|GET|REQUEST)\s*\[\s*['\"](?P<key>step|stage|phase)['\"]\s*\]"
    r"\s*={2,3}\s*['\"](?P<value>[A-Za-z0-9_-]{1,32})['\"]",
    re.IGNORECASE,
)
_INPUT_TAG = re.compile(r"<input\b[^>]{0,1024}>", re.IGNORECASE)
_ATTRIBUTE = re.compile(
    r"(?P<name>[A-Za-z_:][-A-Za-z0-9_:.]*)\s*=\s*(?P<quote>['\"])(?P<value>.*?)\2",
    re.DOTALL,
)
_VERIFICATION_GATE = re.compile(
    r"\b(?:re)?captcha(?:\b|_)|\b(?:verify|validate|check)[A-Za-z0-9_]*(?:otp|totp|mfa|challenge)\b",
    re.IGNORECASE,
)
_FAIL_CLOSED_GATE = re.compile(
    r"\bif\s*\([^)]{0,512}\)\s*\{?[^{}]{0,512}\b(?:return|exit|die|throw)\b",
    re.IGNORECASE | re.DOTALL,
)
_SERVER_SIDE_BINDING = re.compile(
    r"\$_SESSION\s*\[|\bcsrf\b|\bnonce\b|\bhash_equals\s*\(|"
    r"\b(?:verify|validate|check)[A-Za-z0-9_]*(?:token|challenge|state)\b",
    re.IGNORECASE,
)
_MUTATING_SQL = re.compile(r"\b(?:UPDATE|INSERT\s+INTO|DELETE\s+FROM)\b", re.IGNORECASE)
_SQL_EXECUTION = re.compile(
    r"\b(?:mysqli_query|mysql_query|pg_query|sqlite_query)\s*\(|"
    r"(?:->|::)\s*(?:exec|execute|query)\s*\(",
    re.IGNORECASE,
)
_INPUT_ASSIGNMENT = re.compile(
    r"(?P<variable>\$[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"\$_(?P<method>POST|GET|REQUEST)\s*\[\s*['\"](?P<key>[A-Za-z0-9_.-]{1,96})['\"]\s*\]",
    re.IGNORECASE,
)
_INPUT_ACCESS = re.compile(
    r"\$_(?P<method>POST|GET|REQUEST)\s*\[\s*['\"](?P<key>[A-Za-z0-9_.-]{1,96})['\"]\s*\]",
    re.IGNORECASE,
)
_PASSWORD_UPDATE = re.compile(
    r"\bUPDATE\b.{0,1200}?\bSET\b.{0,800}?\b(?:password|passwd|password_hash|pass_hash)\b\s*=",
    re.IGNORECASE | re.DOTALL,
)
_AUTHENTICATED_TARGET = re.compile(
    r"\b(?:ProjectCurrentUser|current_user|authenticated_user|get_current_user)\s*\(|"
    r"\$_SESSION\s*\[\s*['\"](?:user|user_id|username|account_id)['\"]\s*\]",
    re.IGNORECASE,
)
_CREDENTIAL_VERIFICATION = re.compile(
    r"\bpassword_verify\s*\(|"
    r"\b(?:verify|validate|check)[A-Za-z0-9_]*(?:current|old|existing|previous)[A-Za-z0-9_]*"
    r"(?:password|passwd|credential)[A-Za-z0-9_]*\s*\(|"
    r"\b(?:reauth|re_auth|step_up|stepup|verify_credential|validate_credential)\b|"
    r"\b(?:verify|validate|check)[A-Za-z0-9_]*(?:otp|totp|mfa)[A-Za-z0-9_]*\s*\(",
    re.IGNORECASE,
)
_STEP_UP_BINDING = re.compile(
    r"\$_SESSION\s*\[\s*['\"][^'\"]{0,64}(?:reauth|step[_-]?up|mfa|otp|"
    r"current[_-]?(?:password|credential)[_-]?verified)[^'\"]{0,64}['\"]\s*\]",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class WebSource:
    path: str
    source: str
    sha256: str


@dataclass(frozen=True, slots=True)
class WebWorkflowFinding:
    native_rule_id: str
    rule_id: str
    line: int
    sink_line: int
    title: str
    description: str
    remediation: str
    impact: str
    source_step: str
    target_step: str
    data_flow: tuple[str, ...]
    evidence_lines: tuple[int, ...]
    weakness_ids: tuple[str, ...]
    preconditions: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _StageBranch:
    method: str
    key: str
    value: str
    header_start: int
    body_start: int
    body_end: int


def analyze_web_source(source: str) -> tuple[WebWorkflowFinding, ...]:
    """Return only locally proven, high-specificity workflow findings."""

    if not source or len(source) > 2 * 1024 * 1024:
        return ()
    comment_masked = _mask_comments(source)
    code_view = _mask_strings(comment_masked)
    branches = _stage_branches(comment_masked, code_view)
    findings: list[WebWorkflowFinding] = []
    for first in branches:
        first_body_text = comment_masked[first.body_start : first.body_end]
        first_body_code = code_view[first.body_start : first.body_end]
        gate = _VERIFICATION_GATE.search(first_body_code)
        if gate is None:
            continue
        next_stages = _hidden_stage_values(first_body_text, key=first.key)
        for hidden_offset, target_value in next_stages:
            if _FAIL_CLOSED_GATE.search(first_body_code, gate.end(), hidden_offset) is None:
                continue
            second = next(
                (
                    item
                    for item in branches
                    if item.header_start > first.body_end
                    and item.method == first.method
                    and item.key == first.key
                    and item.value == target_value
                ),
                None,
            )
            if second is None:
                continue
            second_body_text = comment_masked[second.body_start : second.body_end]
            second_body_code = code_view[second.body_start : second.body_end]
            mutation = _MUTATING_SQL.search(second_body_text)
            execution = _SQL_EXECUTION.search(second_body_code)
            if (
                mutation is None
                or execution is None
                or abs(mutation.start() - execution.start()) > 2_000
                or _VERIFICATION_GATE.search(second_body_code) is not None
                or _SERVER_SIDE_BINDING.search(second_body_code) is not None
            ):
                continue
            gate_line = _line_number(source, first.body_start + gate.start())
            hidden_line = _line_number(source, first.body_start + hidden_offset)
            target_line = _line_number(source, second.header_start)
            sink_line = _line_number(source, second.body_start + mutation.start())
            findings.append(
                WebWorkflowFinding(
                    native_rule_id=CAPTCHA_STAGE_BYPASS_RULE,
                    # Publish the stable business-logic family (CWE-840) as
                    # the interoperable rule identity. The precise
                    # behavioral-workflow child (CWE-841) remains in the
                    # evidence weakness set and native-rule metadata.
                    rule_id="CWE-840",
                    line=target_line,
                    sink_line=sink_line,
                    title="Client-controlled stage bypasses the verification gate",
                    description=(
                        f"The {first.method} parameter {first.key!r} selects a verification branch at stage "
                        f"{first.value!r}, but the response emits client-controlled stage {target_value!r}. "
                        "A direct request to that later branch reaches a state-changing SQL operation without "
                        "revalidating the challenge or checking a visible server-bound transition token."
                    ),
                    remediation=(
                        "Bind the successful challenge to the authenticated server-side session using a "
                        "single-use, expiring transition token and validate it in the state-changing branch. "
                        "Do not authorize workflow state from a hidden request field alone."
                    ),
                    impact=(
                        "An attacker may skip the intended anti-automation or interaction gate and invoke the "
                        "protected state change directly."
                    ),
                    source_step=first.value,
                    target_step=target_value,
                    data_flow=(
                        f"request:{first.method}.{first.key}={target_value}",
                        f"branch:{first.key}={target_value}",
                        f"sink:mutating_sql@{sink_line}",
                    ),
                    evidence_lines=tuple(sorted({gate_line, hidden_line, target_line, sink_line})),
                    weakness_ids=("CWE-840", "CWE-841", "CWE-602"),
                    preconditions=(
                        "The later client-selected stage is reachable by an HTTP request.",
                        "No server-bound transition check is visible in the state-changing branch.",
                    ),
                )
            )
            if len(findings) >= _MAX_FINDINGS:
                return tuple(findings)
    findings.extend(_password_change_findings(source, comment_masked, code_view, branches))
    findings.sort(key=lambda item: (item.line, item.native_rule_id, item.sink_line))
    if len(findings) > _MAX_FINDINGS:
        del findings[_MAX_FINDINGS:]
    return tuple(findings)


def _password_change_findings(
    source: str,
    comment_masked: str,
    code_view: str,
    branches: tuple[_StageBranch, ...],
) -> tuple[WebWorkflowFinding, ...]:
    """Prove a password update that omits current-credential verification.

    This is intentionally narrower than a general authentication audit.  It
    requires two independently named request fields, a local equality gate, a
    password-column update, an SQL execution call, and an authenticated-user
    target in one bounded branch.  A current-password input or any visible
    step-up/credential verification suppresses the claim.
    """

    all_password_inputs = tuple(
        match.group("key") for match in _INPUT_ACCESS.finditer(comment_masked) if _is_password_key(match.group("key"))
    )
    if any(_password_key_role(key) not in {"new", "confirmation"} for key in all_password_inputs):
        return ()
    if _CREDENTIAL_VERIFICATION.search(code_view) is not None:
        return ()

    findings: list[WebWorkflowFinding] = []
    for branch in branches:
        branch_text = comment_masked[branch.body_start : branch.body_end]
        branch_code = code_view[branch.body_start : branch.body_end]
        if _STEP_UP_BINDING.search(branch_text) is not None:
            continue
        assignments = tuple(_INPUT_ASSIGNMENT.finditer(branch_text))
        new_inputs = tuple(item for item in assignments if _password_key_role(item.group("key")) == "new")
        confirmations = tuple(item for item in assignments if _password_key_role(item.group("key")) == "confirmation")
        if not new_inputs or not confirmations:
            continue

        comparison: re.Match[str] | None = None
        selected_new: re.Match[str] | None = None
        selected_confirmation: re.Match[str] | None = None
        for new_input in new_inputs:
            for confirmation in confirmations:
                left = re.escape(new_input.group("variable"))
                right = re.escape(confirmation.group("variable"))
                comparison = re.search(
                    rf"(?:{left}\s*={{2,3}}\s*{right}|{right}\s*={{2,3}}\s*{left})",
                    branch_code,
                    re.IGNORECASE,
                )
                if comparison is not None:
                    selected_new = new_input
                    selected_confirmation = confirmation
                    break
            if comparison is not None:
                break
        if comparison is None or selected_new is None or selected_confirmation is None:
            continue

        mutation = _PASSWORD_UPDATE.search(branch_text)
        if mutation is None or comparison.start() >= mutation.start():
            continue
        sink_window = branch_text[mutation.start() : mutation.start() + 2_000]
        if selected_new.group("variable").casefold() not in sink_window.casefold():
            continue
        execution = _SQL_EXECUTION.search(branch_code, mutation.start())
        if execution is None or execution.start() - mutation.start() > 2_000:
            continue
        if _AUTHENTICATED_TARGET.search(sink_window) is None:
            continue

        branch_line = _line_number(source, branch.header_start)
        new_line = _line_number(source, branch.body_start + selected_new.start())
        confirmation_line = _line_number(source, branch.body_start + selected_confirmation.start())
        comparison_line = _line_number(source, branch.body_start + comparison.start())
        sink_line = _line_number(source, branch.body_start + mutation.start())
        execution_line = _line_number(source, branch.body_start + execution.start())
        findings.append(
            WebWorkflowFinding(
                native_rule_id=PASSWORD_CHANGE_WITHOUT_REAUTH_RULE,
                rule_id="CWE-620",
                line=sink_line,
                sink_line=execution_line,
                title="Password change does not verify the current credential",
                description=(
                    "The state-changing branch accepts a new password and confirmation, checks only that those "
                    "two attacker-supplied values match, and updates the authenticated user's password. No "
                    "current/original password check or other visible step-up authentication protects this branch."
                ),
                remediation=(
                    "Before changing the password, require and verify the current password or perform equivalent "
                    "session-bound step-up authentication. Keep CSRF and workflow-transition checks as separate "
                    "defenses, and invalidate other active sessions after a successful credential change."
                ),
                impact=(
                    "If an authenticated session is stolen, left unattended, or reached through a separate request "
                    "forgery weakness, an attacker may replace that account's credential and lock out its owner."
                ),
                source_step=branch.value,
                target_step="credential_update",
                data_flow=(
                    f"request:{selected_new.group('method').upper()}.{selected_new.group('key')}",
                    f"confirmation:{selected_confirmation.group('method').upper()}.{selected_confirmation.group('key')}",
                    f"equality_gate@{comparison_line}",
                    f"sink:password_update@{sink_line}",
                ),
                evidence_lines=tuple(
                    sorted({branch_line, new_line, confirmation_line, comparison_line, sink_line, execution_line})
                ),
                weakness_ids=("CWE-620",),
                preconditions=(
                    "The current-user helper identifies an already authenticated account.",
                    "No out-of-file middleware performs equivalent session-bound step-up authentication.",
                ),
            )
        )
        weak_hash = re.search(
            rf"{re.escape(selected_new.group('variable'))}\s*=\s*"
            rf"(?P<algorithm>md5|sha1)\s*\(\s*{re.escape(selected_new.group('variable'))}\s*\)",
            branch_code[: mutation.start()],
            re.IGNORECASE,
        )
        if weak_hash is not None:
            algorithm = weak_hash.group("algorithm").upper()
            hash_line = _line_number(source, branch.body_start + weak_hash.start())
            findings.append(
                WebWorkflowFinding(
                    native_rule_id=WEAK_PASSWORD_HASH_RULE,
                    rule_id="CWE-327",
                    line=hash_line,
                    sink_line=sink_line,
                    title=f"Password is stored using a fast {algorithm} digest",
                    description=(
                        f"The request-derived replacement password is transformed with {algorithm} and the "
                        "result is persisted in the authenticated user's password column. A fast general-purpose "
                        "digest does not provide the work factor and salt handling required for password storage."
                    ),
                    remediation=(
                        "Use the platform password-hashing API backed by Argon2id, scrypt, bcrypt, or PBKDF2 with "
                        "an appropriate work factor and automatic per-password salt. Rehash existing values after "
                        "successful authentication."
                    ),
                    impact=(
                        "If the password database is exposed, attackers can test guesses at high speed and recover "
                        "weak user passwords more cheaply."
                    ),
                    source_step=branch.value,
                    target_step="password_storage",
                    data_flow=(
                        f"request:{selected_new.group('method').upper()}.{selected_new.group('key')}",
                        f"weak_digest:{algorithm.casefold()}@{hash_line}",
                        f"sink:password_update@{sink_line}",
                    ),
                    evidence_lines=tuple(sorted({new_line, hash_line, sink_line, execution_line})),
                    weakness_ids=("CWE-327", "CWE-916"),
                    preconditions=("The persisted value is used as the account password verifier.",),
                )
            )
    return tuple(findings)


def _password_key_role(key: str) -> str | None:
    normalized = re.sub(r"[^a-z0-9]+", "_", key.casefold()).strip("_")
    tokens = frozenset(part for part in normalized.split("_") if part)
    if not ({"password", "passwd", "passphrase", "pass"} & tokens):
        return None
    if {"current", "old", "existing", "previous", "original"} & tokens:
        return "current"
    if {"confirm", "confirmation", "conf", "repeat", "again"} & tokens:
        return "confirmation"
    if {"new", "replacement"} & tokens:
        return "new"
    return None


def _is_password_key(key: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]+", "_", key.casefold()).strip("_")
    return bool({"password", "passwd", "passphrase", "pass"} & set(normalized.split("_")))


def _stage_branches(source: str, code_view: str) -> tuple[_StageBranch, ...]:
    branches: list[_StageBranch] = []
    for match in _STAGE_ACCESS.finditer(source):
        if code_view[match.start() : match.start() + 2] != "$_":
            continue
        header_start = _nearest_if(code_view, match.start())
        if header_start is None:
            continue
        open_brace = code_view.find("{", match.end(), min(len(code_view), match.end() + _MAX_CONDITION_CHARS))
        if open_brace < 0 or ";" in code_view[match.end() : open_brace]:
            continue
        body_end = _matching_brace(code_view, open_brace)
        if body_end is None:
            continue
        branches.append(
            _StageBranch(
                method=match.group("method").upper(),
                key=match.group("key").casefold(),
                value=match.group("value"),
                header_start=header_start,
                body_start=open_brace + 1,
                body_end=body_end,
            )
        )
        if len(branches) >= _MAX_BRANCHES:
            break
    unique = {(item.header_start, item.body_end, item.key, item.value): item for item in branches}
    return tuple(sorted(unique.values(), key=lambda item: (item.header_start, item.key, item.value)))


def _nearest_if(source: str, offset: int) -> int | None:
    lower = max(0, offset - _MAX_CONDITION_CHARS)
    candidates = list(re.finditer(r"\bif\s*\(", source[lower:offset], re.IGNORECASE))
    if not candidates:
        return None
    return lower + candidates[-1].start()


def _hidden_stage_values(body: str, *, key: str) -> tuple[tuple[int, str], ...]:
    values: list[tuple[int, str]] = []
    for tag in _INPUT_TAG.finditer(body):
        normalized_tag = tag.group().replace(r"\"", '"').replace(r"\'", "'")
        attributes = {
            match.group("name").casefold(): match.group("value") for match in _ATTRIBUTE.finditer(normalized_tag)
        }
        if attributes.get("type", "").casefold() != "hidden" or attributes.get("name", "").casefold() != key:
            continue
        value = attributes.get("value", "")
        if value and len(value) <= 32 and re.fullmatch(r"[A-Za-z0-9_-]+", value):
            values.append((tag.start(), value))
    return tuple(values)


def _matching_brace(source: str, opening: int) -> int | None:
    depth = 0
    state = "normal"
    escaped = False
    index = opening
    while index < len(source):
        character = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if state == "normal":
            if character == "/" and following == "/":
                state = "line_comment"
                index += 2
                continue
            if character == "/" and following == "*":
                state = "block_comment"
                index += 2
                continue
            if character == "#":
                state = "line_comment"
            elif character == "'":
                state = "single"
            elif character == '"':
                state = "double"
            elif character == "{":
                depth += 1
            elif character == "}":
                depth -= 1
                if depth == 0:
                    return index
        elif state == "line_comment":
            if character == "\n":
                state = "normal"
        elif state == "block_comment":
            if character == "*" and following == "/":
                state = "normal"
                index += 2
                continue
        elif escaped:
            escaped = False
        elif character == "\\":
            escaped = True
        elif (state == "single" and character == "'") or (state == "double" and character == '"'):
            state = "normal"
        index += 1
    return None


def _mask_comments(source: str) -> str:
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
            if character == "#":
                output[index] = " "
                state = "line_comment"
            elif character == "'":
                state = "single"
            elif character == '"':
                state = "double"
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
        elif escaped:
            escaped = False
        elif character == "\\":
            escaped = True
        elif (state == "single" and character == "'") or (state == "double" and character == '"'):
            state = "normal"
        index += 1
    return "".join(output)


def _mask_strings(source: str) -> str:
    """Blank string literals while preserving byte offsets and newlines."""

    output = list(source)
    quote: str | None = None
    escaped = False
    for index, character in enumerate(source):
        if quote is None:
            if character in {"'", '"'}:
                quote = character
                output[index] = " "
            continue
        if character != "\n":
            output[index] = " "
        if escaped:
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == quote:
            quote = None
    return "".join(output)


def _line_number(source: str, offset: int) -> int:
    return source.count("\n", 0, max(0, offset)) + 1


__all__ = [
    "CAPTCHA_STAGE_BYPASS_RULE",
    "PASSWORD_CHANGE_WITHOUT_REAUTH_RULE",
    "WEAK_PASSWORD_HASH_RULE",
    "RULE_BUNDLE_DIGEST",
    "TOOL_NAME",
    "TOOL_VERSION",
    "WebSource",
    "WebWorkflowFinding",
    "analyze_web_source",
]
