from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import re
import unicodedata
from collections.abc import Iterable, Mapping, Sequence, Set
from enum import Enum
from itertools import islice
from typing import Any

REDACTED = "[REDACTED]"
TRUNCATED = "[TRUNCATED]"

# Exact-answer values are the one deliberately narrow exception to the
# high-entropy detector.  They are restored only below a typed ``answer``
# object, never for arbitrary evidence/log fields.  Known credential shapes
# remain rejected even when a caller supplies them as an exact-answer
# candidate.
_EXACT_VALUE_KEYS = frozenset({"answer", "value", "values"})
_SAFE_EXACT_FLAG = re.compile(
    r"(?P<prefix>[A-Za-z][A-Za-z0-9_-]{0,31})\{[A-Za-z0-9!#$%&()*+,./:;=?@\[\\\]^_`|~+-]{1,256}\}"
)

_ZERO_WIDTH = re.compile(
    "[\\u00ad\\u034f\\u061c\\u115f\\u1160\\u17b4\\u17b5\\u180b-\\u180f"
    "\\u200b-\\u200f\\u202a-\\u202e\\u2060-\\u206f\\u3164\\ufe00-\\ufe0f\\ufeff]"
)

_SENSITIVE_KEY = re.compile(
    r"(?i)(?:^|[._-])(?:"
    r"access[_-]?token|refresh[_-]?token|api[_-]?key|apikey|authorization|proxy[_-]?authorization|"
    r"client[_-]?secret|cookie|credential|passphrase|password|passwd|pwd|private[_-]?key|secret|"
    r"session[_-]?(?:id|token)|set[_-]?cookie|token|x[_-]?api[_-]?key"
    r")(?:$|[._-])"
)

# A generic assignment matcher is deliberately followed by ``is_sensitive_key``
# instead of carrying another allowlist in the expression.  This lets the
# structured-key and text paths share exactly the same component-boundary
# rules (including camelCase and PascalCase names).
_GENERIC_ASSIGNMENT = re.compile(
    r"(?P<prefix>(?P<name>[\"']?[\w][\w.-]*[\"']?\s*[:=]\s*))"
    r"(?P<value>\"[^\"\r\n]*\"|'[^'\r\n]*'|"
    r"(?:(?!\s+[\"']?[A-Za-z][A-Za-z0-9_.-]*[\"']?\s*[:=])[^,;&}\r\n])+)"
)
_QUERY_ASSIGNMENT = re.compile(r"(?i)(?P<prefix>[?&][\w][\w.-]*\s*=\s*)(?P<value>[^&#\s]+)")
_SENSITIVE_HEADER = re.compile(
    r"(?im)^(\s*(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key)\s*:\s*)[^\r\n]*$"
)
_BEARER = re.compile(r"(?i)(\bbearer\s+)[A-Za-z0-9._~+/=-]{4,}")
_PRIVATE_KEY = re.compile(
    r"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----.*?-----END(?: [A-Z0-9]+)? PRIVATE KEY-----",
    re.DOTALL,
)
_COMMON_TOKEN = re.compile(
    r"(?<![A-Za-z0-9])(?:"
    r"sk-[A-Za-z0-9_-]{12,}|"
    r"gh[pousr]_[A-Za-z0-9]{16,}|"
    r"github_pat_[A-Za-z0-9_]{20,}|"
    r"glpat-[A-Za-z0-9_-]{12,}|"
    r"xox[baprs]-[A-Za-z0-9-]{10,}|"
    r"(?:AKIA|ASIA)[0-9A-Z]{16}|"
    r"AIza[0-9A-Za-z_-]{30,}|"
    r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"
    r")(?![A-Za-z0-9])"
)

_JWT_LIKE = re.compile(r"(?<![A-Za-z0-9])(?:[A-Za-z0-9_-]{8,}\.){2,4}[A-Za-z0-9_-]{8,}(?![A-Za-z0-9])")
_HEX_DIGEST = re.compile(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$|^[0-9a-fA-F]{96}$|^[0-9a-fA-F]{128}$")
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
_HIGH_ENTROPY_CANDIDATE = re.compile(r"(?<![A-Za-z0-9])([A-Za-z0-9+/_-]{20,}={0,2})(?![A-Za-z0-9])")
_MIXED_SECRET_CANDIDATE = re.compile(
    r"(?<![A-Za-z0-9])([A-Za-z0-9!#$%&()*+,\-./:;=?@\[\\\]^_`{|}~]{20,256})(?![A-Za-z0-9])"
)
_PUBLIC_CURSOR = re.compile(r"^[A-Za-z0-9_-]{32,2048}$")
_PUBLIC_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_UPLOAD_PREFIXED_BASENAME = re.compile(
    r"^(?P<upload_id>[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12})-(?P<basename>.+)$"
)
_PUBLIC_IDENTIFIER_PREFIXES = (
    "answer-",
    "artifact-",
    "audit-",
    "actor-",
    "candidate-",
    "canonical-",
    "case-",
    "claim-",
    "coverage-",
    "critic-evidence-",
    "delta-",
    "evidence-",
    "ev-",
    "event-",
    "finding-",
    "fnd-",
    "invocation-",
    "java-",
    "operation-",
    "primary-evidence-",
    "question-",
    "run-",
    "semantic-",
    "secmind-",
    "step-",
    "task-",
    "tool-",
    "typed-",
    "upload-",
)


_SENSITIVE_SINGLE_TOKENS = frozenset(
    {
        "access-token",
        "authorization",
        "cookie",
        "credential",
        "credentials",
        "passphrase",
        "password",
        "passwd",
        "pwd",
        "secret",
        "token",
        "set-cookie",
        "signature",
        "signing",
        "encryption",
        "encrypt",
        "decrypt",
        "webhook",
        "smtp",
        "database",
        "db",
        "密钥",
        "密码",
        "令牌",
        "签名",
        "加密",
        "私钥",
        "授权",
        "口令",
    }
)
_SENSITIVE_PHRASES = (
    ("access", "token"),
    ("access", "key"),
    ("refresh", "token"),
    ("api", "key"),
    ("apikey",),
    ("authorization",),
    ("proxy", "authorization"),
    ("client", "secret"),
    ("cookie",),
    ("credential",),
    ("credentials",),
    ("passphrase",),
    ("password",),
    ("passwd",),
    ("pwd",),
    ("private", "key"),
    ("secret",),
    ("session", "id"),
    ("session", "token"),
    ("set", "cookie"),
    ("token",),
    ("x", "api", "key"),
    ("signing", "key"),
    ("signing", "secret"),
    ("encryption", "key"),
    ("encrypt", "key"),
    ("smtp", "password"),
    ("smtp", "credential"),
    ("webhook",),
    ("webhook", "url"),
    ("database", "password"),
    ("db", "password"),
    ("aws", "key"),
    ("密钥",),
    ("密码",),
    ("令牌",),
    ("签名",),
    ("加密",),
    ("私钥",),
    ("授权",),
    ("口令",),
)
_CAMEL_BOUNDARY = re.compile(r"([a-z0-9])([A-Z])")
_ACRONYM_BOUNDARY = re.compile(r"([A-Z]+)([A-Z][a-z])")
_LETTER_DIGIT_BOUNDARY = re.compile(r"([A-Za-z])([0-9])")
_DIGIT_LETTER_BOUNDARY = re.compile(r"([0-9])([A-Za-z])")


def _key_tokens(key: str) -> tuple[str, ...]:
    """Split a field name at all supported naming-style boundaries.

    The old regular expression only saw separators, so ``apiKey``,
    ``ApiKey`` and ``OAuthClientSecret`` could evade redaction.  Keeping the
    split logic small and deterministic also makes it safe to use for text
    assignments and recursively nested mappings.
    """

    normalized = _ZERO_WIDTH.sub("", unicodedata.normalize("NFKC", key)).strip().strip("\"'")
    normalized = _ACRONYM_BOUNDARY.sub(r"\1 \2", normalized)
    normalized = _CAMEL_BOUNDARY.sub(r"\1 \2", normalized)
    normalized = _LETTER_DIGIT_BOUNDARY.sub(r"\1 \2", normalized)
    normalized = _DIGIT_LETTER_BOUNDARY.sub(r"\1 \2", normalized)
    return tuple(token.casefold() for token in re.split(r"[\W_]+", normalized, flags=re.UNICODE) if token)


def _contains_phrase(tokens: tuple[str, ...], phrase: tuple[str, ...]) -> bool:
    width = len(phrase)
    return width <= len(tokens) and any(
        tokens[index : index + width] == phrase for index in range(len(tokens) - width + 1)
    )


def is_sensitive_key(key: str) -> bool:
    """Return whether a JSON-like field name is reserved for sensitive data."""

    tokens = _key_tokens(key)
    if not tokens:
        return False
    if any(token in _SENSITIVE_SINGLE_TOKENS for token in tokens):
        return True
    return any(_contains_phrase(tokens, phrase) for phrase in _SENSITIVE_PHRASES)


def _scrub_assignment(match: re.Match[str]) -> str:
    name = match.group("name").strip().strip("\"'")
    if not is_sensitive_key(name):
        return match.group(0)
    if _is_redacted_assignment_value(match.group("value")):
        return match.group(0)
    return f"{match.group('prefix')}{REDACTED}"


def _is_redacted_assignment_value(value: str) -> bool:
    """Accept a redaction marker followed only by closing source punctuation."""

    candidate = value.strip().lstrip("\"'`(")
    return any(
        candidate.startswith(marker)
        and all(character in "\"'`)]}" for character in candidate[len(marker) :])
        for marker in (REDACTED, TRUNCATED)
    )


def _scrub_query_assignment(match: re.Match[str]) -> str:
    name = match.group("prefix")[1:].split("=", 1)[0].strip()
    return f"{match.group('prefix')}{REDACTED}" if is_sensitive_key(name) else match.group(0)


def scrub_text(value: str) -> str:
    """Return a deterministic copy of *value* with credential material removed."""

    if not isinstance(value, str):
        return REDACTED
    scrubbed = _ZERO_WIDTH.sub("", unicodedata.normalize("NFKC", value))
    scrubbed = _PRIVATE_KEY.sub(REDACTED, scrubbed)
    scrubbed = _SENSITIVE_HEADER.sub(rf"\1{REDACTED}", scrubbed)
    scrubbed = _BEARER.sub(rf"\1{REDACTED}", scrubbed)
    scrubbed = _GENERIC_ASSIGNMENT.sub(_scrub_assignment, scrubbed)
    scrubbed = _QUERY_ASSIGNMENT.sub(_scrub_query_assignment, scrubbed)
    scrubbed = _COMMON_TOKEN.sub(REDACTED, scrubbed)
    scrubbed = _JWT_LIKE.sub(REDACTED, scrubbed)
    scrubbed = _HIGH_ENTROPY_CANDIDATE.sub(_scrub_high_entropy, scrubbed)
    return _MIXED_SECRET_CANDIDATE.sub(_scrub_mixed_secret, scrubbed)


def bytes_metadata(value: bytes | bytearray | memoryview) -> dict[str, Any]:
    """Describe binary data without decoding, hashing, or retaining its contents."""

    size_bytes = value.nbytes if isinstance(value, memoryview) else len(value)
    return {
        "type": "bytes",
        "size_bytes": size_bytes,
        "redacted": True,
    }


def scrub_value(
    value: Any,
    *,
    max_depth: int = 12,
    max_items: int = 1_024,
    trusted_exact_answers: Iterable[str] = (),
) -> Any:
    """Recursively scrub JSON-like data without mutating the source value.

    Binary and unsupported objects are represented only by safe metadata.  This
    deliberately avoids calling arbitrary ``__str__`` implementations or exposing
    a reversible digest of low-entropy credentials.
    """

    if max_depth < 1:
        raise ValueError("max_depth must be positive")
    if max_items < 1:
        raise ValueError("max_items must be positive")
    trusted = _normalize_trusted_exact_answers(trusted_exact_answers)
    result = _scrub(value, depth=0, max_depth=max_depth, max_items=max_items, ancestors=set())
    if trusted:
        result = _restore_trusted_exact_fields(
            value,
            result,
            trusted,
            depth=0,
            max_depth=max_depth,
            max_items=max_items,
            path=(),
        )
    return result


def scrub_metadata(value: Mapping[str, Any] | None, *, max_depth: int = 12, max_items: int = 1_024) -> dict[str, Any]:
    """Compatibility facade for callers that require dictionary metadata."""

    if value is None:
        return {}
    scrubbed = scrub_value(value, max_depth=max_depth, max_items=max_items)
    return scrubbed if isinstance(scrubbed, dict) else {}


def redact(value: Any) -> Any:
    """Compatibility alias for existing pure-function redaction call sites."""

    return scrub_value(value)


class ArtifactLeakageError(ValueError):
    """Raised when a scrubbed artifact still contains credential material."""


def scrub_artifact(
    value: Any,
    *,
    max_depth: int = 12,
    max_items: int = 1_024,
    trusted_exact_answers: Iterable[str] = (),
) -> Any:
    """Scrub an entire public artifact and fail closed if a detector remains.

    Public reports, ledger diagnostics, trace capsules and bridge payloads use
    this boundary instead of serializing the original object.  The recursive
    scrubber runs first; the second detector pass catches a newly introduced
    token shape rather than allowing it to cross the artifact boundary.
    """

    trusted = _normalize_trusted_exact_answers(trusted_exact_answers)
    fragmented = _scrub_fragmented_secret_fields(
        value,
        trusted_exact_answers=trusted,
        depth=0,
        max_depth=max_depth,
        max_items=max_items,
    )
    result = scrub_value(fragmented, max_depth=max_depth, max_items=max_items, trusted_exact_answers=trusted)
    result = _scrub_fragmented_secret_fields(
        result,
        trusted_exact_answers=trusted,
        depth=0,
        max_depth=max_depth,
        max_items=max_items,
    )
    if _contains_secret_material(result, trusted_exact_answers=trusted):
        raise ArtifactLeakageError("scrubbed artifact still contains credential material")
    return result


def sanitize_artifact(
    value: Any,
    *,
    max_depth: int = 12,
    max_items: int = 1_024,
    trusted_exact_answers: Iterable[str] = (),
) -> Any:
    """Explicit alias for integrations that receive tainted artifact trees."""

    return scrub_artifact(
        value,
        max_depth=max_depth,
        max_items=max_items,
        trusted_exact_answers=trusted_exact_answers,
    )


def assert_no_secret_leak(value: Any) -> None:
    """Raise when *value* is not safe for a public artifact boundary."""

    if _contains_secret_material(value):
        raise ArtifactLeakageError("artifact contains credential material")


def scrub_text_chunks(chunks: Sequence[str], *, overlap: int = 256) -> list[str]:
    """Scrub chunked text with bounded overlap so split tokens cannot leak."""

    if overlap < 0 or overlap > 16_384:
        raise ValueError("overlap must be between 0 and 16384")
    source = [item if isinstance(item, str) else REDACTED for item in chunks]
    scrubbed = scrub_text("".join(source))
    output: list[str] = []
    offset = 0
    for item in source:
        output.append(scrubbed[offset : offset + len(item)])
        offset += len(item)
    return output


def _normalize_trusted_exact_answers(values: Iterable[str]) -> frozenset[str]:
    """Bound and validate the narrow exact-answer exception set.

    This helper intentionally accepts strings only.  More importantly, it
    excludes credentials before the values can be used by either the restore
    pass or the post-scrub canary.  The caller still has to prove that every
    retained value is task-contract and evidence bound; this function is not a
    general allowlist for arbitrary public data.
    """

    if isinstance(values, (str, bytes, bytearray, memoryview)):
        candidates: Iterable[object] = (values,)
    else:
        candidates = values
    output: set[str] = set()
    for index, candidate in enumerate(candidates):
        if index >= 256:
            break
        if not isinstance(candidate, str) or not candidate or len(candidate) > 4_096:
            continue
        normalized = _ZERO_WIDTH.sub("", unicodedata.normalize("NFKC", candidate))
        if normalized != candidate or any(unicodedata.category(char) in {"Cc", "Cf"} for char in candidate):
            continue
        if candidate in {REDACTED, TRUNCATED} or _exact_answer_candidate_is_secret(candidate):
            continue
        output.add(candidate)
        if len(output) >= 64:
            break
    return frozenset(output)


def _exact_answer_candidate_is_secret(value: str) -> bool:
    """Reject credential-shaped candidates even under the exact-answer path."""

    if _PRIVATE_KEY.search(value) or _COMMON_TOKEN.search(value) or _JWT_LIKE.search(value):
        return True
    if _BEARER.search(value) or _SENSITIVE_HEADER.search(value):
        return True
    assignment = _GENERIC_ASSIGNMENT.search(value)
    if assignment and is_sensitive_key(assignment.group("name").strip().strip("\"'")):
        return True
    # Ordinary non-secret exact values do not need the exception.  If generic
    # scrubbing would redact a high-entropy value, only an evidence-attested
    # CTF-style flag (or an integrity identifier) may be restored.  This keeps
    # arbitrary random passwords outside the exception without hard-coding a
    # benchmark answer.
    if scrub_text(value) == value or _HEX_DIGEST.fullmatch(value) or _UUID.fullmatch(value):
        return False
    flag = _SAFE_EXACT_FLAG.fullmatch(value)
    return flag is None or is_sensitive_key(flag.group("prefix"))


def _is_exact_answer_mapping(value: Mapping[Any, Any]) -> bool:
    """Identify the typed exact-answer object without trusting field names alone."""

    kind = value.get("answer_kind")
    answer_type = value.get("answer_type")
    return (
        isinstance(kind, str)
        and kind.casefold() in {"exact", "exact_answer"}
        and (
            answer_type is None
            or (isinstance(answer_type, str) and answer_type.casefold() in {"exact", "exact_answer"})
        )
    )


def _restore_trusted_exact_fields(
    original: Any,
    scrubbed: Any,
    trusted: frozenset[str],
    *,
    depth: int,
    max_depth: int,
    max_items: int,
    path: tuple[str, ...],
    exact_context: bool = False,
) -> Any:
    """Restore only exact answer value members after generic scrubbing."""

    if depth >= max_depth:
        return scrubbed
    if isinstance(original, str):
        return original if exact_context and original in trusted else scrubbed
    if isinstance(original, Mapping) and isinstance(scrubbed, Mapping):
        mapping_context = path == ("answer",) and _is_exact_answer_mapping(original)
        restored: dict[Any, Any] = dict(scrubbed)
        for key, item in islice(original.items(), max_items):
            safe_key = _safe_key(key)
            if safe_key not in restored:
                continue
            child = restored[safe_key]
            field_context = mapping_context and safe_key.casefold() in _EXACT_VALUE_KEYS
            restored[safe_key] = _restore_trusted_exact_fields(
                item,
                child,
                trusted,
                depth=depth + 1,
                max_depth=max_depth,
                max_items=max_items,
                path=(*path, safe_key),
                exact_context=field_context,
            )
        return restored
    if isinstance(original, Sequence) and not isinstance(original, (str, bytes, bytearray, memoryview)):
        if not isinstance(scrubbed, list):
            return scrubbed
        restored_items: list[Any] = []
        for index, item in enumerate(original[: len(scrubbed)]):
            restored_items.append(
                _restore_trusted_exact_fields(
                    item,
                    scrubbed[index],
                    trusted,
                    depth=depth + 1,
                    max_depth=max_depth,
                    max_items=max_items,
                    path=(*path, str(index)),
                    exact_context=exact_context and isinstance(item, str),
                )
            )
        return restored_items
    return scrubbed


def _scrub(
    value: Any,
    *,
    depth: int,
    max_depth: int,
    max_items: int,
    ancestors: set[int],
) -> Any:
    if depth >= max_depth:
        return TRUNCATED
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return scrub_text(value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes_metadata(value)
    if isinstance(value, Enum):
        return _scrub(
            value.value,
            depth=depth,
            max_depth=max_depth,
            max_items=max_items,
            ancestors=ancestors,
        )

    identifier = id(value)
    if identifier in ancestors:
        return TRUNCATED

    if isinstance(value, Mapping):
        ancestors.add(identifier)
        try:
            output: dict[str, Any] = {}
            for index, (key, item) in enumerate(value.items()):
                if index >= max_items:
                    output["scrubber.truncated"] = True
                    break
                safe_key = _safe_key(key)
                if is_sensitive_key(safe_key):
                    output[safe_key] = REDACTED
                elif isinstance(item, str):
                    output[safe_key] = _preserve_integrity_value(safe_key, item)
                elif (
                    _is_public_identifier_key(safe_key)
                    and isinstance(item, Sequence)
                    and not isinstance(item, (str, bytes, bytearray, memoryview))
                ):
                    output[safe_key] = [
                        _preserve_integrity_value(safe_key, entry)
                        if isinstance(entry, str)
                        else _scrub(
                            entry,
                            depth=depth + 1,
                            max_depth=max_depth,
                            max_items=max_items,
                            ancestors=ancestors,
                        )
                        for entry in item[:max_items]
                    ]
                    if len(item) > max_items:
                        output["scrubber.truncated"] = True
                else:
                    output[safe_key] = _scrub(
                        item,
                        depth=depth + 1,
                        max_depth=max_depth,
                        max_items=max_items,
                        ancestors=ancestors,
                    )
            return output
        finally:
            ancestors.remove(identifier)

    if isinstance(value, Set) and not isinstance(value, (str, bytes, bytearray, memoryview)):
        if len(value) > max_items:
            return [TRUNCATED]
        ancestors.add(identifier)
        try:
            scrubbed = [
                _scrub(
                    item,
                    depth=depth + 1,
                    max_depth=max_depth,
                    max_items=max_items,
                    ancestors=ancestors,
                )
                for item in value
            ]
            return sorted(scrubbed, key=_canonical_sort_key)
        finally:
            ancestors.remove(identifier)

    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray, memoryview)):
        ancestors.add(identifier)
        try:
            scrubbed = [
                _scrub(
                    item,
                    depth=depth + 1,
                    max_depth=max_depth,
                    max_items=max_items,
                    ancestors=ancestors,
                )
                for item in value[:max_items]
            ]
            if len(value) > max_items:
                scrubbed.append(TRUNCATED)
            return scrubbed
        finally:
            ancestors.remove(identifier)

    return {
        "type": f"{type(value).__module__}.{type(value).__qualname__}",
        "redacted": True,
    }


def _safe_key(value: Any) -> str:
    if isinstance(value, str):
        return value
    if value is None or isinstance(value, (bool, int, float)):
        return str(value)
    return "[REDACTED_KEY]"


def _preserve_integrity_value(key: str, value: str) -> Any:
    """Keep a canonical digest under an explicitly integrity-labelled key."""

    public_path = _safe_public_relative_path(key, value)
    if public_path is not None:
        return public_path
    tokens = _key_tokens(key)
    if key.casefold() in {"path", "file", "relative_path", "source_path"} or (tokens and tokens[-1] == "path"):
        if _is_public_api_route(value):
            # API route templates are public assessment data, not host file
            # paths.  They still pass through text scrubbing so query-string
            # credentials cannot escape the structured scrubber.
            return scrub_text(value)
        # An unsafe path must not degrade into a plausible-looking scrubbed
        # filename such as ``[REDACTED].py``.  Callers can then resolve the
        # path from a trusted manifest digest or report it as unavailable.
        return REDACTED
    if _is_integrity_key(key) and (_HEX_DIGEST.fullmatch(value) or _UUID.fullmatch(value)):
        return value
    # Projection cursors are authenticated, bounded handles rather than
    # credentials.  Preserve them in structured metadata so a public page can
    # actually be continued; free-form text still takes the conservative
    # high-entropy path below.
    if _is_cursor_key(key) and _is_public_cursor(value):
        return value
    if _is_public_identifier_key(key) and _is_public_identifier(value, allow_bare_digest=True):
        return value
    return scrub_text(value)


_FILESYSTEM_ROOT_SEGMENTS = frozenset(
    {
        "dev",
        "etc",
        "home",
        "mnt",
        "opt",
        "proc",
        "root",
        "sys",
        "tmp",
        "usr",
        "var",
    }
)


def _is_public_api_route(value: str) -> bool:
    """Distinguish an API route template from an absolute host path."""

    candidate = value.strip()
    if (
        not candidate.startswith("/")
        or candidate.startswith("//")
        or "\\" in candidate
        or "\x00" in candidate
        or len(candidate) > 2_048
    ):
        return False
    path_only = candidate.split("?", 1)[0].split("#", 1)[0]
    parts = [part for part in path_only.split("/") if part]
    if not parts or any(part in {".", ".."} for part in parts):
        return False
    if parts[0].casefold() in _FILESYSTEM_ROOT_SEGMENTS or parts[0] == "Users":
        return False
    return all(len(part) <= 255 for part in parts)


def _safe_public_relative_path(key: str, value: str) -> str | None:
    """Preserve an input-relative locator without preserving host paths/secrets."""

    tokens = _key_tokens(key)
    if not (key.casefold() in {"path", "file", "relative_path", "source_path"} or (tokens and tokens[-1] == "path")):
        return None
    candidate = value.strip().replace("\\", "/")
    if (
        not candidate
        or len(candidate) > 1_024
        or candidate.startswith("/")
        or "\x00" in candidate
        or re.match(r"^[A-Za-z]:", candidate)
    ):
        return None
    parts = candidate.split("/")
    if any(not part or part in {".", ".."} or len(part) > 255 for part in parts):
        return None
    # A filename is public provenance, but a token-shaped filename still gets
    # redacted. UUID and digest components are stable public identifiers. The
    # upload API deliberately prefixes a basename with ``<uuid>-``; remove only
    # that validated prefix from entropy inspection so it does not cause the
    # entire otherwise-safe relative path to be mistaken for one opaque token.
    # The original candidate is returned unchanged after this check.
    scan_parts: list[str] = []
    for part in parts:
        if _UUID.fullmatch(part) or _HEX_DIGEST.fullmatch(part):
            scan_parts.append(".")
            continue
        upload_match = _UPLOAD_PREFIXED_BASENAME.fullmatch(part)
        basename = upload_match.group("basename") if upload_match is not None else part
        # The bridge creates a fixed <uuid>-workspace wrapper. Like a bare
        # UUID, this contains no user-supplied credential material. A dot ends
        # the token scan instead of adding artificial entropy to its children.
        scan_parts.append("." if upload_match is not None and basename == "workspace" else basename)
    entropy_candidate = "/".join(scan_parts)
    if _COMMON_TOKEN.search(entropy_candidate) or _JWT_LIKE.search(entropy_candidate):
        return None
    # Inspect components too, but keep the joined scan below: a base64 secret
    # containing '/' must not escape by splitting into short path components.
    for part in scan_parts:
        if REDACTED in scrub_text(part):
            return None
    for match in _HIGH_ENTROPY_CANDIDATE.finditer(entropy_candidate):
        opaque = match.group(1)
        classes = sum(
            (
                bool(re.search(r"[a-z]", opaque)),
                bool(re.search(r"[A-Z]", opaque)),
                bool(re.search(r"[0-9]", opaque)),
                bool(re.search(r"[^A-Za-z0-9]", opaque)),
            )
        )
        if len(set(opaque)) >= 8 and _entropy(opaque) >= 4.25 and classes >= 2:
            return None
    return candidate


def _is_integrity_key(key: str) -> bool:
    return any(
        token.startswith("sha") or token in {"hash", "digest", "checksum", "fingerprint"} for token in _key_tokens(key)
    )


def _is_cursor_key(key: str) -> bool:
    return "cursor" in _key_tokens(key)


def _is_public_identifier_key(key: str) -> bool:
    tokens = _key_tokens(key)
    return (
        bool(tokens)
        and (tokens[-1] in {"id", "ids", "ref", "refs"})
        and any(
            token
            in {
                "answer",
                "artifact",
                "actor",
                "candidate",
                "case",
                "claim",
                "delta",
                "evidence",
                "event",
                "finding",
                "invocation",
                "operation",
                "question",
                "run",
                "semantic",
                "step",
                "task",
                "tool",
            }
            for token in tokens
        )
    )


def _is_public_identifier(value: str, *, allow_bare_digest: bool = False) -> bool:
    candidate = value.strip()
    if not _PUBLIC_IDENTIFIER.fullmatch(candidate):
        return False
    if _UUID.fullmatch(candidate) or (allow_bare_digest and _HEX_DIGEST.fullmatch(candidate)):
        return True
    if not candidate.casefold().startswith(_PUBLIC_IDENTIFIER_PREFIXES):
        return False
    return not (_PRIVATE_KEY.search(candidate) or _COMMON_TOKEN.search(candidate) or _JWT_LIKE.search(candidate))


def _is_public_cursor(value: str) -> bool:
    """Recognize only the authenticated cursor shape emitted by Test 3."""

    if not _PUBLIC_CURSOR.fullmatch(value):
        return False
    try:
        padded = value + "=" * (-len(value) % 4)
        decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
        raw, separator, digest = decoded.rpartition(b".")
    except (binascii.Error, UnicodeError, ValueError):
        return False
    return separator == b"." and len(digest) == 32 and digest == hashlib.sha256(raw).hexdigest()[:32].encode("ascii")


def _canonical_sort_key(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), default=lambda _: REDACTED)


def _scrub_high_entropy(match: re.Match[str]) -> str:
    candidate = match.group(1)
    if _UUID.fullmatch(candidate) or (_HEX_DIGEST.fullmatch(candidate) and _integrity_context(match)):
        return candidate
    if _is_public_identifier(candidate):
        return candidate
    entropy_floor = 3.5 if re.fullmatch(r"[0-9a-fA-F]+", candidate) else 4.25
    if len(set(candidate)) < 8 or _entropy(candidate) < entropy_floor:
        return candidate
    # Hex-only material is a common opaque-token encoding.  It must not be
    # treated as an integrity digest unless the surrounding label proves that
    # interpretation; otherwise a token_hex() value would pass the second
    # artifact gate merely because it uses one character class.
    if re.fullmatch(r"[0-9a-fA-F]+", candidate):
        return REDACTED
    classes = sum(
        (
            bool(re.search(r"[a-z]", candidate)),
            bool(re.search(r"[A-Z]", candidate)),
            bool(re.search(r"[0-9]", candidate)),
            bool(re.search(r"[^A-Za-z0-9]", candidate)),
        )
    )
    return REDACTED if classes >= 2 else candidate


def _scrub_mixed_secret(match: re.Match[str]) -> str:
    """Redact unlabeled password-manager style values with punctuation.

    Requiring all four character classes avoids treating ordinary URLs,
    source locators, prose, and public identifiers as credentials while still
    closing the gap left by the base64-oriented entropy detector.
    """

    candidate = match.group(1)
    if _UUID.fullmatch(candidate) or _HEX_DIGEST.fullmatch(candidate) or _is_public_identifier(candidate):
        return candidate
    classes = sum(
        (
            bool(re.search(r"[a-z]", candidate)),
            bool(re.search(r"[A-Z]", candidate)),
            bool(re.search(r"[0-9]", candidate)),
            bool(re.search(r"[^A-Za-z0-9]", candidate)),
        )
    )
    if classes < 4 or len(set(candidate)) < 10 or _entropy(candidate) < 4.0:
        return candidate
    return REDACTED


def _scrub_fragmented_secret_fields(
    value: Any,
    *,
    trusted_exact_answers: frozenset[str],
    depth: int,
    max_depth: int,
    max_items: int,
) -> Any:
    """Redact bounded adjacent fragments that become a secret when joined.

    Model output can split an API key across list members or sibling fields so
    each individual string stays below the normal detector threshold.  Only
    windows of four or fewer short strings are examined, and a window is
    changed only when the joined value is actually scrubbed.  Integrity/public
    identifiers and attested exact values are excluded to avoid changing
    report IDs or the narrow benchmark release path.
    """

    if depth >= max_depth:
        return TRUNCATED
    if isinstance(value, Mapping):
        items = list(value.items())[:max_items]
        output = {
            key: _scrub_fragmented_secret_fields(
                item,
                trusted_exact_answers=trusted_exact_answers,
                depth=depth + 1,
                max_depth=max_depth,
                max_items=max_items,
            )
            for key, item in items
        }
        _redact_fragment_windows(output, trusted_exact_answers)
        if len(value) > max_items:
            output["scrubber.truncated"] = True
        return output
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray, memoryview)):
        sequence_output: list[Any] = [
            _scrub_fragmented_secret_fields(
                item,
                trusted_exact_answers=trusted_exact_answers,
                depth=depth + 1,
                max_depth=max_depth,
                max_items=max_items,
            )
            for item in value[:max_items]
        ]
        _redact_fragment_windows(sequence_output, trusted_exact_answers)
        if len(value) > max_items:
            sequence_output.append(TRUNCATED)
        return sequence_output
    return value


def _redact_fragment_windows(
    container: list[Any] | dict[Any, Any],
    trusted_exact_answers: frozenset[str],
) -> None:
    """Apply the fragment rule in-place to one already bounded container."""

    values = list(container.values()) if isinstance(container, dict) else list(container)
    keys = list(container) if isinstance(container, dict) else []
    for start in range(len(values)):
        for width in range(2, min(4, len(values) - start) + 1):
            window = values[start : start + width]
            if not all(isinstance(item, str) and item not in {REDACTED, TRUNCATED} for item in window):
                continue
            if any(item in trusted_exact_answers for item in window):
                continue
            joined = "".join(window)
            if len(joined) > 4_096 or _looks_like_public_identifier_sequence(window):
                continue
            if not _is_suspicious_fragment_window(window, joined):
                continue
            for offset in range(start, start + width):
                if isinstance(container, dict):
                    key = keys[offset]
                    container[key] = REDACTED
                else:
                    container[offset] = REDACTED
            break


def _is_suspicious_fragment_window(values: Sequence[str], joined: str) -> bool:
    """Require a credential shape before joining unrelated public fields.

    A public proof contains many adjacent short strings (for example
    ``PARTIAL``, ``provider_claimed`` and ``SUCCESS``).  Redacting every
    window whose concatenation happens to contain a flag-shaped token both
    destroys the proof and makes the scrubber non-deterministically lossy.
    Join only when the complete window is a known credential/flag shape, starts
    with a recognized credential prefix, or contains at least two independent
    high-entropy fragments.
    """

    if _COMMON_TOKEN.search(joined) or _PRIVATE_KEY.search(joined):
        return True
    if _JWT_LIKE.fullmatch(joined) and not any("." in item for item in values):
        return True
    if _SAFE_EXACT_FLAG.fullmatch(joined) and not any(_SAFE_EXACT_FLAG.fullmatch(item) for item in values):
        return True
    if any(
        item.casefold().startswith(("sk-", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "glpat-", "xox")) for item in values
    ):
        return True
    if any("." in item for item in values):
        return False
    high_entropy_fragments = 0
    for item in values:
        if (
            _is_public_identifier(item, allow_bare_digest=True)
            or _SAFE_EXACT_FLAG.fullmatch(item)
            or re.fullmatch(r"[A-Za-z]+(?:[_-][A-Za-z]+)*", item)
        ):
            continue
        classes = sum(
            (
                bool(re.search(r"[a-z]", item)),
                bool(re.search(r"[A-Z]", item)),
                bool(re.search(r"[0-9]", item)),
                bool(re.search(r"[^A-Za-z0-9]", item)),
            )
        )
        if len(item) >= 8 and classes >= 2 and _entropy(item) >= 3.5:
            high_entropy_fragments += 1
    return high_entropy_fragments == len(values) and high_entropy_fragments >= 2


def _looks_like_public_identifier_sequence(values: Sequence[str]) -> bool:
    """Avoid joining adjacent integrity IDs into a false secret candidate."""

    return all(
        _UUID.fullmatch(value) or _HEX_DIGEST.fullmatch(value) or _is_public_identifier(value, allow_bare_digest=True)
        for value in values
    )


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for character in value:
        counts[character] = counts.get(character, 0) + 1
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _integrity_context(match: re.Match[str]) -> bool:
    """Allow canonical digests only when a surrounding label says so."""

    prefix = match.string[max(0, match.start() - 48) : match.start()].casefold()
    return bool(re.search(r"(?:sha(?:1|224|256|384|512)?|hash|digest|checksum|fingerprint)", prefix))


def _contains_secret_material(
    value: Any,
    *,
    trusted_exact_answers: frozenset[str] = frozenset(),
    exact_context: bool = False,
    path: tuple[str, ...] = (),
) -> bool:
    """Conservative post-scrub canary used by the full-artifact gate."""

    if isinstance(value, str):
        if exact_context and value in trusted_exact_answers and not _exact_answer_candidate_is_secret(value):
            return False
        if value in {REDACTED, TRUNCATED}:
            return False
        if _PRIVATE_KEY.search(value) or _COMMON_TOKEN.search(value) or _JWT_LIKE.search(value):
            return True
        for header in _SENSITIVE_HEADER.finditer(value):
            header_value = value[header.end(1) :].splitlines()[0].strip()
            if header_value not in {REDACTED, TRUNCATED}:
                return True
        for bearer in _BEARER.finditer(value):
            bearer_value = value[bearer.end(1) :].split()[0].strip()
            if bearer_value not in {REDACTED, TRUNCATED}:
                return True
        assignment = _GENERIC_ASSIGNMENT.search(value)
        if assignment:
            label = assignment.group("name").strip().strip("\"'")
            candidate = assignment.group("value")
            if is_sensitive_key(label) and not _is_redacted_assignment_value(candidate):
                return True
        query = _QUERY_ASSIGNMENT.search(value)
        if query:
            label = query.group("prefix")[1:].split("=", 1)[0].strip()
            if is_sensitive_key(label) and query.group("value") not in {REDACTED, TRUNCATED}:
                return True
        for candidate_match in _HIGH_ENTROPY_CANDIDATE.finditer(value):
            candidate = candidate_match.group(1)
            if _UUID.fullmatch(candidate) or (_HEX_DIGEST.fullmatch(candidate) and _integrity_context(candidate_match)):
                continue
            if _is_public_identifier(candidate):
                continue
            entropy_floor = 3.5 if re.fullmatch(r"[0-9a-fA-F]+", candidate) else 4.25
            if len(set(candidate)) >= 8 and _entropy(candidate) >= entropy_floor:
                if re.fullmatch(r"[0-9a-fA-F]+", candidate):
                    return True
                classes = sum(
                    (
                        bool(re.search(r"[a-z]", candidate)),
                        bool(re.search(r"[A-Z]", candidate)),
                        bool(re.search(r"[0-9]", candidate)),
                        bool(re.search(r"[^A-Za-z0-9]", candidate)),
                    )
                )
                if classes >= 2:
                    return True
        for candidate_match in _MIXED_SECRET_CANDIDATE.finditer(value):
            candidate = candidate_match.group(1)
            if _scrub_mixed_secret(candidate_match) == REDACTED:
                return True
        return False
    if isinstance(value, Mapping):
        mapping_context = path == ("answer",) and _is_exact_answer_mapping(value)
        for key, item in value.items():
            key_text = key if isinstance(key, str) else _safe_key(key)
            # Keys are serialized as part of JSON artifacts too.  A token can
            # be smuggled in a dynamic field name even when its value is
            # harmless, so the second pass scans both sides of the mapping.
            if _contains_secret_material(key_text):
                return True
            if is_sensitive_key(key_text) and not _contains_only_markers(item):
                return True
            field_context = mapping_context and key_text.casefold() in _EXACT_VALUE_KEYS
            if (
                _is_integrity_key(key_text)
                and isinstance(item, str)
                and (_HEX_DIGEST.fullmatch(item) or _UUID.fullmatch(item))
            ):
                continue
            if isinstance(item, str) and _safe_public_relative_path(key_text, item) is not None:
                continue
            if _is_cursor_key(key_text) and isinstance(item, str) and _is_public_cursor(item):
                continue
            if (
                _is_public_identifier_key(key_text)
                and isinstance(item, str)
                and _is_public_identifier(item, allow_bare_digest=True)
            ):
                continue
            if _is_public_identifier_key(key_text) and _contains_only_public_identifiers(item):
                continue
            if _contains_secret_material(
                item,
                trusted_exact_answers=trusted_exact_answers,
                exact_context=field_context,
                path=(*path, key_text),
            ):
                return True
        return False
    if isinstance(value, (list, tuple, set, frozenset)):
        return any(
            _contains_secret_material(
                item,
                trusted_exact_answers=trusted_exact_answers,
                exact_context=exact_context and isinstance(item, str),
                path=(*path, str(index)),
            )
            for index, item in enumerate(value)
        )
    return False


def _contains_only_markers(value: Any) -> bool:
    if value in (REDACTED, TRUNCATED, None):
        return True
    if isinstance(value, Mapping):
        return all(_contains_only_markers(item) for item in value.values())
    if isinstance(value, (list, tuple, set, frozenset)):
        return all(_contains_only_markers(item) for item in value)
    return False


def _contains_only_public_identifiers(value: Any) -> bool:
    if isinstance(value, str):
        return _is_public_identifier(value, allow_bare_digest=True) or value in {REDACTED, TRUNCATED}
    if isinstance(value, (list, tuple, set, frozenset)):
        return all(_contains_only_public_identifiers(item) for item in value)
    return False


__all__ = [
    "ArtifactLeakageError",
    "REDACTED",
    "TRUNCATED",
    "bytes_metadata",
    "is_sensitive_key",
    "redact",
    "sanitize_artifact",
    "scrub_artifact",
    "scrub_metadata",
    "scrub_text",
    "scrub_text_chunks",
    "scrub_value",
    "assert_no_secret_leak",
]
