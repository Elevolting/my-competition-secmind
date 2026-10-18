"""Bounded JSON recovery and schema identity helpers."""

from __future__ import annotations

import hashlib
import json
from typing import Any, TypeVar

from pydantic import BaseModel, ValidationError

T = TypeVar("T", bound=BaseModel)


def response_schema_sha256(schema: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(schema, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def extract_first_json_value(text: str, *, max_chars: int, max_depth: int) -> str | None:
    """Return at most the first balanced JSON object/array within hard limits."""

    if max_chars < 1 or max_depth < 1 or len(text) > max_chars:
        return None
    starts = [index for index in (text.find("{"), text.find("[")) if index >= 0]
    if not starts:
        return None
    start = min(starts)
    stack: list[str] = []
    in_string = False
    escaped = False
    for index in range(start, len(text)):
        char = text[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
            continue
        if char in "{[":
            stack.append("}" if char == "{" else "]")
            if len(stack) > max_depth:
                return None
            continue
        if char in "}]":
            if not stack or stack[-1] != char:
                return None
            stack.pop()
            if not stack:
                return text[start : index + 1]
    return None


def repair_truncated_json_once(text: str, *, max_chars: int, max_depth: int) -> str | None:
    """Close only a single truncated JSON object/array under hard bounds.

    This is deliberately a syntax completion, not a semantic repair: it may
    close one unterminated string and the already-open containers, but never
    invents a key, value, comma, or replacement type. The result must still
    pass the caller's exact Pydantic schema.
    """

    if max_chars < 1 or max_depth < 1 or len(text) > max_chars:
        return None
    starts = [index for index in (text.find("{"), text.find("[")) if index >= 0]
    if not starts:
        return None
    start = min(starts)
    candidate = text[start:].strip()
    stack: list[str] = []
    in_string = False
    escaped = False
    for char in candidate:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
            continue
        if char in "{[":
            stack.append("}" if char == "{" else "]")
            if len(stack) > max_depth:
                return None
            continue
        if char in "}]":
            if not stack or stack[-1] != char:
                return None
            stack.pop()
            if not stack:
                # A balanced first value is handled by
                # ``extract_first_json_value``. Appending to it would conceal
                # trailing or multiple-value errors.
                return None
    if not stack or escaped:
        return None
    suffix = ('"' if in_string else "") + "".join(reversed(stack))
    if len(candidate) + len(suffix) > max_chars:
        return None
    return candidate + suffix


def parse_model(
    raw: str,
    output_model: type[T],
    *,
    max_chars: int,
    max_depth: int,
) -> T:
    """Validate a provider string, allowing one bounded balanced-value recovery."""

    text = raw.strip()
    if len(text) > max_chars:
        raise json.JSONDecodeError("structured model response exceeds the recovery character limit", text, 0)
    try:
        return output_model.model_validate_json(text)
    except (ValidationError, json.JSONDecodeError) as exact_error:
        candidate = extract_first_json_value(text, max_chars=max_chars, max_depth=max_depth)
        if candidate is not None and candidate != text:
            # Do not scan for a second candidate when this one is invalid.
            return output_model.model_validate_json(candidate)
        repaired = repair_truncated_json_once(text, max_chars=max_chars, max_depth=max_depth)
        if repaired is None:
            raise exact_error
        # Syntax recovery never weakens semantic validation: incorrect field
        # names, missing required fields and wrong types still fail here.
        return output_model.model_validate_json(repaired)


__all__ = [
    "extract_first_json_value",
    "parse_model",
    "repair_truncated_json_once",
    "response_schema_sha256",
]
