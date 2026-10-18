from __future__ import annotations

import json
import re
from typing import Any


FENCED_BLOCK_RE = re.compile(r"```(?:json)?\s*\n?(.*?)```", re.IGNORECASE | re.DOTALL)

# Keys that identify the JSON bundle a task phase actually asks for.  Prose in
# the same message often quotes an unrelated object (for example a decoded
# cookie payload), and taking the first decodable object then made the contract
# parser reject an otherwise valid answer as "accepted must be true or false".
PROTOCOL_KEYS = frozenset({
    "accepted", "data", "description", "fact", "complete", "intents", "intent",
})


def extract_json_object(text: str) -> dict[str, Any]:
    """Return the protocol object from a Worker message.

    Explicit fenced JSON blocks win over inline objects, and among inline
    objects the one carrying protocol keys wins over a quoted data literal.
    """
    seen: set[str] = set()

    for candidate in _candidate_segments(text):
        segment = candidate.strip()
        if not segment or segment in seen:
            continue
        seen.add(segment)

        parsed = _decode_objects(segment)
        if parsed:
            return parsed

    raise ValueError("no JSON object found in output")


def _candidate_segments(text: str) -> list[str]:
    """Fenced blocks first, then the whole message."""
    segments = [match.group(1).strip() for match in FENCED_BLOCK_RE.finditer(text)]
    segments.append(text.strip())
    return segments


def _decode_objects(segment: str) -> dict[str, Any] | None:
    decoder = json.JSONDecoder()
    decoded: list[dict[str, Any]] = []
    try:
        whole = json.loads(segment)
    except json.JSONDecodeError:
        pass
    else:
        if isinstance(whole, dict):
            decoded.append(whole)
    for start in _object_start_positions(segment):
        try:
            parsed, _end = decoder.raw_decode(segment[start:])
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            decoded.append(parsed)
    if not decoded:
        return None
    return next((item for item in decoded if PROTOCOL_KEYS & set(item)), decoded[0])


def _object_start_positions(text: str) -> list[int]:
    return [index for index, char in enumerate(text) if char == "{"]
