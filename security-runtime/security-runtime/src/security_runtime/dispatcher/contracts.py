from __future__ import annotations

from typing import Any

from security_runtime.dispatcher.output_parser import extract_json_object
from security_runtime.server.models import ResultItem


# Fields a Worker may report on a result bundle.  ``output_key`` and ``outcome``
# belong here: the explore prompt requires a named output, and Workers commonly
# report it on the enclosing fact instead of on each item, so treating them as
# unknown fields rejected every otherwise-valid bundle.
FACT_KEYS = frozenset({"description", "title", "items", "output_key", "outcome"})
ITEM_KEYS = frozenset({
    "id", "type", "title", "summary", "evidence_ids", "finding_id",
    "verification_status", "output_key", "outcome",
})
OUTCOMES = ("observed", "negative", "unverified")


def parse_json_output(stdout: str) -> dict[str, Any]:
    return extract_json_object(stdout)


def _unwrap_wrapped_payload(payload: dict[str, Any]) -> tuple[bool | None, dict[str, Any] | None]:
    accepted = payload.get("accepted")
    if accepted is False:
        return False, None
    if accepted is True:
        data = payload.get("data")
        if not isinstance(data, dict):
            raise ValueError("data must be an object")
        return True, data
    return None, None


def _is_dict(value: Any) -> bool:
    return isinstance(value, dict)


def _looks_like_reason_data(payload: dict[str, Any]) -> bool:
    if not isinstance(payload, dict):
        return False
    keys = set(payload)
    if keys == {"complete"}:
        complete = payload["complete"]
        return isinstance(complete, dict) and "from" in complete and "description" in complete
    if keys == {"intents"}:
        return isinstance(payload["intents"], list)
    if keys == {"intent"}:
        intent = payload["intent"]
        return isinstance(intent, dict) and "from" in intent and "description" in intent
    return False


def _looks_like_bootstrap_execute_data(payload: dict[str, Any]) -> bool:
    if not isinstance(payload, dict) or set(payload) != {"fact", "complete"}:
        return False
    return _is_dict(payload.get("fact")) and _is_dict(payload.get("complete"))


def _looks_like_bootstrap_conclude_data(payload: dict[str, Any]) -> bool:
    if not isinstance(payload, dict):
        return False
    keys = set(payload)
    if keys not in ({"fact"}, {"fact", "complete"}):
        return False
    return _is_dict(payload.get("fact"))


def _looks_like_explore_data(payload: dict[str, Any]) -> bool:
    """Accept a bare fact bundle that skipped the accepted/data envelope.

    Workers frequently return the fact object itself.  The keys recognized here
    are exactly the ones ``_structured_fact`` accepts, so an unknown field still
    has to arrive inside an explicit envelope.
    """
    return isinstance(payload, dict) and "description" in payload and set(payload) <= FACT_KEYS


def _named_output_key(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > 120:
        raise ValueError("output_key must be short nonempty text")
    return value.strip()


def _attach_output_key(items: list[dict[str, Any]], output_key: str) -> None:
    """Carry a fact-level ``output_key`` onto the item that demonstrated it.

    The protocol asks for the key on an item, but Workers routinely report it on
    the enclosing fact.  Dropping it left every step without a validated output,
    so each dependent step stayed blocked and the chain stalled.
    """
    if any(item.get("output_key") == output_key for item in items):
        return
    target = next((item for item in items if item.get("evidence_ids")), None)
    if target is None and items:
        target = items[0]
    if target is not None:
        target["output_key"] = output_key


def _structured_fact(fact: dict[str, Any]) -> str | dict[str, Any]:
    description = fact.get("description")
    if not isinstance(description, str) or not description.strip():
        raise ValueError("description is required")
    if not (set(fact) & {"title", "items", "output_key"}):
        return description.strip()
    unexpected = set(fact) - FACT_KEYS
    if unexpected:
        raise ValueError(f"unexpected fact fields: {', '.join(sorted(unexpected))}")
    title = fact.get("title")
    if title is not None and (not isinstance(title, str) or not title.strip()):
        raise ValueError("title must be nonempty text")
    items = fact.get("items", [])
    if not isinstance(items, list):
        raise ValueError("items must be an array")
    output_key = _named_output_key(fact.get("output_key"))
    outcome = fact.get("outcome")
    if outcome is not None and outcome not in OUTCOMES:
        raise ValueError(f"outcome must be one of {', '.join(OUTCOMES)}")
    validated = [ResultItem.model_validate(item).model_dump(exclude_none=True, exclude_defaults=True)
                 | {key: value for key, value in item.items() if key in ITEM_KEYS}
                 for item in items]
    if output_key is not None:
        _attach_output_key(validated, output_key)
    for item in validated:
        item.setdefault("type", "fact")
        # ``exclude_defaults`` drops the implicit ``observed`` outcome, but both
        # the runtime confirmation check and the workbench require the outcome
        # to be explicit before a named output can unlock a dependent step.
        if item.get("output_key"):
            item.setdefault("outcome", outcome or "observed")
    return {"description": description.strip(), **({"title": title.strip()} if title is not None else {}), "items": validated}


def validate_reason_payload(
    payload: dict[str, Any], open_intents_empty: bool, max_intents: int,
) -> tuple[str, dict[str, Any] | list[dict[str, Any]] | None]:
    accepted, data = _unwrap_wrapped_payload(payload)
    if accepted is False:
        return "rejected", None
    if accepted is None:
        if not _looks_like_reason_data(payload):
            raise ValueError("accepted must be true or false")
        data = payload
    if not isinstance(data, dict):
        raise ValueError("accepted must be true or false")
    complete = data.get("complete")
    intents = data.get("intents")
    # backward compat: accept singular "intent" key from LLMs
    if intents is None:
        singular = data.get("intent")
        if isinstance(singular, dict):
            intents = [singular]
    if complete is not None:
        if intents is not None:
            raise ValueError("complete and intents cannot coexist")
        if not isinstance(complete, dict) or "from" not in complete or "description" not in complete:
            raise ValueError("invalid complete payload")
        return "complete", complete
    if intents is not None:
        if not isinstance(intents, list):
            raise ValueError("intents must be an array")
        for i, intent in enumerate(intents):
            if not isinstance(intent, dict) or "from" not in intent or "description" not in intent:
                raise ValueError(f"invalid intent at index {i}")
        if not intents and open_intents_empty:
            raise ValueError("intents must not be empty when open_intents is empty")
        intents = intents[:max_intents]
        if not intents:
            return "noop", None
        return "intents", intents
    if open_intents_empty:
        raise ValueError("intents is required when open_intents is empty")
    return "noop", None


def validate_bootstrap_execute_payload(payload: dict[str, Any]) -> tuple[str, dict[str, Any] | None]:
    accepted, data = _unwrap_wrapped_payload(payload)
    if accepted is False:
        return "rejected", None
    if accepted is None:
        if not _looks_like_bootstrap_execute_data(payload):
            raise ValueError("accepted must be true or false")
        data = payload
    if not isinstance(data, dict):
        raise ValueError("accepted must be true or false")

    fact = data.get("fact")
    if not isinstance(fact, dict):
        raise ValueError("fact is required")
    fact_description = fact.get("description")
    if not isinstance(fact_description, str) or not fact_description.strip():
        raise ValueError("fact.description is required")

    result = {"fact_description": _structured_fact(fact)}
    complete = data.get("complete")
    if complete is None:
        raise ValueError("complete is required")
    if not isinstance(complete, dict):
        raise ValueError("complete must be an object")
    complete_description = complete.get("description")
    if not isinstance(complete_description, str) or not complete_description.strip():
        raise ValueError("complete.description is required")
    result["complete_description"] = complete_description.strip()
    return "complete", result


def validate_bootstrap_conclude_payload(payload: dict[str, Any]) -> tuple[str, str | dict[str, Any] | None]:
    accepted, data = _unwrap_wrapped_payload(payload)
    if accepted is False:
        return "rejected", None
    if accepted is None:
        if not _looks_like_bootstrap_conclude_data(payload):
            raise ValueError("accepted must be true or false")
        data = payload
    if not isinstance(data, dict):
        raise ValueError("accepted must be true or false")
    extra_keys = set(data) - {"fact", "complete"}
    if extra_keys:
        raise ValueError("unexpected keys in conclude payload")
    fact = data.get("fact")
    if not isinstance(fact, dict):
        raise ValueError("fact is required")
    fact_description = fact.get("description")
    if not isinstance(fact_description, str) or not fact_description.strip():
        raise ValueError("fact.description is required")
    return "fact", _structured_fact(fact)


def validate_explore_payload(payload: dict[str, Any]) -> tuple[str, str | dict[str, Any] | None]:
    accepted, data = _unwrap_wrapped_payload(payload)
    if accepted is False:
        return "rejected", None
    if accepted is None:
        if not _looks_like_explore_data(payload):
            raise ValueError("accepted must be true or false")
        data = payload
    if not isinstance(data, dict):
        raise ValueError("accepted must be true or false")
    description = data.get("description")
    if not isinstance(description, str) or not description.strip():
        raise ValueError("description is required")
    return "fact", _structured_fact(data)
