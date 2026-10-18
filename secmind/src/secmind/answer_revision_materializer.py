"""Pure materialization of typed answer revisions."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from secmind.answer_revision_contracts import (
    ExactAnswerPatch,
    RevisionError,
    RevisionField,
    RevisionOperation,
)
from secmind.answer_revision_obligations import coerce_answer
from secmind.published_answer_models import PublishedAnswer, PublishedAnswerRevision


def apply_revision(base: PublishedAnswer, revision: PublishedAnswerRevision) -> PublishedAnswer:
    """Return a new answer after one digest-checked append-only revision."""

    if revision.answer_id != base.answer_id or revision.run_id != base.run_id:
        raise RevisionError("revision belongs to another answer/run")
    if revision.base_answer_digest != base.answer_digest:
        raise RevisionError("base_answer_digest does not match current answer")
    if revision.revision_number != base.revision_number + 1:
        raise RevisionError("revision number is not the next append-only revision")
    if revision.revision_id in base.revision_ids:
        raise RevisionError("revision id is already present in the append-only chain")
    answer_payload = base.answer.model_dump(mode="python")
    _apply_payload(answer_payload, revision)
    typed = coerce_answer(base.scoring_mode, answer_payload)
    revised = base.model_copy(
        deep=True,
        update={
            "answer": typed,
            "revision_ids": (*base.revision_ids, revision.revision_id),
            "revision_number": revision.revision_number,
            "published_at": base.published_at,
            "answer_digest": "",
        },
    )
    validated = PublishedAnswer.model_validate(revised.model_dump(mode="python"))
    if validated.receipt != base.receipt:
        raise RevisionError("revision attempted to mutate immutable receipt")
    return validated


def validate_revision(base: PublishedAnswer, revision: PublishedAnswerRevision) -> tuple[bool, str | None]:
    try:
        apply_revision(base, revision)
    except (RevisionError, ValueError) as exc:
        return False, str(exc)
    return True, None


def _apply_payload(answer: dict[str, Any], revision: PublishedAnswerRevision) -> None:
    if revision.field == RevisionField.FINDINGS:
        _apply_list_patch(answer, "findings", revision)
    elif revision.field == RevisionField.TIMELINE:
        _apply_list_patch(answer, "events", revision)
    elif revision.field == RevisionField.ACTOR:
        _apply_list_patch(answer, "actors", revision)
    elif revision.field == RevisionField.API_OPERATION:
        container, key = _extension_container(answer, ("operations", "api_operations"))
        _apply_list_patch(container, key, revision)
    elif revision.field == RevisionField.EXACT_ANSWER:
        _apply_exact_answer(answer, revision)
    else:  # pragma: no cover
        raise RevisionError(f"unsupported revision field: {revision.field}")
    if revision.operation == RevisionOperation.SUPPLEMENT:
        evidence_ids = set(revision.evidence_ids)
        if revision.payload is not None:
            evidence_ids.update(getattr(revision.payload, "evidence_ids", ()))
        if evidence_ids:
            _merge_evidence(answer, evidence_ids)


def _apply_list_patch(answer: dict[str, Any], key: str, revision: PublishedAnswerRevision) -> None:
    values = answer.get(key)
    if not isinstance(values, list):
        values = []
    target = revision.target_id
    if revision.operation == RevisionOperation.RETRACT:
        retracted = [item for item in values if not isinstance(item, Mapping) or _item_id(item) != target]
        if len(retracted) == len(values):
            raise RevisionError(f"cannot retract absent {key} target {target}")
        answer[key] = retracted
        return
    if revision.payload is None:
        raise RevisionError("list revision requires a typed payload")
    converted = revision.payload.model_dump(mode="python")
    found = False
    patched: list[Any] = []
    for item in values:
        if isinstance(item, Mapping) and target is not None and _item_id(item) == target:
            found = True
            patched.append(
                converted
                if revision.operation == RevisionOperation.REPLACE
                else _supplement_item(dict(item), converted)
            )
        else:
            patched.append(item)
    if revision.operation == RevisionOperation.REPLACE and not found:
        raise RevisionError(f"cannot replace absent {key} target {target}")
    if revision.operation == RevisionOperation.SUPPLEMENT and not found:
        patched.append(converted)
    answer[key] = patched


def _apply_exact_answer(answer: dict[str, Any], revision: PublishedAnswerRevision) -> None:
    if revision.operation == RevisionOperation.RETRACT:
        target = revision.target_id
        mapping = answer.get("mapping")
        if isinstance(mapping, dict) and target in mapping:
            mapping.pop(target, None)
            return
        if target == "values" and answer.get("values") is not None:
            answer["values"] = None
            return
        items = answer.get("items")
        if isinstance(items, list):
            result = [item for item in items if not (isinstance(item, Mapping) and _item_id(item) == target)]
            if len(result) != len(items):
                answer["items"] = result
                return
        container = answer.get("extensions")
        if isinstance(container, dict) and target in container:
            container.pop(target, None)
            return
        raise RevisionError(f"cannot retract absent exact-answer target {target}")
    if not isinstance(revision.payload, ExactAnswerPatch):
        raise RevisionError("exact answer revision requires ExactAnswerPatch")
    target = revision.target_id or revision.payload.answer_id
    mapping = answer.get("mapping")
    if not isinstance(mapping, dict):
        mapping = {}
        answer["mapping"] = mapping
    if revision.operation == RevisionOperation.REPLACE:
        if target not in mapping and not (target == "values" and answer.get("values") is not None):
            raise RevisionError(f"cannot replace absent exact-answer target {target}")
        if target == "values":
            answer["values"] = revision.payload.value
        else:
            mapping[target] = revision.payload.value
    else:
        if target == "values":
            answer["values"] = _supplement_value(answer.get("values"), revision.payload.value)
        elif target == "items":
            items = answer.get("items")
            if not isinstance(items, list):
                items = []
                answer["items"] = items
            if revision.payload.value not in items:
                items.append(revision.payload.value)
        elif target in mapping:
            mapping[target] = _supplement_value(mapping[target], revision.payload.value)
        else:
            mapping[target] = revision.payload.value


def _extension_container(answer: dict[str, Any], keys: tuple[str, ...]) -> tuple[dict[str, Any], str]:
    for key in keys:
        if key in answer:
            return answer, key
    extensions = answer.get("extensions")
    if not isinstance(extensions, dict):
        extensions = {}
        answer["extensions"] = extensions
    for key in keys:
        if key in extensions:
            return extensions, key
    return extensions, keys[0]


def _item_id(item: Mapping[str, Any]) -> str | None:
    for key in ("finding_id", "event_id", "actor_id", "operation_id", "answer_id", "id"):
        if item.get(key) is not None:
            return str(item[key])
    return None


def _supplement_item(original: dict[str, Any], supplement: dict[str, Any]) -> dict[str, Any]:
    merged = dict(original)
    for key, value in supplement.items():
        if key not in {"fields", "evidence_ids"} and value is not None:
            merged[key] = value
    fields = dict(original.get("fields") or {})
    fields.update(supplement.get("fields") or {})
    if fields:
        merged["fields"] = fields
    evidence = {*_string_values(original.get("evidence_ids")), *_string_values(supplement.get("evidence_ids"))}
    if evidence:
        merged["evidence_ids"] = sorted(evidence)
    return merged


def _merge_evidence(answer: dict[str, Any], evidence_ids: Iterable[str]) -> None:
    existing = set(_string_values(answer.get("evidence")))
    extensions = answer.get("extensions")
    if isinstance(extensions, dict):
        existing.update(_string_values(extensions.get("evidence")))
        existing.update(_string_values(extensions.get("evidence_ids")))
        extensions["evidence_ids"] = sorted(existing | {str(item) for item in evidence_ids if str(item).strip()})
    elif evidence_ids:
        answer["extensions"] = {
            "evidence_ids": sorted(existing | {str(item) for item in evidence_ids if str(item).strip()})
        }
    if "evidence" in answer:
        answer["evidence"] = sorted(existing | {str(item) for item in evidence_ids if str(item).strip()})


def _string_values(value: Any) -> set[str]:
    if not isinstance(value, (list, tuple, set)):
        return set()
    return {str(item) for item in value if str(item).strip()}


def _supplement_value(old: Any, addition: Any) -> Any:
    if old is None:
        return addition
    if isinstance(old, list) and isinstance(addition, list):
        return [*old, *[item for item in addition if item not in old]]
    if isinstance(old, dict) and isinstance(addition, dict):
        merged = dict(old)
        for key, value in addition.items():
            if key in merged and merged[key] != value:
                raise RevisionError("SUPPLEMENT cannot replace an existing exact-answer field")
            merged.setdefault(key, value)
        return merged
    if old == addition:
        return old
    raise RevisionError("SUPPLEMENT requires compatible exact-answer values")


__all__ = ["apply_revision", "validate_revision"]
