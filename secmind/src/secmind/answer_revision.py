"""Append-only answer revision materialization for v0.8.4."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from copy import deepcopy
from typing import Any

from secmind.task_contract import (
    AnswerRevisionAction,
    PublishedAnswerRevision,
    canonical_digest,
)


class AnswerRevisionError(ValueError):
    pass


def make_revision(
    *,
    revision_id: str,
    base_answer: Mapping[str, Any],
    action: AnswerRevisionAction,
    target_path: str,
    value: Any,
    evidence_ids: Iterable[str],
    observation_ids: Iterable[str] = (),
    supersedes_revision_ids: Iterable[str] = (),
    reason_code: str,
    expected_old_value: Any = None,
) -> PublishedAnswerRevision:
    values: dict[str, Any] = {
        "revision_id": revision_id,
        "base_answer_digest": canonical_digest(base_answer),
        "action": action,
        "target_path": target_path,
        "expected_old_digest": (None if expected_old_value is None else canonical_digest(expected_old_value)),
        "value": value,
        "evidence_ids": sorted(set(evidence_ids)),
        "observation_ids": sorted(set(observation_ids)),
        "supersedes_revision_ids": sorted(set(supersedes_revision_ids)),
        "verifier_status": "accepted",
        "reason_code": reason_code,
    }
    provisional = PublishedAnswerRevision.model_validate({**values, "revision_digest": "0" * 64})
    normalized = provisional.model_dump(mode="json", exclude={"revision_digest"})
    return provisional.model_copy(update={"revision_digest": canonical_digest(normalized)})


def materialize_answer(
    anchor_answer: Mapping[str, Any],
    revisions: Iterable[PublishedAnswerRevision],
) -> dict[str, Any]:
    """Apply accepted revisions deterministically without mutating the Anchor."""

    answer = deepcopy(dict(anchor_answer))
    ordered = _causal_order(revisions)
    for revision in ordered:
        if revision.verifier_status != "accepted":
            continue
        if canonical_digest(revision.model_dump(mode="json", exclude={"revision_digest"})) != revision.revision_digest:
            raise AnswerRevisionError("answer revision digest mismatch")
        _apply(answer, revision)
    return answer


def _causal_order(
    revisions: Iterable[PublishedAnswerRevision],
) -> list[PublishedAnswerRevision]:
    """Return a deterministic topological order for the revision chain.

    Revision IDs are stable identities, not sequence numbers.  Sorting only by
    ID can apply a child before the revision it supersedes and makes replay
    depend on naming conventions.  Missing parents and cycles are corruption,
    so fail closed before touching the active answer.
    """

    by_id: dict[str, PublishedAnswerRevision] = {}
    for revision in revisions:
        if revision.revision_id in by_id:
            raise AnswerRevisionError("duplicate answer revision id")
        by_id[revision.revision_id] = revision
    children: dict[str, set[str]] = {revision_id: set() for revision_id in by_id}
    indegree: dict[str, int] = {revision_id: 0 for revision_id in by_id}
    for revision in by_id.values():
        for parent_id in set(revision.supersedes_revision_ids):
            if parent_id not in by_id:
                raise AnswerRevisionError("answer revision supersedes an unknown revision")
            children[parent_id].add(revision.revision_id)
            indegree[revision.revision_id] += 1
    ready = sorted(revision_id for revision_id, degree in indegree.items() if degree == 0)
    ordered: list[PublishedAnswerRevision] = []
    while ready:
        revision_id = ready.pop(0)
        ordered.append(by_id[revision_id])
        for child_id in sorted(children[revision_id]):
            indegree[child_id] -= 1
            if indegree[child_id] == 0:
                ready.append(child_id)
                ready.sort()
    if len(ordered) != len(by_id):
        raise AnswerRevisionError("answer revision chain contains a cycle")
    return ordered


def _apply(answer: dict[str, Any], revision: PublishedAnswerRevision) -> None:
    parts = [_unescape(item) for item in revision.target_path.split("/")[1:] if item]
    if not revision.target_path.startswith("/") or not parts:
        raise AnswerRevisionError("revision target must be a non-root JSON pointer")
    parent: Any = answer
    for part in parts[:-1]:
        if isinstance(parent, dict):
            parent = parent.setdefault(part, {})
        elif isinstance(parent, list):
            match = next(
                (
                    item
                    for item in parent
                    if isinstance(item, dict) and str(item.get("finding_id") or item.get("id")) == part
                ),
                None,
            )
            if match is None:
                raise AnswerRevisionError("revision targets an unknown stable list item")
            parent = match
        else:
            raise AnswerRevisionError("revision path crosses a non-object value")
    key = parts[-1]
    list_index = None
    if isinstance(parent, list):
        list_index = next(
            (
                index
                for index, item in enumerate(parent)
                if isinstance(item, dict) and str(item.get("finding_id") or item.get("id")) == key
            ),
            None,
        )
        old = None if list_index is None else parent[list_index]
    else:
        old = parent.get(key) if isinstance(parent, dict) else None
    if revision.expected_old_digest is not None and canonical_digest(old) != revision.expected_old_digest:
        raise AnswerRevisionError("revision expected-old digest is stale")
    if isinstance(parent, list):
        if revision.action == AnswerRevisionAction.RETRACT:
            if list_index is not None:
                parent.pop(list_index)
        elif revision.action == AnswerRevisionAction.ADD:
            if list_index is not None:
                raise AnswerRevisionError("ADD cannot overwrite an active list item")
            parent.append(deepcopy(revision.value))
        elif revision.action == AnswerRevisionAction.REPLACE_FIELD:
            if list_index is None:
                raise AnswerRevisionError("replacement targets an unknown list item")
            parent[list_index] = deepcopy(revision.value)
        elif revision.action == AnswerRevisionAction.SUPPLEMENT:
            if list_index is None:
                raise AnswerRevisionError("supplement targets an unknown list item")
            parent[list_index] = _supplement_value(parent[list_index], revision.value)
        return
    if not isinstance(parent, dict):
        raise AnswerRevisionError("revision target parent is not an object")
    if revision.action == AnswerRevisionAction.RETRACT:
        parent.pop(key, None)
    elif revision.action == AnswerRevisionAction.ADD:
        if key in parent:
            raise AnswerRevisionError("ADD cannot overwrite an active field")
        parent[key] = deepcopy(revision.value)
    elif revision.action == AnswerRevisionAction.REPLACE_FIELD:
        parent[key] = deepcopy(revision.value)
    elif revision.action == AnswerRevisionAction.SUPPLEMENT:
        parent[key] = _supplement_value(old, revision.value)
    else:  # pragma: no cover - exhaustive enum guard
        raise AnswerRevisionError("unsupported answer revision action")


def _unescape(value: str) -> str:
    return value.replace("~1", "/").replace("~0", "~")


def _supplement_value(old: Any, addition: Any) -> Any:
    """Add non-conflicting detail without disguising a replacement."""

    if old is None:
        return deepcopy(addition)
    if isinstance(old, list) and isinstance(addition, list):
        merged_list = deepcopy(old)
        known = {canonical_digest(item) for item in old}
        for item in addition:
            digest = canonical_digest(item)
            if digest not in known:
                merged_list.append(deepcopy(item))
                known.add(digest)
        return merged_list
    if isinstance(old, dict) and isinstance(addition, dict):
        merged_mapping = deepcopy(old)
        for key, value in addition.items():
            if key in merged_mapping and canonical_digest(merged_mapping[key]) != canonical_digest(value):
                raise AnswerRevisionError("SUPPLEMENT cannot replace an existing field")
            merged_mapping.setdefault(key, deepcopy(value))
        return merged_mapping
    if canonical_digest(old) == canonical_digest(addition):
        return deepcopy(old)
    raise AnswerRevisionError("SUPPLEMENT requires compatible list or object values")


__all__ = ["AnswerRevisionError", "make_revision", "materialize_answer"]
