"""Safe, observable influence of governed Knowledge and signed Skills.

Only already-approved tool candidates may be reordered. Advisory knowledge can
improve ranking, but it can never add a capability, modify scope, or change
policy text. Signed Skill material is represented by package/content digests in
the WorkItem; the actual instructions remain in the bounded context pack.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from secmind.schemas import ContextItemRef, PlanStep, ToolManifest

_SECRET_PATTERNS = (
    re.compile(r"(?i)(api[_-]?key|token|secret|password)\s*[:=]\s*[^\s,;]+"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+"),
)


def redact_advisory_text(value: str, *, max_chars: int = 8_000) -> str:
    """Bound and redact advisory content before it influences tool ranking."""

    result = value[:max_chars]
    for pattern in _SECRET_PATTERNS:
        result = pattern.sub("[REDACTED_ADVISORY_VALUE]", result)
    return result


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class ContextInfluence:
    knowledge_refs: tuple[str, ...]
    signed_skill_refs: tuple[str, ...]
    knowledge_digests: tuple[str, ...]
    skill_digests: tuple[str, ...]
    tool_selection_digest: str
    reason_codes: tuple[str, ...]

    @property
    def context_digest(self) -> str:
        return _digest(
            {
                "knowledge_refs": self.knowledge_refs,
                "signed_skill_refs": self.signed_skill_refs,
                "knowledge_digests": self.knowledge_digests,
                "skill_digests": self.skill_digests,
                "tool_selection_digest": self.tool_selection_digest,
                "reason_codes": self.reason_codes,
            }
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "knowledge_refs": list(self.knowledge_refs),
            "signed_skill_refs": list(self.signed_skill_refs),
            "knowledge_digests": list(self.knowledge_digests),
            "skill_digests": list(self.skill_digests),
            "tool_selection_digest": self.tool_selection_digest,
            "reason_codes": list(self.reason_codes),
            "context_digest": self.context_digest,
        }


@dataclass(frozen=True, slots=True)
class ContextAwarePlan:
    steps: tuple[PlanStep, ...]
    influence: ContextInfluence


def build_context_influence(
    *,
    context_items: Sequence[ContextItemRef],
    steps: Sequence[PlanStep],
    manifests: Mapping[str, ToolManifest],
) -> ContextAwarePlan:
    """Rank only existing candidates using bounded, digest-bound context."""

    knowledge = [
        item for item in context_items if item.kind == "knowledge" and item.taint.value in {"advisory", "trusted"}
    ]
    skills = [
        item
        for item in context_items
        if item.kind == "audit_skill" and item.taint.value == "trusted" and item.metadata.get("package_digest")
    ]
    knowledge_refs = tuple(sorted({item.source for item in knowledge}))
    signed_skill_refs = tuple(
        sorted(
            {
                f"{item.metadata.get('skill_id', item.source)}@{item.metadata.get('version', 'unknown')}"
                for item in skills
            }
        )
    )
    knowledge_digests = tuple(sorted({item.content_hash.lower() for item in knowledge}))
    skill_digests = tuple(sorted(str(item.metadata["package_digest"]).lower() for item in skills))

    advisory_text = " ".join(redact_advisory_text(str(item.metadata.get("selection_hint", ""))) for item in knowledge)
    advisory_text += " " + " ".join(redact_advisory_text(item.source) for item in knowledge)
    advisory_tokens = {token.casefold() for token in re.findall(r"[a-z][a-z0-9_.-]{2,}", advisory_text)}
    rewritten: list[PlanStep] = []
    selection_rows: list[dict[str, Any]] = []
    for step in steps:
        candidates = list(dict.fromkeys(step.tool_candidates))
        ranked: list[tuple[tuple[int, int, str], str]] = []
        for index, tool_name in enumerate(candidates):
            manifest = manifests.get(tool_name)
            if manifest is None:
                ranked.append(((0, -index, tool_name), tool_name))
                continue
            searchable = {tool_name.casefold()}
            searchable.update(item.casefold() for item in manifest.capability_tags)
            searchable.update(re.findall(r"[a-z][a-z0-9_.-]{2,}", manifest.description.casefold()))
            searchable.update(item.casefold() for item in manifest.evidence_types)
            overlap = len(advisory_tokens.intersection(searchable))
            skill_match = sum(
                int(capability in manifest.capability_tags)
                for item in skills
                for capability in item.metadata.get("capability_tags", [])
            )
            ranked.append(((skill_match + overlap, -index, tool_name), tool_name))
        ranked.sort(key=lambda item: item[0], reverse=True)
        ordered = [item[1] for item in ranked]
        selection_rows.append(
            {
                "step_id": step.step_id,
                "before": candidates,
                "after": ordered,
                "knowledge_refs": list(knowledge_refs),
                "signed_skill_refs": list(signed_skill_refs),
            }
        )
        rewritten.append(
            step.model_copy(
                update={
                    "tool_candidates": ordered,
                    "context_requirements": {
                        **step.context_requirements,
                        "context_influence": True,
                    },
                }
            )
        )
    influence = ContextInfluence(
        knowledge_refs=knowledge_refs,
        signed_skill_refs=signed_skill_refs,
        knowledge_digests=knowledge_digests,
        skill_digests=skill_digests,
        tool_selection_digest=_digest(selection_rows),
        reason_codes=(
            "signed_skill_ranked_existing_tools" if skills else "no_signed_skill_ranking",
            "advisory_knowledge_ranked_existing_tools" if knowledge else "no_advisory_knowledge",
            "policy_and_scope_unchanged",
        ),
    )
    return ContextAwarePlan(steps=tuple(rewritten), influence=influence)


def work_item_context_fields(
    *,
    context_pack: Any | None,
    context_influence_digest: str | None = None,
) -> dict[str, Any]:
    """Return non-authoritative, digest-bound WorkItem context metadata."""

    if context_pack is None:
        return {
            "knowledge_refs": [],
            "signed_skill_refs": [],
            "context_pack_digest": None,
            "context_influence_digest": context_influence_digest,
        }
    return {
        "knowledge_refs": list(getattr(context_pack, "knowledge_refs", [])),
        "signed_skill_refs": list(getattr(context_pack, "selected_skill_refs", [])),
        "context_pack_digest": getattr(context_pack, "pack_digest", None),
        "context_influence_digest": context_influence_digest,
    }


__all__ = [
    "ContextAwarePlan",
    "ContextInfluence",
    "build_context_influence",
    "redact_advisory_text",
    "work_item_context_fields",
]
