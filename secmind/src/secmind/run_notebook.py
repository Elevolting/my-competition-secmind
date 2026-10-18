from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from secmind.schemas import RunNotebook


class RunNotebookError(ValueError):
    """Notebook state is invalid, stale, or has been modified out of band."""


class NotebookFailure(BaseModel):
    model_config = ConfigDict(extra="forbid")

    step_id: str = Field(min_length=1, max_length=200)
    attempt: int = Field(ge=1, le=100)
    error_code: str = Field(min_length=1, max_length=100)
    summary: str = Field(min_length=1, max_length=2_000)

    @field_validator("step_id", "error_code", "summary")
    @classmethod
    def reject_controls(cls, value: str) -> str:
        return _safe_text(value)


class NotebookPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    verified_facts: list[str] = Field(default_factory=list)
    open_hypotheses: list[str] = Field(default_factory=list)
    rejected_hypotheses: list[str] = Field(default_factory=list)
    completed_steps: list[str] = Field(default_factory=list)
    failed_attempts: list[NotebookFailure] = Field(default_factory=list)
    active_evidence_handles: list[str] = Field(default_factory=list)
    resolved_evidence_handles: list[str] = Field(default_factory=list)
    unresolved_claims: list[str] = Field(default_factory=list)
    resolved_claims: list[str] = Field(default_factory=list)
    next_recommended_actions: list[str] | None = None
    budget_snapshot: dict[str, Any] | None = None

    @field_validator(
        "verified_facts",
        "open_hypotheses",
        "rejected_hypotheses",
        "completed_steps",
        "active_evidence_handles",
        "resolved_evidence_handles",
        "unresolved_claims",
        "resolved_claims",
        "next_recommended_actions",
    )
    @classmethod
    def sanitize_text_lists(cls, value: list[str] | None) -> list[str] | None:
        return None if value is None else [_safe_text(item) for item in value]


class RunNotebookManager:
    """Pure digest-checked notebook updates; the notebook is navigation, not evidence."""

    def create(
        self,
        *,
        objective: str,
        immutable_constraints: list[str] | None = None,
        budget_snapshot: dict[str, Any] | None = None,
    ) -> RunNotebook:
        notebook = RunNotebook(
            objective=_safe_text(objective),
            immutable_constraints=_sorted_unique(immutable_constraints or []),
            budget_snapshot=_canonical_mapping(budget_snapshot or {}),
            notebook_digest="0" * 64,
        )
        return notebook.model_copy(update={"notebook_digest": self.digest(notebook)})

    def apply(
        self,
        notebook: RunNotebook,
        patch: NotebookPatch,
        *,
        expected_digest: str | None = None,
    ) -> RunNotebook:
        if not self.verify(notebook):
            raise RunNotebookError("run notebook digest verification failed")
        if expected_digest is not None and not hmac.compare_digest(
            notebook.notebook_digest,
            expected_digest.lower(),
        ):
            raise RunNotebookError("run notebook compare-and-swap digest is stale")

        rejected = _sorted_unique([*notebook.rejected_hypotheses, *patch.rejected_hypotheses])
        open_hypotheses = _sorted_unique([*notebook.open_hypotheses, *patch.open_hypotheses])
        open_hypotheses = [item for item in open_hypotheses if item not in set(rejected)]
        active_evidence = _sorted_unique([*notebook.active_evidence_handles, *patch.active_evidence_handles])
        resolved_evidence = set(patch.resolved_evidence_handles)
        active_evidence = [item for item in active_evidence if item not in resolved_evidence]
        unresolved_claims = _sorted_unique([*notebook.unresolved_claims, *patch.unresolved_claims])
        resolved_claims = set(patch.resolved_claims)
        unresolved_claims = [item for item in unresolved_claims if item not in resolved_claims]
        failures = [
            *notebook.failed_attempts,
            *(item.model_dump(mode="json") for item in patch.failed_attempts),
        ]
        failures = sorted(
            {_canonical_json(item): _canonical_mapping(item) for item in failures}.values(),
            key=_canonical_json,
        )
        next_actions = (
            notebook.next_recommended_actions
            if patch.next_recommended_actions is None
            else patch.next_recommended_actions
        )
        budget = notebook.budget_snapshot if patch.budget_snapshot is None else patch.budget_snapshot
        updated = notebook.model_copy(
            update={
                "verified_facts": _sorted_unique([*notebook.verified_facts, *patch.verified_facts]),
                "open_hypotheses": open_hypotheses,
                "rejected_hypotheses": rejected,
                "completed_steps": _sorted_unique([*notebook.completed_steps, *patch.completed_steps]),
                "failed_attempts": failures,
                "active_evidence_handles": active_evidence,
                "unresolved_claims": unresolved_claims,
                "next_recommended_actions": _sorted_unique(next_actions),
                "budget_snapshot": _canonical_mapping(budget),
                "notebook_digest": "0" * 64,
            }
        )
        return updated.model_copy(update={"notebook_digest": self.digest(updated)})

    def verify(self, notebook: RunNotebook) -> bool:
        try:
            expected = self.digest(notebook)
        except (TypeError, ValueError):
            return False
        return hmac.compare_digest(expected, notebook.notebook_digest.lower())

    @staticmethod
    def digest(notebook: RunNotebook) -> str:
        payload = notebook.model_dump(mode="json", exclude={"notebook_digest"})
        return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def _safe_text(value: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise ValueError("notebook text must not be empty")
    if len(normalized) > 2_000:
        raise ValueError("notebook text exceeds the safe summary limit")
    if any((ord(char) < 32 and char not in {"\n", "\t"}) or ord(char) == 127 for char in normalized):
        raise ValueError("notebook text contains control characters")
    return normalized


def _sorted_unique(values: list[str]) -> list[str]:
    return sorted({_safe_text(value) for value in values})


def _canonical_mapping(value: dict[str, Any]) -> dict[str, Any]:
    try:
        encoded = _canonical_json(value)
        decoded = json.loads(encoded)
    except (TypeError, ValueError) as exc:
        raise RunNotebookError("notebook mapping must be canonical JSON") from exc
    if not isinstance(decoded, dict):  # pragma: no cover - signature already narrows this
        raise RunNotebookError("notebook mapping must be an object")
    return decoded


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
