from __future__ import annotations

import pytest
from pydantic import ValidationError

from secmind.run_notebook import (
    NotebookFailure,
    NotebookPatch,
    RunNotebookError,
    RunNotebookManager,
)


def test_run_notebook_updates_are_deterministic_digest_checked_and_navigational() -> None:
    manager = RunNotebookManager()
    notebook = manager.create(
        objective="Audit the supplied repository",
        immutable_constraints=["offline only", "offline only", "target scope: src"],
        budget_snapshot={"steps_remaining": 10},
    )
    patch = NotebookPatch(
        verified_facts=["Bandit completed with evidence ev-1", "Bandit completed with evidence ev-1"],
        open_hypotheses=["SQL injection may be reachable"],
        rejected_hypotheses=["Hard-coded secret is live"],
        completed_steps=["bandit", "inventory"],
        failed_attempts=[
            NotebookFailure(step_id="semgrep", attempt=1, error_code="TIMEOUT", summary="Timed out safely")
        ],
        active_evidence_handles=["ev-1", "ev-2"],
        unresolved_claims=["claim-1"],
        next_recommended_actions=["Run targeted Semgrep rules"],
        budget_snapshot={"steps_remaining": 8},
    )
    updated = manager.apply(notebook, patch, expected_digest=notebook.notebook_digest)
    repeated = manager.apply(notebook, patch, expected_digest=notebook.notebook_digest)

    assert manager.verify(updated)
    assert updated == repeated
    assert updated.objective == notebook.objective
    assert updated.immutable_constraints == ["offline only", "target scope: src"]
    assert updated.verified_facts == ["Bandit completed with evidence ev-1"]
    assert updated.completed_steps == ["bandit", "inventory"]
    assert updated.failed_attempts == [
        {"step_id": "semgrep", "attempt": 1, "error_code": "TIMEOUT", "summary": "Timed out safely"}
    ]


def test_run_notebook_resolves_navigation_handles_without_becoming_evidence() -> None:
    manager = RunNotebookManager()
    notebook = manager.create(objective="audit")
    first = manager.apply(
        notebook,
        NotebookPatch(
            open_hypotheses=["candidate issue"],
            active_evidence_handles=["ev-1"],
            unresolved_claims=["claim-1"],
        ),
    )
    resolved = manager.apply(
        first,
        NotebookPatch(
            rejected_hypotheses=["candidate issue"],
            resolved_evidence_handles=["ev-1"],
            resolved_claims=["claim-1"],
        ),
    )
    assert resolved.open_hypotheses == []
    assert resolved.rejected_hypotheses == ["candidate issue"]
    assert resolved.active_evidence_handles == []
    assert resolved.unresolved_claims == []
    assert manager.verify(resolved)


def test_run_notebook_rejects_tampering_stale_cas_and_raw_failure_payloads() -> None:
    manager = RunNotebookManager()
    notebook = manager.create(objective="audit")
    tampered = notebook.model_copy(update={"objective": "different objective"})
    assert not manager.verify(tampered)
    with pytest.raises(RunNotebookError, match="digest"):
        manager.apply(tampered, NotebookPatch())
    with pytest.raises(RunNotebookError, match="stale"):
        manager.apply(notebook, NotebookPatch(), expected_digest="a" * 64)
    with pytest.raises(ValidationError):
        NotebookFailure.model_validate(
            {
                "step_id": "tool",
                "attempt": 1,
                "error_code": "ERROR",
                "summary": "safe summary",
                "raw_output": "must not be accepted",
            }
        )
