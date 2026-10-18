from __future__ import annotations

import pytest

from secmind.answer_revisions import (
    ActorPatch,
    ApiOperationPatch,
    ExactAnswerPatch,
    FindingPatch,
    ProviderIdentity,
    PublishedAnswer,
    ReceiptBinding,
    RevisionError,
    ScoringMode,
    apply_revision,
    make_revision,
    revise,
)


def _provider() -> ProviderIdentity:
    return ProviderIdentity(
        provider="deepseek",
        model_id="deepseek-v4-flash",
        request_id="provider-request-1",
        request_digest="a" * 64,
        response_digest="b" * 64,
        response_schema_digest="c" * 64,
        provider_requests=1,
    )


def _answer(mode: ScoringMode, answer: dict) -> PublishedAnswer:
    provider = _provider()
    receipt = ReceiptBinding.create(
        receipt_id="primary-receipt-1",
        provider=provider.provider,
        model_id=provider.model_id,
        request_digest=provider.request_digest,
        response_digest=provider.response_digest,
        response_schema_digest=provider.response_schema_digest,
    )
    domains = {
        ScoringMode.SECURITY_FINDING: "code_audit_and_patch",
        ScoringMode.FORENSIC_ATTRIBUTION: "logs_ir_hunting",
        ScoringMode.EXACT_ANSWER_WITH_EVIDENCE: "complex_input_understanding",
    }
    return PublishedAnswer(
        answer_id=f"answer-{mode.value}",
        run_id="run-revisions",
        task_id=f"task-{mode.value}",
        scoring_mode=mode,
        domain=domains.get(mode, mode.value),
        provider=provider,
        receipt=receipt,
        answer={"task_id": f"task-{mode.value}", "status": "completed", **answer},
    )


def test_finding_replace_is_typed_and_does_not_mutate_base_or_receipt() -> None:
    base = _answer(
        ScoringMode.SECURITY_FINDING,
        {
            "findings": [{"finding_id": "finding-1", "rule_id": "CWE-89", "path": "app.py", "line": 10}],
            "checked_paths": ["app.py"],
        },
    )
    revised, revision = revise(
        base,
        operation="replace",
        field="findings",
        target_id="finding-1",
        payload=FindingPatch(finding_id="finding-1", cwe=79, path="app.py", line=11),
        reason="independent source corrected the taxonomy and line",
    )
    assert revised.answer.findings[0]["cwe"] == 79
    assert revised.answer.findings[0]["line"] == 11
    assert base.answer.findings[0]["rule_id"] == "CWE-89"
    assert revised.receipt == base.receipt
    assert revised.revision_ids == (revision.revision_id,)
    assert revised.answer_digest != base.answer_digest


def test_timeline_retract_removes_only_the_typed_event() -> None:
    base = _answer(
        ScoringMode.FORENSIC_ATTRIBUTION,
        {
            "events": [
                {"event_id": "event-1", "timestamp": "2026-08-17T00:00:00Z", "event_type": "login"},
                {"event_id": "event-2", "timestamp": "2026-08-17T00:01:00Z", "event_type": "logout"},
            ],
            "facts": [{"fact": "session"}],
            "limitations": ["bounded fixture"],
        },
    )
    revision = make_revision(
        base,
        operation="retract",
        field="timeline",
        target_id="event-1",
        reason="the source locator was invalidated",
    )
    revised = apply_revision(base, revision)
    assert [item["event_id"] for item in revised.answer.events] == ["event-2"]
    assert [item["event_id"] for item in base.answer.events] == ["event-1", "event-2"]
    assert revised.status == "completed"


def test_actor_replace_preserves_event_and_adds_a_real_actor_fact() -> None:
    base = _answer(
        ScoringMode.FORENSIC_ATTRIBUTION,
        {
            "events": [{"event_id": "event-1", "timestamp": "2026-08-17T00:00:00Z", "event_type": "login"}],
            "facts": [{"fact": "login"}],
            "actors": [{"actor_id": "actor-1", "name": "alice"}],
            "limitations": ["bounded fixture"],
        },
    )
    revised, _ = revise(
        base,
        operation="replace",
        field="actor",
        target_id="actor-1",
        payload=ActorPatch(actor_id="actor-1", account="alice@example.test", role="operator"),
        reason="identity binding was corrected",
    )
    assert revised.answer.actors[0]["account"] == "alice@example.test"
    assert revised.answer.actors[0]["role"] == "operator"
    assert revised.answer.events == base.answer.events


def test_api_operation_supplement_is_typed_and_evidence_bound() -> None:
    base = _answer(
        ScoringMode.EXACT_ANSWER_WITH_EVIDENCE,
        {
            "values": {"answer": "api inventory"},
            "source_offsets": [{"source_ref": "api.json"}],
            "extensions": {"operations": [{"operation_id": "op-1", "method": "GET", "path": "/items"}]},
        },
    )
    revised, _ = revise(
        base,
        operation="supplement",
        field="api_operation",
        payload=ApiOperationPatch(
            operation_id="op-2",
            method="POST",
            path="/items",
            status_code=201,
            evidence_ids=("ev-2",),
        ),
        reason="the parser exposed a previously omitted operation",
    )
    operations = revised.answer.extensions["operations"]
    assert [item["operation_id"] for item in operations] == ["op-1", "op-2"]
    assert operations[1]["status_code"] == 201
    assert "ev-2" in revised.answer.extensions["evidence_ids"]


def test_exact_answer_replace_accepts_falsey_but_exact_values() -> None:
    base = _answer(
        ScoringMode.EXACT_ANSWER_WITH_EVIDENCE,
        {"values": "old-answer", "source_offsets": [{"source_ref": "capture"}]},
    )
    revised, _ = revise(
        base,
        operation="replace",
        field="exact_answer",
        target_id="values",
        payload=ExactAnswerPatch(answer_id="values", value=0, evidence_ids=("ev-2",)),
        reason="the exact value was corrected to zero",
    )
    assert revised.answer.values == 0
    assert revised.status == "completed"
    assert base.answer.values == "old-answer"


def test_exact_answer_retract_removes_scalar_value() -> None:
    base = _answer(
        ScoringMode.EXACT_ANSWER_WITH_EVIDENCE,
        {"values": "withdrawn-answer", "source_offsets": [{"source_ref": "capture"}]},
    )
    revised, _ = revise(
        base,
        operation="retract",
        field="exact_answer",
        target_id="values",
        reason="the source answer was withdrawn",
    )
    assert revised.answer.values is None
    assert revised.status == "partial"


def test_stale_base_digest_is_rejected() -> None:
    base = _answer(
        ScoringMode.SECURITY_FINDING,
        {"findings": [{"finding_id": "finding-1", "rule_id": "CWE-89", "path": "app.py", "line": 10}]},
    )
    revision = make_revision(
        base,
        operation="retract",
        field="findings",
        target_id="finding-1",
        reason="remove unsupported claim",
    )
    with pytest.raises(RevisionError, match="base_answer_digest"):
        apply_revision(base.model_copy(update={"answer_digest": "d" * 64}), revision)


def test_scoring_mode_rejects_a_mismatched_known_domain() -> None:
    provider = _provider()
    receipt = ReceiptBinding.create(
        receipt_id="primary-receipt-mismatch",
        provider=provider.provider,
        model_id=provider.model_id,
        request_digest=provider.request_digest,
        response_digest=provider.response_digest,
        response_schema_digest=provider.response_schema_digest,
    )
    with pytest.raises(ValueError, match="domain"):
        PublishedAnswer(
            answer_id="answer-mismatch",
            run_id="run-mismatch",
            task_id="task-mismatch",
            scoring_mode=ScoringMode.SECURITY_FINDING,
            domain="agent_safety",
            provider=provider,
            receipt=receipt,
            answer={"task_id": "task-mismatch", "status": "partial"},
        )


@pytest.mark.parametrize(
    ("mode", "payload"),
    [
        (ScoringMode.SECURITY_FINDING, {"findings": [], "checked_paths": []}),
        (ScoringMode.FORENSIC_ATTRIBUTION, {"events": [], "facts": [], "limitations": []}),
        (ScoringMode.EXACT_ANSWER_WITH_EVIDENCE, {"values": None, "source_offsets": []}),
        (ScoringMode.AGENT_POLICY_COMPLIANCE, {"decision": None, "safe_actions": [], "blocked_actions": []}),
    ],
)
def test_empty_critical_field_matrix_cannot_self_report_completed(mode: ScoringMode, payload: dict) -> None:
    answer = _answer(mode, payload)
    assert answer.status == "partial"
    assert answer.obligations.complete is False
    assert any(item.status == "unverified" and item.critical for item in answer.obligations.obligations)


def test_explicit_negative_security_coverage_can_complete_without_findings() -> None:
    answer = _answer(
        ScoringMode.SECURITY_FINDING,
        {
            "findings": [],
            "checked_paths": ["app.py", "requirements.txt"],
            "negative_evidence": [{"path": "app.py", "summary": "no vulnerable sink"}],
        },
    )
    assert answer.status == "completed"
