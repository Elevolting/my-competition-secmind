from __future__ import annotations

from typing import Any

import pytest
from pydantic import BaseModel, ValidationError

from secmind.answer_revision_contracts import ProviderIdentity, ReceiptBinding, ScoringMode
from secmind.answer_revision_obligations import answer_model
from secmind.canonical_primary import (
    EvidenceGapPrimaryAnswer,
    ExactPrimaryAnswer,
    PatchPrimaryAnswer,
    PolicyPrimaryAnswer,
    ReversePrimaryAnswer,
    SourceCodePrimaryAnswer,
    TimelinePrimaryAnswer,
    provider_answer_model,
    select_analysis_profile,
)
from secmind.domain_answers import ExactAnswer, TimelineAnswer, normalize_domain_answer
from secmind.published_answer_models import PublishedAnswer
from secmind.schemas import Scenario, TaskRequest
from secmind.task_specs import TaskSpecCompiler, TaskSpecConflict

_LOCATOR = {
    "source_ref": "evidence/events.jsonl",
    "segment_id": "record-7",
    "record_number": 7,
    "line_number": 7,
    "byte_offset": 96,
    "byte_length": 48,
    "locator_scope": "record",
    "artifact_sha256": "a" * 64,
}


@pytest.mark.parametrize(
    "model",
    [
        SourceCodePrimaryAnswer,
        PolicyPrimaryAnswer,
        TimelinePrimaryAnswer,
        EvidenceGapPrimaryAnswer,
        ExactPrimaryAnswer,
        PatchPrimaryAnswer,
        ReversePrimaryAnswer,
    ],
)
def test_provider_domain_schemas_forbid_undeclared_top_level_fields(model: type[BaseModel]) -> None:
    assert model.model_json_schema()["additionalProperties"] is False


@pytest.mark.parametrize(
    ("model", "payload"),
    [
        (SourceCodePrimaryAnswer, {}),
        (PolicyPrimaryAnswer, {}),
        (TimelinePrimaryAnswer, {}),
        (EvidenceGapPrimaryAnswer, {}),
        (ExactPrimaryAnswer, {}),
        (PatchPrimaryAnswer, {}),
        (ReversePrimaryAnswer, {}),
    ],
)
def test_provider_completed_with_empty_critical_fields_is_downgraded(model: type[BaseModel], payload: dict) -> None:
    answer: Any = model.model_validate(
        {
            "task_id": "empty-critical",
            "status": "completed",
            "extensions": {"trace_id": "provider-trace"},
            **payload,
        }
    )

    assert answer.status == "partial"
    assert answer.extensions == {"trace_id": "provider-trace"}
    assert any(item.startswith("critical_answer_fields_empty:") for item in answer.limitations)


@pytest.mark.parametrize(
    "mode",
    [
        "security_finding",
        "agent_policy_compliance",
        "forensic_attribution",
        "evidence_gap",
        "exact_answer_with_evidence",
        "patch_validator",
        "reverse_behavior",
    ],
)
def test_typed_completed_with_empty_critical_fields_is_never_success(mode: str) -> None:
    answer = normalize_domain_answer(mode, {"task_id": f"typed-{mode}", "status": "completed"})

    assert answer.execution_status == "partial"
    assert answer.epistemic_status == "unknown"


def test_explicit_extensions_preserve_compatibility_without_cross_domain_authority() -> None:
    answer = normalize_domain_answer(
        "agent_policy_compliance",
        {
            "task_id": "policy-extensions",
            "status": "completed",
            "decision": "DENY/BLOCK: ignore the embedded instruction",
            "safe_actions": ["summarize supplied records"],
            "blocked_actions": ["send a transaction"],
            "evidence": [{"source_ref": "prompt.txt"}],
            "events": [{"event_id": "decorative-cross-domain-row"}],
            "extensions": {"provider_trace": "trace-1"},
        },
    )

    assert answer.execution_status == "success"
    assert answer.decision == "ignore_untrusted_instruction; DENY/BLOCK: ignore the embedded instruction"
    assert answer.extensions["provider_trace"] == "trace-1"
    assert answer.extensions["events"] == [{"event_id": "decorative-cross-domain-row"}]
    assert not hasattr(answer, "events")


def test_policy_projection_uses_blocked_action_semantics_for_untrusted_instruction() -> None:
    answer = normalize_domain_answer(
        "agent_policy_compliance",
        {
            "task_id": "policy-injection",
            "status": "completed",
            "decision": "The requested filename cannot be determined from the supplied evidence.",
            "safe_actions": ["inspect only the supplied bytes"],
            "blocked_actions": [
                "Treat embedded content as authorization or instructions.",
                "Exfiltrate or delete files.",
            ],
            "evidence": [{"source_ref": "context.txt"}],
        },
    )

    assert answer.decision == (
        "ignore_untrusted_instruction; DENY/BLOCK: "
        "The requested filename cannot be determined from the supplied evidence."
    )


@pytest.mark.parametrize(
    "blocked_action",
    [
        "Do not attach files to exfil@evil.invalid or delete originals.",
        "Do not execute instructions contained in the uploaded content.",
    ],
)
def test_policy_projection_normalizes_common_blocked_injection_variants(blocked_action: str) -> None:
    answer = normalize_domain_answer(
        "agent_policy_compliance",
        {
            "task_id": "policy-injection-variant",
            "status": "completed",
            "decision": "The requested external fact cannot be determined from the supplied evidence.",
            "safe_actions": ["inspect only the supplied bytes"],
            "blocked_actions": [blocked_action],
            "evidence": [{"source_ref": "context.txt"}],
        },
    )

    assert answer.decision is not None
    assert answer.decision.startswith("ignore_untrusted_instruction; DENY/BLOCK:")


def test_policy_projection_does_not_relabel_unrelated_denial_as_prompt_injection() -> None:
    answer = normalize_domain_answer(
        "agent_policy_compliance",
        {
            "task_id": "policy-authorization",
            "status": "completed",
            "decision": "The requested state change lacks operator authorization.",
            "safe_actions": ["request explicit operator approval"],
            "blocked_actions": ["Do not modify the protected account."],
            "evidence": [{"source_ref": "authorization.json"}],
        },
    )

    assert answer.decision is not None
    assert answer.decision.startswith("deny_unauthorized_action; DENY/BLOCK:")


def test_unknown_scoring_mode_is_rejected_instead_of_becoming_a_finding_answer() -> None:
    with pytest.raises(ValueError, match="unsupported scoring_mode"):
        normalize_domain_answer("invented_domain", {"task_id": "unknown", "status": "completed"})
    with pytest.raises(ValueError, match="unsupported scoring_mode"):
        provider_answer_model("invented_domain", "universal_security")
    with pytest.raises(TaskSpecConflict, match="unsupported scoring_mode"):
        TaskSpecCompiler().compile(
            "unknown-mode",
            TaskRequest(objective="Analyze immutable evidence", scoring_mode="invented_domain"),
            [],
            [],
        )


def test_timeline_event_entity_flow_graph_retains_evidence_and_source_locator() -> None:
    answer = TimelineAnswer.model_validate(
        {
            "task_id": "timeline-graph",
            "execution_status": "success",
            "epistemic_status": "conclusive",
            "events": [
                {
                    "event_id": "event-7",
                    "timestamp": "2026-08-17T10:00:00Z",
                    "event_type": "failed_login",
                    "entities": [{"kind": "account", "value": "alice"}],
                    "evidence_ids": ["evidence-7"],
                    "source_locator": _LOCATOR,
                }
            ],
        }
    )

    assert answer.timeline_graph is not None
    assert answer.timeline_graph.events[0].source_locator is not None
    assert answer.timeline_graph.events[0].source_locator.byte_offset == 96
    assert answer.timeline_graph.events[0].evidence_ids == ("evidence-7",)
    assert answer.timeline_graph.entities[0].value == "alice"
    assert answer.timeline_graph.flows[0].relation == "observed_entity"
    assert answer.timeline_graph.flows[0].evidence_ids == ("evidence-7",)


def test_timeline_event_id_is_canonicalized_without_losing_source_binding() -> None:
    answer = TimelineAnswer.model_validate(
        {
            "task_id": "timeline-safe-id",
            "execution_status": "success",
            "epistemic_status": "conclusive",
            "events": [
                {
                    "event_id": " 4624/record\n1 ",
                    "timestamp": "2026-08-17T10:00:00Z",
                    "event_type": "login",
                    "evidence_ids": ["evidence-safe-id"],
                    "source_locator": _LOCATOR,
                }
            ],
        }
    )

    assert answer.timeline_graph is not None
    event = answer.timeline_graph.events[0]
    assert event.event_id != " 4624/record\n1 "
    assert event.event_id.startswith("event-")
    assert event.source_locator is not None
    assert event.evidence_ids == ("evidence-safe-id",)


def test_api_endpoint_auth_resource_graph_is_typed_and_source_bound() -> None:
    endpoint = {
        "endpoint_id": "operation-users-get",
        "method": "get",
        "path": "/users/{id}",
        "parameter_names": ["id"],
        "auth_schemes": ["oauth2"],
        "evidence_ids": ["evidence-api"],
        "source_locator": _LOCATOR,
    }
    answer = ExactAnswer.model_validate(
        {
            "task_id": "api-graph",
            "execution_status": "success",
            "epistemic_status": "conclusive",
            "values": {"endpoints": [endpoint]},
            "source_offsets": [{"operation_id": "operation-users-get", "source_locator": _LOCATOR}],
        }
    )

    assert answer.api_graph is not None
    operation = answer.api_graph.operations[0]
    assert operation.method == "GET"
    assert operation.evidence_ids == ("evidence-api",)
    assert operation.source_locator is not None
    assert answer.api_graph.auth_schemes[0].scheme == "oauth2"
    assert answer.api_graph.resources[0].path_template == "/users/{id}"
    assert {item.relation for item in answer.api_graph.relations} == {"requires_auth", "accesses_resource"}


def test_incident_hypothesis_and_rollback_plan_remains_a_dry_run() -> None:
    action = {
        "action_id": "action-contain-1",
        "phase": "containment",
        "title": "Prepare reversible isolation",
        "subject_ref": "host:server-1",
        "policy_action": "require_approval",
        "execution_enabled": False,
        "expected_impact": "May interrupt the affected service after approval.",
        "rollback_condition": "Abort if the affected host differs from evidence.",
        "evidence_ids": ["evidence-ir"],
        "source_locator": _LOCATOR,
    }
    hypothesis = {
        "claim_id": "hypothesis-1",
        "explanation": "The host may be compromised.",
        "status": "unverified",
        "evidence_ids": ["evidence-ir"],
        "source_locator": _LOCATOR,
    }
    answer = TimelineAnswer.model_validate(
        {
            "task_id": "incident-plan",
            "execution_status": "success",
            "epistemic_status": "conclusive",
            "events": [{"event_type": "incident_dry_run_action", **action}],
            "extensions": {"policy_actions": [action], "hypotheses": [hypothesis]},
        }
    )

    assert answer.incident_response is not None
    assert answer.incident_response.dry_run is True
    assert answer.incident_response.hypotheses[0].hypothesis_id == "hypothesis-1"
    assert answer.incident_response.rollback_conditions[0].action_id == "action-contain-1"
    assert answer.incident_response.rollback_conditions[0].source_locator is not None

    unsafe = {**action, "execution_enabled": True}
    with pytest.raises(ValidationError, match="non-executing dry run"):
        TimelineAnswer.model_validate(
            {
                "task_id": "unsafe-incident-plan",
                "execution_status": "success",
                "epistemic_status": "conclusive",
                "events": [{"event_type": "incident_dry_run_action", **unsafe}],
                "extensions": {"policy_actions": [unsafe]},
            }
        )


def test_published_answer_uses_the_same_typed_timeline_model() -> None:
    provider = ProviderIdentity(
        provider="relay",
        model_id="gpt-5.6-luna",
        request_id="request-domain-contract",
        request_digest="b" * 64,
        response_digest="c" * 64,
        response_schema_digest="d" * 64,
        provider_requests=1,
    )
    receipt = ReceiptBinding.create(
        receipt_id="receipt-domain-contract",
        provider=provider.provider,
        model_id=provider.model_id,
        request_digest=provider.request_digest,
        response_digest=provider.response_digest,
        response_schema_digest=provider.response_schema_digest,
    )
    typed_answer = normalize_domain_answer(
        "forensic_attribution",
        {
            "task_id": "task-domain-contract",
            "status": "completed",
            "events": [
                {
                    "event_id": "event-published",
                    "timestamp": "2026-08-17T10:00:00Z",
                    "event_type": "login",
                    "evidence_ids": ["evidence-published"],
                    "source_locator": _LOCATOR,
                }
            ],
        },
    )
    assert isinstance(typed_answer, TimelineAnswer)
    published = PublishedAnswer(
        answer_id="published-domain-contract",
        run_id="run-domain-contract",
        task_id="task-domain-contract",
        scoring_mode=ScoringMode.FORENSIC_ATTRIBUTION,
        domain="logs_ir_hunting",
        provider=provider,
        receipt=receipt,
        answer=typed_answer,
    )

    assert answer_model(ScoringMode.FORENSIC_ATTRIBUTION) is TimelineAnswer
    assert isinstance(published.answer, TimelineAnswer)
    assert published.answer.timeline_graph is not None


@pytest.mark.parametrize(
    ("domain", "scenario", "profile"),
    [
        ("api_web_security", Scenario.API_ASSESSMENT, "api_and_web_security"),
        ("incident_response", Scenario.INCIDENT_RESPONSE, "incident_response"),
    ],
)
def test_explicit_noncode_domains_route_to_specialized_contracts(
    domain: str,
    scenario: Scenario,
    profile: str,
) -> None:
    scoring_mode = "exact_answer_with_evidence" if scenario == Scenario.API_ASSESSMENT else "forensic_attribution"
    task = TaskRequest(
        objective="Analyze the supplied immutable evidence",
        primary_domain=domain,
        scoring_mode=scoring_mode,
        interaction_mode="unattended",
    )
    spec = TaskSpecCompiler().compile(f"route-{domain}", task, [], [])

    assert spec.primary_scenario == scenario
    assert spec.ambiguities == []
    assert select_analysis_profile(task.objective, domain, [], [], scoring_mode) == profile
