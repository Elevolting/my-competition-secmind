from __future__ import annotations

from secmind.integrations.test3 import (
    MAX_PUBLIC_EVIDENCE,
    MAX_PUBLIC_ITEMS_PER_FIELD,
    build_trusted_task_payload,
    project_domain_result,
)


def test_bridge_payload_preserves_trusted_domain_contract() -> None:
    payload = build_trusted_task_payload(
        {"objective": "answer", "autonomy_policy": "graded"},
        {
            "primary_domain": "agent_safety",
            "secondary_capabilities": ["prompt_injection_resistance"],
            "required_output": {
                "scoring_mode": "agent_policy_compliance",
                "required_fields": ["decision", "safe_actions", "blocked_actions"],
            },
        },
    )

    assert payload["interaction_mode"] == "unattended"
    assert payload["autonomy_policy"] == "automatic"
    assert payload["primary_domain"] == "agent_safety"
    assert payload["scoring_mode"] == "agent_policy_compliance"
    assert payload["expected_outputs"] == ["decision", "safe_actions", "blocked_actions"]


def test_bridge_payload_preserves_opaque_upload_reference_byte_for_byte() -> None:
    reference = "738fcf1d-e6bd-4c01-8a83-283051bc1451-evaluation-input.zip"
    payload = build_trusted_task_payload(
        {
            "objective": "Analyze the supplied immutable input.",
            "attachments": [{"ref": reference, "name": "evaluation-input.zip"}],
        },
        {},
    )

    assert payload["attachments"] == [{"ref": reference, "name": "evaluation-input.zip"}]


def test_bridge_projection_keeps_typed_answer_and_all_plan_aliases() -> None:
    result = project_domain_result(
        {
            "answer": {"summary": "safe summary"},
            "decision_summary": {
                "plan_or_steps": [{"step_id": "primary"}],
                "final_validation": {"status": "verified"},
                "confidence_or_unknowns": ["one unknown"],
            },
            "run_proof": {},
        },
        {
            "answer_type": "policy_decision",
            "answer_payload": {
                "decision": "allow_summary_only",
                "safe_actions": ["summarize"],
                "blocked_actions": ["alter_payment"],
            },
            "coverage": {
                "canonical_primary_status": "completed",
                "accepted_delta_count": 1,
                "deterministic_primary_skip_diagnostics": {
                    "schema_version": "deterministic-primary-skip-diagnostics-v1",
                    "scope": "exact_contract",
                    "eligible": False,
                    "check_count": 2,
                    "passed_count": 1,
                    "failed_count": 1,
                    "reason_codes": ["exact.no_last_error"],
                    "checks": {"exact.no_last_error": False, "exact.not_cancelled": True},
                },
                "workspace": "must-not-be-exported",
                "model_gateway_failure": {"message": "Authorization: Bearer sk-secret-value-123456"},
            },
        },
        summary={"last_error": None},
    )

    assert result["answer"]["summary"] == "safe summary"
    assert result["answer"]["decision"] == "allow_summary_only"
    assert result["answer"]["answer_type"] == "policy_decision"
    assert result["decision"] == "allow_summary_only"
    assert result["safe_actions"] == ["summarize"]
    assert result["blocked_actions"] == ["alter_payment"]
    assert result["decision_summary"]["plan"] == [{"step_id": "primary"}]
    assert result["decision_summary"]["steps"] == [{"step_id": "primary"}]
    # Caller-authored validation is untrusted and must not be upgraded into a
    # terminal verification receipt.
    assert "validation" not in result["decision_summary"]
    assert result["decision_summary"]["unknowns"] == ["one unknown"]
    diagnostics = result["run_proof"]["agent_diagnostics"]
    assert diagnostics["canonical_primary_status"] == "completed"
    assert diagnostics["accepted_delta_count"] == 1
    assert diagnostics["deterministic_primary_skip_diagnostics"]["reason_codes"] == ["exact.no_last_error"]
    assert "sk-secret-value" not in diagnostics["model_gateway_failure"]["message"]
    assert "[REDACTED]" in diagnostics["model_gateway_failure"]["message"]


def test_bridge_projection_prefers_existing_plan_alias_before_summary_fallback() -> None:
    result = project_domain_result(
        {"answer": {}, "decision_summary": {"plan": [{"step_id": "sealed-plan"}]}},
        {"answer_payload": {}, "coverage": {}},
        summary={"plan": [{"step_id": "mutable-summary"}]},
    )

    assert result["decision_summary"]["plan_or_steps"] == [{"step_id": "sealed-plan"}]


def test_bridge_projection_preserves_conclusive_anchor_and_locates_scenario_evidence() -> None:
    result = project_domain_result(
        {
            "status": "PARTIAL",
            "answer": {},
            "decision_summary": {"decisions": [{"decision": "offline_log_analysis_completed"}]},
            "evidence": [
                {
                    "evidence_id": "ev-1",
                    "sha256": "a" * 64,
                    "metadata": {
                        "source_artifact_sha256": "a" * 64,
                        "source_locator": {
                            "source_ref": "upload-evaluation-input/capture.pcapng",
                            "byte_offset": 42,
                            "line_number": 0,
                        },
                    },
                }
            ],
        },
        {
            "answer_type": "exact_answer_with_evidence",
            "answer_payload": {
                "status": "completed",
                "execution_status": "success",
                "epistemic_status": "conclusive",
                "validation": {"exact_match": True},
            },
            "coverage": {"scenario_projection": {"scenario": "log_analysis"}},
        },
        task={"required_output": {"required_fields": ["answer", "evidence"]}},
    )

    # A conclusive typed answer cannot upgrade a native PARTIAL status.  The
    # native bridge state remains authoritative for evaluation and operations.
    assert result["status"] == "PARTIAL"
    assert result["evidence"][0]["path"] == "capture.pcapng"
    assert result["evidence"][0]["file_sha256"] == "a" * 64
    assert result["evidence"][0]["byte_offset"] == 42
    assert result["decision_summary"]["plan"]
    assert result["decision_summary"]["success_criteria"]
    assert result["decision_summary"]["tools"] == ["deterministic:log_analysis"]
    # Provider-authored answer fields cannot self-attest terminal validity.
    assert "final_validation" not in result["decision_summary"]


def test_bridge_projection_bounds_public_answer_and_evidence() -> None:
    result = project_domain_result(
        {
            "answer": {},
            "decision_summary": {"decisions": [{"decision": str(index)} for index in range(200)]},
            "evidence": [
                {"evidence_id": f"ev-{index:04d}", "sha256": "a" * 64, "summary": "observed"} for index in range(1_000)
            ],
            "findings": [],
            "limitations": [f"limit-{index}" for index in range(200)],
        },
        {
            "answer_payload": {"events": [{"id": index} for index in range(1_000)]},
            "coverage": {},
        },
    )

    # Hard caps do not append a sentinel row; truncation is explicit in the
    # projection metadata and dropped IDs.
    assert len(result["answer"]["events"]) == MAX_PUBLIC_ITEMS_PER_FIELD
    assert len(result["evidence"]) == MAX_PUBLIC_EVIDENCE
    assert len(result["limitations"]) == MAX_PUBLIC_ITEMS_PER_FIELD
    assert len(result["decision_summary"]["decisions"]) == MAX_PUBLIC_ITEMS_PER_FIELD
    assert result["run_proof"]["projection"]["collections"]["evidence"]["truncated_count"] == 744
