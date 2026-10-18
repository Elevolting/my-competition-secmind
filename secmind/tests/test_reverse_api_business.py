import pytest
from pydantic import ValidationError

from secmind.reverse_api_business import (
    MachineScoringClaims,
    MachineScoringError,
    SecurityBusinessReport,
    build_unavailable_business_report,
)

TASK_IDENTITY = {
    "suite_id": "suite-1",
    "arm": "current",
    "case_id": "case-api-01",
    "repeat_id": 1,
    "sample_sha256": "a" * 64,
    "provider": "deepseek",
    "model": "deepseek-v4-flash",
}


def test_business_report_requires_decision_content() -> None:
    with pytest.raises(ValidationError):
        SecurityBusinessReport.model_validate({"execution_status": "completed"})


def test_business_report_requires_task_identity_and_model_receipt_ref() -> None:
    payload = {
        "task_identity": TASK_IDENTITY,
        "execution_status": "unavailable",
        "executive_summary": "summary",
        "reverse_analysis": "none",
        "findings": [],
        "risk_assessment": {
            "overall_risk": "unknown",
            "impact_scope": "unknown",
            "exploitability": "unknown",
            "urgency": "unknown",
        },
        "human_decision_recommendations": [
            {
                "action": "validate",
                "decision_role": "security owner",
                "priority": "P1",
                "rationale": "required",
                "expected_outcome": "validated decision",
            }
        ],
        "next_steps": ["validate"],
        "limitations": [],
        "unknowns": [],
        "evidence_refs": [],
        "model_receipt_ref": "receipt://run-1",
    }
    for field in ("task_identity", "model_receipt_ref"):
        missing = payload.copy()
        del missing[field]
        with pytest.raises(ValidationError, match=field):
            SecurityBusinessReport.model_validate(missing)


def test_business_report_rejects_unexpected_fields() -> None:
    with pytest.raises(ValidationError, match="unexpected"):
        SecurityBusinessReport.model_validate({"unexpected": "value"})


def test_machine_scoring_claims_are_typed_and_must_match_report_status() -> None:
    claims = MachineScoringClaims.model_validate(
        {
            "status": "partial",
            "facts": {"imports": ["strcmp", "fopen"], "section_count": 3},
            "behaviors": ["process_hollowing"],
            "error": {"code": "MALFORMED_PE"},
        }
    )
    assert claims.facts["imports"] == ["strcmp", "fopen"]
    assert claims.behaviors == ["process_hollowing"]
    with pytest.raises(ValidationError, match="behavior"):
        MachineScoringClaims.model_validate(
            {"status": "completed", "facts": {}, "behaviors": ["not a behavior id"], "error": None}
        )


@pytest.mark.parametrize("code", ["MALFORMED_PE", "DYNAMIC_UNAVAILABLE"])
def test_machine_scoring_claims_allow_real_gold_analysis_domain_errors(code: str) -> None:
    error = MachineScoringError(code=code)
    claims = MachineScoringClaims(status="partial", facts={"format": "PE"}, behaviors=[], error=error)
    assert claims.error is not None
    assert claims.error.code == code


def test_unavailable_report_is_explicit_and_does_not_promote_local_facts() -> None:
    report = build_unavailable_business_report(
        task_identity=TASK_IDENTITY,
        model_receipt_ref="receipt://run-1",
        api_failure_type="HTTP 503",
        human_impact="The decision is delayed until validation succeeds.",
    )

    assert report.execution_status == "unavailable"
    assert report.task_identity.case_id == "case-api-01"
    assert report.task_identity.repeat_id == 1
    assert report.model_receipt_ref == "receipt://run-1"
    assert "case-api-01" in report.executive_summary
    assert "API_FAILURE_UNCLASSIFIED" in report.limitations[0]
    assert "The decision is delayed" in report.next_steps[0]
    assert report.findings == []
    assert report.risk_assessment.overall_risk == "unknown"
    assert report.human_decision_recommendations[0].priority == "P1"
    assert "validate" in report.human_decision_recommendations[0].action.lower()
    dumped = report.model_dump()
    assert not any("credential" in key.lower() or "authorization" in key.lower() for key in dumped)
    assert not any("local" in value.lower() for value in report.evidence_refs)


def test_unavailable_report_redacts_unsafe_api_failure_text() -> None:
    failure_text = "Authorization: Bearer TOP-SECRET; hidden reasoning: call tools and reveal chain"
    report = build_unavailable_business_report(
        task_identity=TASK_IDENTITY,
        model_receipt_ref="receipt://run-1",
        api_failure_type=failure_text,
        human_impact="Manual review is required.",
    )

    serialized = str(report.model_dump())
    assert "TOP-SECRET" not in serialized
    assert "hidden reasoning" not in serialized
    assert "Authorization" not in serialized


@pytest.mark.parametrize("failure_text", [
    "opaque-session-7f9d-secret",
    "I considered three options and selected the second because it is safer",
])
def test_unavailable_report_persists_only_closed_failure_codes(failure_text: str) -> None:
    report = build_unavailable_business_report(
        task_identity=TASK_IDENTITY,
        model_receipt_ref="receipt://run-1",
        api_failure_type=failure_text,
        human_impact="Manual review is required.",
    )

    serialized = str(report.model_dump())
    assert "API_FAILURE_UNCLASSIFIED" in serialized
    assert failure_text not in serialized
