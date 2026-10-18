"""Business-facing contract for reports produced by the reverse-analysis API lane."""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator, model_validator

_BEHAVIOR_ID = re.compile(r"^[a-z][a-z0-9_]{1,127}$")
AnalysisDomainErrorCode = Literal["MALFORMED_PE", "DYNAMIC_UNAVAILABLE"]
ProviderFailureCode = Literal[
    "MODEL_GATEWAY_ERROR",
    "TIMEOUT",
    "AUTHENTICATION_FAILED",
    "RATE_LIMITED",
    "STRUCTURED_OUTPUT_INVALID",
    "UNSAFE_MODEL_PAYLOAD",
    "LOCAL_POST_RESPONSE_FAILURE",
    "ORCHESTRATION_INTERRUPTED",
    "ORCHESTRATION_SLOT_FAILURE",
    "API_FAILURE_UNCLASSIFIED",
]


class MachineScoringError(BaseModel):
    """Closed, machine-readable error claimed by the API report."""

    model_config = ConfigDict(extra="forbid")

    code: AnalysisDomainErrorCode | ProviderFailureCode


class MachineScoringClaims(BaseModel):
    """Explicit API claims used by the sealed evaluator, never prose heuristics."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["completed", "partial", "unavailable"]
    facts: dict[str, JsonValue] = Field(default_factory=dict)
    behaviors: list[str] = Field(default_factory=list, max_length=128)
    error: MachineScoringError | None = None

    @field_validator("behaviors")
    @classmethod
    def validate_behavior_ids(cls, values: list[str]) -> list[str]:
        if len(set(values)) != len(values) or any(not _BEHAVIOR_ID.fullmatch(value) for value in values):
            raise ValueError("behavior identifiers must be unique normalized snake_case values")
        return values


class BusinessFinding(BaseModel):
    """A security finding expressed in terms a human decision-maker can use."""

    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=1)
    severity: str = Field(min_length=1)
    confidence: str = Field(min_length=1)
    evidence_refs: list[str]
    business_impact: str = Field(min_length=1)
    technical_explanation: str = Field(min_length=1)


class RiskAssessment(BaseModel):
    """Conservative risk summary; unknown is valid when evidence is unavailable."""

    model_config = ConfigDict(extra="forbid")

    overall_risk: str = Field(min_length=1)
    impact_scope: str = Field(min_length=1)
    exploitability: str = Field(min_length=1)
    urgency: str = Field(min_length=1)


class HumanDecisionRecommendation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: str = Field(min_length=1)
    decision_role: str = Field(min_length=1)
    priority: Literal["P0", "P1", "P2", "P3"]
    rationale: str = Field(min_length=1)
    expected_outcome: str = Field(min_length=1)


class TaskIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid")

    suite_id: str = Field(min_length=1)
    arm: Literal["current", "optimized"]
    case_id: str = Field(min_length=1)
    repeat_id: Literal[1, 2]
    sample_sha256: str = Field(pattern=r"^[0-9a-fA-F]{64}$")
    provider: Literal["deepseek"]
    model: Literal["deepseek-v4-flash"]


class SecurityBusinessReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    task_identity: TaskIdentity
    execution_status: Literal["completed", "partial", "unavailable"]
    executive_summary: str = Field(min_length=1)
    reverse_analysis: str = Field(min_length=1)
    findings: list[BusinessFinding]
    risk_assessment: RiskAssessment
    human_decision_recommendations: list[HumanDecisionRecommendation] = Field(min_length=1)
    next_steps: list[str] = Field(min_length=1)
    limitations: list[str]
    unknowns: list[str]
    evidence_refs: list[str]
    model_receipt_ref: str = Field(min_length=1)
    scoring_claims: MachineScoringClaims

    @model_validator(mode="after")
    def scoring_status_matches_report(self) -> SecurityBusinessReport:
        if self.scoring_claims.status != self.execution_status:
            raise ValueError("scoring_claims.status must match execution_status")
        return self


FailureCode = Literal[
    "MODEL_GATEWAY_ERROR",
    "TIMEOUT",
    "AUTHENTICATION_FAILED",
    "RATE_LIMITED",
    "STRUCTURED_OUTPUT_INVALID",
    "UNSAFE_MODEL_PAYLOAD",
    "LOCAL_POST_RESPONSE_FAILURE",
    "ORCHESTRATION_INTERRUPTED",
    "ORCHESTRATION_SLOT_FAILURE",
    "API_FAILURE_UNCLASSIFIED",
]


def _canonical_failure_code(value: str) -> FailureCode:
    """Map arbitrary gateway diagnostics to the closed report vocabulary."""

    codes: tuple[FailureCode, ...] = (
        "MODEL_GATEWAY_ERROR",
        "TIMEOUT",
        "AUTHENTICATION_FAILED",
        "RATE_LIMITED",
        "STRUCTURED_OUTPUT_INVALID",
        "UNSAFE_MODEL_PAYLOAD",
        "LOCAL_POST_RESPONSE_FAILURE",
        "ORCHESTRATION_INTERRUPTED",
        "ORCHESTRATION_SLOT_FAILURE",
        "API_FAILURE_UNCLASSIFIED",
    )
    return value if value in codes else "API_FAILURE_UNCLASSIFIED"  # type: ignore[return-value]


def build_unavailable_business_report(
    task_identity: TaskIdentity | dict[str, object],
    model_receipt_ref: str,
    api_failure_type: str,
    human_impact: str,
    evidence_refs: list[str] | None = None,
) -> SecurityBusinessReport:
    """Build a deterministic fail-closed report when the API cannot answer.

    No local evidence is converted into a finding here.  References, when
    supplied, are retained only as references to the sealed execution record.
    """

    if not api_failure_type:
        raise ValueError("api_failure_type must not be empty")
    if not human_impact:
        raise ValueError("human_impact must not be empty")
    identity = TaskIdentity.model_validate(task_identity)
    failure_code = _canonical_failure_code(api_failure_type)

    refs = list(evidence_refs or [])
    return SecurityBusinessReport(
        task_identity=identity,
        execution_status="unavailable",
        executive_summary=(
            f"Case {identity.case_id} has no API business conclusion because the model run was unavailable."
        ),
        reverse_analysis=(
            "No reverse-analysis conclusion is asserted. Local evidence, if any, remains unpromoted "
            "until an independent validated API response is available."
        ),
        findings=[],
        risk_assessment=RiskAssessment(
            overall_risk="unknown",
            impact_scope="unknown",
            exploitability="unknown",
            urgency="unknown",
        ),
        human_decision_recommendations=[
            HumanDecisionRecommendation(
                action="Validate the API execution and rerun the business report",
                decision_role="security owner",
                priority="P1",
                rationale=f"The API failed with {failure_code}; the report cannot support a security decision.",
                expected_outcome="A validated report or an explicitly documented manual decision.",
            )
        ],
        next_steps=[human_impact, "Record the failure and perform manual validation before taking action."],
        limitations=[f"API failure type: {failure_code}.", "No model conclusion is available."],
        unknowns=["The security impact, exploitability, and urgency remain unknown."],
        evidence_refs=refs,
        model_receipt_ref=model_receipt_ref,
        scoring_claims=MachineScoringClaims(
            status="unavailable",
            facts={},
            behaviors=[],
            error=MachineScoringError(code=failure_code),
        ),
    )
