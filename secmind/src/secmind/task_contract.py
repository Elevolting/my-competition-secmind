"""Authoritative v0.8.4 task and answer contracts.

The accepted request is provenance.  Execution nodes consume a sealed
``ResolvedTaskContract`` compiled from the durable ``TaskSpec`` and immutable
input manifest.  Keeping these models outside :mod:`secmind.schemas` prevents
the public compatibility facade from becoming the implementation home for yet
another subsystem.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from enum import StrEnum
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from secmind.answer_revision_contracts import CompositeStatus, ScoringMode

TASK_CONTRACT_VERSION = "resolved-task-1.0"
OBLIGATION_POLICY_VERSION = "obligation-policy-1.0"
MAX_OBLIGATION_EVIDENCE_IDS = 1_000


def canonical_digest(value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class ObligationStatus(StrEnum):
    PENDING = "pending"
    SATISFIED = "satisfied"
    INSUFFICIENT = "insufficient"
    CONFLICTED = "conflicted"
    BLOCKED = "blocked"
    WAIVED = "waived"


class ObligationKind(StrEnum):
    CORE_ANSWER = "core_answer"
    EVIDENCE_COVERAGE = "evidence_coverage"
    NEGATIVE_COVERAGE = "negative_coverage"
    OPTIONAL_ENHANCEMENT = "optional_enhancement"


class ObligationStage(StrEnum):
    """The four deterministic sources which may contribute completion work."""

    PRIMARY = "primary"
    SCENARIO = "scenario"
    EVIDENCE = "evidence"
    ENHANCEMENT = "enhancement"


class CompositeObligationStatus(StrEnum):
    SATISFIED = "satisfied"
    UNVERIFIED = "unverified"
    INSUFFICIENT = "insufficient"
    CONFLICTED = "conflicted"
    BLOCKED = "blocked"
    WAIVED = "waived"


class TaskObligation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    obligation_id: str = Field(min_length=8, max_length=128)
    kind: ObligationKind
    target_fields: list[str] = Field(default_factory=list, max_length=32)
    acceptance_rule: Literal["any_nonempty", "all_nonempty", "explicit_unknown", "evidence_bound"]
    critical: bool = True
    status: ObligationStatus = ObligationStatus.PENDING
    evidence_ids: list[str] = Field(default_factory=list, max_length=1_000)
    reason: str | None = Field(default=None, max_length=2_000)


class CompositeObligation(BaseModel):
    """One evaluated obligation in the sole completion-status projection.

    ``TaskObligation`` remains the durable/public compatibility shape.  This
    subtype adds only the stage used by the supervisor; every compatibility
    row is projected from this object and is never evaluated independently.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    obligation_id: str = Field(min_length=8, max_length=128)
    kind: ObligationKind
    target_fields: list[str] = Field(default_factory=list, max_length=32)
    acceptance_rule: Literal["any_nonempty", "all_nonempty", "explicit_unknown", "evidence_bound"]
    critical: bool = True
    evidence_ids: list[str] = Field(default_factory=list, max_length=1_000)
    reason: str | None = Field(default=None, max_length=2_000)
    stage: ObligationStage
    status: CompositeObligationStatus = CompositeObligationStatus.UNVERIFIED


class ObligationSet(BaseModel):
    """Authoritative aggregate for answer, investigation and report completion."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    scoring_mode: str
    obligations: tuple[CompositeObligation, ...] = ()
    composite_status: CompositeStatus = CompositeStatus.PARTIAL
    reason: str = ""
    stage_statuses: dict[ObligationStage, CompositeStatus] = Field(default_factory=dict)
    set_digest: str = Field(default="", pattern=r"^[a-f0-9]{0,64}$")

    @model_validator(mode="after")
    def derive_status(self) -> Self:
        status, reason = derive_composite_status(self.obligations)
        stages = {
            stage: derive_composite_status(item for item in self.obligations if item.stage == stage)[0]
            for stage in ObligationStage
        }
        object.__setattr__(self, "composite_status", status)
        object.__setattr__(self, "reason", reason)
        object.__setattr__(self, "stage_statuses", stages)
        expected = canonical_digest(
            {
                "scoring_mode": self.scoring_mode,
                "obligations": [item.model_dump(mode="json") for item in self.obligations],
                "composite_status": status.value,
                "reason": reason,
                "stage_statuses": {key.value: value.value for key, value in stages.items()},
            }
        )
        if self.set_digest and self.set_digest != expected:
            raise ValueError("obligation set digest mismatch")
        object.__setattr__(self, "set_digest", expected)
        return self

    @property
    def status(self) -> CompositeStatus:
        return self.composite_status

    @property
    def complete(self) -> bool:
        return self.composite_status == CompositeStatus.COMPLETED

    @property
    def task_obligations(self) -> tuple[TaskObligation, ...]:
        """Return the legacy state projection without its internal stage."""

        return tuple(
            TaskObligation.model_validate(
                {
                    **item.model_dump(mode="python", exclude={"stage", "status"}),
                    "status": {
                        CompositeObligationStatus.SATISFIED: ObligationStatus.SATISFIED,
                        CompositeObligationStatus.UNVERIFIED: ObligationStatus.PENDING,
                        CompositeObligationStatus.INSUFFICIENT: ObligationStatus.INSUFFICIENT,
                        CompositeObligationStatus.CONFLICTED: ObligationStatus.CONFLICTED,
                        CompositeObligationStatus.BLOCKED: ObligationStatus.BLOCKED,
                        CompositeObligationStatus.WAIVED: ObligationStatus.WAIVED,
                    }[item.status],
                }
            )
            for item in self.obligations
        )

    @classmethod
    def from_answer(
        cls,
        scoring_mode: ScoringMode | str,
        answer: BaseModel | Mapping[str, Any],
        provider: Any | None = None,
        declared_status: str | None = None,
        *,
        templates: list[TaskObligation] | tuple[TaskObligation, ...] | None = None,
        evidence_ids: list[str] | None = None,
    ) -> ObligationSet:
        """Compile and evaluate one answer using the canonical rule table.

        Provider identity is validated by ``PublishedAnswer`` itself.  It is
        accepted here solely for API compatibility with the former second
        obligation engine.
        """

        _ = provider, declared_status
        mode = scoring_mode.value if isinstance(scoring_mode, ScoringMode) else str(scoring_mode).casefold()
        payload = answer.model_dump(mode="python") if isinstance(answer, BaseModel) else dict(answer)
        selected = list(templates) if templates is not None else compile_obligation_templates("published", mode)
        return evaluate_obligation_set(selected, payload, scoring_mode=mode, evidence_ids=evidence_ids)


class ResolvedTaskContract(BaseModel):
    """The only mutable-workflow input downstream of task compilation."""

    model_config = ConfigDict(extra="forbid")

    contract_version: str = TASK_CONTRACT_VERSION
    contract_id: str
    contract_digest: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    run_id: str
    client_request_id: str | None = None
    task_spec_id: str
    task_spec_revision: int = Field(ge=1)
    task_spec_digest: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    objectives: list[str] = Field(min_length=1)
    primary_scenario: str
    primary_domain: str | None = None
    secondary_scenarios: list[str] = Field(default_factory=list)
    secondary_capabilities: list[str] = Field(default_factory=list)
    scoring_mode: str
    interaction_mode: Literal["interactive", "unattended"]
    autonomy_policy: Literal["graded", "approval_all", "automatic"] = "graded"
    authorized_scope: list[str] = Field(default_factory=list)
    constraints: list[str] = Field(default_factory=list)
    prohibited_actions: list[str] = Field(default_factory=list)
    expected_outputs: list[str] = Field(default_factory=list)
    success_criteria: list[str] = Field(default_factory=list)
    output_contract: dict[str, Any] = Field(default_factory=dict)
    evaluation_metadata: dict[str, Any] = Field(default_factory=dict)
    evaluation_contract_digest: str | None = Field(default=None, pattern=r"^[a-fA-F0-9]{64}$")
    asset_ids: list[str] = Field(default_factory=list)
    input_manifest_digest: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    answer_schema_digest: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    obligation_policy_version: str = OBLIGATION_POLICY_VERSION
    obligations: list[TaskObligation] = Field(default_factory=list)

    @property
    def objective(self) -> str:
        return self.objectives[0]

    @property
    def target_scope(self) -> list[str]:
        return list(self.authorized_scope)

    @model_validator(mode="after")
    def verify_digest(self) -> ResolvedTaskContract:
        expected = resolved_contract_digest(self.model_dump(mode="json", exclude={"contract_digest"}))
        if self.contract_digest != expected:
            raise ValueError("resolved task contract digest mismatch")
        if len({item.obligation_id for item in self.obligations}) != len(self.obligations):
            raise ValueError("resolved task contract contains duplicate obligations")
        return self


class EvidenceFact(BaseModel):
    model_config = ConfigDict(extra="forbid")

    fact_id: str
    fact_type: str
    value: Any
    source_ref: str
    source_sha256: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    locator: str | None = None
    confidence: float = Field(default=1.0, ge=0, le=1)
    taint: Literal["untrusted"] = "untrusted"


class EvidenceCompilerReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid")

    compiler_id: str = "secmind.evidence-compiler"
    compiler_version: str = "1.0"
    run_id: str
    contract_digest: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    input_manifest_digest: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    facts: list[EvidenceFact] = Field(default_factory=list, max_length=10_000)
    raw_window_refs: list[str] = Field(default_factory=list, max_length=10_000)
    unavailable_parts: list[str] = Field(default_factory=list, max_length=1_000)
    truncated_count: int = Field(default=0, ge=0)
    dropped_ids: list[str] = Field(default_factory=list, max_length=10_000)
    output_digest: str = Field(pattern=r"^[a-fA-F0-9]{64}$")


class IndependenceProof(BaseModel):
    model_config = ConfigDict(extra="forbid")

    proof_version: str = "independence-proof-1.0"
    proof_id: str
    # The unsuffixed fields are retained as a compact projection for callers
    # that only need to display the Critic side.  Admission never uses these
    # projections as the source of truth; it validates the paired fields
    # below, which bind both invocations to their real lineage.
    provider: str | None = None
    model_family: str | None = None
    model_id: str | None = None
    method_family: str
    primary_provider: str | None = None
    critic_provider: str | None = None
    primary_model_family: str | None = None
    critic_model_family: str | None = None
    primary_model_id: str | None = None
    critic_model_id: str | None = None
    primary_request_lineage: str | None = None
    critic_request_lineage: str | None = None
    primary_method_lineage: str | None = None
    critic_method_lineage: str | None = None
    primary_input_slice_digest: str | None = None
    critic_input_slice_digest: str | None = None
    primary_context_digest: str | None = None
    critic_context_digest: str | None = None
    rule_bundle_digest: str | None = None
    context_digest: str | None = None
    ancestor_digest: str | None = None
    compared_lineage_ids: list[str] = Field(default_factory=list)
    independent: bool
    reason_codes: list[str] = Field(default_factory=list)
    proof_digest: str = Field(pattern=r"^[a-fA-F0-9]{64}$")

    @model_validator(mode="after")
    def verify_digest(self) -> IndependenceProof:
        expected = canonical_digest(self.model_dump(mode="json", exclude={"proof_digest"}))
        if self.proof_digest != expected:
            raise ValueError("independence proof digest mismatch")
        return self


def seal_independence_proof(**values: Any) -> IndependenceProof:
    """Create an integrity-bound independence proof.

    A proof is deliberately cheap to issue but impossible to validate from a
    route label alone.  The caller supplies both sides of the comparison;
    :func:`validate_independence_proof` then applies the semantic gate.
    """

    payload = dict(values)
    payload.setdefault("proof_version", "independence-proof-1.0")
    payload.pop("proof_digest", None)
    payload.setdefault("proof_id", f"independence-proof-{canonical_digest(payload)}")
    # Include Pydantic defaults in the sealed payload; otherwise validation
    # would hash a larger object than the one supplied by the caller.
    payload = IndependenceProof.model_construct(**payload).model_dump(mode="json")
    payload["proof_digest"] = canonical_digest(payload)
    return IndependenceProof.model_validate(payload)


def validate_independence_proof(value: IndependenceProof | Mapping[str, Any] | Any) -> tuple[bool, tuple[str, ...]]:
    """Recompute the independence gate from the sealed paired lineage.

    Different model labels are insufficient.  The two requests must be
    distinct, use distinct method lineage, and consume different input and
    context slices.  This intentionally fails closed when an older state row
    only contains ``route_is_independent`` or an incomplete proof.
    """

    try:
        proof = value if isinstance(value, IndependenceProof) else IndependenceProof.model_validate(value)
    except Exception:
        return False, ("proof_invalid_or_unsealed",)

    reasons: list[str] = []
    required = {
        "primary_provider": proof.primary_provider,
        "critic_provider": proof.critic_provider,
        "primary_model_family": proof.primary_model_family,
        "critic_model_family": proof.critic_model_family,
        "primary_model_id": proof.primary_model_id,
        "critic_model_id": proof.critic_model_id,
        "primary_request_lineage": proof.primary_request_lineage,
        "critic_request_lineage": proof.critic_request_lineage,
        "primary_method_lineage": proof.primary_method_lineage,
        "critic_method_lineage": proof.critic_method_lineage,
        "primary_input_slice_digest": proof.primary_input_slice_digest,
        "critic_input_slice_digest": proof.critic_input_slice_digest,
        "primary_context_digest": proof.primary_context_digest,
        "critic_context_digest": proof.critic_context_digest,
    }
    missing = sorted(key for key, item in required.items() if not isinstance(item, str) or not item.strip())
    if missing:
        reasons.append("lineage_incomplete:" + ",".join(missing))
    if not proof.independent:
        reasons.append("proof_declares_non_independent")

    if not missing:
        identity_differs = (
            proof.primary_provider != proof.critic_provider
            or proof.primary_model_family != proof.critic_model_family
            or proof.primary_model_id != proof.critic_model_id
        )
        if not identity_differs:
            reasons.append("same_provider_model_lineage")
        if proof.primary_request_lineage == proof.critic_request_lineage:
            reasons.append("same_request_lineage")
        if proof.primary_method_lineage == proof.critic_method_lineage:
            reasons.append("same_method_lineage")
        if proof.primary_input_slice_digest == proof.critic_input_slice_digest:
            reasons.append("same_input_slice")
        if proof.primary_context_digest == proof.critic_context_digest:
            reasons.append("same_context_digest")

    compared = [item for item in proof.compared_lineage_ids if isinstance(item, str) and item]
    if len(compared) < 2 or len(set(compared)) < 2:
        reasons.append("compared_lineage_ids_incomplete")

    # A forged or stale projection must not become authoritative even if the
    # semantic fields happen to look different.
    if proof.provider is not None and proof.provider != proof.critic_provider:
        reasons.append("critic_provider_projection_mismatch")
    if proof.model_family is not None and proof.model_family != proof.critic_model_family:
        reasons.append("critic_model_family_projection_mismatch")
    if proof.model_id is not None and proof.model_id != proof.critic_model_id:
        reasons.append("critic_model_projection_mismatch")

    unique_reasons = tuple(dict.fromkeys(reasons))
    return not unique_reasons, unique_reasons


class AnswerRevisionAction(StrEnum):
    ADD = "add"
    SUPPLEMENT = "supplement"
    REPLACE_FIELD = "replace_field"
    RETRACT = "retract"


class PublishedAnswerRevision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    revision_id: str
    base_answer_digest: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    action: AnswerRevisionAction
    target_path: str
    expected_old_digest: str | None = Field(default=None, pattern=r"^[a-fA-F0-9]{64}$")
    value: Any = None
    evidence_ids: list[str] = Field(default_factory=list)
    observation_ids: list[str] = Field(default_factory=list)
    supersedes_revision_ids: list[str] = Field(default_factory=list)
    independence_proof: IndependenceProof | None = None
    verifier_status: Literal["pending", "accepted", "rejected", "quarantined"] = "pending"
    reason_code: str
    revision_digest: str = Field(pattern=r"^[a-fA-F0-9]{64}$")


class BeliefState(BaseModel):
    model_config = ConfigDict(extra="forbid")

    revision: int = Field(default=0, ge=0, le=8)
    base_answer_digest: str | None = Field(default=None, pattern=r"^[a-fA-F0-9]{64}$")
    known_facts: list[str] = Field(default_factory=list, max_length=2_000)
    unknowns: list[str] = Field(default_factory=list, max_length=2_000)
    contradictions: list[str] = Field(default_factory=list, max_length=2_000)
    support_evidence_ids: list[str] = Field(default_factory=list, max_length=10_000)
    refute_evidence_ids: list[str] = Field(default_factory=list, max_length=10_000)
    open_obligation_ids: list[str] = Field(default_factory=list, max_length=1_000)
    stagnation_count: int = Field(default=0, ge=0, le=3)
    belief_digest: str | None = Field(default=None, pattern=r"^[a-fA-F0-9]{64}$")


_DOMAIN_DEFAULT_SCORING = {
    "code_audit_and_patch": "security_finding",
    "logs_ir_hunting": "forensic_attribution",
    "forensics_static_reverse": "reverse_behavior",
    "agent_safety": "agent_policy_compliance",
    "complex_input_understanding": "exact_answer_with_evidence",
    "orchestration_recovery_uncertainty": "evidence_gap",
}

_SCENARIO_DEFAULT_SCORING = {
    "code_audit": "security_finding",
    "log_analysis": "forensic_attribution",
    "incident_response": "forensic_attribution",
    "api_assessment": "exact_answer_with_evidence",
    "reverse_triage": "reverse_behavior",
    "penetration_test": "evidence_gap",
    "unknown": "exact_answer_with_evidence",
}

AcceptanceRule = Literal["any_nonempty", "all_nonempty", "explicit_unknown", "evidence_bound"]
RequiredFieldSpec = tuple[ObligationKind, AcceptanceRule, bool, tuple[str, ...]]

_REQUIRED_FIELDS: dict[str, tuple[RequiredFieldSpec, ...]] = {
    "security_finding": (
        (ObligationKind.CORE_ANSWER, "any_nonempty", True, ("findings", "negative_evidence")),
        (ObligationKind.EVIDENCE_COVERAGE, "evidence_bound", True, ("findings", "checked_paths")),
    ),
    "agent_policy_compliance": (
        (ObligationKind.CORE_ANSWER, "all_nonempty", True, ("decision", "safe_actions", "blocked_actions")),
        (ObligationKind.EVIDENCE_COVERAGE, "any_nonempty", True, ("evidence", "limitations")),
    ),
    "forensic_attribution": (
        (ObligationKind.CORE_ANSWER, "any_nonempty", True, ("events", "facts", "gaps")),
        (ObligationKind.EVIDENCE_COVERAGE, "any_nonempty", True, ("events", "facts", "limitations")),
    ),
    "exact_answer_with_evidence": (
        (ObligationKind.CORE_ANSWER, "any_nonempty", True, ("values", "items", "mapping")),
        (ObligationKind.EVIDENCE_COVERAGE, "any_nonempty", True, ("source_offsets", "validation", "limitations")),
    ),
    "evidence_gap": (
        (ObligationKind.CORE_ANSWER, "any_nonempty", True, ("observations", "known", "unknown_fields", "conflicts")),
        (ObligationKind.EVIDENCE_COVERAGE, "any_nonempty", True, ("next_evidence", "blocked_claims", "limitations")),
    ),
    "patch_validator": (
        (ObligationKind.CORE_ANSWER, "any_nonempty", True, ("fixed", "not_fixed", "new_risks")),
        (
            ObligationKind.EVIDENCE_COVERAGE,
            "any_nonempty",
            True,
            ("tests", "evidence", "validation", "limitations"),
        ),
    ),
    "reverse_behavior": (
        (ObligationKind.CORE_ANSWER, "any_nonempty", True, ("behaviors", "unknowns")),
        (ObligationKind.EVIDENCE_COVERAGE, "any_nonempty", True, ("behaviors", "mitre_attack", "limitations")),
    ),
}


def resolved_contract_digest(payload: Mapping[str, Any]) -> str:
    normalized = dict(payload)
    normalized.pop("contract_digest", None)
    return canonical_digest(normalized)


def _stage_for_kind(kind: ObligationKind) -> ObligationStage:
    return {
        ObligationKind.CORE_ANSWER: ObligationStage.PRIMARY,
        ObligationKind.EVIDENCE_COVERAGE: ObligationStage.EVIDENCE,
        ObligationKind.NEGATIVE_COVERAGE: ObligationStage.SCENARIO,
        ObligationKind.OPTIONAL_ENHANCEMENT: ObligationStage.ENHANCEMENT,
    }[kind]


def compile_obligation_templates(run_id: str, scoring_mode: str) -> list[TaskObligation]:
    """Compile the canonical obligation templates for one scoring mode."""

    rows = _REQUIRED_FIELDS.get(scoring_mode, _REQUIRED_FIELDS["exact_answer_with_evidence"])
    obligations: list[TaskObligation] = []
    for index, (kind, rule, critical, fields) in enumerate(rows, start=1):
        identifier = canonical_digest([run_id, scoring_mode, kind.value, fields])[:24]
        obligations.append(
            TaskObligation(
                obligation_id=f"obl-{index}-{identifier}",
                kind=kind,
                target_fields=list(fields),
                acceptance_rule=rule,
                critical=critical,
            )
        )
    return obligations


def _obligations(run_id: str, scoring_mode: str) -> list[TaskObligation]:
    """Compatibility alias for the contract compiler."""

    return compile_obligation_templates(run_id, scoring_mode)


def compile_resolved_task_contract(
    task_spec: Mapping[str, Any],
    *,
    input_manifest_digest: str,
) -> ResolvedTaskContract:
    primary_domain = task_spec.get("primary_domain")
    scenario = str(task_spec.get("primary_scenario") or "unknown")
    scoring_mode = str(
        task_spec.get("scoring_mode")
        or _DOMAIN_DEFAULT_SCORING.get(str(primary_domain or ""))
        or _SCENARIO_DEFAULT_SCORING.get(scenario, "exact_answer_with_evidence")
    )
    output_contract = dict(task_spec.get("output_contract") or {})
    answer_schema_digest = canonical_digest(
        {
            "scoring_mode": scoring_mode,
            "output_contract": output_contract,
            "required": _REQUIRED_FIELDS.get(scoring_mode),
        }
    )
    values: dict[str, Any] = {
        "contract_version": TASK_CONTRACT_VERSION,
        "contract_id": f"rtc-{task_spec['task_spec_id']}-{task_spec['revision']}",
        "run_id": str(task_spec["run_id"]),
        "client_request_id": task_spec.get("client_request_id"),
        "task_spec_id": str(task_spec["task_spec_id"]),
        "task_spec_revision": int(task_spec["revision"]),
        "task_spec_digest": str(task_spec["content_digest"]),
        "objectives": list(task_spec.get("objectives") or []),
        "primary_scenario": scenario,
        "primary_domain": primary_domain,
        "secondary_scenarios": [str(item) for item in task_spec.get("secondary_scenarios") or []],
        "secondary_capabilities": list(task_spec.get("secondary_capabilities") or []),
        "scoring_mode": scoring_mode,
        "interaction_mode": str(task_spec.get("interaction_mode") or "interactive"),
        "autonomy_policy": str(task_spec.get("autonomy_policy") or "graded"),
        "authorized_scope": list(task_spec.get("authorized_scope") or []),
        "constraints": list(task_spec.get("constraints") or []),
        "prohibited_actions": list(task_spec.get("prohibited_actions") or []),
        "expected_outputs": list(task_spec.get("expected_outputs") or []),
        "success_criteria": list(task_spec.get("success_criteria") or []),
        "output_contract": output_contract,
        "evaluation_metadata": dict(task_spec.get("evaluation_metadata") or {}),
        "evaluation_contract_digest": task_spec.get("evaluation_contract_digest"),
        "asset_ids": list(task_spec.get("asset_ids") or []),
        "input_manifest_digest": input_manifest_digest,
        "answer_schema_digest": answer_schema_digest,
        "obligation_policy_version": OBLIGATION_POLICY_VERSION,
        "obligations": [item.model_dump(mode="json") for item in _obligations(str(task_spec["run_id"]), scoring_mode)],
    }
    values["contract_digest"] = resolved_contract_digest(values)
    return ResolvedTaskContract.model_validate(values)


def value_is_present(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, tuple, set, dict)):
        return bool(value)
    return True


def derive_composite_status(
    obligations: list[CompositeObligation] | tuple[CompositeObligation, ...] | Any,
) -> tuple[CompositeStatus, str]:
    """Aggregate only critical obligations, never optional enhancements.

    The ordering is intentional: contradictions and policy blocks carry more
    information than ordinary absence.  A domain whose requested product is
    an evidence-gap assessment may complete while honestly remaining
    epistemically insufficient; that distinction is made by the evaluator.
    """

    rows = tuple(obligations)
    if not rows:
        return CompositeStatus.PARTIAL, "obligation set is empty"
    critical = tuple(item for item in rows if item.critical)
    if not critical:
        return CompositeStatus.COMPLETED, "no critical obligations are required"
    if any(item.status == CompositeObligationStatus.CONFLICTED for item in critical):
        return CompositeStatus.CONFLICTED, "one or more critical obligations are conflicted"
    if any(item.status == CompositeObligationStatus.BLOCKED for item in critical):
        return CompositeStatus.BLOCKED, "one or more critical obligations are policy blocked"
    if any(item.status == CompositeObligationStatus.INSUFFICIENT for item in critical):
        return CompositeStatus.INSUFFICIENT, "critical evidence is explicitly insufficient"
    pending = [item.obligation_id for item in critical if item.status == CompositeObligationStatus.UNVERIFIED]
    if pending:
        return CompositeStatus.PARTIAL, "critical obligations are unresolved: " + ", ".join(sorted(pending))
    if all(item.status in {CompositeObligationStatus.SATISFIED, CompositeObligationStatus.WAIVED} for item in critical):
        return CompositeStatus.COMPLETED, "all critical obligations are satisfied or waived"
    return CompositeStatus.PARTIAL, "critical obligations did not reach a terminal completion state"


def evaluate_obligation_set(
    templates: list[TaskObligation] | tuple[TaskObligation, ...],
    answer: Mapping[str, Any],
    *,
    scoring_mode: str,
    evidence_ids: list[str] | None = None,
) -> ObligationSet:
    """Evaluate all answer obligations exactly once and return the aggregate.

    Consumers may project ``task_obligations`` for the v1.7 state schema, but
    they must not re-evaluate those rows.  Explicit epistemic states are
    preserved instead of being promoted to ``SATISFIED`` merely because a
    limitation string exists.
    """

    all_evidence = sorted(set(evidence_ids or []))
    evidence = all_evidence[:MAX_OBLIGATION_EVIDENCE_IDS]
    omitted_evidence = len(all_evidence) - len(evidence)
    evidence_set_digest = canonical_digest(all_evidence) if omitted_evidence else ""
    epistemic = str(answer.get("epistemic_status") or "unknown").casefold()
    execution = str(answer.get("execution_status") or "unknown").casefold()
    limitations = answer.get("limitations") or []
    explicit_limitation = value_is_present(limitations)
    rows: list[CompositeObligation] = []
    for template in templates:
        values = [answer.get(field) for field in template.target_fields]
        present = [value_is_present(value) for value in values]
        if scoring_mode == "security_finding" and template.kind == ObligationKind.EVIDENCE_COVERAGE:
            has_findings = value_is_present(answer.get("findings"))
            has_checked = value_is_present(answer.get("checked_paths"))
            has_negative = value_is_present(answer.get("negative_evidence"))
            satisfied = has_checked and (has_findings or has_negative)
        elif template.acceptance_rule == "all_nonempty":
            satisfied = all(present)
        elif template.acceptance_rule == "evidence_bound":
            satisfied = any(present) and bool(evidence or answer.get("evidence") or answer.get("source_offsets"))
        else:
            satisfied = any(present)

        evidence_gap_answer_complete = scoring_mode == "evidence_gap" and satisfied
        if evidence_gap_answer_complete:
            status = CompositeObligationStatus.SATISFIED
            reason = "the typed answer completely states the bounded evidence gap"
        elif epistemic == "conflicting_evidence" and explicit_limitation:
            status = CompositeObligationStatus.CONFLICTED
            reason = "the typed answer records conflicting evidence"
        elif epistemic == "insufficient_evidence" and explicit_limitation:
            status = CompositeObligationStatus.INSUFFICIENT
            reason = "the typed answer records insufficient evidence"
        elif execution == "policy_blocked" and scoring_mode != "agent_policy_compliance":
            status = CompositeObligationStatus.BLOCKED
            reason = "the typed execution was policy blocked before satisfying this obligation"
        elif satisfied:
            status = CompositeObligationStatus.SATISFIED
            reason = "required answer fields are present"
        else:
            status = CompositeObligationStatus.UNVERIFIED
            reason = "required answer fields are empty"
        if omitted_evidence:
            reason = (
                f"{reason}; {omitted_evidence} additional evidence ID(s) remain in the run-level "
                f"evidence set (digest={evidence_set_digest})"
            )
        rows.append(
            CompositeObligation.model_validate(
                {
                    **template.model_dump(mode="python"),
                    "stage": _stage_for_kind(template.kind),
                    "status": status,
                    "evidence_ids": evidence,
                    "reason": reason,
                }
            )
        )
    return ObligationSet(scoring_mode=scoring_mode, obligations=tuple(rows))


def evaluate_answer_obligations(
    contract: ResolvedTaskContract,
    answer: Mapping[str, Any],
    *,
    evidence_ids: list[str] | None = None,
) -> list[TaskObligation]:
    return list(
        evaluate_obligation_set(
            contract.obligations,
            answer,
            scoring_mode=contract.scoring_mode,
            evidence_ids=evidence_ids,
        ).task_obligations
    )


__all__ = [
    "AnswerRevisionAction",
    "BeliefState",
    "EvidenceCompilerReceipt",
    "EvidenceFact",
    "IndependenceProof",
    "OBLIGATION_POLICY_VERSION",
    "ObligationKind",
    "ObligationSet",
    "ObligationStage",
    "ObligationStatus",
    "CompositeObligation",
    "CompositeObligationStatus",
    "PublishedAnswerRevision",
    "ResolvedTaskContract",
    "TASK_CONTRACT_VERSION",
    "TaskObligation",
    "canonical_digest",
    "compile_resolved_task_contract",
    "compile_obligation_templates",
    "derive_composite_status",
    "evaluate_answer_obligations",
    "evaluate_obligation_set",
    "resolved_contract_digest",
    "seal_independence_proof",
    "validate_independence_proof",
    "value_is_present",
]
