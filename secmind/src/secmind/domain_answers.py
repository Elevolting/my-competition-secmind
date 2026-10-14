"""Typed, domain-preserving public answers for the v0.8.3 Primary lane.

The provider still returns one backward-compatible universal object.  This
module deterministically projects it into a discriminated domain answer before
the immutable baseline is published.  It never invents semantic values: fields
not present in the provider response remain empty/unknown.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from secmind.domain_semantics import (
    ApiGraph,
    IncidentResponsePlan,
    RecordLocator,
    TimelineGraph,
    canonicalize_timeline_event_rows,
    normalize_api_graph,
    normalize_incident_plan,
    normalize_timeline_graph,
)
from secmind.schemas import RunStatus
from secmind.task_contract import ObligationStatus, TaskObligation, value_is_present

_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")


class ArtifactDigest(BaseModel):
    """One content-addressed artifact digest with explicit raw/derived role."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    sha256: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    artifact_ref: str | None = Field(default=None, min_length=1, max_length=512)
    role: Literal["raw", "derived", "input", "output", "member", "unknown"] = "unknown"
    media_type: str | None = Field(default=None, max_length=200)
    size_bytes: int | None = Field(default=None, ge=0)
    parent_sha256: tuple[str, ...] = Field(default_factory=tuple, max_length=100)

    @model_validator(mode="after")
    def normalize_digest(self) -> ArtifactDigest:
        for digest in self.parent_sha256:
            if _SHA256.fullmatch(digest) is None:
                raise ValueError("artifact parent digests must be SHA-256 values")
        object.__setattr__(self, "sha256", self.sha256.lower())
        object.__setattr__(self, "parent_sha256", tuple(item.lower() for item in self.parent_sha256))
        return self


class ProcessProvenance(BaseModel):
    """Deterministic process lineage for a semantic projection."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    process_id: str = Field(min_length=1, max_length=256)
    process_version: str = Field(min_length=1, max_length=128)
    operation: str = Field(min_length=1, max_length=256)
    input_artifact_digests: tuple[str, ...] = Field(default_factory=tuple, max_length=256)
    output_artifact_digests: tuple[str, ...] = Field(default_factory=tuple, max_length=256)
    parent_process_ids: tuple[str, ...] = Field(default_factory=tuple, max_length=64)
    rule_bundle_digest: str | None = Field(default=None, pattern=r"^[a-fA-F0-9]{64}$")
    parser_id: str | None = Field(default=None, max_length=256)
    parser_version: str | None = Field(default=None, max_length=128)
    network_access_performed: bool = False
    model_calls: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def normalize_digests(self) -> ProcessProvenance:
        for digest in (*self.input_artifact_digests, *self.output_artifact_digests):
            if _SHA256.fullmatch(digest) is None:
                raise ValueError("process artifact digests must be SHA-256 values")
        object.__setattr__(self, "input_artifact_digests", tuple(item.lower() for item in self.input_artifact_digests))
        object.__setattr__(
            self,
            "output_artifact_digests",
            tuple(item.lower() for item in self.output_artifact_digests),
        )
        return self


class EvidenceClosure(BaseModel):
    """Evidence references and provenance needed to replay one semantic row."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    evidence_ids: tuple[str, ...] = Field(default_factory=tuple, max_length=2_000)
    record_locators: tuple[RecordLocator, ...] = Field(default_factory=tuple, max_length=2_000)
    raw_artifact_digests: tuple[str, ...] = Field(default_factory=tuple, max_length=256)
    derived_artifact_digests: tuple[str, ...] = Field(default_factory=tuple, max_length=256)
    complete: bool = False
    missing: tuple[str, ...] = Field(default_factory=tuple, max_length=256)

    @model_validator(mode="after")
    def normalize_and_check(self) -> EvidenceClosure:
        for digest in (*self.raw_artifact_digests, *self.derived_artifact_digests):
            if _SHA256.fullmatch(digest) is None:
                raise ValueError("evidence closure artifact digests must be SHA-256 values")
        if self.complete and (
            not self.evidence_ids or not self.record_locators or not self.raw_artifact_digests or self.missing
        ):
            raise ValueError(
                "complete evidence closure requires evidence IDs, record locators, raw digests, and no missing fields"
            )
        object.__setattr__(self, "raw_artifact_digests", tuple(item.lower() for item in self.raw_artifact_digests))
        object.__setattr__(
            self,
            "derived_artifact_digests",
            tuple(item.lower() for item in self.derived_artifact_digests),
        )
        return self


def _semantic_api_endpoints(facts: tuple[dict[str, Any], ...]) -> tuple[dict[str, Any], ...]:
    rows: list[dict[str, Any]] = []
    for fact in facts:
        if fact.get("method") and (fact.get("path") or fact.get("url_template")):
            rows.append(dict(fact))
        value = fact.get("value")
        if not isinstance(value, Mapping):
            continue
        endpoints = value.get("endpoints")
        if isinstance(endpoints, list):
            rows.extend(dict(item) for item in endpoints if isinstance(item, Mapping))
    return tuple(rows[:2_000])


def _semantic_incident_rows(
    facts: tuple[dict[str, Any], ...],
    conflicts: tuple[dict[str, Any], ...],
) -> tuple[tuple[dict[str, Any], ...], tuple[dict[str, Any], ...]]:
    actions: list[dict[str, Any]] = []
    hypotheses: list[dict[str, Any]] = []
    for fact in facts:
        value = fact.get("value")
        if isinstance(value, Mapping) and value.get("action_id") and value.get("rollback_condition"):
            actions.append(dict(value))
        elif fact.get("action_id") and fact.get("rollback_condition"):
            actions.append(dict(fact))
        if fact.get("hypothesis_id") or fact.get("claim_id"):
            hypotheses.append(dict(fact))
    for conflict in conflicts:
        if conflict.get("hypothesis_id") or conflict.get("claim_id"):
            hypotheses.append(dict(conflict))
    return tuple(actions[:2_000]), tuple(hypotheses[:1_000])


class ScenarioSemanticOutput(BaseModel):
    """Strict cross-domain semantic projection consumed by downstream lanes."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    scenario: str = Field(min_length=1, max_length=128)
    answer_kind: str = Field(min_length=1, max_length=128)
    status: Literal["success", "partial", "policy_blocked", "unknown"]
    facts: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=2_000)
    unknowns: tuple[str, ...] = Field(default_factory=tuple, max_length=2_000)
    conflicts: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=1_000)
    events: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=2_000)
    endpoint_graph: dict[str, Any] = Field(default_factory=dict)
    policy_decisions: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=1_000)
    timeline_graph: TimelineGraph | None = None
    api_graph: ApiGraph | None = None
    incident_response: IncidentResponsePlan | None = None
    evidence_closure: EvidenceClosure
    process_provenance: ProcessProvenance

    @model_validator(mode="after")
    def hydrate_typed_graphs(self) -> ScenarioSemanticOutput:
        timeline_graph = self.timeline_graph
        api_graph = self.api_graph
        incident_response = self.incident_response
        if self.events:
            timeline_graph = normalize_timeline_graph(self.events, unknowns=self.unknowns)
        endpoints = _semantic_api_endpoints(self.facts)
        if endpoints:
            api_graph = normalize_api_graph(endpoints, unknowns=self.unknowns)
        actions, hypotheses = _semantic_incident_rows(self.facts, self.conflicts)
        if actions or hypotheses:
            incident_response = normalize_incident_plan(actions, hypotheses, unknowns=self.unknowns)
        object.__setattr__(self, "timeline_graph", timeline_graph)
        object.__setattr__(self, "api_graph", api_graph)
        object.__setattr__(self, "incident_response", incident_response)
        return self


class TypedSemanticDelta(BaseModel):
    """A non-code semantic delta; it is append-only and never an Anchor."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = "semantic-delta-1.0"
    delta_id: str = Field(min_length=1, max_length=256)
    run_id: str = Field(min_length=1, max_length=100)
    scenario: str = Field(min_length=1, max_length=128)
    answer_kind: str = Field(min_length=1, max_length=128)
    action: Literal["add", "supplement", "correct", "observe", "gap", "blocked"] = "observe"
    disposition: Literal["accepted", "rejected", "quarantined", "shadow"] = "accepted"
    semantic_digest: str = Field(default="0" * 64, pattern=r"^[a-fA-F0-9]{64}$")
    evidence_ids: tuple[str, ...] = Field(default_factory=tuple, max_length=2_000)
    finding_ids: tuple[str, ...] = Field(default_factory=tuple, max_length=1_000)
    facts: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=2_000)
    unknowns: tuple[str, ...] = Field(default_factory=tuple, max_length=2_000)
    conflicts: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=1_000)
    record_locators: tuple[RecordLocator, ...] = Field(default_factory=tuple, max_length=2_000)
    endpoint_graph: dict[str, Any] = Field(default_factory=dict)
    policy_decisions: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=1_000)
    timeline_graph: TimelineGraph | None = None
    api_graph: ApiGraph | None = None
    incident_response: IncidentResponsePlan | None = None
    raw_artifact_digests: tuple[str, ...] = Field(default_factory=tuple, max_length=256)
    derived_artifact_digests: tuple[str, ...] = Field(default_factory=tuple, max_length=256)
    process_provenance: ProcessProvenance
    evidence_closure: EvidenceClosure
    anchor_semantic_digest: str | None = Field(default=None, pattern=r"^[a-fA-F0-9]{64}$")
    anchor_preserved: bool = True
    admission_ready: bool = False
    source_content_trust: Literal["untrusted_data", "deterministic_projection", "unknown"] = "deterministic_projection"

    @model_validator(mode="after")
    def validate_closure(self) -> TypedSemanticDelta:
        if self.evidence_closure.evidence_ids and not set(self.evidence_closure.evidence_ids).issubset(
            set(self.evidence_ids)
        ):
            raise ValueError("semantic delta evidence closure references IDs outside evidence_ids")
        if self.raw_artifact_digests != self.evidence_closure.raw_artifact_digests:
            raise ValueError("semantic delta raw artifact digests must match its evidence closure")
        if self.derived_artifact_digests != self.evidence_closure.derived_artifact_digests:
            raise ValueError("semantic delta derived artifact digests must match its evidence closure")
        if self.admission_ready and (not self.anchor_preserved or not self.evidence_closure.complete):
            raise ValueError("admission-ready semantic delta requires preserved Anchor and complete evidence")
        timeline_graph = self.timeline_graph
        api_graph = self.api_graph
        incident_response = self.incident_response
        if self.answer_kind == "timeline" and self.facts:
            event_rows = tuple(
                row
                for row in self.facts
                if isinstance(row, dict) and (row.get("event_id") or row.get("event_type") or row.get("action_id"))
            )
            if event_rows:
                timeline_graph = normalize_timeline_graph(event_rows, unknowns=self.unknowns)
        endpoints = _semantic_api_endpoints(self.facts)
        if endpoints:
            api_graph = normalize_api_graph(endpoints, unknowns=self.unknowns)
        actions, hypotheses = _semantic_incident_rows(self.facts, self.conflicts)
        if actions or hypotheses:
            incident_response = normalize_incident_plan(actions, hypotheses, unknowns=self.unknowns)
        object.__setattr__(self, "timeline_graph", timeline_graph)
        object.__setattr__(self, "api_graph", api_graph)
        object.__setattr__(self, "incident_response", incident_response)
        return self


# Names used by different integration generations.  They intentionally point
# to the same strict model so an adapter cannot silently create a second delta
# dialect for one scenario.
DomainSemanticDelta = TypedSemanticDelta
SemanticDelta = TypedSemanticDelta
SemanticOutput = ScenarioSemanticOutput


def _present(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (Mapping, list, tuple, set)):
        return bool(value)
    return True


def _conclusive_completion_guard(
    answer: DomainAnswerBase,
    *groups: tuple[Literal["any", "all"], tuple[str, ...]],
) -> DomainAnswerBase:
    """Downgrade self-reported conclusive answers with empty critical fields.

    An explicit ``insufficient_evidence`` answer follows a separate unknown/gap
    contract and is not rewritten here.  This guard targets the unsafe state
    called out by P0-03: a provider saying ``completed`` while returning an
    empty domain payload.
    """

    if answer.execution_status not in {"success", "policy_blocked"} or answer.epistemic_status != "conclusive":
        return answer
    missing: list[str] = []
    for rule, fields in groups:
        presence = [_present(getattr(answer, field, None)) for field in fields]
        satisfied = all(presence) if rule == "all" else any(presence)
        if not satisfied:
            missing.append("|".join(fields))
    if not missing:
        return answer
    limitation = "critical_answer_fields_empty:" + ",".join(missing)
    object.__setattr__(answer, "execution_status", "partial")
    object.__setattr__(answer, "epistemic_status", "unknown")
    object.__setattr__(answer, "limitations", [*answer.limitations, limitation][:100])
    return answer


class DomainAnswerBase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    answer_kind: str
    task_id: str = Field(min_length=1, max_length=128)
    execution_status: Literal["success", "partial", "policy_blocked", "unknown"]
    epistemic_status: Literal["conclusive", "insufficient_evidence", "conflicting_evidence", "unknown"]
    executive_summary: str = Field(default="", max_length=4_000)
    limitations: list[str] = Field(default_factory=list, max_length=100)
    # ``unknowns`` is deliberately separate from limitations: a limitation is
    # an execution/coverage condition, while an unknown is a semantic field
    # that cannot be asserted from the supplied evidence.
    unknowns: list[str] = Field(default_factory=list, max_length=2_000)
    semantic_output: ScenarioSemanticOutput | None = None
    semantic_delta: TypedSemanticDelta | None = None
    extensions: dict[str, Any] = Field(default_factory=dict)


class FindingAnswer(DomainAnswerBase):
    answer_kind: Literal["finding"] = "finding"
    findings: list[dict[str, Any]] = Field(default_factory=list, max_length=100)
    checked_paths: list[str] = Field(default_factory=list, max_length=500)
    negative_evidence: list[dict[str, Any] | str] = Field(default_factory=list, max_length=100)
    patches: list[dict[str, Any] | str] = Field(default_factory=list, max_length=100)

    @model_validator(mode="after")
    def validate_completion(self) -> FindingAnswer:
        guarded = _conclusive_completion_guard(self, ("any", ("findings", "negative_evidence")))
        if guarded.execution_status == "success" and guarded.epistemic_status == "conclusive":
            has_findings = bool(self.findings)
            negative_complete = bool(self.checked_paths and self.negative_evidence)
            if not has_findings and not negative_complete:
                object.__setattr__(self, "execution_status", "partial")
                object.__setattr__(self, "epistemic_status", "unknown")
                object.__setattr__(
                    self,
                    "limitations",
                    [*self.limitations, "critical_answer_fields_empty:checked_paths+negative_evidence"][:100],
                )
        return self


class PolicyDecisionAnswer(DomainAnswerBase):
    answer_kind: Literal["policy_decision"] = "policy_decision"
    decision: str | None = Field(default=None, max_length=2_000)
    safe_actions: list[str] = Field(default_factory=list, max_length=100)
    blocked_actions: list[str] = Field(default_factory=list, max_length=100)
    evidence: list[dict[str, Any] | str] = Field(default_factory=list, max_length=100)

    @model_validator(mode="after")
    def validate_completion(self) -> PolicyDecisionAnswer:
        _conclusive_completion_guard(
            self,
            ("all", ("decision", "safe_actions", "blocked_actions")),
            ("any", ("evidence", "limitations")),
        )
        return self


class TacticHypothesis(BaseModel):
    """Evidence-bound ATT&CK tactic interpretation for a timeline.

    A tactic is a higher-level interpretation of observed events and mapped
    techniques, not a fact that an attack succeeded.  Keeping that distinction
    in the typed contract prevents renderers from upgrading a low-confidence
    remote-service event into an unsupported incident conclusion.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    tactic_id: str = Field(pattern=r"^TA\d{4}$")
    tactic_name: str = Field(min_length=1, max_length=128)
    technique_ids: list[str] = Field(default_factory=list, max_length=100)
    evidence_ids: list[str] = Field(min_length=1, max_length=500)
    confidence: float = Field(ge=0, le=1)
    interpretation: Literal["evidence_bound_hypothesis", "low_confidence_context"]
    limitations: list[str] = Field(default_factory=list, max_length=20)


class TimelineAnswer(DomainAnswerBase):
    answer_kind: Literal["timeline"] = "timeline"
    facts: list[dict[str, Any] | str] = Field(default_factory=list, max_length=500)
    inferences: list[dict[str, Any] | str] = Field(default_factory=list, max_length=500)
    events: list[dict[str, Any]] = Field(default_factory=list, max_length=1_000)
    actors: list[dict[str, Any] | str] = Field(default_factory=list, max_length=200)
    iocs: list[dict[str, Any] | str] = Field(default_factory=list, max_length=500)
    techniques: list[dict[str, Any] | str] = Field(default_factory=list, max_length=200)
    # Additive v0.8.6 field.  Existing ``techniques`` consumers remain valid;
    # callers that understand tactic hypotheses gain an explicit, bounded and
    # evidence-linked interpretation instead of scraping prose.
    tactics: list[TacticHypothesis] = Field(default_factory=list, max_length=50)
    gaps: list[dict[str, Any] | str] = Field(default_factory=list, max_length=200)
    timeline_graph: TimelineGraph | None = None
    incident_response: IncidentResponsePlan | None = None

    @model_validator(mode="after")
    def validate_and_hydrate(self) -> TimelineAnswer:
        normalized_events = canonicalize_timeline_event_rows(self.events)
        object.__setattr__(self, "events", normalized_events)
        _conclusive_completion_guard(
            self,
            ("any", ("events", "facts", "gaps")),
            ("any", ("events", "facts", "limitations")),
        )
        if self.events or self.actors:
            explicit_flows = self.extensions.get("flows", [])
            flows = explicit_flows if isinstance(explicit_flows, list) else []
            object.__setattr__(
                self,
                "timeline_graph",
                normalize_timeline_graph(self.events, self.actors, flows, unknowns=self.unknowns),
            )
        actions = self.extensions.get("policy_actions", [])
        hypotheses = self.extensions.get("hypotheses", self.extensions.get("alternatives", []))
        if isinstance(actions, list) and isinstance(hypotheses, list) and (actions or hypotheses):
            object.__setattr__(
                self,
                "incident_response",
                normalize_incident_plan(actions, hypotheses, unknowns=self.unknowns),
            )
        return self


class EvidenceGapAnswer(DomainAnswerBase):
    answer_kind: Literal["evidence_gap"] = "evidence_gap"
    observations: list[dict[str, Any] | str] = Field(default_factory=list, max_length=500)
    known: list[dict[str, Any] | str] = Field(default_factory=list, max_length=500)
    unknown_fields: list[str] = Field(default_factory=list, max_length=500)
    conflicts: list[dict[str, Any] | str] = Field(default_factory=list, max_length=200)
    blocked_claims: list[dict[str, Any] | str] = Field(default_factory=list, max_length=200)
    next_evidence: list[dict[str, Any] | str] = Field(default_factory=list, max_length=200)
    incident_response: IncidentResponsePlan | None = None

    @model_validator(mode="after")
    def validate_and_hydrate(self) -> EvidenceGapAnswer:
        _conclusive_completion_guard(
            self,
            ("any", ("observations", "known", "unknown_fields", "conflicts")),
            ("any", ("next_evidence", "blocked_claims", "limitations")),
        )
        actions = self.extensions.get("policy_actions", [])
        hypotheses = self.extensions.get("hypotheses", self.extensions.get("alternatives", self.conflicts))
        if isinstance(actions, list) and isinstance(hypotheses, list) and (actions or hypotheses):
            object.__setattr__(
                self,
                "incident_response",
                normalize_incident_plan(actions, hypotheses, unknowns=self.unknowns),
            )
        return self


class ExactAnswer(DomainAnswerBase):
    answer_kind: Literal["exact"] = "exact"
    values: list[Any] | dict[str, Any] | str | int | float | bool | None = None
    items: list[Any] = Field(default_factory=list, max_length=1_000)
    mapping: dict[str, Any] = Field(default_factory=dict)
    derivation: list[dict[str, Any] | str] | str = Field(default_factory=list)
    source_offsets: list[dict[str, Any]] = Field(default_factory=list, max_length=1_000)
    validation: dict[str, Any] | list[Any] | str = Field(default_factory=dict)
    api_graph: ApiGraph | None = None

    @model_validator(mode="after")
    def validate_and_hydrate(self) -> ExactAnswer:
        _conclusive_completion_guard(
            self,
            ("any", ("values", "items", "mapping")),
            ("any", ("source_offsets", "validation", "limitations")),
        )
        endpoints: list[Any] = []
        if isinstance(self.values, Mapping) and isinstance(self.values.get("endpoints"), list):
            endpoints.extend(self.values["endpoints"])
        endpoints.extend(
            item for item in self.items if isinstance(item, Mapping) and item.get("method") and item.get("path")
        )
        for key in ("operations", "api_operations"):
            rows = self.extensions.get(key)
            if isinstance(rows, list):
                endpoints.extend(rows)
        if endpoints:
            object.__setattr__(self, "api_graph", normalize_api_graph(endpoints, unknowns=self.unknowns))
        return self


class PatchValidationAnswer(DomainAnswerBase):
    answer_kind: Literal["patch_validation"] = "patch_validation"
    fixed: list[dict[str, Any] | str] | bool = Field(default_factory=list)
    not_fixed: list[dict[str, Any] | str] = Field(default_factory=list, max_length=500)
    new_risks: list[dict[str, Any] | str] = Field(default_factory=list, max_length=500)
    changed_flows: list[dict[str, Any] | str] = Field(default_factory=list, max_length=500)
    tests: list[dict[str, Any] | str] = Field(default_factory=list, max_length=500)
    evidence: list[dict[str, Any] | str] = Field(default_factory=list, max_length=500)
    validation: dict[str, Any] | list[Any] | str = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_completion(self) -> PatchValidationAnswer:
        _conclusive_completion_guard(
            self,
            ("any", ("fixed", "not_fixed", "new_risks")),
            ("any", ("tests", "evidence", "validation", "limitations")),
        )
        return self


class ReverseBehaviorAnswer(DomainAnswerBase):
    answer_kind: Literal["reverse_behavior"] = "reverse_behavior"
    behaviors: list[dict[str, Any] | str] = Field(default_factory=list, max_length=500)
    persistence: list[dict[str, Any] | str] = Field(default_factory=list, max_length=200)
    injection: list[dict[str, Any] | str] = Field(default_factory=list, max_length=200)
    evasion: list[dict[str, Any] | str] = Field(default_factory=list, max_length=200)
    protocol: str | None = Field(default=None, max_length=500)
    c2: str | list[str] | None = None
    mitre_attack: list[str] = Field(default_factory=list, max_length=200)
    unknowns: list[str] = Field(default_factory=list, max_length=500)

    @model_validator(mode="after")
    def validate_completion(self) -> ReverseBehaviorAnswer:
        _conclusive_completion_guard(
            self,
            ("any", ("behaviors", "unknowns")),
            ("any", ("behaviors", "mitre_attack", "limitations")),
        )
        return self


DomainAnswer = (
    FindingAnswer
    | PolicyDecisionAnswer
    | TimelineAnswer
    | EvidenceGapAnswer
    | ExactAnswer
    | PatchValidationAnswer
    | ReverseBehaviorAnswer
)

_ANSWER_MODELS: dict[str, type[DomainAnswerBase]] = {
    "security_finding": FindingAnswer,
    "agent_policy_compliance": PolicyDecisionAnswer,
    "forensic_attribution": TimelineAnswer,
    "exact_answer_with_evidence": ExactAnswer,
    "evidence_gap": EvidenceGapAnswer,
    "patch_validator": PatchValidationAnswer,
    "reverse_behavior": ReverseBehaviorAnswer,
}

_UNTRUSTED_INSTRUCTION_DECISION = re.compile(
    r"\b(?:instructions?|prompts?|embedded|untrusted|exfil(?:trat(?:e|ion))?|data\s+exfiltration)\b",
    re.IGNORECASE,
)
_CANONICAL_POLICY_PREFIX = re.compile(
    r"^(?:ignore_untrusted_instruction|deny_unauthorized_action)\s*;\s*",
    re.IGNORECASE,
)
_DENY_BLOCK_PREFIX = re.compile(r"^DENY\s*/\s*BLOCK\s*:\s*", re.IGNORECASE)


def _canonical_policy_decision(decision: str, blocked_actions: list[Any]) -> str:
    """Return a stable public policy action while preserving provider prose.

    The provider receipt remains immutable.  This function only normalizes the
    discriminated public answer.  Typed ``blocked_actions`` are part of the
    policy schema, so they may select the portable action label; arbitrary
    context prose cannot.
    """

    blocked_text = " ".join(item for item in blocked_actions if isinstance(item, str))
    semantic_text = f"{decision} {blocked_text}"
    action = (
        "ignore_untrusted_instruction"
        if _UNTRUSTED_INSTRUCTION_DECISION.search(semantic_text) is not None
        else "deny_unauthorized_action"
    )
    rationale = _CANONICAL_POLICY_PREFIX.sub("", decision.strip(), count=1).strip()
    rationale = _DENY_BLOCK_PREFIX.sub("", rationale, count=1).strip()
    return f"{action}; DENY/BLOCK: {rationale}"


def normalize_domain_answer(scoring_mode: str | None, raw: dict[str, Any]) -> DomainAnswerBase:
    """Project the universal provider envelope into one strict domain schema.

    Fields belonging to another domain never become authoritative merely
    because the provider returned the universal compatibility shape. Meaningful
    legacy values remain auditable under ``extensions``.
    """

    mode = (scoring_mode or "security_finding").strip().casefold()
    model = _ANSWER_MODELS.get(mode)
    if model is None:
        raise ValueError(f"unsupported scoring_mode: {scoring_mode}")
    status = str(raw.get("status") or "partial")
    execution_status: Literal["success", "partial", "policy_blocked", "unknown"]
    if status in {"completed", "insufficient_evidence"}:
        execution_status = "success"
    elif status == "blocked":
        execution_status = "policy_blocked"
    elif status == "partial":
        execution_status = "partial"
    else:
        execution_status = "unknown"
    epistemic_status: Literal["conclusive", "insufficient_evidence", "conflicting_evidence", "unknown"]
    if status == "completed":
        epistemic_status = "conclusive"
    elif status == "insufficient_evidence":
        epistemic_status = "insufficient_evidence"
    else:
        epistemic_status = "unknown"
    allowed = set(model.model_fields)
    explicit_extensions = raw.get("extensions", {})
    if explicit_extensions is None:
        explicit_extensions = {}
    if not isinstance(explicit_extensions, Mapping):
        raise ValueError("extensions must be an object")
    legacy = {
        **{str(key): value for key, value in explicit_extensions.items()},
        **{
            key: value
            for key, value in raw.items()
            if key not in allowed and key not in {"status", "task_id", "extensions"} and value_is_present(value)
        },
    }
    normalized_raw = dict(raw)
    if mode == "evidence_gap":
        # The provider's execution status and the epistemic result are
        # independent.  A well-formed gap answer may be ``partial`` because
        # source bytes are absent while still conclusively establishing that
        # the requested attribution cannot be made.  Canonicalize that typed
        # meaning from explicit gap fields so harmless wording variation does
        # not turn the same evidence into ``unknown`` on another run.  The raw
        # provider receipt remains unchanged.
        if any(
            value_is_present(normalized_raw.get(field_name))
            for field_name in ("unknown_fields", "blocked_claims", "next_evidence", "unknowns")
        ):
            epistemic_status = "insufficient_evidence"
        elif value_is_present(normalized_raw.get("conflicts")):
            epistemic_status = "conflicting_evidence"
    # Keep the immutable provider receipt byte-for-byte unchanged while making
    # the typed policy projection unambiguous. A model can correctly describe
    # that an embedded action was ignored without using the scorer/operator's
    # action verb. Explicit blocked actions are sufficient provenance for this
    # deterministic label; no new policy conclusion is invented here.
    if mode == "agent_policy_compliance":
        decision = normalized_raw.get("decision")
        blocked_actions = normalized_raw.get("blocked_actions")
        if isinstance(decision, str) and decision.strip() and isinstance(blocked_actions, list) and blocked_actions:
            # ``blocked_actions`` is a typed provider field in the policy
            # schema, not a phrase inferred from free-form prose.  Treat it as
            # the authoritative block signal even when the rationale says
            # "will not", "must not", or another language-specific refusal
            # that the deliberately small lexical recognizer does not cover.
            # The immutable provider receipt is unchanged; only the public
            # discriminated projection receives the portable action label.
            normalized_raw["decision"] = _canonical_policy_decision(decision, blocked_actions)
    payload = {
        **{key: value for key, value in normalized_raw.items() if key in allowed and key != "extensions"},
        "answer_kind": model.model_fields["answer_kind"].default,
        "execution_status": execution_status,
        "epistemic_status": epistemic_status,
        "extensions": legacy,
    }
    return model.model_validate(payload)


def primary_answer_run_status(
    scoring_mode: str | None,
    answer_status: str,
    *,
    has_findings: bool,
    negative_coverage_complete: bool,
    obligations: list[TaskObligation] | None = None,
) -> RunStatus:
    """Separate successful execution from the answer's epistemic state."""

    if obligations is not None:
        critical = [item for item in obligations if item.critical]
        unresolved = [
            item for item in critical if item.status not in {ObligationStatus.SATISFIED, ObligationStatus.WAIVED}
        ]
        if unresolved:
            return RunStatus.PARTIAL
        if critical:
            return RunStatus.COMPLETED
    mode = scoring_mode or "security_finding"
    if mode == "security_finding":
        complete = answer_status == "completed" and (has_findings or negative_coverage_complete)
    elif mode == "agent_policy_compliance":
        # A safe refusal plus an explicit statement that the requested fact is
        # absent is a fully executed policy answer, not a product failure.
        complete = answer_status in {"completed", "blocked", "insufficient_evidence"}
    elif mode == "evidence_gap":
        complete = answer_status in {"completed", "insufficient_evidence"}
    else:
        # Execution success and epistemic certainty are independent. A static
        # forensic, reverse, patch, or exact-answer task that exhaustively says
        # the supplied bytes are insufficient has completed its contract; the
        # typed answer still exposes ``epistemic_status=insufficient_evidence``.
        complete = answer_status in {"completed", "insufficient_evidence"}
    return RunStatus.COMPLETED if complete else RunStatus.PARTIAL


__all__ = [
    "ApiGraph",
    "ArtifactDigest",
    "DomainAnswer",
    "DomainAnswerBase",
    "DomainSemanticDelta",
    "EvidenceClosure",
    "EvidenceGapAnswer",
    "ExactAnswer",
    "FindingAnswer",
    "IncidentResponsePlan",
    "PatchValidationAnswer",
    "PolicyDecisionAnswer",
    "ProcessProvenance",
    "RecordLocator",
    "ReverseBehaviorAnswer",
    "ScenarioSemanticOutput",
    "SemanticDelta",
    "SemanticOutput",
    "TacticHypothesis",
    "TimelineAnswer",
    "TimelineGraph",
    "TypedSemanticDelta",
    "normalize_domain_answer",
    "primary_answer_run_status",
]
