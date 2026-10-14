"""Obligation-driven, bounded cross-domain investigation plans.

The plan is deliberately a pure value object.  It does not execute a tool or
mutate ``AgentState``; the orchestrator may persist and dispatch the returned
actions at its own causal boundary.  Every action carries the references it
may read and produce so an observation can be replayed without treating a
receipt as an answer.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from secmind.schemas import AgentState, RiskLevel
from secmind.task_contract import AnswerRevisionAction, canonical_digest

GAP_PLAN_VERSION = "obligation-gap-plan-1.2"
SHA256_PATTERN = r"^[a-f0-9]{64}$"


class GapDomain(StrEnum):
    """Supported semantic domains for a bounded evidence-gap observation."""

    CODE = "code"
    LOG = "log"
    API = "api"
    EXACT = "exact"
    EVIDENCE_GAP = "evidence_gap"
    FORENSICS = "forensics"
    FIRMWARE = "firmware"
    PATCH = "patch"
    IR = "ir"


# This catalog is the capability boundary for cross-domain gap work.  It is a
# catalog, not an execution grant: the selected PlanStep/ToolManifest still
# has to authorize the concrete tool and risk level.
GAP_DOMAIN_CAPABILITIES: dict[GapDomain, tuple[str, ...]] = {
    GapDomain.CODE: ("code_context", "sast", "source_flow"),
    GapDomain.LOG: ("log_timeline_retrieval", "log_event_correlation", "evtx_analysis"),
    GapDomain.API: ("api_contract_retrieval", "api_auth_resource", "api_static_assessment"),
    GapDomain.EXACT: ("exact_value_retrieval", "bounded_extraction", "artifact_lookup"),
    GapDomain.EVIDENCE_GAP: (
        "evidence_context_retrieval",
        "evidence_verification",
        "context_retrieval",
    ),
    GapDomain.FORENSICS: ("forensic_artifact_retrieval", "pcap_analysis", "reverse_triage"),
    GapDomain.FIRMWARE: ("firmware_static_retrieval", "firmware_strings", "firmware_behavior"),
    GapDomain.PATCH: ("patch_evidence_retrieval", "patch_diff_analysis", "patch_validation"),
    GapDomain.IR: ("incident_evidence_retrieval", "incident_hypothesis", "incident_dry_run"),
}

GAP_DOMAIN_FIELD_PATHS: dict[GapDomain, str] = {
    GapDomain.CODE: "/findings",
    GapDomain.LOG: "/timeline",
    GapDomain.API: "/operations",
    GapDomain.EXACT: "/answer",
    GapDomain.EVIDENCE_GAP: "/evidence_gap",
    GapDomain.FORENSICS: "/behaviors",
    GapDomain.FIRMWARE: "/firmware",
    GapDomain.PATCH: "/patch_validation",
    GapDomain.IR: "/incident_response",
}

# EIRS domains are semantic coverage lanes.  CODE keeps its approved Broker
# capability; non-code lanes use distinct R0 retrieval capabilities so a
# generic worker can never impersonate a domain parser.
GAP_EXECUTION_CAPABILITIES: dict[GapDomain, str] = {
    GapDomain.CODE: "sast",
    GapDomain.LOG: "log_timeline_retrieval",
    GapDomain.API: "api_contract_retrieval",
    GapDomain.EXACT: "exact_value_retrieval",
    GapDomain.EVIDENCE_GAP: "evidence_context_retrieval",
    GapDomain.FORENSICS: "forensic_artifact_retrieval",
    GapDomain.FIRMWARE: "firmware_static_retrieval",
    GapDomain.PATCH: "patch_evidence_retrieval",
    GapDomain.IR: "incident_evidence_retrieval",
}

# These lanes are implemented as deterministic, read-only retrieval actions.
# They consume only already sealed state/CAS references and therefore do not
# masquerade as an external scanner or inherit the generic inventory/SAST
# authority.  CODE remains an ordinary ToolBroker lane.
CONTROLLED_RETRIEVAL_DOMAINS = frozenset(
    {
        GapDomain.LOG,
        GapDomain.API,
        GapDomain.EXACT,
        GapDomain.EVIDENCE_GAP,
        GapDomain.FORENSICS,
        GapDomain.FIRMWARE,
        GapDomain.PATCH,
        GapDomain.IR,
    }
)

_DOMAIN_ALIASES = {
    "code_audit": GapDomain.CODE,
    "log_analysis": GapDomain.LOG,
    "api_assessment": GapDomain.API,
    "exact_answer": GapDomain.EXACT,
    "evidence_gap": GapDomain.EVIDENCE_GAP,
    "reverse_triage": GapDomain.FORENSICS,
    "forensics_static_reverse": GapDomain.FORENSICS,
    "firmware": GapDomain.FIRMWARE,
    "patch": GapDomain.PATCH,
    "patch_validator": GapDomain.PATCH,
    "code_audit_and_patch": GapDomain.PATCH,
    "ir": GapDomain.IR,
    "incident_response": GapDomain.IR,
    "logs_ir_hunting": GapDomain.IR,
}


def normalize_gap_domain(value: GapDomain | str) -> GapDomain:
    """Normalize a scenario/domain label without accepting arbitrary routes."""

    if isinstance(value, GapDomain):
        return value
    normalized = str(value).strip().casefold().replace("-", "_")
    try:
        return GapDomain(normalized)
    except ValueError:
        try:
            return _DOMAIN_ALIASES[normalized]
        except KeyError as exc:
            raise ValueError(f"unsupported cross-domain gap domain: {value!r}") from exc


def supported_gap_domains() -> tuple[GapDomain, ...]:
    """Return the stable, reviewable domain catalog order."""

    return tuple(GapDomain)


def domain_for_capability(capability: str) -> GapDomain | None:
    """Resolve a catalog capability to its bounded semantic domain."""

    normalized = str(capability).strip().casefold()
    for domain, capabilities in GAP_DOMAIN_CAPABILITIES.items():
        if normalized in capabilities:
            return domain
    try:
        return normalize_gap_domain(normalized)
    except ValueError:
        return None


def execution_capability_for_domain(domain: GapDomain | str) -> str:
    """Return the approved execution or retrieval capability for one lane."""

    normalized = normalize_gap_domain(domain)
    return GAP_EXECUTION_CAPABILITIES[normalized]


class GapActionKind(StrEnum):
    RETRIEVE_CONTEXT = "retrieve_context"
    RETRIEVE_DOMAIN = "retrieve_domain"
    OBSERVE_DOMAIN = "observe_domain"
    RUN_TOOL = "run_tool"
    VERIFY_EVIDENCE = "verify_evidence"
    RESYNTHESIZE = "resynthesize"


class GapActionBudget(BaseModel):
    """Server-owned budget for one action.

    R2/R3 actions are intentionally rejected here.  A non-idempotent action
    can never receive more than one tool call, even if a caller supplies a
    larger requested budget.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_tool_calls: int = Field(default=0, ge=0, le=2)
    max_model_calls: int = Field(default=0, ge=0, le=1)
    max_runtime_ms: int = Field(default=0, ge=0, le=120_000)
    recovery_reserve_ms: int = Field(default=0, ge=0, le=120_000)
    idempotent: bool = True
    risk_level: RiskLevel = RiskLevel.R0

    @model_validator(mode="after")
    def enforce_bounded_risk_and_retry(self) -> GapActionBudget:
        if self.risk_level > RiskLevel.R1:
            raise ValueError("cross-domain gap actions are limited to R0/R1")
        if not self.idempotent and self.max_tool_calls > 1:
            raise ValueError("non-idempotent gap actions allow at most one tool call")
        if self.recovery_reserve_ms > self.max_runtime_ms:
            raise ValueError("recovery reserve cannot exceed the action runtime budget")
        return self


class FieldImpact(BaseModel):
    """Typed description of which answer field an observation may change."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    domain: GapDomain
    field_path: str = Field(min_length=2, max_length=512)
    impact_kind: Literal["add", "replace", "supplement", "retract", "annotate"] = "supplement"
    obligation_ids: list[str] = Field(default_factory=list, max_length=1_000)
    evidence_ids: list[str] = Field(default_factory=list, max_length=1_000)
    observation_refs: list[str] = Field(default_factory=list, max_length=1_000)
    before_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    after_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    rationale: str = Field(min_length=1, max_length=1_000)

    @model_validator(mode="after")
    def validate_json_pointer(self) -> FieldImpact:
        if not self.field_path.startswith("/"):
            raise ValueError("field impact path must be a JSON pointer")
        return self


class GapRevisionProposal(BaseModel):
    """A typed, not-yet-authoritative revision emitted by gap investigation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    proposal_id: str
    run_id: str
    base_answer_digest: str = Field(pattern=SHA256_PATTERN)
    action: AnswerRevisionAction
    target_path: str = Field(min_length=2, max_length=512)
    expected_old_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    value: Any = None
    obligation_ids: list[str] = Field(default_factory=list, max_length=1_000)
    evidence_ids: list[str] = Field(default_factory=list, max_length=1_000)
    observation_refs: list[str] = Field(default_factory=list, max_length=1_000)
    field_impacts: list[FieldImpact] = Field(min_length=1, max_length=128)
    reason_code: str = Field(min_length=1, max_length=160)
    status: Literal["proposed", "accepted", "rejected", "quarantined"] = "proposed"
    proposal_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_target(self) -> GapRevisionProposal:
        if not self.target_path.startswith("/"):
            raise ValueError("revision target must be a JSON pointer")
        return self


_MISSING = object()


def make_gap_revision_proposal(
    *,
    run_id: str,
    base_answer: Mapping[str, Any] | None = None,
    base_answer_digest: str | None = None,
    action: AnswerRevisionAction = AnswerRevisionAction.SUPPLEMENT,
    target_path: str = "/evidence_gap",
    value: Any = None,
    expected_old_value: Any = _MISSING,
    obligation_ids: Iterable[str] = (),
    evidence_ids: Iterable[str] = (),
    observation_refs: Iterable[str] = (),
    field_impacts: Iterable[FieldImpact] = (),
    reason_code: str = "bounded_cross_domain_observation",
    status: Literal["proposed", "accepted", "rejected", "quarantined"] = "proposed",
) -> GapRevisionProposal:
    """Build a replay-stable proposal without mutating an answer or state."""

    normalized_obligations = sorted({str(item) for item in obligation_ids if str(item).strip()})
    normalized_evidence = sorted({str(item) for item in evidence_ids if str(item).strip()})
    normalized_observations = sorted({str(item) for item in observation_refs if str(item).strip()})
    impacts = list(field_impacts)
    if not impacts:
        impacts = [
            FieldImpact(
                domain=GapDomain.EVIDENCE_GAP,
                field_path=target_path,
                obligation_ids=normalized_obligations,
                evidence_ids=normalized_evidence,
                observation_refs=normalized_observations,
                rationale=reason_code,
            )
        ]
    answer_digest = base_answer_digest or canonical_digest(dict(base_answer or {}))
    old_digest = None if expected_old_value is _MISSING else canonical_digest(expected_old_value)
    payload = {
        "run_id": run_id,
        "base_answer_digest": answer_digest,
        "action": action,
        "target_path": target_path,
        "expected_old_digest": old_digest,
        "value": value,
        "obligation_ids": normalized_obligations,
        "evidence_ids": normalized_evidence,
        "observation_refs": normalized_observations,
        "field_impacts": [item.model_dump(mode="json") for item in impacts],
        "reason_code": reason_code,
        "status": status,
    }
    proposal_id = "gap-revision-" + canonical_digest(payload)[:24]
    return GapRevisionProposal.model_validate(
        {
            **payload,
            "proposal_id": proposal_id,
            "proposal_digest": canonical_digest(payload),
        }
    )


class GapAction(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    action_id: str
    kind: GapActionKind
    obligation_ids: list[str] = Field(min_length=1, max_length=1_000)
    capability: str = Field(min_length=1, max_length=160)
    domain: GapDomain = GapDomain.EVIDENCE_GAP
    covered_domains: list[GapDomain] = Field(default_factory=list, max_length=9)
    tool_name: str | None = None
    depends_on: list[str] = Field(default_factory=list)
    max_tool_calls: int = Field(default=0, ge=0, le=2)
    budget: GapActionBudget | None = None
    input_refs: list[str] = Field(min_length=1, max_length=1_000)
    output_refs: list[str] = Field(min_length=1, max_length=1_000)
    status: Literal["completed", "proposed"] = "proposed"
    observation_refs: list[str] = Field(default_factory=list, max_length=1_000)
    result_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    revision_proposal_ids: list[str] = Field(default_factory=list, max_length=128)
    stop_condition: str = Field(min_length=1, max_length=1_000)

    @model_validator(mode="after")
    def validate_action_refs(self) -> GapAction:
        if any(not str(item).strip() for item in [*self.input_refs, *self.output_refs]):
            raise ValueError("gap action references cannot be empty")
        if self.budget is not None and self.max_tool_calls and self.max_tool_calls < self.budget.max_tool_calls:
            raise ValueError("action max_tool_calls cannot understate its budget")
        if self.kind == GapActionKind.RUN_TOOL and not self.tool_name:
            raise ValueError("RUN_TOOL action requires a tool name")
        return self


class GapPlan(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: str = GAP_PLAN_VERSION
    plan_id: str
    run_id: str
    contract_digest: str
    belief_digest: str
    max_actions: int = Field(ge=2, le=4)
    max_tool_calls: int = Field(ge=0, le=4)
    actions: list[GapAction] = Field(max_length=4)
    supported_domains: list[GapDomain] = Field(default_factory=lambda: list(GapDomain), max_length=9)
    revision_proposals: list[GapRevisionProposal] = Field(default_factory=list, max_length=128)
    stop_reasons: list[str]
    plan_digest: str

    @model_validator(mode="after")
    def validate_bounded_action_count(self) -> GapPlan:
        if not 2 <= len(self.actions) <= 4:
            raise ValueError("gap plans must contain between 2 and 4 actions")
        if self.max_tool_calls > 4:
            raise ValueError("gap plans cannot reserve more than four tool calls")
        return self


def _safe_risk(value: object) -> RiskLevel:
    if isinstance(value, RiskLevel):
        risk = value
    elif isinstance(value, int):
        try:
            risk = RiskLevel(value)
        except ValueError:
            risk = RiskLevel.R0
    elif isinstance(value, str):
        try:
            risk = RiskLevel(int(value))
        except (TypeError, ValueError):
            risk = RiskLevel.R0
    else:
        risk = RiskLevel.R0
    if risk > RiskLevel.R1:
        raise ValueError("cross-domain gap actions are limited to R0/R1")
    return risk


def _action_budget(
    *,
    max_tool_calls: int = 0,
    max_model_calls: int = 0,
    max_runtime_ms: int = 0,
    recovery_reserve_ms: int = 0,
    idempotent: bool = True,
    risk_level: RiskLevel | int = RiskLevel.R0,
) -> GapActionBudget:
    """Create a fail-closed budget, clamping non-idempotent retries to one."""

    calls = max(0, min(2, int(max_tool_calls)))
    if not idempotent:
        calls = min(1, calls)
    return GapActionBudget(
        max_tool_calls=calls,
        max_model_calls=max(0, min(1, int(max_model_calls))),
        max_runtime_ms=max(0, min(120_000, int(max_runtime_ms))),
        recovery_reserve_ms=max(0, min(120_000, int(recovery_reserve_ms))),
        idempotent=bool(idempotent),
        risk_level=_safe_risk(risk_level),
    )


def _domain_budget(
    domain: GapDomain,
    budgets: Mapping[str, GapActionBudget | Mapping[str, Any]] | None,
) -> GapActionBudget:
    configured = None if budgets is None else budgets.get(domain.value)
    if configured is None:
        return _action_budget(max_tool_calls=1, max_runtime_ms=30_000, recovery_reserve_ms=5_000)
    if isinstance(configured, GapActionBudget):
        if configured.risk_level > RiskLevel.R1:
            raise ValueError("cross-domain gap actions are limited to R0/R1")
        if not configured.idempotent and configured.max_tool_calls > 1:
            # A caller-supplied unsafe budget is reduced, never expanded.
            return configured.model_copy(update={"max_tool_calls": 1})
        return configured
    values = dict(configured)
    return _action_budget(
        max_tool_calls=values.get("max_tool_calls", 1),
        max_model_calls=values.get("max_model_calls", 0),
        max_runtime_ms=values.get("max_runtime_ms", 30_000),
        recovery_reserve_ms=values.get("recovery_reserve_ms", 5_000),
        idempotent=values.get("idempotent", True),
        risk_level=values.get("risk_level", RiskLevel.R0),
    )


def _infer_gap_domains(state: AgentState) -> tuple[GapDomain, ...]:
    configured = state.audit_coverage.get("gap_domains")
    values: list[GapDomain] = []
    if isinstance(configured, (list, tuple, set)):
        for item in configured:
            try:
                values.append(normalize_gap_domain(item))
            except ValueError:
                continue
    contract = state.resolved_task_contract
    scoring_domain: GapDomain | None = None
    if contract is not None:
        # The scoring contract is authoritative when one Scenario hosts more
        # than one semantic lane (for example exact extraction from logs or a
        # patch validation inside code_audit).  This prevents an EIRS run from
        # silently falling back to a generic code/inventory worker.
        scoring_domains = {
            "security_finding": GapDomain.CODE,
            "forensic_attribution": GapDomain.IR if state.scenario.value == "incident_response" else GapDomain.LOG,
            "exact_answer_with_evidence": GapDomain.EXACT,
            "evidence_gap": GapDomain.EVIDENCE_GAP,
            "patch_validator": GapDomain.PATCH,
            "reverse_behavior": GapDomain.FORENSICS,
        }
        scoring_domain = scoring_domains.get(str(contract.scoring_mode).casefold())
        if scoring_domain is not None and scoring_domain != GapDomain.EVIDENCE_GAP:
            values.append(scoring_domain)
    projection = state.audit_coverage.get("pre_primary_scenario_projection")
    scenario_value = projection.get("scenario") if isinstance(projection, dict) else state.scenario.value
    try:
        values.append(normalize_gap_domain(str(scenario_value)))
    except ValueError:
        pass
    if state.belief_state.open_obligation_ids:
        values.append(GapDomain.EVIDENCE_GAP)
    if scoring_domain == GapDomain.EVIDENCE_GAP:
        values.append(scoring_domain)
    if not values:
        values.append(GapDomain.EVIDENCE_GAP)
    return tuple(dict.fromkeys(values))


def _state_input_refs(state: AgentState) -> list[str]:
    refs: list[str] = []
    if state.repository_index is not None:
        refs.append(f"repository-index:{state.repository_index.digest}")
    if state.evidence_compiler_receipt is not None:
        refs.append(f"evidence-receipt:{state.evidence_compiler_receipt.output_digest}")
    refs.extend(f"evidence:{item.evidence_id}" for item in state.evidence[:1_000])
    refs.extend(f"context:{item.context_id}" for item in state.context_items[:1_000])
    refs.extend(f"artifact:{item.sha256.lower()}" for item in state.input_artifacts[:1_000])
    if state.report is not None:
        refs.append(f"answer:{canonical_digest(state.report.answer_payload)}")
    if not refs:
        return [f"run:{state.run_id}:immutable-input"]
    priority = {
        "repository-index": 0,
        "evidence-receipt": 1,
        "answer": 2,
        "evidence": 3,
        "context": 4,
        "artifact": 5,
    }
    return sorted(
        set(refs),
        key=lambda item: (priority.get(item.split(":", 1)[0], 99), item),
    )[:1_000]


def _plan_payload(
    *,
    plan_id: str,
    run_id: str,
    contract_digest: str,
    belief_digest: str,
    max_actions: int,
    actions: Sequence[GapAction],
    supported_domains: Sequence[GapDomain],
    revision_proposals: Sequence[GapRevisionProposal],
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "version": GAP_PLAN_VERSION,
        "plan_id": plan_id,
        "run_id": run_id,
        "contract_digest": contract_digest,
        "belief_digest": belief_digest,
        "max_actions": max_actions,
        "max_tool_calls": sum(
            item.budget.max_tool_calls if item.budget is not None else item.max_tool_calls for item in actions
        ),
        "actions": [item.model_dump(mode="json") for item in actions],
        "supported_domains": [item.value for item in supported_domains],
        "revision_proposals": [item.model_dump(mode="json") for item in revision_proposals],
        "stop_reasons": [
            "obligations_satisfied",
            "two_rounds_without_new_verified_evidence",
            "repeated_action_digest",
            "budget_or_recovery_reserve_reached",
            "non_idempotent_action_single_call_limit",
            "no_legal_evidence_path",
        ],
    }
    payload["plan_digest"] = canonical_digest(payload)
    return payload


def compile_cross_domain_gap_plan(
    state: AgentState,
    *,
    domains: Iterable[GapDomain | str] = (),
    max_actions: int = 4,
    input_refs: Mapping[str, Sequence[str]] | None = None,
    observation_refs: Mapping[str, Sequence[str]] | None = None,
    budgets: Mapping[str, GapActionBudget | Mapping[str, Any]] | None = None,
) -> GapPlan | None:
    """Compile a pure 2–4 action EIRS plan for one unresolved state.

    ``domains`` is a request for coverage, not permission to execute.  The
    returned plan includes the complete nine-domain catalog and records all
    requested domains in the revision's field-impact list; at most two domain
    actions are materialized so the global action budget remains four.
    """

    if not 2 <= max_actions <= 4:
        raise ValueError("cross-domain gap plans must contain between 2 and 4 actions")
    contract = state.resolved_task_contract
    belief = state.belief_state
    if contract is None or belief is None or not belief.open_obligation_ids:
        return None
    requested = tuple(dict.fromkeys(normalize_gap_domain(item) for item in domains)) or _infer_gap_domains(state)
    base_inputs = sorted(set(_state_input_refs(state)))
    input_by_domain = input_refs or {}
    observed_by_domain = observation_refs or {}
    selected = requested[: max(1, max_actions - 2)]
    actions: list[GapAction] = []

    if max_actions >= 3:
        context_output = [f"gap-context:{state.run_id}:{canonical_digest(base_inputs)[:24]}"]
        context_budget = _action_budget(max_runtime_ms=5_000, recovery_reserve_ms=1_000)
        actions.append(
            GapAction(
                action_id="gap-action-" + canonical_digest([state.run_id, "context", base_inputs])[:24],
                kind=GapActionKind.RETRIEVE_CONTEXT,
                obligation_ids=list(belief.open_obligation_ids),
                capability="context_retrieval",
                domain=GapDomain.EVIDENCE_GAP,
                covered_domains=list(requested),
                budget=context_budget,
                input_refs=base_inputs,
                output_refs=context_output,
                stop_condition="stop when immutable context is sufficient or the recovery reserve is reached",
            )
        )

    domain_actions: list[GapAction] = []
    for index, domain in enumerate(selected):
        previous_outputs = actions[-1].output_refs if actions else []
        domain_inputs = sorted(set([*previous_outputs, *input_by_domain.get(domain.value, ())]))[:1_000]
        refs = [str(item) for item in observed_by_domain.get(domain.value, ()) if str(item).strip()][:1_000]
        completed = bool(refs)
        output = refs or [f"observation:{state.run_id}:{domain.value}:{index}"]
        budget = _domain_budget(domain, budgets)
        controlled = domain in CONTROLLED_RETRIEVAL_DOMAINS
        if controlled:
            # A controlled retrieval has no execution side effect and cannot
            # consume a tool-call reservation supplied by a caller.
            budget = budget.model_copy(
                update={
                    "max_tool_calls": 0,
                    "idempotent": True,
                    "risk_level": RiskLevel.R0,
                }
            )
        capability = GAP_EXECUTION_CAPABILITIES[domain] if controlled else GAP_DOMAIN_CAPABILITIES[domain][0]
        domain_actions.append(
            GapAction(
                action_id="gap-action-" + canonical_digest([state.run_id, "observe", domain.value, domain_inputs])[:24],
                kind=GapActionKind.RETRIEVE_DOMAIN if controlled else GapActionKind.OBSERVE_DOMAIN,
                obligation_ids=list(belief.open_obligation_ids),
                capability=capability,
                domain=domain,
                covered_domains=list(requested) if index == 0 else [domain],
                depends_on=[item.action_id for item in actions[-1:]],
                max_tool_calls=budget.max_tool_calls,
                budget=budget,
                input_refs=domain_inputs or base_inputs,
                output_refs=output,
                status="completed" if completed else "proposed",
                observation_refs=refs,
                result_digest=canonical_digest(refs) if completed else None,
                stop_condition=(
                    f"stop {domain.value} observation when its obligation is satisfied, evidence repeats, "
                    "the controlled retrieval is exhausted, the tool is denied, or the R0/R1 budget is exhausted"
                ),
            )
        )
        actions.append(domain_actions[-1])

    # At max_actions=4, two domain observations consume the available slots;
    # otherwise reserve one slot for an explicit verification action.
    if max_actions == 4 and len(actions) <= 2:
        verify_input = sorted({ref for item in actions for ref in item.output_refs})[:1_000]
        verify_output = [f"verified-gap:{state.run_id}:{canonical_digest(verify_input)[:24]}"]
        actions.append(
            GapAction(
                action_id="gap-action-" + canonical_digest([state.run_id, "verify", verify_input])[:24],
                kind=GapActionKind.VERIFY_EVIDENCE,
                obligation_ids=list(belief.open_obligation_ids),
                capability="evidence_verification",
                domain=GapDomain.EVIDENCE_GAP,
                covered_domains=list(requested),
                depends_on=[item.action_id for item in actions[-1:]],
                budget=_action_budget(max_runtime_ms=10_000, recovery_reserve_ms=1_000),
                input_refs=verify_input or base_inputs,
                output_refs=verify_output,
                stop_condition="stop when every observed reference has an integrity and semantic verdict",
            )
        )

    answer = state.report.answer_payload if state.report is not None else {}
    proposal_refs = sorted({ref for item in actions for ref in item.output_refs})[:1_000]
    impacts = [
        FieldImpact(
            domain=domain,
            field_path=GAP_DOMAIN_FIELD_PATHS[domain],
            obligation_ids=list(belief.open_obligation_ids),
            observation_refs=proposal_refs,
            rationale=f"{domain.value} observation may supplement the typed answer only after verification",
        )
        for domain in requested
    ]
    proposal = make_gap_revision_proposal(
        run_id=state.run_id,
        base_answer=answer,
        target_path="/evidence_gap",
        value={
            "domains": [item.value for item in requested],
            "observation_refs": proposal_refs,
            "status": "proposed",
        },
        obligation_ids=belief.open_obligation_ids,
        observation_refs=proposal_refs,
        field_impacts=impacts,
        reason_code="cross_domain_gap_observation_requires_verification",
    )
    revision_input = sorted({ref for item in actions for ref in item.output_refs})[:1_000]
    actions.append(
        GapAction(
            action_id="gap-action-" + canonical_digest([state.run_id, "resynthesize", proposal.proposal_id])[:24],
            kind=GapActionKind.RESYNTHESIZE,
            obligation_ids=list(belief.open_obligation_ids),
            capability="typed_answer_revision",
            domain=GapDomain.EVIDENCE_GAP,
            covered_domains=list(requested),
            depends_on=[item.action_id for item in actions[-1:]],
            budget=_action_budget(max_model_calls=1, max_runtime_ms=30_000, recovery_reserve_ms=5_000),
            input_refs=revision_input or base_inputs,
            output_refs=[
                f"revision:{proposal.proposal_id}",
                *[f"field-impact:{item.domain.value}" for item in impacts],
            ],
            revision_proposal_ids=[proposal.proposal_id],
            stop_condition="emit a proposal only; stop before publication until verifier and admission accept it",
        )
    )
    actions = actions[:max_actions]
    # Preserve the typed proposal even when max_actions=2 has to omit context
    # or verification from the action sequence.
    payload = _plan_payload(
        plan_id="gap-plan-" + canonical_digest([state.run_id, belief.belief_digest, requested])[:24],
        run_id=state.run_id,
        contract_digest=contract.contract_digest,
        belief_digest=belief.belief_digest or "0" * 64,
        max_actions=max_actions,
        actions=actions,
        supported_domains=supported_gap_domains(),
        revision_proposals=[proposal],
    )
    return GapPlan.model_validate(payload)


def compile_gap_plan(state: AgentState) -> GapPlan | None:
    """Backward-compatible receipt plan used by the existing orchestrator path."""

    contract = state.resolved_task_contract
    belief = state.belief_state
    if contract is None or belief is None or not belief.open_obligation_ids:
        return None
    observed_actions: list[GapAction] = []
    receipt = state.evidence_compiler_receipt
    if receipt is not None:
        budget = _action_budget(max_runtime_ms=5_000, recovery_reserve_ms=1_000)
        observed_actions.append(
            GapAction(
                action_id="gap-action-" + canonical_digest([state.run_id, "compiled", receipt.output_digest])[:24],
                kind=GapActionKind.RETRIEVE_CONTEXT,
                obligation_ids=list(belief.open_obligation_ids),
                capability="evidence_compilation",
                domain=GapDomain.EVIDENCE_GAP,
                covered_domains=[GapDomain.EVIDENCE_GAP],
                budget=budget,
                input_refs=[f"run:{state.run_id}:immutable-input"],
                output_refs=[f"evidence-receipt:{receipt.output_digest}"],
                status="completed",
                observation_refs=[item.fact_id for item in receipt.facts[:1_000]],
                result_digest=receipt.output_digest,
                stop_condition="the immutable evidence compiler receipt was observed",
            )
        )
    scenario_projection = state.audit_coverage.get("pre_primary_scenario_projection")
    if isinstance(scenario_projection, dict):
        scenario_digest = canonical_digest(scenario_projection)
        evidence_ids = scenario_projection.get("evidence_ids")
        try:
            domain = normalize_gap_domain(str(scenario_projection.get("scenario", "evidence_gap")))
        except ValueError:
            domain = GapDomain.EVIDENCE_GAP
        budget = _action_budget(max_runtime_ms=30_000, recovery_reserve_ms=5_000)
        scenario_refs = [str(item) for item in evidence_ids[:1_000]] if isinstance(evidence_ids, list) else []
        observed_actions.append(
            GapAction(
                action_id="gap-action-" + canonical_digest([state.run_id, "scenario", scenario_digest])[:24],
                kind=GapActionKind.OBSERVE_DOMAIN,
                obligation_ids=list(belief.open_obligation_ids),
                capability=f"scenario:{scenario_projection.get('scenario', 'unknown')}",
                domain=domain,
                covered_domains=[domain],
                depends_on=[item.action_id for item in observed_actions[-1:]],
                budget=budget,
                input_refs=[item.action_id for item in observed_actions[-1:]] or [f"run:{state.run_id}"],
                output_refs=scenario_refs or [f"scenario-observation:{state.run_id}"],
                status="completed",
                observation_refs=scenario_refs,
                result_digest=scenario_digest,
                stop_condition="the deterministic domain observation was fused into the Primary context",
            )
        )
    observed_actions = observed_actions[:2]

    tool_actions: list[GapAction] = []
    for step in sorted(state.plan, key=lambda item: item.step_id):
        if len(tool_actions) >= max(0, 2 - len(observed_actions)) or not step.tool_candidates:
            break
        tool = step.tool_candidates[0]
        action_id = "gap-action-" + canonical_digest([state.run_id, belief.belief_digest, step.step_id, tool])[:24]
        budget = _action_budget(
            max_tool_calls=min(2, max(1, step.max_attempts)),
            max_runtime_ms=120_000,
            recovery_reserve_ms=5_000,
            risk_level=min(int(step.risk_hint), int(RiskLevel.R1)),
        )
        try:
            domain = normalize_gap_domain(step.capability)
        except ValueError:
            domain = GapDomain.CODE
        tool_actions.append(
            GapAction(
                action_id=action_id,
                kind=GapActionKind.RUN_TOOL,
                obligation_ids=list(belief.open_obligation_ids),
                capability=step.capability,
                domain=domain,
                covered_domains=[domain],
                tool_name=tool,
                depends_on=[item.action_id for item in [*observed_actions, *tool_actions][-1:]],
                max_tool_calls=budget.max_tool_calls,
                budget=budget,
                input_refs=[f"step:{step.step_id}", *sorted(step.inputs)],
                output_refs=[f"tool-observation:{step.step_id}"],
                stop_condition="obligation closed, repeated observation, denial, or budget reserve reached",
            )
        )
    prefix = [*observed_actions, *tool_actions]
    verify_id = "gap-action-" + canonical_digest([state.run_id, "verify", belief.belief_digest])[:24]
    verified_refs = sorted(
        {
            link.evidence_id
            for link in state.evidence_links
            if link.evidence_id and any(claim.claim_id == link.claim_id for claim in state.claims)
        }
    )
    proposal: GapRevisionProposal | None = None
    if state.report is not None:
        proposal = make_gap_revision_proposal(
            run_id=state.run_id,
            base_answer=state.report.answer_payload,
            target_path="/evidence_gap",
            value={"status": "proposed", "observation_refs": verified_refs},
            obligation_ids=belief.open_obligation_ids,
            evidence_ids=verified_refs,
            observation_refs=verified_refs,
            field_impacts=[
                FieldImpact(
                    domain=GapDomain.EVIDENCE_GAP,
                    field_path="/evidence_gap",
                    obligation_ids=list(belief.open_obligation_ids),
                    evidence_ids=verified_refs,
                    observation_refs=verified_refs,
                    rationale="verified gap evidence may revise the typed answer",
                )
            ],
        )
    actions = [
        *prefix,
        GapAction(
            action_id=verify_id,
            kind=GapActionKind.VERIFY_EVIDENCE,
            obligation_ids=list(belief.open_obligation_ids),
            capability="evidence_verification",
            domain=GapDomain.EVIDENCE_GAP,
            covered_domains=[GapDomain.EVIDENCE_GAP],
            depends_on=[item.action_id for item in prefix[-1:]],
            budget=_action_budget(max_runtime_ms=10_000, recovery_reserve_ms=1_000),
            input_refs=sorted({ref for item in prefix for ref in item.output_refs}) or [f"run:{state.run_id}"],
            output_refs=verified_refs[:1_000] or [f"verified-gap:{state.run_id}"],
            status="completed",
            observation_refs=verified_refs[:1_000],
            result_digest=canonical_digest(verified_refs),
            stop_condition="all candidate evidence has a CAS and semantic verdict",
        ),
        GapAction(
            action_id="gap-action-" + canonical_digest([state.run_id, "resynthesize", belief.belief_digest])[:24],
            kind=GapActionKind.RESYNTHESIZE,
            obligation_ids=list(belief.open_obligation_ids),
            capability="typed_answer_revision",
            domain=GapDomain.EVIDENCE_GAP,
            covered_domains=[GapDomain.EVIDENCE_GAP],
            depends_on=[verify_id],
            budget=_action_budget(max_model_calls=1, max_runtime_ms=30_000, recovery_reserve_ms=5_000),
            input_refs=verified_refs[:1_000] or [f"verified-gap:{state.run_id}"],
            output_refs=(
                [f"revision:{proposal.proposal_id}"] if proposal is not None else [f"revision:{state.run_id}"]
            ),
            revision_proposal_ids=([proposal.proposal_id] if proposal is not None else []),
            status="completed" if state.report is not None else "proposed",
            observation_refs=([proposal.proposal_id] if proposal is not None else []),
            result_digest=(proposal.proposal_digest if proposal is not None else None),
            stop_condition="one typed revision pass completed or belief stagnated",
        ),
    ][:4]
    revision_proposals = [proposal] if proposal is not None else []
    payload = _plan_payload(
        plan_id="gap-plan-" + canonical_digest([state.run_id, belief.belief_digest])[:24],
        run_id=state.run_id,
        contract_digest=contract.contract_digest,
        belief_digest=belief.belief_digest or "0" * 64,
        max_actions=max(2, len(actions)),
        actions=actions,
        supported_domains=supported_gap_domains(),
        revision_proposals=revision_proposals,
    )
    return GapPlan.model_validate(payload)


__all__ = [
    "CONTROLLED_RETRIEVAL_DOMAINS",
    "GAP_DOMAIN_CAPABILITIES",
    "GAP_EXECUTION_CAPABILITIES",
    "GAP_DOMAIN_FIELD_PATHS",
    "GAP_PLAN_VERSION",
    "GapAction",
    "GapActionBudget",
    "GapActionKind",
    "GapDomain",
    "GapPlan",
    "GapRevisionProposal",
    "FieldImpact",
    "compile_cross_domain_gap_plan",
    "compile_gap_plan",
    "domain_for_capability",
    "execution_capability_for_domain",
    "make_gap_revision_proposal",
    "normalize_gap_domain",
    "supported_gap_domains",
]
