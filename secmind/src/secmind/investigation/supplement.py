from __future__ import annotations

import hashlib
from collections import defaultdict
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from typing import Any, Literal
from uuid import NAMESPACE_URL, uuid5

from pydantic import BaseModel, ConfigDict, Field, model_validator

from secmind.evidence_graph import EvidenceGraph
from secmind.gap_plan import (
    GAP_DOMAIN_FIELD_PATHS,
    FieldImpact,
    GapAction,
    GapActionBudget,
    GapActionKind,
    GapDomain,
    GapPlan,
    GapRevisionProposal,
    compile_cross_domain_gap_plan,
    domain_for_capability,
    make_gap_revision_proposal,
    normalize_gap_domain,
)
from secmind.investigation.evidence import EvidenceGap, EvidenceGraphView
from secmind.schemas import (
    AgentState,
    Claim,
    ClaimStatus,
    Evidence,
    PlanStep,
    RiskLevel,
    Scenario,
    StepStatus,
    ToolHealth,
    ToolManifest,
)
from secmind.task_contract import (
    AnswerRevisionAction,
    IndependenceProof,
    PublishedAnswerRevision,
    canonical_digest,
    seal_independence_proof,
    validate_independence_proof,
)


def _stable_lineage_id(value: str) -> str:
    normalized = " ".join(value.strip().split())
    if normalized:
        return normalized
    return "unknown:" + hashlib.sha256(value.encode()).hexdigest()


def stable_plan_revision_id(run_id: str, revision: int, parent_digest: str, plan_digest: str) -> str:
    """Return the replay-stable identity of one authority-chain revision."""

    return str(
        uuid5(
            NAMESPACE_URL,
            f"secmind:plan-revision:{run_id}:{revision}:{parent_digest}:{plan_digest}",
        )
    )


def build_lineage_graph_views(
    graph: EvidenceGraph,
    lineage_by_evidence_id: Mapping[str, str],
) -> tuple[EvidenceGraphView, ...]:
    """Split a verified projection into original invocation/tool lineages.

    ``InvestigationEvidenceGraph`` deliberately treats evidence from the same
    graph lineage as non-independent.  Passing a whole run as one view would
    therefore make the required second source impossible even when two tools
    really executed.  This adapter keeps each evidence item in exactly one
    provenance view and repeats only the immutable claim projection needed to
    validate its links.
    """

    evidence_by_id = {item.evidence_id: item for item in graph.evidence}
    claims_by_id = {item.claim_id: item for item in graph.claims}
    groups: dict[str, set[str]] = defaultdict(set)
    for evidence_id, evidence in evidence_by_id.items():
        configured = lineage_by_evidence_id.get(evidence_id)
        if configured is None:
            tool = str(evidence.metadata.get("tool_name") or evidence.source).casefold()
            step = str(evidence.metadata.get("step_id") or "unknown-step").casefold()
            configured = f"tool:{tool}:step:{step}"
        groups[_stable_lineage_id(configured)].add(evidence_id)

    views: list[EvidenceGraphView] = []
    represented_claim_ids: set[str] = set()
    for lineage, evidence_ids in sorted(groups.items()):
        links = tuple(item for item in graph.links if item.evidence_id in evidence_ids)
        claim_ids = {item.claim_id for item in links}
        represented_claim_ids.update(claim_ids)
        fragment = EvidenceGraph(
            claims=[claims_by_id[item] for item in sorted(claim_ids)],
            evidence=[evidence_by_id[item] for item in sorted(evidence_ids)],
            links=list(links),
        )
        views.append(EvidenceGraphView(graph_id=lineage, graph=fragment))

    # Claims without evidence are still part of the authoritative report
    # projection.  Keep them visible to the completion integrity check without
    # pretending they form an evidence lineage.
    unrepresented = sorted(set(claims_by_id) - represented_claim_ids)
    if unrepresented:
        digest = hashlib.sha256("\x1f".join(unrepresented).encode()).hexdigest()
        views.append(
            EvidenceGraphView(
                graph_id=f"claims-only:{digest}",
                graph=EvidenceGraph(claims=[claims_by_id[item] for item in unrepresented]),
            )
        )
    return tuple(views)


class GapObservation(BaseModel):
    """Typed feedback for one bounded gap action.

    The observation deliberately carries both the immutable references read
    by the action and the references it produced.  A receipt can therefore be
    replayed as an observation, but it cannot silently become an accepted
    answer revision.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    observation_id: str
    action_id: str
    domain: GapDomain
    capability: str = Field(min_length=1, max_length=160)
    obligation_ids: list[str] = Field(default_factory=list, max_length=1_000)
    input_refs: list[str] = Field(min_length=1, max_length=1_000)
    output_refs: list[str] = Field(min_length=1, max_length=1_000)
    evidence_ids: list[str] = Field(default_factory=list, max_length=1_000)
    field_impacts: list[FieldImpact] = Field(default_factory=list, max_length=128)
    budget: GapActionBudget | None = None
    status: Literal["observed", "insufficient", "rejected"] = "observed"
    observation_digest: str = Field(pattern=r"^[a-f0-9]{64}$")

    @model_validator(mode="after")
    def validate_refs(self) -> GapObservation:
        refs = [*self.input_refs, *self.output_refs]
        if any(not str(item).strip() for item in refs):
            raise ValueError("gap observations cannot contain empty references")
        return self


def make_gap_observation(
    *,
    action_id: str,
    domain: GapDomain | str,
    capability: str,
    obligation_ids: Iterable[str] = (),
    input_refs: Iterable[str],
    output_refs: Iterable[str],
    evidence_ids: Iterable[str] = (),
    field_impacts: Iterable[FieldImpact] = (),
    budget: GapActionBudget | None = None,
    status: Literal["observed", "insufficient", "rejected"] = "observed",
) -> GapObservation:
    """Create a replay-stable typed observation from an action result."""

    normalized_domain: GapDomain | None
    if isinstance(domain, GapDomain):
        normalized_domain = domain
    else:
        try:
            normalized_domain = normalize_gap_domain(domain)
        except ValueError:
            normalized_domain = domain_for_capability(capability)
    if normalized_domain is None:
        normalized_domain = GapDomain.EVIDENCE_GAP
    normalized_obligations = sorted({str(item) for item in obligation_ids if str(item).strip()})
    normalized_inputs = sorted({str(item) for item in input_refs if str(item).strip()})
    normalized_outputs = sorted({str(item) for item in output_refs if str(item).strip()})
    normalized_evidence = sorted({str(item) for item in evidence_ids if str(item).strip()})
    impacts = list(field_impacts)
    if not impacts:
        impacts = [
            FieldImpact(
                domain=normalized_domain,
                field_path=GAP_DOMAIN_FIELD_PATHS[normalized_domain],
                obligation_ids=normalized_obligations,
                evidence_ids=normalized_evidence,
                observation_refs=normalized_outputs,
                rationale="typed gap observation feedback",
            )
        ]
    payload = {
        "action_id": action_id,
        "domain": normalized_domain.value,
        "capability": capability,
        "obligation_ids": normalized_obligations,
        "input_refs": normalized_inputs,
        "output_refs": normalized_outputs,
        "evidence_ids": normalized_evidence,
        "field_impacts": [item.model_dump(mode="json") for item in impacts],
        "budget": budget.model_dump(mode="json") if budget is not None else None,
        "status": status,
    }
    digest = canonical_digest(payload)
    return GapObservation.model_validate(
        {
            **payload,
            "observation_id": "gap-observation-" + digest[:24],
            "observation_digest": digest,
        }
    )


def gap_domain_scenario(domain: GapDomain, current: Scenario) -> Scenario:
    """Map a semantic gap lane to the closest registered tool scenario."""

    return {
        GapDomain.CODE: Scenario.CODE_AUDIT,
        GapDomain.LOG: Scenario.LOG_ANALYSIS,
        GapDomain.API: Scenario.API_ASSESSMENT,
        GapDomain.FORENSICS: Scenario.REVERSE_TRIAGE,
        GapDomain.FIRMWARE: Scenario.UNKNOWN,
        GapDomain.EXACT: current,
        GapDomain.EVIDENCE_GAP: current,
        GapDomain.PATCH: Scenario.CODE_AUDIT,
        GapDomain.IR: Scenario.INCIDENT_RESPONSE,
    }.get(domain, current)


def gap_worker_role(capability: str) -> str | None:
    """Return the already-registered bounded worker profile for a capability."""

    return {
        "inventory": "scout",
        "sast": "sast_specialist",
        # Bandit treats the capability name as a password-like assignment.
        "secret_scan": "secret_specialist",  # nosec B105
        "sbom": "dependency_specialist",
        "dependency_audit": "dependency_specialist",
    }.get(capability)


def json_pointer_value(answer: Mapping[str, Any], pointer: str) -> Any:
    """Read an RFC 6901 object pointer without mutating the answer."""

    if not pointer.startswith("/"):
        return None
    current: Any = answer
    for raw in pointer.split("/")[1:]:
        key = raw.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, Mapping) or key not in current:
            return None
        current = current[key]
    return current


def gap_observation_for_step(
    state: AgentState,
    action: GapAction,
    step_id: str,
) -> GapObservation:
    """Project an ordinary worker receipt into a typed gap observation."""

    runtime = state.step_runtime.get(step_id)
    evidence_ids: set[str] = set()
    output_refs: set[str] = set(action.output_refs)
    status: Literal["observed", "insufficient", "rejected"] = "insufficient"
    if runtime is not None:
        for index in runtime.observation_indexes:
            if 0 <= index < len(state.observations):
                observation = state.observations[index]
                evidence_ids.update(item.evidence_id for item in observation.evidence)
                output_refs.update(item.artifact_id for item in observation.artifacts)
                output_refs.update(item.evidence_id for item in observation.evidence)
        status = "observed" if runtime.status == StepStatus.SUCCEEDED else "insufficient"
        if runtime.last_error:
            output_refs.add(f"error:{runtime.last_error}")
    if not output_refs:
        output_refs.add(f"observation:{state.run_id}:{action.action_id}")
    return make_gap_observation(
        action_id=action.action_id,
        domain=action.domain,
        capability=action.capability,
        obligation_ids=action.obligation_ids,
        input_refs=action.input_refs,
        output_refs=sorted(output_refs),
        evidence_ids=sorted(evidence_ids),
        budget=action.budget,
        status=status,
    )


def controlled_domain_retrieval_observation(
    state: AgentState,
    action: GapAction,
) -> GapObservation:
    """Retrieve sealed non-code context without pretending a scanner ran.

    The scenario analyzers already own CAS reads, parser limits, and claim
    verification.  EIRS may reuse their immutable receipts, the compiler
    receipt, context references, and input artifact identities, but it must
    neither reread a mutable workspace nor rename a generic inventory/SAST
    worker as a domain specialist.  This is therefore a pure R0 retrieval
    receipt; a later verifier/admission gate still owns publication.
    """

    if action.kind != GapActionKind.RETRIEVE_DOMAIN:
        raise ValueError("controlled domain retrieval requires RETRIEVE_DOMAIN")
    output_refs: set[str] = set()
    evidence_ids: set[str] = set()
    known_evidence_ids = {item.evidence_id for item in state.evidence}

    raw_delta = state.audit_coverage.get("scenario_semantic_delta")
    if isinstance(raw_delta, Mapping) and _semantic_delta_matches_domain(raw_delta, action.domain, state):
        delta_id = str(raw_delta.get("delta_id") or "").strip()
        if delta_id:
            output_refs.add(f"semantic-delta:{delta_id}")
        raw_ids = raw_delta.get("evidence_ids")
        if isinstance(raw_ids, (list, tuple)):
            evidence_ids.update(str(item) for item in raw_ids if str(item) in known_evidence_ids)
        digest = str(raw_delta.get("semantic_digest") or "").strip().casefold()
        if len(digest) == 64:
            output_refs.add(f"semantic-digest:{digest}")

    projection = state.audit_coverage.get("pre_primary_scenario_projection")
    if isinstance(projection, Mapping) and _scenario_matches_domain(
        str(projection.get("scenario") or ""), action.domain, state
    ):
        projection_ids = projection.get("evidence_ids")
        if isinstance(projection_ids, list):
            evidence_ids.update(str(item) for item in projection_ids if str(item) in known_evidence_ids)
        output_refs.add(
            "scenario-projection:" + canonical_digest({str(key): value for key, value in projection.items()})
        )

    receipt = state.evidence_compiler_receipt
    if receipt is not None:
        output_refs.add(f"evidence-receipt:{receipt.output_digest}")
        for fact in receipt.facts[:1_000]:
            if _fact_matches_domain(fact.fact_type, action.domain):
                output_refs.add(f"fact:{fact.fact_id}")

    output_refs.update(f"context:{item.context_id}" for item in state.context_items[:1_000])
    output_refs.update(f"artifact:{item.sha256.lower()}" for item in state.input_artifacts[:1_000])
    if not output_refs:
        output_refs.add(f"retrieval-empty:{state.run_id}:{action.domain.value}")
    priority = {
        "semantic-delta": 0,
        "semantic-digest": 1,
        "scenario-projection": 2,
        "evidence-receipt": 3,
        "fact": 4,
        "context": 5,
        "artifact": 6,
        "retrieval-empty": 7,
    }
    bounded_output_refs = sorted(
        output_refs,
        key=lambda item: (priority.get(item.split(":", 1)[0], 99), item),
    )[:1_000]
    status: Literal["observed", "insufficient", "rejected"] = (
        "observed" if any(not item.startswith("retrieval-empty:") for item in bounded_output_refs) else "insufficient"
    )
    return make_gap_observation(
        action_id=action.action_id,
        domain=action.domain,
        capability=action.capability,
        obligation_ids=action.obligation_ids,
        input_refs=action.input_refs,
        output_refs=bounded_output_refs,
        evidence_ids=sorted(evidence_ids)[:1_000],
        budget=action.budget,
        status=status,
    )


def _semantic_delta_matches_domain(
    delta: Mapping[str, Any],
    domain: GapDomain,
    state: AgentState,
) -> bool:
    return (
        _scenario_matches_domain(str(delta.get("scenario") or ""), domain, state)
        or {
            "timeline": GapDomain.LOG,
            "exact": GapDomain.EXACT,
            "reverse_behavior": GapDomain.FORENSICS,
            "patch_validation": GapDomain.PATCH,
            "evidence_gap": GapDomain.EVIDENCE_GAP,
        }.get(str(delta.get("answer_kind") or "").casefold())
        == domain
    )


def _scenario_matches_domain(value: str, domain: GapDomain, state: AgentState) -> bool:
    normalized = value.strip().casefold().replace("-", "_")
    direct = {
        "log_analysis": GapDomain.LOG,
        "api_assessment": GapDomain.API,
        "incident_response": GapDomain.IR,
        "reverse_triage": GapDomain.FORENSICS,
    }.get(normalized)
    if direct == domain:
        return True
    contract = state.resolved_task_contract
    scoring = str(contract.scoring_mode).casefold() if contract is not None else ""
    return {
        "exact_answer_with_evidence": GapDomain.EXACT,
        "patch_validator": GapDomain.PATCH,
        "reverse_behavior": GapDomain.FORENSICS,
        "evidence_gap": GapDomain.EVIDENCE_GAP,
    }.get(scoring) == domain


def _fact_matches_domain(fact_type: str, domain: GapDomain) -> bool:
    normalized = str(fact_type).casefold()
    terms = {
        GapDomain.LOG: ("log", "event", "timeline", "pcap", "evtx"),
        GapDomain.API: ("api", "endpoint", "request", "response", "auth"),
        GapDomain.EXACT: ("exact", "value", "token", "mapping"),
        GapDomain.EVIDENCE_GAP: ("evidence", "unknown", "gap", "conflict"),
        GapDomain.FORENSICS: ("forensic", "reverse", "behavior", "artifact"),
        GapDomain.FIRMWARE: ("firmware", "binary", "string"),
        GapDomain.PATCH: ("patch", "diff", "test", "changed_flow"),
        GapDomain.IR: ("incident", "hypothesis", "rollback", "containment"),
        GapDomain.CODE: ("code", "source", "finding"),
    }[domain]
    return any(term in normalized for term in terms)


def gap_independence_proof(
    first: Evidence,
    second: Evidence,
    *,
    run_id: str,
) -> IndependenceProof | None:
    """Seal independence from two observed evidence lineages, never labels."""

    first_tool = str(first.metadata.get("tool_name") or first.source)
    second_tool = str(second.metadata.get("tool_name") or second.source)
    first_request = str(first.metadata.get("invocation_id") or first.evidence_id)
    second_request = str(second.metadata.get("invocation_id") or second.evidence_id)
    first_method = str(first.metadata.get("method_lineage") or first.source)
    second_method = str(second.metadata.get("method_lineage") or second.source)
    first_input = str(first.metadata.get("input_manifest_digest") or first.sha256 or first.evidence_id)
    second_input = str(second.metadata.get("input_manifest_digest") or second.sha256 or second.evidence_id)
    first_context = str(first.metadata.get("context_pack_digest") or first.artifact_ref or first.evidence_id)
    second_context = str(second.metadata.get("context_pack_digest") or second.artifact_ref or second.evidence_id)
    values = {
        "proof_id": f"gap-independence-{canonical_digest([run_id, first.evidence_id, second.evidence_id])[:24]}",
        "method_family": "verified-evidence-lineage",
        "primary_provider": first_tool,
        "critic_provider": second_tool,
        "primary_model_family": str(first.metadata.get("model_family") or first.source),
        "critic_model_family": str(second.metadata.get("model_family") or second.source),
        "primary_model_id": str(first.metadata.get("model_id") or first.source),
        "critic_model_id": str(second.metadata.get("model_id") or second.source),
        "primary_request_lineage": first_request,
        "critic_request_lineage": second_request,
        "primary_method_lineage": first_method,
        "critic_method_lineage": second_method,
        "primary_input_slice_digest": first_input,
        "critic_input_slice_digest": second_input,
        "primary_context_digest": first_context,
        "critic_context_digest": second_context,
        "compared_lineage_ids": [first.evidence_id, second.evidence_id],
        "independent": True,
        "reason_codes": ["distinct_verified_evidence_graph_lineages"],
    }
    try:
        proof = seal_independence_proof(**values)
        return proof if validate_independence_proof(proof)[0] else None
    except (TypeError, ValueError):
        return None


def build_gap_published_revision(
    answer: Mapping[str, Any],
    result: GapInvestigationResult,
    *,
    candidate_evidence_ids: Iterable[str],
    proof: IndependenceProof,
    existing_revisions: Iterable[PublishedAnswerRevision] = (),
) -> PublishedAnswerRevision | None:
    """Build one observation-backed revision; admission remains the caller's gate."""

    if not result.revision_proposals:
        return None
    proposal = result.revision_proposals[0]
    answer_value = dict(answer)
    if proposal.base_answer_digest != canonical_digest(answer_value):
        return None
    candidate_ids = sorted({str(item) for item in candidate_evidence_ids if str(item).strip()})
    if not candidate_ids:
        return None
    old_value = json_pointer_value(answer_value, proposal.target_path)
    value: dict[str, Any] = {
        "domains": sorted({impact.domain.value for impact in result.field_impacts}),
        "observation_ids": sorted(item.observation_id for item in result.observations),
        "verified_evidence_ids": candidate_ids,
    }
    if isinstance(old_value, dict):
        value = {
            key: item
            for key, item in value.items()
            if key not in old_value or canonical_digest(old_value[key]) == canonical_digest(item)
        }
    if not value:
        return None
    revision_id = f"answer-revision-{proposal.proposal_id}"
    supersedes = sorted(
        item.revision_id
        for item in existing_revisions
        if item.target_path == proposal.target_path and item.verifier_status == "accepted"
    )
    payload: dict[str, Any] = {
        "revision_id": revision_id,
        "base_answer_digest": canonical_digest(answer_value),
        "action": AnswerRevisionAction.SUPPLEMENT,
        "target_path": proposal.target_path,
        "expected_old_digest": None if old_value is None else canonical_digest(old_value),
        "value": value,
        "evidence_ids": candidate_ids,
        "observation_ids": sorted(item.observation_id for item in result.observations),
        "supersedes_revision_ids": supersedes,
        "independence_proof": proof.model_dump(mode="json"),
        "verifier_status": "accepted",
        "reason_code": "eirs_verified_independent_observation",
    }
    payload["revision_digest"] = canonical_digest(payload)
    try:
        return PublishedAnswerRevision.model_validate(payload)
    except (TypeError, ValueError):
        return None


class GapInvestigationResult(BaseModel):
    """Pure EIRS result containing observations and non-authoritative proposals."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    plan: GapPlan
    observations: list[GapObservation] = Field(default_factory=list, max_length=4)
    revision_proposals: list[GapRevisionProposal] = Field(default_factory=list, max_length=128)
    field_impacts: list[FieldImpact] = Field(default_factory=list, max_length=256)
    status: Literal["proposed", "observed", "partial", "blocked"] = "proposed"
    result_digest: str = Field(pattern=r"^[a-f0-9]{64}$")


def lower_gap_plan_steps(
    state: AgentState,
    plan: GapPlan,
    *,
    resolve_tool_candidates: Callable[[GapAction], tuple[str, list[str], PlanStep | None] | None],
    rehash_evidence: Callable[[AgentState], tuple[dict[str, str], dict[str, str]]],
    concurrency_key_for: Callable[[str], str],
    investigation_store_available: bool,
) -> tuple[list[PlanStep], dict[str, str], list[GapObservation]]:
    """Lower pure gap actions into ordinary bounded worker steps.

    The callbacks are authority adapters supplied by the orchestrator.  This
    module owns action/observation semantics; it never dispatches a tool.
    """

    steps: list[PlanStep] = []
    action_steps: dict[str, str] = {}
    deterministic: list[GapObservation] = []
    for action in plan.actions:
        if action.kind == GapActionKind.RESYNTHESIZE:
            deterministic.append(
                make_gap_observation(
                    action_id=action.action_id,
                    domain=action.domain,
                    capability=action.capability,
                    obligation_ids=action.obligation_ids,
                    input_refs=action.input_refs,
                    output_refs=action.output_refs,
                    budget=action.budget,
                    status="observed",
                )
            )
            continue
        if action.kind == GapActionKind.RETRIEVE_DOMAIN:
            deterministic.append(controlled_domain_retrieval_observation(state, action))
            continue
        if action.kind in {GapActionKind.RETRIEVE_CONTEXT, GapActionKind.VERIFY_EVIDENCE}:
            evidence_ids = sorted(
                {
                    ref.split(":", 1)[1]
                    for ref in action.input_refs
                    if ref.startswith("evidence:") and ref.split(":", 1)[1]
                }
                & {item.evidence_id for item in state.evidence}
            )
            output_refs = sorted(
                {
                    *action.output_refs,
                    *(f"context:{item.context_id}" for item in state.context_items[:1_000]),
                }
            )
            status: Literal["observed", "insufficient", "rejected"] = "observed"
            if action.kind == GapActionKind.VERIFY_EVIDENCE and evidence_ids:
                hashes, failures = rehash_evidence(state)
                if any(item not in hashes for item in evidence_ids) or failures:
                    status = "insufficient"
            deterministic.append(
                make_gap_observation(
                    action_id=action.action_id,
                    domain=action.domain,
                    capability=action.capability,
                    obligation_ids=action.obligation_ids,
                    input_refs=action.input_refs,
                    output_refs=output_refs or action.output_refs,
                    evidence_ids=evidence_ids,
                    budget=action.budget,
                    status=status,
                )
            )
            continue
        resolved = resolve_tool_candidates(action)
        if resolved is None:
            deterministic.append(
                make_gap_observation(
                    action_id=action.action_id,
                    domain=action.domain,
                    capability=action.capability,
                    obligation_ids=action.obligation_ids,
                    input_refs=action.input_refs,
                    output_refs=[*action.output_refs, f"blocked:{action.action_id}"],
                    budget=action.budget,
                    status="rejected",
                )
            )
            continue
        capability, candidates, template = resolved
        if template is not None:
            existing_runtime = state.step_runtime.get(template.step_id)
            if existing_runtime is not None and existing_runtime.status == StepStatus.SUCCEEDED:
                deterministic.append(gap_observation_for_step(state, action, template.step_id))
                continue
        role = gap_worker_role(capability)
        if role is None:
            deterministic.append(
                make_gap_observation(
                    action_id=action.action_id,
                    domain=action.domain,
                    capability=capability,
                    obligation_ids=action.obligation_ids,
                    input_refs=action.input_refs,
                    output_refs=[*action.output_refs, f"blocked:profile:{capability}"],
                    budget=action.budget,
                    status="rejected",
                )
            )
            continue
        step_id = f"eirs-{plan.plan_id[-12:]}-{action.action_id[-16:]}"[:128]
        if any(item.step_id == step_id for item in state.plan):
            action_steps[action.action_id] = step_id
            continue
        tool_calls = action.budget.max_tool_calls if action.budget is not None else max(1, action.max_tool_calls)
        inputs = dict(template.inputs) if template is not None else {"target": state.workspace or "."}
        step = PlanStep(
            step_id=step_id,
            objective=f"Bounded {action.domain.value} evidence-gap observation.",
            agent_role=role,
            capability=capability,
            dependencies=([template.step_id] if template is not None and investigation_store_available else []),
            tool_candidates=candidates,
            inputs=inputs,
            success_criteria=[
                "The registered tool returns schema-valid observation evidence.",
                action.stop_condition,
            ],
            output_contract=(dict(template.output_contract) if template is not None else {}),
            concurrency_key=concurrency_key_for(candidates[0]) if candidates else "gap-observation",
            estimated_tool_calls=min(2, tool_calls),
            risk_hint=(action.budget.risk_level if action.budget is not None else RiskLevel.R0),
            max_attempts=1,
            context_requirements={
                "eirs_action_id": action.action_id,
                "eirs_plan_id": plan.plan_id,
                "eirs_input_refs": list(action.input_refs),
                "eirs_max_tool_calls": tool_calls,
            },
        )
        steps.append(step)
        action_steps[action.action_id] = step_id
    return steps, action_steps, deterministic


def _proposal_with_feedback(
    proposal: GapRevisionProposal,
    *,
    observations: Sequence[GapObservation],
    field_impacts: Sequence[FieldImpact],
) -> GapRevisionProposal:
    """Attach observation feedback while preserving proposal-only authority."""

    evidence_ids = sorted({*proposal.evidence_ids, *(item for obs in observations for item in obs.evidence_ids)})
    observation_refs = sorted(
        {
            *proposal.observation_refs,
            *(item for obs in observations for item in [obs.observation_id, *obs.output_refs]),
        }
    )
    payload = proposal.model_dump(mode="json")
    payload.update(
        {
            "evidence_ids": evidence_ids,
            "observation_refs": observation_refs,
            "field_impacts": [item.model_dump(mode="json") for item in field_impacts],
        }
    )
    digest_payload = {key: value for key, value in payload.items() if key not in {"proposal_id", "proposal_digest"}}
    digest = canonical_digest(digest_payload)
    payload["proposal_id"] = "gap-revision-" + digest[:24]
    payload["proposal_digest"] = digest
    return GapRevisionProposal.model_validate(payload)


def build_gap_investigation_result(
    plan: GapPlan,
    observations: Iterable[GapObservation] = (),
) -> GapInvestigationResult:
    """Fold pure observations into typed proposal/field-impact feedback.

    This function performs no tool dispatch and does not mutate the plan,
    answer, or ``AgentState``.  All proposals remain ``proposed`` until the
    caller runs its existing verifier/admission boundary.
    """

    normalized_observations = sorted(tuple(observations), key=lambda item: item.observation_id)
    action_ids = {item.action_id for item in plan.actions}
    unknown_actions = sorted({item.action_id for item in normalized_observations} - action_ids)
    if unknown_actions:
        raise ValueError(f"observation references unknown gap actions: {unknown_actions}")

    impacts: dict[str, FieldImpact] = {}
    for impact in [item for proposal in plan.revision_proposals for item in proposal.field_impacts]:
        impacts[canonical_digest(impact.model_dump(mode="json"))] = impact
    for observation in normalized_observations:
        for impact in observation.field_impacts:
            impacts[canonical_digest(impact.model_dump(mode="json"))] = impact
    normalized_impacts = [impacts[key] for key in sorted(impacts)]

    proposals = [
        _proposal_with_feedback(item, observations=normalized_observations, field_impacts=normalized_impacts)
        if normalized_observations
        else item
        for item in plan.revision_proposals
    ]
    if not normalized_observations:
        status: Literal["proposed", "observed", "partial", "blocked"] = "proposed"
    elif any(item.status in {"insufficient", "rejected"} for item in normalized_observations):
        status = "partial"
    elif all(item.status == "observed" for item in normalized_observations):
        status = "observed"
    else:
        status = "partial"
    payload = {
        "plan": plan,
        "observations": normalized_observations,
        "revision_proposals": proposals,
        "field_impacts": normalized_impacts,
        "status": status,
    }
    return GapInvestigationResult.model_validate(
        {
            **payload,
            "result_digest": canonical_digest(
                {
                    "plan": plan.model_dump(mode="json"),
                    "observations": [item.model_dump(mode="json") for item in normalized_observations],
                    "revision_proposals": [item.model_dump(mode="json") for item in proposals],
                    "field_impacts": [item.model_dump(mode="json") for item in normalized_impacts],
                    "status": status,
                }
            ),
        }
    )


def compile_eirs_gap_plan(
    state: AgentState,
    *,
    domains: Iterable[GapDomain | str] = (),
    max_actions: int = 4,
    input_refs: Mapping[str, Sequence[str]] | None = None,
    observation_refs: Mapping[str, Sequence[str]] | None = None,
    budgets: Mapping[str, GapActionBudget | Mapping[str, Any]] | None = None,
    observations: Iterable[GapObservation] = (),
) -> GapInvestigationResult | None:
    """Compile and optionally fold feedback for a pure EIRS call boundary."""

    plan = compile_cross_domain_gap_plan(
        state,
        domains=domains,
        max_actions=max_actions,
        input_refs=input_refs,
        observation_refs=observation_refs,
        budgets=budgets,
    )
    return None if plan is None else build_gap_investigation_result(plan, observations)


# Name used by callers that treat EIRS as an investigation rather than a gap
# plan.  Keeping it as an alias preserves one deterministic implementation.
compile_gap_investigation = compile_eirs_gap_plan


@dataclass(frozen=True, slots=True)
class GapSupplementProposal:
    original_step_id: str
    target_claim_ids: tuple[str, ...]
    gap_ids: tuple[str, ...]
    tool_name: str
    requested_evidence_types: tuple[str, ...]
    independence_requirement: int
    domain: GapDomain = GapDomain.EVIDENCE_GAP
    obligation_ids: tuple[str, ...] = ()
    input_refs: tuple[str, ...] = ()
    output_refs: tuple[str, ...] = ()
    budget: GapActionBudget = field(default_factory=GapActionBudget)
    revision_proposal: GapRevisionProposal | None = None


class EvidenceGapSupplementPlanner:
    """Choose one genuinely new approved source per affected execution step."""

    def propose(
        self,
        gaps: Iterable[EvidenceGap],
        *,
        claims: Sequence[Claim],
        plan: Sequence[PlanStep],
        manifests: Iterable[ToolManifest],
        scenario: Scenario,
        supplement_round: int,
    ) -> tuple[GapSupplementProposal, ...]:
        if supplement_round >= 2:
            return ()
        by_step = {item.step_id: item for item in plan}
        claims_by_subject: dict[str, list[Claim]] = defaultdict(list)
        for claim in claims:
            if claim.status == ClaimStatus.VERIFIED:
                claims_by_subject[claim.subject_ref].append(claim)
        gap_groups: dict[str, list[EvidenceGap]] = defaultdict(list)
        claim_groups: dict[str, set[str]] = defaultdict(set)
        for gap in gaps:
            if gap.target_type != "finding":
                continue
            for claim in claims_by_subject.get(gap.target_id, ()):
                if claim.producer in by_step:
                    gap_groups[claim.producer].append(gap)
                    claim_groups[claim.producer].add(claim.claim_id)

        manifest_by_name = {item.name: item for item in manifests}
        used_tools_by_capability: dict[str, set[str]] = defaultdict(set)
        for step in plan:
            if step.tool_candidates:
                used_tools_by_capability[step.capability].add(step.tool_candidates[0])

        proposals: list[GapSupplementProposal] = []
        for step_id, selected_gaps in sorted(gap_groups.items()):
            original = by_step[step_id]
            alternatives: list[ToolManifest] = []
            for name in original.tool_candidates:
                manifest = manifest_by_name.get(name)
                if (
                    manifest is None
                    or name in used_tools_by_capability[original.capability]
                    or manifest.health_status != ToolHealth.HEALTHY
                    or manifest.risk_level > RiskLevel.R1
                    or (manifest.platform_risk is not None and manifest.platform_risk > RiskLevel.R1)
                    or scenario not in manifest.scenarios
                    or (manifest.capability_tags and original.capability not in manifest.capability_tags)
                ):
                    continue
                alternatives.append(manifest)
            if not alternatives:
                continue
            selected = sorted(alternatives, key=lambda item: (int(item.platform_risk or item.risk_level), item.name))[0]
            requested = {
                value.strip().casefold()
                for gap in selected_gaps
                for value in gap.requested_evidence_types
                if value.strip()
            }
            requested.update(value.strip().casefold() for value in selected.evidence_types if value.strip())
            if not requested:
                requested.add("supporting_evidence")
            domain = domain_for_capability(original.capability) or GapDomain.EVIDENCE_GAP
            max_tool_calls = 2 if selected.idempotent else 1
            runtime_ms = min(120_000, max(1_000, selected.timeout_seconds * 1_000))
            platform_risk = selected.platform_risk or selected.risk_level
            budget = GapActionBudget(
                max_tool_calls=max_tool_calls,
                max_runtime_ms=runtime_ms,
                recovery_reserve_ms=min(5_000, runtime_ms),
                idempotent=selected.idempotent,
                risk_level=max(selected.risk_level, platform_risk),
            )
            input_refs = (f"step:{step_id}", *tuple(sorted(str(key) for key in original.inputs)))
            proposals.append(
                GapSupplementProposal(
                    original_step_id=step_id,
                    target_claim_ids=tuple(sorted(claim_groups[step_id])),
                    gap_ids=tuple(sorted({item.gap_id for item in selected_gaps})),
                    tool_name=selected.name,
                    requested_evidence_types=tuple(sorted(requested)),
                    independence_requirement=2,
                    domain=domain,
                    obligation_ids=tuple(sorted({item.gap_id for item in selected_gaps})),
                    input_refs=input_refs,
                    output_refs=(f"gap-observation:{step_id}:{selected.name}",),
                    budget=budget,
                )
            )
        return tuple(proposals)

    @staticmethod
    def propose_typed_revisions(
        proposals: Iterable[GapSupplementProposal],
        *,
        run_id: str,
        base_answer: Mapping[str, Any] | None = None,
        evidence_ids: Iterable[str] = (),
        observation_refs: Iterable[str] = (),
    ) -> tuple[GapSupplementProposal, ...]:
        """Attach typed, still-unpublished revisions to supplement proposals."""

        shared_evidence = sorted({str(item) for item in evidence_ids if str(item).strip()})
        shared_observations = sorted({str(item) for item in observation_refs if str(item).strip()})
        typed: list[GapSupplementProposal] = []
        for proposal in proposals:
            domain = proposal.domain
            refs = sorted({*proposal.output_refs, *shared_observations})
            impact = FieldImpact(
                domain=domain,
                field_path=GAP_DOMAIN_FIELD_PATHS[domain],
                impact_kind="supplement",
                obligation_ids=list(proposal.obligation_ids),
                evidence_ids=shared_evidence,
                observation_refs=refs,
                rationale="independent supplement may change this typed answer field",
            )
            revision = make_gap_revision_proposal(
                run_id=run_id,
                base_answer=base_answer,
                action=AnswerRevisionAction.SUPPLEMENT,
                target_path=GAP_DOMAIN_FIELD_PATHS[domain],
                value={
                    "domain": domain.value,
                    "tool_name": proposal.tool_name,
                    "target_claim_ids": list(proposal.target_claim_ids),
                    "requested_evidence_types": list(proposal.requested_evidence_types),
                },
                obligation_ids=proposal.obligation_ids,
                evidence_ids=shared_evidence,
                observation_refs=refs,
                field_impacts=[impact],
                reason_code="independent_supplement_typed_field_impact",
            )
            typed.append(replace(proposal, revision_proposal=revision))
        return tuple(typed)


__all__ = [
    "EvidenceGapSupplementPlanner",
    "GapInvestigationResult",
    "GapObservation",
    "GapSupplementProposal",
    "build_gap_published_revision",
    "build_gap_investigation_result",
    "build_lineage_graph_views",
    "compile_eirs_gap_plan",
    "compile_gap_investigation",
    "controlled_domain_retrieval_observation",
    "gap_domain_scenario",
    "gap_independence_proof",
    "gap_observation_for_step",
    "gap_worker_role",
    "json_pointer_value",
    "lower_gap_plan_steps",
    "make_gap_observation",
    "stable_plan_revision_id",
]
