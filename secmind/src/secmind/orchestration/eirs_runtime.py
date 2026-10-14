"""Typed EIRS runtime helpers used by the orchestration graph.

The module owns the deterministic evidence-gap feedback loop, while the
orchestrator remains the only owner of graph transitions, stores, leases,
budgets, and ToolBroker execution.  Every callback that can cross an
authority boundary is supplied by the orchestrator; this module never
dispatches a tool or publishes a report on its own.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from secmind.answer_revision_contracts import (
    ActorPatch,
    ApiOperationPatch,
    ExactAnswerPatch,
    FindingPatch,
    RevisionField,
    RevisionOperation,
    RevisionPayload,
    TimelineEventPatch,
)
from secmind.cognitive_loop import COGNITIVE_LOOP_VERSION
from secmind.cognitive_loop import update_belief as update_cognitive_belief
from secmind.evidence_graph import EvidenceGraph
from secmind.gap_plan import (
    GapAction,
    GapActionKind,
    GapDomain,
    GapPlan,
    compile_gap_plan,
    domain_for_capability,
    execution_capability_for_domain,
)
from secmind.investigation.evidence import InvestigationEvidenceGraph
from secmind.investigation.supplement import (
    GapInvestigationResult,
    GapObservation,
    build_gap_investigation_result,
    build_lineage_graph_views,
    compile_eirs_gap_plan,
    gap_domain_scenario,
    gap_independence_proof,
    gap_observation_for_step,
    lower_gap_plan_steps,
)
from secmind.language_registry import language_for_path
from secmind.orchestration.obligation_runtime import refresh_obligation_set
from secmind.orchestration.typed_answer_runtime import (
    active_answer,
    project_active_answer,
    revise_active_answer,
)
from secmind.schemas import (
    AgentState,
    ClaimStatus,
    PlanStep,
    RiskLevel,
    RunStatus,
    StepRuntime,
    StepStatus,
    ToolHealth,
)
from secmind.task_contract import canonical_digest
from secmind.tools import ToolError


def effective_answer_payload(state: AgentState) -> dict[str, Any]:
    """Project deterministic tool-only results into the typed answer contract."""

    payload = dict(state.report.answer_payload if state.report is not None else {})
    contract = state.resolved_task_contract
    if contract is not None and contract.scoring_mode == "security_finding":
        gate = state.audit_coverage.get("tool_gain_gate", {})
        quarantined = (
            {str(item) for item in gate.get("quarantined_finding_ids", [])} if isinstance(gate, dict) else set()
        )
        baseline_ids = (
            {item.finding_id for item in state.published_baseline.findings}
            if state.published_baseline is not None
            else set()
        )
        verified_ids = {item.subject_ref for item in state.claims if item.status == ClaimStatus.VERIFIED}
        admitted = [
            item
            for item in state.findings
            if item.finding_id not in quarantined and item.finding_id in (baseline_ids | verified_ids)
        ]
        if admitted:
            payload["findings"] = [item.model_dump(mode="json") for item in admitted]
            payload.pop("negative_evidence", None)
        elif state.audit_coverage.get("negative_coverage_complete") is True:
            payload.setdefault("negative_evidence", ["bounded audit completed without an admitted finding"])
            payload.pop("findings", None)
        checked_paths = sorted(
            {
                str(item.metadata.get("path"))
                for item in state.evidence
                if isinstance(item.metadata.get("path"), str) and item.metadata.get("path")
            }
        )
        if state.audit_coverage.get("negative_coverage_complete") is True:
            checked_paths = sorted(
                {
                    *checked_paths,
                    *(item.relative_path for item in state.input_artifacts if item.relative_path),
                }
            )
        if checked_paths:
            payload.setdefault("checked_paths", checked_paths)
    return payload


def gap_tool_candidates(
    host: Any,
    state: AgentState,
    action: GapAction,
) -> tuple[str, list[str], PlanStep | None] | None:
    """Resolve a gap action to a registered, healthy R0/R1 tool lane."""

    input_languages = {
        language
        for artifact in state.input_artifacts
        if (language := language_for_path(artifact.relative_path)) is not None
    }

    def supports_input(manifest: Any) -> bool:
        supported = {str(item).casefold() for item in manifest.supported_languages}
        return not supported or bool(input_languages.intersection(supported))

    templates: list[PlanStep] = []
    for step in sorted(state.plan, key=lambda item: item.step_id):
        if step.step_id.startswith("eirs-") or not step.tool_candidates:
            continue
        try:
            manifest = host.broker.registry.get(step.tool_candidates[0]).manifest
        except (KeyError, ToolError):
            continue
        effective_risk = max(manifest.risk_level, manifest.platform_risk or RiskLevel.R0)
        if manifest.health_status == ToolHealth.UNAVAILABLE or effective_risk > RiskLevel.R1:
            continue
        if (
            action.kind == GapActionKind.RUN_TOOL
            and action.tool_name is not None
            and action.tool_name not in step.tool_candidates
        ):
            continue
        domain = domain_for_capability(step.capability)
        if action.kind != GapActionKind.RUN_TOOL:
            # A capability that is not in the cross-domain catalog is not a
            # wildcard.  The former ``domain is None`` branch let inventory
            # and SAST templates satisfy unrelated log/exact/API actions.
            # Require the concrete domain capability on the manifest before
            # considering an existing plan step.
            if action.capability not in manifest.capability_tags:
                continue
            if domain is not None and domain != action.domain:
                continue
        templates.append(step)

    templates.sort(
        key=lambda item: (
            0 if action.tool_name and action.tool_name in item.tool_candidates else 1,
            item.step_id,
        )
    )
    if templates:
        template = templates[0]
        try:
            first_manifest = host.broker.registry.get(template.tool_candidates[0]).manifest
        except (KeyError, ToolError):  # pragma: no cover - filtered above
            first_manifest = None
        if first_manifest is not None:
            capability = template.capability
            candidates = list(dict.fromkeys(template.tool_candidates))
            if action.tool_name in candidates:
                candidates.remove(action.tool_name)
                candidates.insert(0, action.tool_name)
            safe: list[str] = []
            for name in candidates:
                try:
                    manifest = host.broker.registry.get(name).manifest
                except (KeyError, ToolError):
                    continue
                effective_risk = max(manifest.risk_level, manifest.platform_risk or RiskLevel.R0)
                if (
                    manifest.health_status != ToolHealth.UNAVAILABLE
                    and effective_risk <= RiskLevel.R1
                    and (not manifest.capability_tags or capability in manifest.capability_tags)
                    and supports_input(manifest)
                ):
                    safe.append(name)
            if safe:
                return capability, safe, template

    requested_capability = action.capability
    scenario = gap_domain_scenario(action.domain, state.scenario)
    resolved = host.capability_resolver.resolve(
        requested_capability,
        scenario=scenario,
        maximum_risk=RiskLevel.R1,
    )
    if not resolved:
        fallback_capability = execution_capability_for_domain(action.domain)
        resolved = host.capability_resolver.resolve(
            fallback_capability,
            scenario=scenario,
            maximum_risk=RiskLevel.R1,
        )
        if resolved:
            requested_capability = fallback_capability
    if not resolved:
        return None
    selected = [
        item
        for item in resolved
        if item.manifest.health_status != ToolHealth.UNAVAILABLE and supports_input(item.manifest)
    ]
    if action.tool_name:
        selected.sort(key=lambda item: (0 if item.manifest.name == action.tool_name else 1, item.score))
    selected = selected[:2]
    return (requested_capability, [item.manifest.name for item in selected], None) if selected else None


def gap_plan_steps(
    host: Any,
    state: AgentState,
    plan: GapPlan,
) -> tuple[list[PlanStep], dict[str, str], list[GapObservation]]:
    """Lower EIRS actions into ordinary bounded worker steps."""

    return lower_gap_plan_steps(
        state,
        plan,
        resolve_tool_candidates=lambda action: gap_tool_candidates(host, state, action),
        rehash_evidence=host._rehash_evidence_artifacts,
        concurrency_key_for=lambda capability: host.broker.registry.get(capability).manifest.concurrency_key,
        investigation_store_available=host.investigation_store is not None,
    )


def materialize_eirs_steps(host: Any, state: AgentState, steps: list[PlanStep]) -> bool:
    """Commit EIRS worker authority through the normal plan/control boundary."""

    if not steps or len(state.plan) + len(steps) > state.budget.max_steps:
        return False
    if host.investigation_store is not None:
        return host._activate_supplement_steps(state, steps)
    contracts = []
    try:
        for step in steps:
            contract = host._compile_outcome_contract(step)
            step.outcome_contract_id = contract.contract_id
            contracts.append(contract)
    except (KeyError, ToolError, TypeError, ValueError):
        return False
    state.plan.extend(steps)
    state.outcome_contracts.extend(contracts)
    host.dag_scheduler.initialize(state)
    return True


def publish_eirs_revision(
    host: Any,
    state: AgentState,
    result: GapInvestigationResult,
) -> tuple[bool, tuple[str, ...]]:
    """Admit one observation-backed typed revision after all gates."""

    if state.report is None or not result.revision_proposals or active_answer(state) is None:
        return False, ()
    graph = EvidenceGraph(claims=state.claims, evidence=state.evidence, links=state.evidence_links)
    claims_by_id = {claim.claim_id: claim for claim in graph.claims}
    verified_ids = {
        link.evidence_id
        for link in graph.links
        if link.verifier_status == ClaimStatus.VERIFIED
        and claims_by_id.get(link.claim_id) is not None
        and claims_by_id[link.claim_id].status == ClaimStatus.VERIFIED
    }
    observed_ids = {
        evidence_id
        for observation in result.observations
        if observation.status == "observed"
        for evidence_id in observation.evidence_ids
    }
    candidate_ids = sorted(verified_ids & observed_ids)
    if not candidate_ids:
        return False, ()
    lineage = {
        item.evidence_id: str(item.metadata.get("step_id") or item.metadata.get("invocation_id") or item.source)
        for item in state.evidence
    }
    try:
        views = build_lineage_graph_views(graph, lineage)
        independent = InvestigationEvidenceGraph(views).independent_evidence(candidate_ids)
    except (TypeError, ValueError):
        return False, ()
    independent_ids = tuple(item.evidence.evidence_id for item in independent)
    if len(independent) < 2:
        return False, independent_ids
    proof = gap_independence_proof(independent[0].evidence, independent[1].evidence, run_id=state.run_id)
    if proof is None:
        return False, independent_ids
    proposal = result.revision_proposals[0]
    runtime = state.audit_coverage.get("typed_answer_runtime")
    prior_proposals = runtime.get("revision_proposal_ids", []) if isinstance(runtime, dict) else []
    if proposal.proposal_id in prior_proposals:
        return True, independent_ids
    revision_spec = _typed_eirs_revision(state, result, proposal, candidate_ids)
    if revision_spec is None or not host._adjudicate_deltas(state, "eirs_revision"):
        return False, independent_ids
    operation, field, payload, target = revision_spec
    typed = revise_active_answer(
        state,
        operation=operation,
        field=field,
        payload=payload,
        target_id=target,
        reason=f"eirs:{proposal.proposal_id}:{result.result_digest}",
        evidence_ids=candidate_ids,
    )
    if typed is None:
        return False, independent_ids
    active, _revision = typed
    if state.resolved_task_contract is not None:
        refresh_obligation_set(
            state,
            active.answer.model_dump(mode="json"),
            evidence_ids=[item.evidence_id for item in state.evidence],
        )
    project_active_answer(state, active)
    state.audit_coverage.setdefault("eirs_runtime", {})
    if not isinstance(state.audit_coverage["eirs_runtime"], dict):
        state.audit_coverage["eirs_runtime"] = {}
    state.audit_coverage["eirs_runtime"]["typed_revision_id"] = _revision.revision_id
    state.audit_coverage["eirs_runtime"]["typed_revision_field"] = _revision.field.value
    state.audit_coverage["eirs_runtime"]["typed_revision_operation"] = _revision.operation.value
    typed_runtime = state.audit_coverage.get("typed_answer_runtime")
    if isinstance(typed_runtime, dict):
        typed_runtime["revision_proposal_ids"] = [*prior_proposals, proposal.proposal_id]
    return True, independent_ids


def _typed_eirs_revision(
    state: AgentState,
    result: GapInvestigationResult,
    proposal: Any,
    evidence_ids: Sequence[str],
) -> tuple[RevisionOperation, RevisionField, RevisionPayload | None, str | None] | None:
    """Turn one EIRS field impact into a real five-field typed patch."""

    impact = next(iter([*result.field_impacts, *proposal.field_impacts]), None)
    if impact is None:
        return None
    field = _revision_field(impact.field_path, impact.domain)
    if field is None:
        return None
    operation = _revision_operation(impact.impact_kind)
    payload, target = _revision_payload(state, field, operation, result, proposal, evidence_ids)
    if operation != RevisionOperation.RETRACT and payload is None:
        return None
    if operation in {RevisionOperation.REPLACE, RevisionOperation.RETRACT} and not target:
        operation = RevisionOperation.SUPPLEMENT
    if operation == RevisionOperation.RETRACT:
        payload = None
    return operation, field, payload, target


def _revision_field(path: str, domain: GapDomain) -> RevisionField | None:
    normalized = str(path).casefold()
    if normalized.startswith("/findings") or domain == GapDomain.CODE:
        return RevisionField.FINDINGS
    if normalized.startswith(("/timeline", "/events")) or domain == GapDomain.LOG:
        return RevisionField.TIMELINE
    if normalized.startswith(("/actors", "/behavior")) or domain == GapDomain.FORENSICS:
        return RevisionField.ACTOR
    if normalized.startswith(("/operations", "/api_operations")) or domain == GapDomain.API:
        return RevisionField.API_OPERATION
    if normalized.startswith(("/answer", "/values", "/items", "/mapping")) or domain in {
        GapDomain.EXACT,
        GapDomain.EVIDENCE_GAP,
        GapDomain.FIRMWARE,
    }:
        return RevisionField.EXACT_ANSWER
    return None


def _revision_operation(value: str) -> RevisionOperation:
    normalized = str(value).casefold()
    if normalized == "replace":
        return RevisionOperation.REPLACE
    if normalized == "retract":
        return RevisionOperation.RETRACT
    return RevisionOperation.SUPPLEMENT


def _revision_payload(
    state: AgentState,
    field: RevisionField,
    operation: RevisionOperation,
    result: GapInvestigationResult,
    proposal: Any,
    evidence_ids: Sequence[str],
) -> tuple[RevisionPayload | None, str | None]:
    answer = active_answer(state)
    if answer is None:
        return None, None
    raw = answer.answer.model_dump(mode="python")
    observation = next((item for item in result.observations if item.status == "observed"), None)
    candidate = _candidate_row(raw, field, evidence_ids)
    if field == RevisionField.FINDINGS:
        row = candidate or _finding_candidate(state, evidence_ids)
        if row is None:
            return None, None
        try:
            finding_patch = FindingPatch.model_validate(_finding_values(row, evidence_ids))
        except (TypeError, ValueError):
            return None, None
        return finding_patch, finding_patch.finding_id
    if field == RevisionField.TIMELINE:
        values = _timeline_values(candidate, observation, evidence_ids, proposal.proposal_id)
        try:
            timeline_patch = TimelineEventPatch.model_validate(values)
        except (TypeError, ValueError):
            return None, None
        return timeline_patch, timeline_patch.event_id
    if field == RevisionField.ACTOR:
        values = _actor_values(candidate, observation, evidence_ids, proposal.proposal_id)
        try:
            actor_patch = ActorPatch.model_validate(values)
        except (TypeError, ValueError):
            return None, None
        return actor_patch, actor_patch.actor_id
    if field == RevisionField.API_OPERATION:
        values = _api_values(candidate, observation, evidence_ids, proposal.proposal_id)
        try:
            api_patch = ApiOperationPatch.model_validate(values)
        except (TypeError, ValueError):
            return None, None
        return api_patch, api_patch.operation_id
    values = _exact_values(candidate, observation, evidence_ids, proposal.proposal_id)
    try:
        exact_patch = ExactAnswerPatch.model_validate(values)
    except (TypeError, ValueError):
        return None, None
    return exact_patch, exact_patch.answer_id


def _candidate_row(
    answer: Mapping[str, Any], field: RevisionField, evidence_ids: Sequence[str]
) -> dict[str, Any] | None:
    keys = {
        RevisionField.FINDINGS: ("findings",),
        RevisionField.TIMELINE: ("events",),
        RevisionField.ACTOR: ("actors",),
        RevisionField.API_OPERATION: ("operations", "api_operations"),
        RevisionField.EXACT_ANSWER: ("items", "mapping"),
    }[field]
    wanted = set(evidence_ids)
    for key in keys:
        values = answer.get(key)
        if isinstance(values, dict):
            values = [dict(value, answer_id=str(name)) for name, value in values.items() if isinstance(value, dict)]
        if not isinstance(values, list):
            continue
        for value in values:
            if isinstance(value, Mapping) and wanted.intersection(_row_evidence(value)):
                return dict(value)
        for value in values:
            if isinstance(value, Mapping):
                return dict(value)
    return None


def _finding_candidate(state: AgentState, evidence_ids: Sequence[str]) -> dict[str, Any] | None:
    wanted = set(evidence_ids)
    for finding in state.findings:
        if wanted.intersection(finding.evidence_ids):
            return finding.model_dump(mode="python")
    return None


def _finding_values(row: Mapping[str, Any], evidence_ids: Sequence[str]) -> dict[str, Any]:
    return {
        "finding_id": str(row.get("finding_id") or row.get("id") or "eirs-finding"),
        "rule_id": row.get("rule_id"),
        "cwe": row.get("cwe"),
        "severity": row.get("severity") or "UNKNOWN",
        "path": row.get("path") or row.get("relative_path"),
        "line": row.get("line") or 1,
        "title": row.get("title"),
        "description": row.get("description"),
        "remediation": row.get("remediation"),
        "evidence_ids": tuple(sorted({*evidence_ids, *_row_evidence(row)})),
        "fields": row.get("fields") if isinstance(row.get("fields"), dict) else {},
    }


def _timeline_values(
    row: Mapping[str, Any] | None,
    observation: Any,
    evidence_ids: Sequence[str],
    proposal_id: str,
) -> dict[str, Any]:
    row = row or {}
    return {
        "event_id": str(row.get("event_id") or row.get("id") or f"eirs-event-{proposal_id}"),
        "timestamp": str(row.get("timestamp") or row.get("time") or "unknown"),
        "event_type": str(row.get("event_type") or row.get("type") or "eirs_observation"),
        "actor_id": row.get("actor_id"),
        "source_ref": row.get("source_ref") or _observation_ref(observation),
        "evidence_ids": tuple(sorted({*evidence_ids, *_row_evidence(row)})),
        "fields": {"observation_id": getattr(observation, "observation_id", proposal_id)},
    }


def _actor_values(
    row: Mapping[str, Any] | None,
    observation: Any,
    evidence_ids: Sequence[str],
    proposal_id: str,
) -> dict[str, Any]:
    row = row or {}
    return {
        "actor_id": str(row.get("actor_id") or row.get("id") or f"eirs-actor-{proposal_id}"),
        "name": row.get("name"),
        "role": row.get("role") or getattr(getattr(observation, "domain", None), "value", None),
        "account": row.get("account"),
        "evidence_ids": tuple(sorted({*evidence_ids, *_row_evidence(row)})),
        "fields": {"observation_id": getattr(observation, "observation_id", proposal_id)},
    }


def _api_values(
    row: Mapping[str, Any] | None,
    observation: Any,
    evidence_ids: Sequence[str],
    proposal_id: str,
) -> dict[str, Any]:
    row = row or {}
    evidence = next(
        (item for item in getattr(observation, "evidence_ids", ()) if item in set(evidence_ids)),
        None,
    )
    evidence_values = {*evidence_ids, *_row_evidence(row)}
    if evidence is not None:
        evidence_values.add(evidence)
    return {
        "operation_id": str(row.get("operation_id") or row.get("id") or f"eirs-operation-{proposal_id}"),
        "method": str(row.get("method") or "GET"),
        "path": str(row.get("path") or row.get("endpoint") or f"/eirs/{proposal_id}"),
        "status_code": row.get("status_code"),
        "request": row.get("request") if isinstance(row.get("request"), dict) else None,
        "response": row.get("response") if isinstance(row.get("response"), dict) else None,
        "evidence_ids": tuple(sorted(evidence_values)),
        "fields": {"observation_id": getattr(observation, "observation_id", proposal_id)},
    }


def _exact_values(
    row: Mapping[str, Any] | None,
    observation: Any,
    evidence_ids: Sequence[str],
    proposal_id: str,
) -> dict[str, Any]:
    row = row or {}
    value = row.get("value")
    if value is None:
        value = {
            "observation_id": getattr(observation, "observation_id", proposal_id),
            "evidence_ids": list(evidence_ids),
        }
    return {
        "answer_id": str(row.get("answer_id") or row.get("id") or f"eirs-answer-{proposal_id}"),
        "value": value,
        "evidence_ids": tuple(sorted({*evidence_ids, *_row_evidence(row)})),
        "source_ref": _observation_ref(observation),
    }


def _row_evidence(row: Mapping[str, Any]) -> set[str]:
    raw = row.get("evidence_ids")
    return {str(item) for item in raw if str(item).strip()} if isinstance(raw, (list, tuple, set)) else set()


def _observation_ref(observation: Any) -> str | None:
    if observation is None:
        return None
    outputs = getattr(observation, "output_refs", ())
    return str(outputs[0]) if outputs else str(getattr(observation, "observation_id", "")) or None


def _semantic_candidate_count(state: AgentState, domain: GapDomain) -> int:
    """Count bounded deterministic candidates without treating gaps as facts."""

    raw = state.audit_coverage.get("scenario_semantic_delta")
    if not isinstance(raw, Mapping):
        return 0
    scenario = str(raw.get("scenario") or "").casefold()
    answer_kind = str(raw.get("answer_kind") or "").casefold()
    domain_match = {
        GapDomain.LOG: scenario == "log_analysis" or answer_kind == "timeline",
        GapDomain.API: scenario == "api_assessment",
        GapDomain.EXACT: answer_kind == "exact",
        GapDomain.EVIDENCE_GAP: answer_kind == "evidence_gap",
        GapDomain.FORENSICS: scenario == "reverse_triage" or answer_kind == "reverse_behavior",
        GapDomain.FIRMWARE: "firmware" in scenario,
        GapDomain.PATCH: answer_kind == "patch_validation",
        GapDomain.IR: scenario == "incident_response",
        GapDomain.CODE: answer_kind == "finding",
    }.get(domain, False)
    if not domain_match:
        return 0
    candidates: list[Any] = []
    for key in ("facts", "policy_decisions"):
        values = raw.get(key)
        if isinstance(values, (list, tuple)):
            candidates.extend(values)
    graph_key = "endpoint_graph" if domain == GapDomain.API else None
    if graph_key is not None and isinstance(raw.get(graph_key), Mapping) and raw.get(graph_key):
        candidates.append(raw[graph_key])
    incident = raw.get("incident_response")
    if domain == GapDomain.IR and isinstance(incident, Mapping):
        for key in ("actions", "hypotheses"):
            values = incident.get(key)
            if isinstance(values, (list, tuple)):
                candidates.extend(values)
    # One semantic delta is still a candidate when it carries an evidence
    # closure but its domain values are scalar (common for exact extraction).
    evidence_ids = raw.get("evidence_ids")
    if not candidates and isinstance(evidence_ids, (list, tuple)) and evidence_ids:
        candidates.append({"evidence_ids": list(evidence_ids)})
    return min(2_000, len(candidates))


def _semantic_delta_is_admitted(state: AgentState) -> bool:
    raw = state.audit_coverage.get("scenario_semantic_delta")
    published = (
        state.report.answer_payload.get("semantic_delta")
        if state.report is not None and isinstance(state.report.answer_payload, dict)
        else None
    )
    return bool(
        isinstance(raw, Mapping)
        and isinstance(published, Mapping)
        and raw.get("delta_id") == published.get("delta_id")
        and raw.get("disposition") == "accepted"
        and raw.get("admission_ready") is True
    )


def _record_current_semantic_pipeline(state: AgentState) -> None:
    """Record an already fused parser delta even when EIRS finds no gap."""

    raw = state.audit_coverage.get("scenario_semantic_delta")
    if not isinstance(raw, Mapping):
        return
    known = {item.evidence_id for item in state.evidence}
    raw_ids = raw.get("evidence_ids")
    evidence_ids = (
        sorted({str(item) for item in raw_ids if str(item) in known}) if isinstance(raw_ids, (list, tuple)) else []
    )
    verified_claim_ids = {item.claim_id for item in state.claims if item.status == ClaimStatus.VERIFIED}
    verified_ids = {
        link.evidence_id
        for link in state.evidence_links
        if link.claim_id in verified_claim_ids and link.evidence_id in evidence_ids
    }
    rows: dict[str, dict[str, Any]] = {}
    for domain in GapDomain:
        candidate_count = _semantic_candidate_count(state, domain)
        if candidate_count == 0:
            continue
        correlated_count = min(candidate_count, len(evidence_ids))
        verified_count = min(correlated_count, len(verified_ids))
        admitted_count = verified_count if _semantic_delta_is_admitted(state) else 0
        rows[domain.value] = {
            "capability": execution_capability_for_domain(domain),
            "execution_mode": "controlled_retrieval",
            "candidate_count": candidate_count,
            "correlated_count": correlated_count,
            "verified_count": verified_count,
            "admitted_count": admitted_count,
            "observation_count": 1,
            "evidence_ids": evidence_ids[:1_000],
            "status": ("admitted" if admitted_count else "verified_not_admitted" if verified_count else "observed"),
        }
    _write_cross_domain_pipeline(state, rows)


def _write_cross_domain_pipeline(state: AgentState, rows: Mapping[str, Mapping[str, Any]]) -> None:
    normalized = {str(key): dict(value) for key, value in sorted(rows.items())}
    totals = {
        key: sum(_metric_int(row.get(key)) for row in normalized.values())
        for key in ("candidate_count", "correlated_count", "verified_count", "admitted_count")
    }
    pipeline: dict[str, Any] = {
        "version": "cross-domain-capability-pipeline-1",
        "domains": normalized,
        **totals,
        "counting_scope": "domain_lanes",
        "dynamic_or_attack_execution": False,
    }
    pipeline["pipeline_digest"] = canonical_digest(pipeline)
    state.audit_coverage["cross_domain_capability_pipeline"] = pipeline
    if state.report is not None:
        state.report = state.report.model_copy(update={"coverage": dict(state.audit_coverage)})


def _metric_int(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def _pipeline_runtime_fields(state: AgentState) -> dict[str, Any]:
    raw = state.audit_coverage.get("cross_domain_capability_pipeline")
    if not isinstance(raw, Mapping):
        return {}
    admitted = _metric_int(raw.get("admitted_count"))
    return {
        "capability_pipeline_digest": raw.get("pipeline_digest"),
        "candidate_count": _metric_int(raw.get("candidate_count")),
        "correlated_count": _metric_int(raw.get("correlated_count")),
        "verified_count": _metric_int(raw.get("verified_count")),
        "admitted_count": admitted,
        # Release evaluation historically names an admitted typed revision an
        # accepted delta.  Keep the alias in the EIRS diagnostic envelope,
        # not in the public Admission contract.
        "accepted_delta_count": admitted,
    }


def _record_cross_domain_pipeline(
    state: AgentState,
    result: GapInvestigationResult,
    *,
    revision_admitted: bool,
) -> None:
    """Persist the real candidate→correlated→verified→admitted funnel.

    Counts are deliberately monotonic and evidence-derived.  A retrieval
    receipt with no semantic candidate remains zero rather than claiming a
    capability gain.  The metric is written into run truth so the final
    report, evaluation adapter, and replay all observe the same result.
    """

    semantic_admitted = _semantic_delta_is_admitted(state)
    verified_claim_ids = {item.claim_id for item in state.claims if item.status == ClaimStatus.VERIFIED}
    verified_evidence_ids = {
        link.evidence_id for link in state.evidence_links if link.claim_id in verified_claim_ids and link.evidence_id
    }
    observations_by_action: dict[str, list[Any]] = {}
    known_evidence_ids = {item.evidence_id for item in state.evidence}
    for observation in result.observations:
        observations_by_action.setdefault(observation.action_id, []).append(observation)
    existing = state.audit_coverage.get("cross_domain_capability_pipeline")
    existing_domains = existing.get("domains") if isinstance(existing, Mapping) else None
    rows: dict[str, dict[str, Any]] = (
        {str(key): dict(value) for key, value in existing_domains.items() if isinstance(value, Mapping)}
        if isinstance(existing_domains, Mapping)
        else {}
    )
    for action in result.plan.actions:
        if action.kind not in {
            GapActionKind.RETRIEVE_DOMAIN,
            GapActionKind.OBSERVE_DOMAIN,
            GapActionKind.RUN_TOOL,
        }:
            continue
        observations = observations_by_action.get(action.action_id, [])
        evidence_ids = sorted(
            {
                evidence_id
                for observation in observations
                for evidence_id in observation.evidence_ids
                if evidence_id in known_evidence_ids
            }
        )
        semantic_candidates = _semantic_candidate_count(state, action.domain)
        candidate_count = max(semantic_candidates, len(evidence_ids))
        correlated_count = min(candidate_count, len(evidence_ids))
        verified_count = min(
            correlated_count,
            len(set(evidence_ids).intersection(verified_evidence_ids)),
        )
        admitted_count = verified_count if revision_admitted or semantic_admitted else 0
        current = rows.get(action.domain.value, {})
        current_ids = current.get("evidence_ids")
        merged_candidate = max(candidate_count, _metric_int(current.get("candidate_count")))
        merged_correlated = max(correlated_count, _metric_int(current.get("correlated_count")))
        merged_verified = max(verified_count, _metric_int(current.get("verified_count")))
        merged_admitted = max(admitted_count, _metric_int(current.get("admitted_count")))
        rows[action.domain.value] = {
            "capability": action.capability,
            "execution_mode": (
                "controlled_retrieval" if action.kind == GapActionKind.RETRIEVE_DOMAIN else "tool_broker"
            ),
            "candidate_count": merged_candidate,
            "correlated_count": merged_correlated,
            "verified_count": merged_verified,
            "admitted_count": merged_admitted,
            "observation_count": max(len(observations), _metric_int(current.get("observation_count"))),
            "evidence_ids": sorted(
                {
                    *evidence_ids,
                    *(
                        (str(item) for item in current_ids if str(item).strip())
                        if isinstance(current_ids, (list, tuple, set))
                        else ()
                    ),
                }
            )[:1_000],
            "status": (
                "admitted"
                if merged_admitted
                else "verified_not_admitted"
                if merged_verified
                else "observed"
                if merged_candidate
                else "no_candidate"
            ),
        }
    _write_cross_domain_pipeline(state, rows)


def advance_eirs_runtime(host: Any, state: AgentState) -> tuple[bool, dict[str, Any]]:
    """Advance one replay-stable EIRS round; return whether scheduling is needed."""

    _record_current_semantic_pipeline(state)
    raw_runtime = state.audit_coverage.get("eirs_runtime")
    runtime = dict(raw_runtime) if isinstance(raw_runtime, dict) else {}
    if runtime.get("status") in {"published", "blocked", "exhausted"}:
        return False, runtime
    if runtime.get("status") == "scheduled":
        try:
            plan = GapPlan.model_validate(runtime["plan"])
        except (TypeError, ValueError):
            runtime.update({"status": "blocked", "reason": "gap_plan_corrupt"})
            return False, runtime
        action_steps = {str(key): str(value) for key, value in dict(runtime.get("action_steps", {})).items()}
        if any(
            state.step_runtime.get(step_id, StepRuntime(step_id=step_id)).status
            not in {StepStatus.SUCCEEDED, StepStatus.FAILED, StepStatus.SKIPPED, StepStatus.CANCELLED}
            for step_id in action_steps.values()
        ):
            return True, runtime
        observations = [GapObservation.model_validate(item) for item in runtime.get("deterministic_observations", [])]
        for action in plan.actions:
            step_id = action_steps.get(action.action_id)
            if step_id is not None:
                observations.append(gap_observation_for_step(state, action, step_id))
        result = build_gap_investigation_result(plan, observations)
        published, independent_ids = publish_eirs_revision(host, state, result)
        _record_cross_domain_pipeline(state, result, revision_admitted=published)
        runtime.update(
            {
                "status": "published" if published else "blocked",
                "result": result.model_dump(mode="json"),
                "independent_evidence_ids": list(independent_ids),
                "revision_ids": [item.revision_proposal_ids for item in plan.actions if item.revision_proposal_ids],
                "reason": "revision_admitted" if published else "verifier_or_independence_gate",
                **_pipeline_runtime_fields(state),
            }
        )
        return False, runtime

    configured_budgets = state.audit_coverage.get("eirs_budgets")
    eirs_budgets = configured_budgets if isinstance(configured_budgets, Mapping) else None
    try:
        compiled_result = compile_eirs_gap_plan(state, max_actions=4, budgets=eirs_budgets)
    except (TypeError, ValueError):
        runtime.update({"status": "blocked", "reason": "eirs_budget_invalid"})
        return False, runtime
    if compiled_result is None:
        runtime.update(
            {
                "status": "closed",
                "reason": "no_open_obligations",
                **_pipeline_runtime_fields(state),
            }
        )
        return False, runtime
    steps, action_steps, deterministic = gap_plan_steps(host, state, compiled_result.plan)
    if steps and materialize_eirs_steps(host, state, steps):
        state.status = RunStatus.RUNNING
        runtime.update(
            {
                "status": "scheduled",
                "plan": compiled_result.plan.model_dump(mode="json"),
                "action_steps": action_steps,
                "deterministic_observations": [item.model_dump(mode="json") for item in deterministic],
                "result_digest": compiled_result.result_digest,
                **_pipeline_runtime_fields(state),
            }
        )
        return True, runtime
    if deterministic:
        folded = build_gap_investigation_result(compiled_result.plan, deterministic)
        published, independent_ids = publish_eirs_revision(host, state, folded)
        _record_cross_domain_pipeline(state, folded, revision_admitted=published)
        runtime.update(
            {
                "status": "published" if published else "blocked",
                "plan": compiled_result.plan.model_dump(mode="json"),
                "result": folded.model_dump(mode="json"),
                "independent_evidence_ids": list(independent_ids),
                "reason": "revision_admitted" if published else "deterministic_only",
                **_pipeline_runtime_fields(state),
            }
        )
    else:
        runtime.update({"status": "blocked", "reason": "no_legal_evidence_path"})
    return False, runtime


async def update_belief(host: Any, value: Any) -> Any:
    """Apply one bounded evidence-to-belief revision and checkpoint it."""

    state = host._state(value)
    if state.resolved_task_contract is not None and state.report is not None:
        refresh_obligation_set(
            state,
            effective_answer_payload(state),
            evidence_ids=[item.evidence_id for item in state.evidence],
        )
    previous_digest = state.belief_state.belief_digest if state.belief_state is not None else None
    state.belief_state = update_cognitive_belief(state)
    gap_plan = compile_gap_plan(state)
    state.audit_coverage["cognitive_gap_plan"] = (
        {"status": "closed", "reason": "no_open_obligations"} if gap_plan is None else gap_plan.model_dump(mode="json")
    )
    eirs_schedule, eirs_runtime = advance_eirs_runtime(host, state)
    state.audit_coverage["eirs_runtime"] = eirs_runtime
    if eirs_runtime.get("status") == "published":
        state.belief_state = update_cognitive_belief(state)
        refreshed_gap_plan = compile_gap_plan(state)
        state.audit_coverage["cognitive_gap_plan"] = (
            {"status": "closed", "reason": "no_open_obligations"}
            if refreshed_gap_plan is None
            else refreshed_gap_plan.model_dump(mode="json")
        )
    return await host._checkpoint(
        state,
        "belief.revised",
        {
            "cognitive_loop_version": COGNITIVE_LOOP_VERSION,
            "previous_digest": previous_digest,
            "belief_digest": state.belief_state.belief_digest,
            "revision": state.belief_state.revision,
            "known_fact_count": len(state.belief_state.known_facts),
            "open_obligation_ids": list(state.belief_state.open_obligation_ids),
            "contradiction_count": len(state.belief_state.contradictions),
            "stagnation_count": state.belief_state.stagnation_count,
            "gap_plan_id": None if gap_plan is None else gap_plan.plan_id,
            "gap_action_count": 0 if gap_plan is None else len(gap_plan.actions),
            "eirs_plan_id": eirs_runtime.get("plan", {}).get("plan_id")
            if isinstance(eirs_runtime.get("plan"), dict)
            else None,
            "eirs_status": eirs_runtime.get("status"),
        },
        "schedule" if eirs_schedule else "completion",
    )


__all__ = [
    "advance_eirs_runtime",
    "effective_answer_payload",
    "gap_plan_steps",
    "gap_tool_candidates",
    "materialize_eirs_steps",
    "publish_eirs_revision",
    "update_belief",
]
