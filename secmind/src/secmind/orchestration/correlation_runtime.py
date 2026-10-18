"""Correlation node: analyst first, then store-backed delta adjudication."""

from __future__ import annotations

from typing import Any

from secmind.direct_anchor_pipeline import (
    DeltaAction,
    DeltaDisposition,
    TypedDelta,
    evidence_semantic_checks,
    stable_digest,
)
from secmind.evidence_graph import make_claim, make_link
from secmind.investigation.contracts import EvidenceRequest
from secmind.schemas import (
    SCHEMA_VERSION,
    AgentState,
    Claim,
    ClaimStatus,
    Evidence,
    EvidenceLink,
    EvidenceRelation,
    Finding,
    Scenario,
    StepStatus,
)
from secmind.tool_assurance import deterministic_negative_coverage_complete


async def correlate(host: Any, value: Any) -> Any:
    state = host._state(value)
    if state.audit_coverage.get("direct_anchor_pipeline") is True:
        state = await host.analyst.run(state)
        host._adjudicate_deltas(state, "direct-anchor-delta")
        state = await host.delta_critic.run(state)
        state = await host.delta_verifier.run(state)
    else:
        host._adjudicate_deltas(state, "delta")
        state = await host.analyst.run(state)
    quarantined_ids = {
        str(item) for item in state.audit_coverage.get("tool_gain_gate", {}).get("quarantined_finding_ids", [])
    }
    state.audit_coverage["negative_coverage_complete"] = (
        state.scenario == Scenario.CODE_AUDIT
        and deterministic_negative_coverage_complete(
            plan=state.plan,
            runtimes=state.step_runtime,
            observations=state.observations,
            findings=state.findings,
            quarantined_finding_ids=quarantined_ids,
        )
    )
    canonical_claims = [item for item in state.claims if item.producer == "canonical-primary"]
    canonical_claim_ids = {item.claim_id for item in canonical_claims}
    canonical_links = [item for item in state.evidence_links if item.claim_id in canonical_claim_ids]
    evidence_by_id = {item.evidence_id: item for item in state.evidence}
    producer_by_evidence: dict[str, str] = {}
    for step_id, runtime in state.step_runtime.items():
        for observation_index in runtime.observation_indexes:
            if observation_index >= len(state.observations):
                continue
            for evidence in state.observations[observation_index].evidence:
                producer_by_evidence[evidence.evidence_id] = step_id
    claims: list[Claim] = []
    links: list[EvidenceLink] = []
    confidence_values = {"HIGH": 0.95, "MEDIUM": 0.85, "LOW": 0.6, "UNKNOWN": 0.5}
    for finding in state.findings:
        producer = (
            "model-source-review"
            if finding.rule_id.startswith("CWE-") and isinstance(finding.raw.get("model_id"), str)
            else next(
                (
                    producer_by_evidence[evidence_id]
                    for evidence_id in finding.evidence_ids
                    if evidence_id in producer_by_evidence
                ),
                "unknown-producer",
            )
        )
        step = next((item for item in state.plan if item.step_id == producer), None)
        capability = (
            "model_source_review"
            if producer == "model-source-review"
            else (step.capability if step is not None else "unknown")
        )
        claim = make_claim(
            claim_type=f"{capability}.finding",
            statement=f"{finding.title}: {finding.description}",
            subject_ref=finding.finding_id,
            producer=producer,
            severity=finding.severity,
            confidence=confidence_values[finding.confidence],
            version=SCHEMA_VERSION,
        )
        claims.append(claim)
        links.extend(
            make_link(claim_id=claim.claim_id, evidence_id=evidence_id, relation=EvidenceRelation.SUPPORTS)
            for evidence_id in sorted(set(finding.evidence_ids))
            if evidence_id in evidence_by_id
        )
    for item in state.evidence:
        if item.metadata.get("evidence_type") != "canonical_primary_negative_coverage":
            continue
        path = str(item.metadata.get("path") or item.source)
        claim = make_claim(
            claim_type="code_audit.negative_coverage",
            statement=f"The bounded Canonical Primary explicitly checked {path} without a supported finding.",
            subject_ref=f"negative-coverage:{path}",
            producer="canonical-primary",
            confidence=0.85,
            version=SCHEMA_VERSION,
        )
        claims.append(claim)
        links.append(
            make_link(
                claim_id=claim.claim_id,
                evidence_id=item.evidence_id,
                relation=EvidenceRelation.SUPPORTS,
            )
        )
    for unit in state.audit_units:
        if unit.final_verdict == "inconclusive":
            continue
        claim = make_claim(
            claim_type="model_source_review.coverage",
            statement=(
                f"{unit.path} received an explicit {unit.final_verdict} verdict "
                f"bound to source digest {unit.source_sha256}."
            ),
            subject_ref=f"audit-unit:{unit.unit_id}",
            producer="model-source-review",
            confidence=unit.confidence,
            version=SCHEMA_VERSION,
        )
        claims.append(claim)
        links.extend(
            make_link(claim_id=claim.claim_id, evidence_id=evidence_id, relation=EvidenceRelation.SUPPORTS)
            for evidence_id in sorted(set(unit.evidence_ids))
            if evidence_id in evidence_by_id
        )
    for step in state.plan:
        step_runtime = state.step_runtime.get(step.step_id)
        if step_runtime is None or step_runtime.status != StepStatus.SUCCEEDED:
            continue
        coverage_evidence = next(
            (
                item
                for item in state.evidence
                if item.metadata.get("step_id") == step.step_id
                and item.metadata.get("evidence_type") == "execution_coverage"
            ),
            None,
        )
        if coverage_evidence is None:
            continue
        claim = make_claim(
            claim_type=f"{step.capability}.coverage",
            statement=f"{step.objective} completed with immutable execution coverage evidence.",
            subject_ref=f"coverage:{step.step_id}",
            producer=step.step_id,
            confidence=0.99,
            version=SCHEMA_VERSION,
        )
        claims.append(claim)
        links.append(
            make_link(
                claim_id=claim.claim_id,
                evidence_id=coverage_evidence.evidence_id,
                relation=EvidenceRelation.SUPPORTS,
            )
        )
    links.extend(supplement_evidence_links(host, state, claims, evidence_by_id))
    claims.extend(canonical_claims)
    links.extend(canonical_links)
    state.claims = sorted({item.claim_id: item for item in claims}.values(), key=lambda item: item.claim_id)
    state.evidence_links = sorted({item.link_id: item for item in links}.values(), key=lambda item: item.link_id)
    return await host._checkpoint(
        state,
        "analysis.correlated",
        {
            "finding_count": len(state.findings),
            "evidence_count": len(state.evidence),
            "claim_count": len(state.claims),
            "link_count": len(state.evidence_links),
        },
    )


def register_verified_scenario_deltas(state: AgentState) -> None:
    """Publish verifier-backed scenario findings through the typed-delta lane."""

    baseline = state.published_baseline
    if baseline is None or state.audit_coverage.get("direct_anchor_pipeline") is not True:
        return
    baseline_ids = {item.finding_id for item in baseline.findings}
    verified_subjects = {
        claim.subject_ref
        for claim in state.claims
        if claim.producer == "deterministic-scenario-analyzer" and claim.status == ClaimStatus.VERIFIED
    }
    evidence_by_id = {item.evidence_id: item for item in state.evidence}
    existing_raw = state.audit_coverage.get("typed_deltas", [])
    existing = [item for item in existing_raw if isinstance(item, dict)]
    existing_finding_ids = {
        str(item.get("finding", {}).get("finding_id")) for item in existing if isinstance(item.get("finding"), dict)
    }
    for finding in sorted(state.findings, key=lambda item: item.finding_id):
        if (
            finding.finding_id in baseline_ids
            or finding.finding_id not in verified_subjects
            or finding.finding_id in existing_finding_ids
        ):
            continue
        checks = evidence_semantic_checks(finding, evidence_by_id)
        if not checks["evidence_complete"]:
            continue
        candidate_id = f"scenario-candidate-{stable_digest(finding)[:32]}"
        cluster_id = f"scenario-cluster-{stable_digest({'finding_id': finding.finding_id})[:32]}"
        gate_digest = stable_digest(
            {
                "finding_id": finding.finding_id,
                "verified_subject": True,
                "producer": "deterministic-scenario-analyzer",
                "policy": "DETERMINISTIC-SCENARIO-DELTA-V1",
            }
        )
        payload = {
            "run_id": state.run_id,
            "cluster_id": cluster_id,
            "candidate_ids": (candidate_id,),
            "action": DeltaAction.ADD,
            "disposition": DeltaDisposition.ACCEPTED,
            "finding": finding,
            "evidence_ids": tuple(sorted(set(finding.evidence_ids))),
            "producer_ids": ("deterministic-scenario-analyzer",),
            "reason_code": "deterministic_scenario_verified",
            "evidence_complete": True,
            "semantic_checks": checks,
            "admission_ready": True,
            "anchor_semantic_digest": baseline.semantic_digest,
            "gate_digest": gate_digest,
        }
        delta = TypedDelta.model_validate({"delta_id": f"delta-{stable_digest(payload)[:32]}", **payload})
        existing.append(delta.model_dump(mode="json"))
    if existing:
        state.audit_coverage["typed_deltas"] = existing


def supplement_evidence_links(
    host: Any,
    state: AgentState,
    claims: list[Claim],
    evidence_by_id: dict[str, Evidence],
) -> list[EvidenceLink]:
    """Link only location-matching supplemental results to their target claim."""

    if host.investigation_store is None or not state.active_evidence_request_ids:
        return []
    claims_by_id = {item.claim_id: item for item in claims}
    findings_by_id = {item.finding_id: item for item in state.findings}
    evidence_requests = latest_evidence_requests(host, state)
    links: list[EvidenceLink] = []
    for request_id in sorted(state.active_evidence_request_ids):
        request = evidence_requests.get(request_id)
        target = claims_by_id.get(request.target_claim_id or "") if request is not None else None
        original = findings_by_id.get(target.subject_ref) if target is not None else None
        if request is None or target is None or original is None:
            continue
        for step_id, runtime in sorted(state.step_runtime.items()):
            if not step_id.startswith("supplement-"):
                continue
            for observation_index in runtime.observation_indexes:
                if observation_index >= len(state.observations):
                    continue
                observation = state.observations[observation_index]
                observation_evidence_ids = {item.evidence_id for item in observation.evidence}
                for raw in observation.data.get("findings", []):
                    try:
                        finding = Finding.model_validate(raw)
                    except (TypeError, ValueError):
                        continue
                    same_location = finding.path == original.path and (
                        finding.line == original.line or finding.line is None or original.line is None
                    )
                    same_signature = finding.rule_id == original.rule_id or finding.title == original.title
                    if not same_location or not same_signature:
                        continue
                    for evidence_id in sorted(set(finding.evidence_ids) & observation_evidence_ids):
                        if evidence_id in evidence_by_id:
                            links.append(
                                make_link(
                                    claim_id=target.claim_id,
                                    evidence_id=evidence_id,
                                )
                            )
    return links


def latest_evidence_requests(host: Any, state: AgentState) -> dict[str, EvidenceRequest]:
    if host.investigation_store is None:
        return {}
    latest: dict[str, EvidenceRequest] = {}
    active = set(state.active_evidence_request_ids)
    for payload in host.investigation_store.list_objects(state.run_id, "evidence_request"):
        request_id = payload.get("request_id")
        if request_id not in active:
            continue
        request = EvidenceRequest.model_validate(payload)
        if request_id not in latest or request.request_version > latest[request_id].request_version:
            latest[request_id] = request
    return latest


__all__ = ["correlate", "latest_evidence_requests", "register_verified_scenario_deltas", "supplement_evidence_links"]
