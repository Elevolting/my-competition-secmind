"""Pure evidence and completion projections for the workflow.

These functions transform an immutable view of ``AgentState`` into derived
contracts or read models. They perform no database, model, network, or tool
calls, which makes the most security-sensitive completion rules reviewable
without navigating the full LangGraph implementation.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal
from uuid import NAMESPACE_URL, uuid5

from secmind.canonical_primary import canonical_input_manifest, canonical_manifest_digest
from secmind.domain_answers import ExactAnswer, TypedSemanticDelta
from secmind.evidence_graph import EvidenceGraph, make_claim, make_link
from secmind.investigation.contracts import (
    ObligationStatus,
    RequirementObligation,
    seal_contract,
)
from secmind.investigation.evidence import InvestigationEvidenceGraph
from secmind.investigation.supplement import build_lineage_graph_views
from secmind.ledger import canonical_json
from secmind.orchestration.domain_projection import build_scenario_semantic_delta_receipt
from secmind.orchestration.obligation_runtime import current_obligation_set
from secmind.primary_baseline import validate_baseline_chain
from secmind.schemas import (
    AgentState,
    Claim,
    ClaimStatus,
    ContextItemRef,
    Evidence,
    EvidenceAssurance,
    EvidenceRelation,
    Finding,
    OutcomeContract,
    Scenario,
    VerificationResult,
)
from secmind.task_context import ResolvedTaskContractRequired, require_resolved_task_contract
from secmind.task_contract import (
    CompositeObligationStatus,
    ObligationKind,
    ObligationSet,
    resolved_contract_digest,
)
from secmind.task_contract import (
    ObligationStatus as AnswerObligationStatus,
)
from secmind.task_contract import (
    canonical_digest as task_contract_digest,
)

_CANONICAL_BASELINE_EVIDENCE_TYPE = "canonical_primary_baseline"
_TASK_OBLIGATION_SET_EVIDENCE_TYPE = "task_obligation_set_receipt"
_CANONICAL_PRIMARY_POLICY_VERSION = "canonical-primary-policy-v0.8.6"
_CANONICAL_PRIMARY_POLICY_RECEIPT_KEYS = frozenset(
    {
        "policy_version",
        "run_id",
        "resolved_contract_id",
        "resolved_contract_digest",
        "input_manifest_digest",
        "policy",
        "network_enabled",
        "receipt_digest",
    }
)


def _task_input_manifest_digest(state: AgentState) -> str:
    """Rebuild the full ingest-manifest digest bound to the task contract."""

    return task_contract_digest(
        [
            {
                "artifact_id": item.artifact_id,
                "relative_path": item.relative_path,
                "sha256": item.sha256.lower(),
                "size_bytes": item.size_bytes,
                "media_type": item.media_type,
            }
            for item in sorted(state.input_artifacts, key=lambda row: row.relative_path.casefold())
        ]
    )


def _value_present(value: object) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (Mapping, list, tuple, set, frozenset)):
        return bool(value)
    return True


def _relative_ref(value: str) -> str:
    normalized = value.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized


def _exact_bound_evidence(answer: ExactAnswer) -> set[str] | None:
    expected = answer.values if isinstance(answer.values, list) else [answer.values]
    expected_keys = {canonical_json(item) for item in expected if _value_present(item)}
    bound: dict[str, set[str]] = {}
    for row in answer.items:
        if not isinstance(row, Mapping) or not _value_present(row.get("value")):
            continue
        raw_evidence_ids = row.get("evidence_ids", [])
        evidence_ids = (
            {str(item) for item in raw_evidence_ids if str(item)}
            if isinstance(raw_evidence_ids, (list, tuple, set, frozenset))
            else set()
        )
        locator = row.get("record_locator") or row.get("source_locator")
        if evidence_ids and isinstance(locator, Mapping):
            bound.setdefault(canonical_json(row["value"]), set()).update(evidence_ids)
    if not expected_keys or not expected_keys <= set(bound):
        return None
    return {item for key in expected_keys for item in bound[key]}


def _skip_check(checks: dict[str, bool], reason_code: str, condition: object) -> bool:
    """Record one non-sensitive fail-closed predicate and return its value."""

    passed = bool(condition)
    checks[reason_code] = passed
    return passed


def _exact_answer_skip_checks(
    state: AgentState,
    delta: TypedSemanticDelta,
    authority: ObligationSet,
    checks: dict[str, bool],
) -> None:
    contract, report = state.resolved_task_contract, state.report
    _skip_check(checks, "exact.run_status_partial", state.status.value == "partial")
    _skip_check(checks, "exact.report_status_matches", report is not None and report.status == state.status)
    _skip_check(
        checks,
        "exact.scoring_mode",
        contract is not None and contract.scoring_mode == "exact_answer_with_evidence",
    )
    _skip_check(checks, "exact.answer_kind", delta.answer_kind == "exact")
    _skip_check(checks, "exact.delta_run_matches", delta.run_id == state.run_id)
    _skip_check(
        checks,
        "exact.deterministic_process",
        delta.process_provenance.process_id == "secmind.deterministic-scenario-analyzer",
    )
    _skip_check(checks, "exact.no_last_error", state.last_error is None)
    _skip_check(checks, "exact.not_cancelled", not state.cancel_requested)
    _skip_check(checks, "exact.no_pending_approval", state.pending_approval is None)
    _skip_check(checks, "exact.no_pending_approvals", not state.pending_approvals)
    _skip_check(checks, "exact.no_pending_clarification", state.pending_clarification is None)
    _skip_check(
        checks,
        "exact.no_integrity_failure_marker",
        state.audit_coverage.get("integrity_failure_source") is None,
    )
    _skip_check(
        checks,
        "exact.no_live_integrity_failure_claim",
        not any(
            item.claim_type == "evidence_integrity_failure" and item.status != ClaimStatus.REJECTED
            for item in state.claims
        ),
    )

    answer: ExactAnswer | None = None
    if report is not None:
        try:
            answer = ExactAnswer.model_validate(report.answer_payload)
        except (TypeError, ValueError):
            pass
    _skip_check(checks, "exact.answer_contract_valid", answer is not None)
    if answer is None or contract is None:
        for code in (
            "exact.task_id_matches",
            "exact.execution_allowed",
            "exact.epistemic_conclusive",
            "exact.source_offsets_present",
            "exact.values_bound_to_evidence",
            "exact.critical_obligation_shape",
            "exact.critical_obligations_satisfied",
        ):
            _skip_check(checks, code, False)
        return

    expected_task_id = contract.client_request_id or state.run_id
    _skip_check(checks, "exact.task_id_matches", answer.task_id == expected_task_id)
    _skip_check(checks, "exact.execution_allowed", answer.execution_status in {"success", "partial"})
    _skip_check(checks, "exact.epistemic_conclusive", answer.epistemic_status == "conclusive")
    _skip_check(checks, "exact.source_offsets_present", bool(answer.source_offsets))
    _skip_check(checks, "exact.values_bound_to_evidence", _exact_bound_evidence(answer) is not None)
    critical = [item for item in contract.obligations if item.critical]
    _skip_check(
        checks,
        "exact.critical_obligation_shape",
        {item.kind for item in critical} == {ObligationKind.CORE_ANSWER, ObligationKind.EVIDENCE_COVERAGE},
    )
    rows = {item.obligation_id: item for item in authority.obligations}
    _skip_check(
        checks,
        "exact.critical_obligations_satisfied",
        bool(critical)
        and all(
            item.obligation_id in rows and rows[item.obligation_id].status == CompositeObligationStatus.SATISFIED
            for item in critical
        ),
    )


def _exact_evidence_skip_checks(
    state: AgentState,
    delta: TypedSemanticDelta,
    checks: dict[str, bool],
) -> None:
    report = state.report
    answer: ExactAnswer | None = None
    if report is not None:
        try:
            answer = ExactAnswer.model_validate(report.answer_payload)
        except (TypeError, ValueError):
            pass
    bound_evidence = _exact_bound_evidence(answer) if answer is not None else None
    exact_claim_ids = {
        item.claim_id
        for item in state.claims
        if item.claim_type == "exact_value_observed" and item.status == ClaimStatus.VERIFIED
    }
    exact_support = {
        item.evidence_id
        for item in state.evidence_links
        if item.claim_id in exact_claim_ids
        and item.relation == EvidenceRelation.SUPPORTS
        and item.verifier_status == ClaimStatus.VERIFIED
    }
    required = set(delta.evidence_ids)
    closure = delta.evidence_closure
    _skip_check(checks, "exact.verified_claim_present", bool(exact_claim_ids))
    _skip_check(checks, "exact.verified_support_present", bool(exact_support))
    _skip_check(
        checks,
        "exact.bound_evidence_in_delta",
        bound_evidence is not None and bool(bound_evidence) and bound_evidence <= required,
    )
    _skip_check(checks, "exact.closure_evidence_exact", required == set(closure.evidence_ids))
    _skip_check(checks, "exact.support_covers_delta", bool(required) and required <= exact_support)

    manifest = {_relative_ref(item.relative_path): item.sha256.lower() for item in state.input_artifacts}
    manifest_digests = set(manifest.values())
    process_digests = set(delta.process_provenance.input_artifact_digests)
    _skip_check(checks, "exact.manifest_present", bool(manifest))
    _skip_check(checks, "exact.process_manifest_digests_match", manifest_digests == process_digests)
    _skip_check(
        checks,
        "exact.closure_raw_digests_in_manifest",
        set(closure.raw_artifact_digests) <= manifest_digests,
    )
    _skip_check(
        checks,
        "exact.closure_locator_paths_in_manifest",
        bool(closure.record_locators)
        and all(_relative_ref(locator.source_ref) in manifest for locator in closure.record_locators),
    )
    _skip_check(
        checks,
        "exact.closure_locator_digests_match",
        bool(closure.record_locators)
        and all(
            locator.artifact_sha256 is None
            or (
                _relative_ref(locator.source_ref) in manifest
                and locator.artifact_sha256.lower() == manifest[_relative_ref(locator.source_ref)]
            )
            for locator in closure.record_locators
        ),
    )


def _common_skip_checks(
    state: AgentState,
    checks: dict[str, bool],
) -> tuple[TypedSemanticDelta | None, ObligationSet | None]:
    contract, report = state.resolved_task_contract, state.report
    raw_delta = state.audit_coverage.get("scenario_semantic_delta")
    raw_receipt = state.audit_coverage.get("scenario_semantic_delta_receipt")
    _skip_check(checks, "common.contract_present", contract is not None)
    _skip_check(checks, "common.report_present", report is not None)
    _skip_check(checks, "common.delta_mapping", isinstance(raw_delta, Mapping))
    _skip_check(checks, "common.receipt_mapping", isinstance(raw_receipt, Mapping))
    delta: TypedSemanticDelta | None = None
    published: TypedSemanticDelta | None = None
    if isinstance(raw_delta, Mapping):
        try:
            delta = TypedSemanticDelta.model_validate(raw_delta)
        except (TypeError, ValueError):
            pass
    if report is not None:
        try:
            published = TypedSemanticDelta.model_validate(report.answer_payload.get("semantic_delta"))
        except (TypeError, ValueError):
            pass
    _skip_check(checks, "common.delta_valid", delta is not None)
    _skip_check(checks, "common.published_delta_valid", published is not None)
    authority = current_obligation_set(state)
    _skip_check(checks, "common.obligation_authority_present", authority is not None)
    if delta is None or contract is None or authority is None:
        return delta, authority

    verified_claims = {item.claim_id for item in state.claims if item.status == ClaimStatus.VERIFIED}
    verified_evidence = {
        item.evidence_id
        for item in state.evidence_links
        if item.claim_id in verified_claims
        and item.relation == EvidenceRelation.SUPPORTS
        and item.verifier_status == ClaimStatus.VERIFIED
    }
    required = set(delta.evidence_ids)
    _skip_check(checks, "common.answer_kind_supported", delta.answer_kind in {"timeline", "evidence_gap", "exact"})
    _skip_check(checks, "common.published_delta_matches", published == delta)
    _skip_check(
        checks,
        "common.receipt_matches",
        isinstance(raw_receipt, Mapping) and dict(raw_receipt) == build_scenario_semantic_delta_receipt(delta),
    )
    _skip_check(checks, "common.delta_accepted", delta.disposition == "accepted")
    _skip_check(checks, "common.admission_ready", delta.admission_ready)
    _skip_check(checks, "common.anchor_preserved", delta.anchor_preserved)
    _skip_check(checks, "common.closure_complete", delta.evidence_closure.complete)
    _skip_check(checks, "common.closure_has_no_missing", not delta.evidence_closure.missing)
    _skip_check(checks, "common.deterministic_projection", delta.source_content_trust == "deterministic_projection")
    _skip_check(checks, "common.no_network", not delta.process_provenance.network_access_performed)
    _skip_check(checks, "common.zero_model_calls", delta.process_provenance.model_calls == 0)
    _skip_check(checks, "common.scoring_mode_matches", authority.scoring_mode == contract.scoring_mode)
    _skip_check(checks, "common.critical_obligation_present", any(item.critical for item in authority.obligations))
    _skip_check(
        checks,
        "common.manifest_receipt_matches",
        contract.input_manifest_digest == _task_input_manifest_digest(state),
    )
    _skip_check(checks, "common.evidence_nonempty", bool(required))
    _skip_check(checks, "common.evidence_known", required <= {item.evidence_id for item in state.evidence})
    _skip_check(checks, "common.evidence_verified", required <= verified_evidence)
    _skip_check(
        checks,
        "common.manifest_digests_in_process",
        {item.sha256.lower() for item in state.input_artifacts} <= set(delta.process_provenance.input_artifact_digests),
    )
    return delta, authority


def deterministic_scenario_primary_skip_diagnostics(state: AgentState) -> dict[str, Any]:
    """Return bounded, value-free diagnostics for every deterministic skip gate."""

    checks: dict[str, bool] = {}
    delta, authority = _common_skip_checks(state, checks)
    scope = "not_applicable"
    if delta is not None and authority is not None:
        if state.status.value == "completed":
            scope = "complete_scenario"
            _skip_check(checks, "complete.authority_complete", authority.complete)
        elif delta.answer_kind == "exact":
            scope = "exact_contract"
            _exact_answer_skip_checks(state, delta, authority, checks)
            _exact_evidence_skip_checks(state, delta, checks)
        else:
            _skip_check(checks, "common.eligible_scope", False)
    else:
        _skip_check(checks, "common.eligible_scope", False)
    failed = sorted(code for code, passed in checks.items() if not passed)
    return {
        "schema_version": "deterministic-primary-skip-diagnostics-v1",
        "scope": scope,
        "eligible": not failed,
        "check_count": len(checks),
        "passed_count": len(checks) - len(failed),
        "failed_count": len(failed),
        "reason_codes": failed,
        "checks": dict(sorted(checks.items())),
    }


def deterministic_scenario_primary_skip_ready(state: AgentState) -> bool:
    """Reuse the sealed semantic-delta and obligation receipts to waive Primary."""

    return bool(deterministic_scenario_primary_skip_diagnostics(state)["eligible"])


def canonical_primary_baseline_required(state: AgentState) -> bool:
    """Return whether completion requires an admitted Primary receipt.

    Missing/unknown policy is deliberately treated as ``required``.  The one
    permitted exception is the contract-bound receipt written by the graph
    before an offline deterministic run skips provider access.
    """

    # Existing semantic-delta and obligation receipts are revalidated against
    # live evidence links; no parallel completion contract is introduced.
    if deterministic_scenario_primary_skip_ready(state):
        return False

    receipt = state.audit_coverage.get("canonical_primary_policy_receipt")
    if not isinstance(receipt, dict) or frozenset(receipt) != _CANONICAL_PRIMARY_POLICY_RECEIPT_KEYS:
        return True

    try:
        contract = require_resolved_task_contract(state)
        observed_contract_digest = resolved_contract_digest(
            contract.model_dump(mode="json", exclude={"contract_digest"})
        )
        observed_manifest_digest = _task_input_manifest_digest(state)
        payload = {key: value for key, value in receipt.items() if key != "receipt_digest"}
        supplied_digest = receipt["receipt_digest"]
        expected_digest = _sha256(payload)
    except (KeyError, TypeError, ValueError, ResolvedTaskContractRequired):
        return True

    network_enabled = payload.get("network_enabled")
    expected_policy = (
        "required" if network_enabled is True else "deterministic_only" if network_enabled is False else None
    )
    valid = (
        isinstance(supplied_digest, str)
        and hmac.compare_digest(supplied_digest, expected_digest)
        and payload.get("policy_version") == _CANONICAL_PRIMARY_POLICY_VERSION
        and payload.get("run_id") == state.run_id
        and payload.get("resolved_contract_id") == contract.contract_id
        and payload.get("resolved_contract_digest") == contract.contract_digest
        and hmac.compare_digest(observed_contract_digest, contract.contract_digest)
        and payload.get("input_manifest_digest") == contract.input_manifest_digest
        and hmac.compare_digest(observed_manifest_digest, contract.input_manifest_digest)
        and payload.get("policy") == expected_policy
    )
    if not valid:
        return True

    # The legacy ``canonical_primary_policy`` entry is display-only.  It is
    # intentionally not consulted here: only the digest-sealed receipt bound
    # to the live contract and immutable input manifest may waive Primary.
    return network_enabled is not False


def _sha256(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def seal_canonical_primary_policy(state: AgentState, *, network_enabled: bool) -> None:
    """Persist a run/contract-bound Primary execution-policy receipt.

    A plain mutable feature flag is not sufficient authority to waive the
    canonical Primary receipt.  The digest is also covered by the durable
    state/checkpoint hash, so accidental or stale recovery mutations fail
    closed at completion.
    """

    contract = require_resolved_task_contract(state)
    observed_contract_digest = resolved_contract_digest(contract.model_dump(mode="json", exclude={"contract_digest"}))
    observed_manifest_digest = _task_input_manifest_digest(state)
    policy = "required" if network_enabled else "deterministic_only"
    payload = {
        "policy_version": _CANONICAL_PRIMARY_POLICY_VERSION,
        "run_id": state.run_id,
        "resolved_contract_id": contract.contract_id,
        "resolved_contract_digest": observed_contract_digest,
        "input_manifest_digest": observed_manifest_digest,
        "policy": policy,
        "network_enabled": network_enabled,
    }
    state.audit_coverage["canonical_primary_policy"] = policy
    state.audit_coverage["canonical_primary_policy_receipt"] = {
        **payload,
        "receipt_digest": _sha256(payload),
    }


def _canonical_primary_binding_evidence(state: AgentState) -> Evidence | None:
    """Derive one integrity-only receipt from a valid immutable Primary lane.

    This evidence proves that the admitted Primary response is bound to the
    declared context and input manifest.  It deliberately does not corroborate
    the semantic truth of any model-proposed finding.
    """

    receipt = state.raw_primary_receipt
    admission = state.baseline_admission
    baseline = state.published_baseline
    if receipt is None or admission is None or baseline is None:
        return None
    valid, _reason = validate_baseline_chain(state)
    if not valid:
        return None

    coverage = baseline.coverage
    if (
        coverage.get("canonical_primary_completed") is not True
        or coverage.get("canonical_primary_status") != "completed"
        or coverage.get("context_sha256") != receipt.context_sha256
    ):
        return None

    try:
        manifest = canonical_input_manifest(state.input_artifacts)
    except ValueError:
        return None
    path_keys: set[str] = set()
    paths_by_sha: dict[str, set[str]] = {}
    for artifact, row in zip(
        sorted(state.input_artifacts, key=lambda item: item.relative_path.casefold()),
        manifest,
        strict=True,
    ):
        normalized = str(row["path"])
        key = normalized.casefold()
        if (
            not normalized
            or key in path_keys
            or len(artifact.sha256) != 64
            or any(char not in "0123456789abcdef" for char in artifact.sha256.lower())
        ):
            return None
        path_keys.add(key)
        paths_by_sha.setdefault(artifact.sha256.lower(), set()).add(normalized)

    try:
        input_count = int(coverage.get("input_count", -1))
        viewed_count = int(coverage.get("viewed_count", -1))
        omitted_count = int(coverage.get("omitted_count", -1))
        unbound_count = int(coverage.get("unbound_primary_candidate_count", -1))
    except (TypeError, ValueError):
        return None
    if (
        input_count != len(manifest)
        or viewed_count < 0
        or omitted_count < 0
        or viewed_count + omitted_count != input_count
        or coverage.get("input_manifest_digest") != canonical_manifest_digest(manifest)
    ):
        return None

    if state.scenario == Scenario.CODE_AUDIT:
        repository = state.repository_index
        if (
            repository is None
            or repository.run_id != state.run_id
            or repository.file_count != input_count
            or coverage.get("repository_snapshot_digest") != repository.digest
        ):
            return None

    evidence_by_id = {item.evidence_id: item for item in baseline.evidence}
    for finding in baseline.findings:
        if not finding.evidence_ids:
            return None
        for evidence_id in finding.evidence_ids:
            evidence = evidence_by_id.get(evidence_id)
            artifact_ref = (
                evidence.artifact_ref.lower() if evidence is not None and evidence.artifact_ref is not None else None
            )
            artifact_paths = paths_by_sha.get(artifact_ref) if artifact_ref is not None else None
            evidence_path = str(evidence.metadata.get("path", "")).replace("\\", "/") if evidence is not None else ""
            if (
                evidence is None
                or evidence.sha256 is None
                or artifact_ref is None
                or artifact_paths is None
                or evidence.sha256.lower() != artifact_ref
                or evidence_path not in artifact_paths
                or evidence_path != finding.path.replace("\\", "/")
                or evidence.metadata.get("line") != finding.line
                or finding.line is None
                or finding.line < 1
            ):
                return None

    if not baseline.findings:
        if input_count < 1 or unbound_count != 0:
            return None
        if state.scenario == Scenario.CODE_AUDIT:
            # An empty code-audit finding set is a substantive negative claim.
            # It is publishable only when every immutable source was viewed and
            # the dedicated negative-coverage gate passed.
            if (
                coverage.get("primary_answer_status") != "completed"
                or coverage.get("negative_coverage_complete") is not True
                or omitted_count != 0
                or viewed_count != input_count
            ):
                return None
        elif not baseline.answer_type or not baseline.answer_payload:
            # Non-code answers do not claim that a scanner found no
            # vulnerabilities. Their integrity obligation is satisfied by a
            # schema-valid typed answer bound to the complete manifest and
            # canonical context; semantic truth remains explicitly outside
            # this receipt.
            return None

    manifest_digest = canonical_manifest_digest(manifest)
    binding_payload = {
        "run_id": state.run_id,
        "receipt_id": receipt.receipt_id,
        "admission_id": admission.admission_id,
        "projection_id": baseline.projection_id,
        "request_sha256": receipt.request_sha256,
        "response_sha256": receipt.response_sha256,
        "response_schema_sha256": receipt.response_schema_sha256,
        "context_sha256": receipt.context_sha256,
        "input_manifest_digest": manifest_digest,
        "repository_snapshot_digest": coverage.get("repository_snapshot_digest"),
        "input_count": input_count,
        "viewed_count": viewed_count,
        "omitted_count": omitted_count,
        "negative_coverage_complete": bool(coverage.get("negative_coverage_complete")),
    }
    binding_digest = _sha256(binding_payload)
    return Evidence(
        evidence_id=f"canonical-primary-baseline-{binding_digest[:32]}",
        source="secmind:canonical-primary-baseline:v0.8",
        summary="The admitted Primary response is bound to the immutable input manifest and canonical context.",
        artifact_ref=receipt.response_artifact_id,
        sha256=receipt.response_sha256,
        metadata={
            "evidence_type": _CANONICAL_BASELINE_EVIDENCE_TYPE,
            "assurance_level": "integrity_verified",
            "semantic_evidence_key": f"canonical-primary-baseline:{baseline.projection_id}",
            "original_source_family": "canonical-primary-response",
            "binding_digest": binding_digest,
            **binding_payload,
        },
    )


def _canonical_primary_baseline_obligation(
    state: AgentState,
    evidence_graph: InvestigationEvidenceGraph,
) -> RequirementObligation | None:
    baseline = state.published_baseline
    if baseline is None and not canonical_primary_baseline_required(state):
        return None
    evidence = _canonical_primary_binding_evidence(state)
    satisfied = bool(
        evidence is not None
        and evidence.evidence_id in evidence_graph.evidence_ids
        and evidence_graph.node(evidence.evidence_id).verified
    )
    obligation_id = str(
        uuid5(
            NAMESPACE_URL,
            "secmind:canonical-primary-baseline-obligation:"
            f"{state.run_id}:{baseline.projection_id if baseline is not None else 'missing'}",
        )
    )
    contract = require_resolved_task_contract(state)
    source_ref = baseline.projection_id if baseline is not None else "missing-required-primary-baseline"
    return seal_contract(
        RequirementObligation,
        obligation_id=obligation_id,
        run_id=state.run_id,
        source_type="canonical_primary_baseline",
        source_ref=source_ref,
        requirement_summary=(
            "The admitted Primary response, canonical context, and complete immutable input manifest remain "
            "cryptographically bound. This obligation proves integrity and coverage, not finding semantics."
        ),
        immutable_scope=list(contract.authorized_scope or ["."]),
        satisfaction_rule_id="canonical-primary-baseline-binding-v0.8",
        required_evidence_types=[_CANONICAL_BASELINE_EVIDENCE_TYPE],
        minimum_independence_level=1,
        status=ObligationStatus.SATISFIED if satisfied else ObligationStatus.UNVERIFIED,
        satisfied_by_evidence_ids=([evidence.evidence_id] if satisfied and evidence is not None else []),
        verifier_receipt_id=(state.baseline_admission.admission_id if satisfied and state.baseline_admission else None),
    )


def _task_obligation_set_receipt_evidence(state: AgentState) -> Evidence | None:
    """Return a control-plane receipt for the one authoritative answer gate.

    The receipt proves only that the sealed resolved contract and the current
    ``ObligationSet`` agree and that every critical answer obligation reached
    a completed state.  It is deliberately separate from semantic evidence:
    it cannot corroborate a finding, increase confidence, or satisfy an
    evidence-bound answer field.
    """

    contract = require_resolved_task_contract(state)
    authority = current_obligation_set(state)
    if (
        authority is None
        or not authority.complete
        or not authority.obligations
        or authority.scoring_mode != contract.scoring_mode
    ):
        return None
    binding_payload = {
        "run_id": state.run_id,
        "resolved_contract_id": contract.contract_id,
        "resolved_contract_digest": contract.contract_digest,
        "task_spec_digest": contract.task_spec_digest,
        "input_manifest_digest": contract.input_manifest_digest,
        "answer_schema_digest": contract.answer_schema_digest,
        "scoring_mode": contract.scoring_mode,
        "obligation_set_digest": authority.set_digest,
        "critical_obligation_ids": sorted(item.obligation_id for item in authority.obligations if item.critical),
    }
    binding_digest = _sha256(binding_payload)
    return Evidence(
        evidence_id=f"task-obligation-set-{binding_digest[:32]}",
        source="secmind:task-obligation-set-receipt:v0.8.6",
        summary=(
            "The sealed task contract and authoritative answer-obligation set "
            "agree and all critical answer obligations are complete."
        ),
        sha256=authority.set_digest,
        metadata={
            "evidence_type": _TASK_OBLIGATION_SET_EVIDENCE_TYPE,
            "assurance_level": "control_plane_verified",
            "semantic_evidence_key": f"task-obligation-set:{authority.set_digest}",
            "original_source_family": "task-obligation-set-receipt",
            "binding_digest": binding_digest,
            **binding_payload,
        },
    )


def _task_obligation_set_receipt_obligation(
    state: AgentState,
    evidence_graph: InvestigationEvidenceGraph,
) -> RequirementObligation:
    """Bind COMPLETE to a non-empty, digest-sealed control-plane receipt."""

    contract = require_resolved_task_contract(state)
    authority = current_obligation_set(state)
    evidence = _task_obligation_set_receipt_evidence(state)
    satisfied = bool(
        evidence is not None
        and evidence.evidence_id in evidence_graph.evidence_ids
        and evidence_graph.node(evidence.evidence_id).verified
    )
    obligation_id = str(
        uuid5(
            NAMESPACE_URL,
            f"secmind:task-obligation-set-receipt:{state.run_id}:{contract.contract_id}",
        )
    )
    return seal_contract(
        RequirementObligation,
        obligation_id=obligation_id,
        run_id=state.run_id,
        source_type="task_obligation_set_receipt",
        source_ref=authority.set_digest if authority is not None else "missing-or-stale-obligation-set",
        requirement_summary=(
            "The digest-sealed authoritative answer-obligation set is current, "
            "run-bound, contract-bound, non-empty, and complete."
        ),
        immutable_scope=list(contract.authorized_scope or ["."]),
        satisfaction_rule_id="task-obligation-set-receipt-v0.8.6",
        required_evidence_types=[_TASK_OBLIGATION_SET_EVIDENCE_TYPE],
        minimum_independence_level=1,
        status=ObligationStatus.SATISFIED if satisfied else ObligationStatus.UNVERIFIED,
        satisfied_by_evidence_ids=([evidence.evidence_id] if satisfied and evidence is not None else []),
        verifier_receipt_id=(
            f"task-obligation-set-verification:{state.run_id}:{authority.set_digest}"
            if satisfied and authority is not None
            else None
        ),
    )


def build_requirement_obligations(
    state: AgentState,
    evidence_graph: InvestigationEvidenceGraph,
) -> list[RequirementObligation]:
    """Project outcome contracts and high-risk findings into gate obligations.

    Direct-first work proves coverage through immutable per-unit decisions.
    Tool-backed work proves coverage through execution evidence. High-risk
    findings additionally require two independent lineages plus attack path,
    preconditions, and impact.
    """

    verified_by_claim = {
        item.claim_id: item.verified_evidence_ids
        for item in state.verification_results
        if item.status == ClaimStatus.VERIFIED
    }
    claims_by_producer: dict[str, list[str]] = {}
    for claim in state.claims:
        if claim.status == ClaimStatus.VERIFIED:
            claims_by_producer.setdefault(claim.producer, []).append(claim.claim_id)

    evidence_by_id = {item.evidence_id: item for item in state.evidence}
    obligations: list[RequirementObligation] = []
    obligations.extend(_resolved_answer_obligations(state, evidence_graph))
    obligations.append(_task_obligation_set_receipt_obligation(state, evidence_graph))
    primary_obligation = _canonical_primary_baseline_obligation(state, evidence_graph)
    if primary_obligation is not None:
        obligations.append(primary_obligation)
    obligations.extend(
        _outcome_contract_obligation(
            state,
            contract,
            claims_by_producer=claims_by_producer,
            verified_by_claim=verified_by_claim,
            evidence_by_id=evidence_by_id,
        )
        for contract in sorted(state.outcome_contracts, key=lambda item: item.contract_id)
    )

    obligations.extend(_high_risk_obligations(state, evidence_graph))
    return obligations


def _resolved_answer_obligations(
    state: AgentState,
    evidence_graph: InvestigationEvidenceGraph,
) -> list[RequirementObligation]:
    """Bridge the authoritative answer contract into the durable completion matrix.

    ``TaskObligation`` is the product-level answer gate while
    ``RequirementObligation`` is the append-only investigation receipt.  A
    COMPLETE receipt must bind both views.  Earlier builds omitted this
    projection for deterministic non-code scenarios, which produced an empty
    requirement set and made a valid completed timeline impossible to commit.

    The projection remains fail closed: a product obligation is only marked
    satisfied when its referenced evidence exists in the run graph, backs a
    verified claim, and exposes at least one typed evidence class.
    """

    contract = require_resolved_task_contract(state)
    scope = list(contract.authorized_scope or ["."])
    projected: list[RequirementObligation] = []
    authority = current_obligation_set(state)
    obligation_rows = (
        authority.task_obligations
        if authority is not None
        else tuple(
            item.model_copy(
                update={
                    "status": AnswerObligationStatus.PENDING,
                    "reason": "authoritative completion obligation set is absent or stale",
                }
            )
            for item in state.obligation_status
        )
    )
    for obligation in sorted(obligation_rows, key=lambda item: item.obligation_id):
        # Field-presence obligations are already evaluated by the sealed
        # ObligationSet.  Recasting them as evidence obligations here created
        # a second, incompatible source of truth.  Only an explicitly
        # evidence-bound answer obligation belongs in this legacy matrix.
        if obligation.acceptance_rule != "evidence_bound":
            continue
        verified_ids = sorted(
            {
                evidence_id
                for evidence_id in obligation.evidence_ids
                if evidence_id in evidence_graph.evidence_ids and evidence_graph.node(evidence_id).verified
            }
        )
        evidence_types = sorted(
            {
                evidence_type
                for evidence_id in verified_ids
                for evidence_type in evidence_graph.node(evidence_id).evidence_types
                if evidence_type
            }
        )
        satisfied = obligation.status.value == "satisfied" and bool(verified_ids) and bool(evidence_types)
        projected.append(
            seal_contract(
                RequirementObligation,
                obligation_id=str(
                    uuid5(
                        NAMESPACE_URL,
                        f"secmind:resolved-answer-obligation:{state.run_id}:{obligation.obligation_id}",
                    )
                ),
                run_id=state.run_id,
                source_type="resolved_task_contract",
                source_ref=obligation.obligation_id,
                requirement_summary=(
                    f"Resolved answer fields {', '.join(obligation.target_fields)} satisfy "
                    f"the {contract.scoring_mode} task contract."
                ),
                immutable_scope=scope,
                satisfaction_rule_id=f"resolved-answer-{obligation.acceptance_rule}-v0.8.4",
                required_evidence_types=evidence_types[:1] or ["verified_answer_evidence"],
                minimum_independence_level=1,
                status=ObligationStatus.SATISFIED if satisfied else ObligationStatus.UNVERIFIED,
                satisfied_by_evidence_ids=verified_ids,
                verifier_receipt_id=(
                    f"task-obligation-verification:{state.run_id}:{obligation.obligation_id}" if satisfied else None
                ),
            )
        )
    return projected


def _high_risk_obligations(
    state: AgentState,
    evidence_graph: InvestigationEvidenceGraph,
) -> list[RequirementObligation]:
    """Build the stricter obligations required for HIGH/CRITICAL findings."""

    verified_claims = {claim.subject_ref: claim for claim in state.claims if claim.status == ClaimStatus.VERIFIED}
    results = {result.claim_id: result for result in state.verification_results}
    return [
        _high_risk_obligation(
            state,
            finding,
            claim=verified_claims.get(finding.finding_id),
            results=results,
            evidence_graph=evidence_graph,
        )
        for finding in sorted(state.findings, key=lambda item: item.finding_id)
        if finding.severity in {"HIGH", "CRITICAL"}
    ]


def _high_risk_obligation(
    state: AgentState,
    finding: Finding,
    *,
    claim: Claim | None,
    results: dict[str, VerificationResult],
    evidence_graph: InvestigationEvidenceGraph,
) -> RequirementObligation:
    """Describe whether one high-risk finding meets the two-lineage gate."""

    result = results.get(claim.claim_id) if claim is not None else None
    evidence_ids = sorted(result.verified_evidence_ids if result is not None else [])
    evidence_types = sorted(
        {
            evidence_type
            for evidence_id in evidence_ids
            if evidence_id in evidence_graph.evidence_ids
            for evidence_type in evidence_graph.node(evidence_id).evidence_types
        }
    )
    raw_preconditions = finding.raw.get("preconditions")
    has_preconditions = bool(
        (isinstance(raw_preconditions, str) and raw_preconditions.strip())
        or (
            isinstance(raw_preconditions, list)
            and any(isinstance(item, str) and item.strip() for item in raw_preconditions)
        )
    )
    has_attack_path = bool(str(finding.raw.get("attack_path_summary") or finding.raw.get("attack_path") or "").strip())
    has_impact = bool(str(finding.raw.get("expected_impact") or finding.raw.get("impact") or "").strip())
    satisfied = bool(
        claim is not None
        and result is not None
        and evidence_ids
        and len(evidence_graph.independent_evidence(evidence_ids)) >= 2
        and has_attack_path
        and has_preconditions
        and has_impact
    )
    obligation_id = str(
        uuid5(
            NAMESPACE_URL,
            f"secmind:high-risk-obligation:{state.run_id}:{finding.finding_id}",
        )
    )
    return seal_contract(
        RequirementObligation,
        obligation_id=obligation_id,
        run_id=state.run_id,
        source_type="high_risk_finding",
        source_ref=finding.finding_id,
        requirement_summary=(
            "High/Critical finding has an attack path, explicit preconditions, impact, and two "
            "independent verified evidence lineages."
        ),
        immutable_scope=[finding.path or "."],
        satisfaction_rule_id="high-risk-independent-validation-v0.6",
        required_evidence_types=[evidence_types[0] if evidence_types else "supporting_evidence"],
        minimum_independence_level=2,
        status=ObligationStatus.SATISFIED if satisfied else ObligationStatus.UNVERIFIED,
        satisfied_by_evidence_ids=evidence_ids,
        verifier_receipt_id=(
            f"verification:{state.run_id}:{state.verification_rounds}:{claim.claim_id}"
            if satisfied and claim is not None
            else None
        ),
    )


def _outcome_contract_obligation(
    state: AgentState,
    contract: OutcomeContract,
    *,
    claims_by_producer: dict[str, list[str]],
    verified_by_claim: dict[str, list[str]],
    evidence_by_id: dict[str, Evidence],
) -> RequirementObligation:
    """Build the coverage obligation for one accepted outcome contract."""

    contract_id = contract.contract_id
    step_id = contract.step_id
    direct_first = step_id == "model-source-review"
    required_evidence_types = sorted(
        {
            value.strip().casefold()
            for value in (contract.required_evidence_types if direct_first else ["execution_coverage"])
            if value.strip()
        }
    )
    evidence_ids = sorted(
        {
            evidence_id
            for claim_id in claims_by_producer.get(step_id, [])
            for evidence_id in verified_by_claim.get(claim_id, [])
            if evidence_id in evidence_by_id
            and str(evidence_by_id[evidence_id].metadata.get("evidence_type", "")).casefold() in required_evidence_types
        }
    )
    grades = state.contract_grades.get(contract_id, [])
    grades_pass = bool(grades) and all(str(item.get("status", "")).casefold() == "passed" for item in grades)
    direct_complete = True
    if direct_first:
        total_units = int(state.audit_coverage.get("total_units", 0))
        scoreable_units = int(state.audit_coverage.get("scoreable_units", len(state.audit_units)))
        projected_evidence = {
            evidence_id for unit_result in state.audit_units for evidence_id in unit_result.evidence_ids
        }
        direct_complete = (
            total_units > 0
            and scoreable_units == total_units
            and len(state.audit_units) == total_units
            and all(len(item.decision_digest) == 64 and item.evidence_ids for item in state.audit_units)
            and projected_evidence.issubset(evidence_ids)
        )
    satisfied = grades_pass and bool(evidence_ids) and direct_complete
    obligation_id = str(uuid5(NAMESPACE_URL, f"secmind:obligation:{state.run_id}:{contract_id}"))
    resolved_contract = require_resolved_task_contract(state)
    return seal_contract(
        RequirementObligation,
        obligation_id=obligation_id,
        run_id=state.run_id,
        source_type="outcome_contract",
        source_ref=contract_id,
        requirement_summary=(
            "Verified immutable per-unit decisions for the Direct-first audit."
            if direct_first
            else f"Verified execution coverage for plan step {step_id}."
        ),
        immutable_scope=list(resolved_contract.authorized_scope or ["."]),
        satisfaction_rule_id=(
            "verified-direct-first-unit-coverage-v0.7" if direct_first else "verified-step-coverage-v0.6"
        ),
        required_evidence_types=required_evidence_types,
        minimum_independence_level=1,
        status=ObligationStatus.SATISFIED if satisfied else ObligationStatus.UNVERIFIED,
        satisfied_by_evidence_ids=evidence_ids,
        verifier_receipt_id=(
            f"verification:{state.run_id}:{state.verification_rounds}:{contract_id}" if satisfied else None
        ),
    )


def verified_direct_first_finding_ids(state: AgentState) -> set[str]:
    """Return verified finding IDs backed by typed Direct-first evidence."""

    typed_evidence_ids = {
        evidence.evidence_id
        for evidence in state.evidence
        if evidence.metadata.get("step_id") == "model-source-review"
        and evidence.metadata.get("evidence_type") == "audit_unit_decision"
    }
    typed_finding_ids = {
        finding.finding_id
        for finding in state.findings
        if any(evidence_id in typed_evidence_ids for evidence_id in finding.evidence_ids)
    }
    direct_first = {
        claim.subject_ref
        for claim in state.claims
        if claim.producer == "model-source-review"
        and claim.claim_type == "model_source_review.finding"
        and claim.status == ClaimStatus.VERIFIED
        and claim.subject_ref in typed_finding_ids
    }
    # The immutable canonical Primary is a distinct, model-proposed lane.  It
    # must not inherit the stronger semantic assurance of a verified v0.7
    # per-unit Direct decision merely because its bytes were provenance-bound.
    return direct_first


def calibrated_model_severity(cwe: int, assurance: EvidenceAssurance) -> Literal["MEDIUM", "HIGH"]:
    """Prevent model-only evidence from manufacturing a HIGH label."""

    if assurance == EvidenceAssurance.MODEL_PROPOSED:
        return "MEDIUM"
    if cwe in {78, 89, 94, 502, 611, 918}:
        return "HIGH"
    return "MEDIUM"


def build_investigation_evidence_graph(
    state: AgentState,
    graph: EvidenceGraph,
) -> InvestigationEvidenceGraph:
    """Attach stable tool/invocation lineages to the generic evidence graph."""

    binding_evidence = _canonical_primary_binding_evidence(state)
    if binding_evidence is not None:
        baseline = state.published_baseline
        if baseline is not None:  # Narrowed by the binding helper; retained for type checkers.
            binding_claim = make_claim(
                claim_type="canonical_primary.baseline_coverage",
                statement=(
                    "The admitted Primary response is bound to the immutable input manifest and canonical context; "
                    "finding semantics remain model-proposed."
                ),
                subject_ref=baseline.projection_id,
                producer="canonical-primary",
                confidence=1.0,
            ).model_copy(update={"status": ClaimStatus.VERIFIED})
            binding_link = make_link(
                claim_id=binding_claim.claim_id,
                evidence_id=binding_evidence.evidence_id,
                grader_id="canonical-primary-baseline-binding-v0.8",
            ).model_copy(update={"verifier_status": ClaimStatus.VERIFIED})
            graph = EvidenceGraph(
                claims=[*graph.claims, binding_claim],
                evidence=[*graph.evidence, binding_evidence],
                links=[*graph.links, binding_link],
            )

    obligation_set_evidence = _task_obligation_set_receipt_evidence(state)
    if obligation_set_evidence is not None:
        contract = require_resolved_task_contract(state)
        obligation_set_claim = make_claim(
            claim_type="task_contract.obligation_set_complete",
            statement=(
                "The sealed task contract and authoritative answer-obligation set are digest-bound and complete."
            ),
            subject_ref=contract.contract_id,
            producer="deterministic-completion-gate",
            confidence=1.0,
        ).model_copy(update={"status": ClaimStatus.VERIFIED})
        obligation_set_link = make_link(
            claim_id=obligation_set_claim.claim_id,
            evidence_id=obligation_set_evidence.evidence_id,
            grader_id="task-obligation-set-receipt-v0.8.6",
        ).model_copy(update={"verifier_status": ClaimStatus.VERIFIED})
        graph = EvidenceGraph(
            claims=[*graph.claims, obligation_set_claim],
            evidence=[*graph.evidence, obligation_set_evidence],
            links=[*graph.links, obligation_set_link],
        )

    lineage_by_evidence_id: dict[str, str] = {}
    for observation in state.observations:
        invocation = observation.invocation_id
        for evidence in observation.evidence:
            tool = str(evidence.metadata.get("tool_name") or evidence.source).casefold()
            step = str(evidence.metadata.get("step_id") or "unknown-step").casefold()
            lineage = f"invocation:{invocation}" if invocation else f"tool:{tool}:step:{step}"
            lineage_by_evidence_id.setdefault(evidence.evidence_id, lineage)
    return InvestigationEvidenceGraph(build_lineage_graph_views(graph, lineage_by_evidence_id))


def outcome_grade_summary(state: AgentState) -> dict[str, str]:
    """Collapse required contract grades into the status-authoritative view.

    Optional contracts remain in durable ``contract_grades`` and the public
    coverage diagnostic, but the legacy evaluator must not reinterpret them
    as a second hard completion gate.
    """

    return {
        contract.contract_id: (
            "passed"
            if state.contract_grades.get(contract.contract_id)
            and all(
                str(item.get("status", "")).casefold() == "passed"
                for item in state.contract_grades[contract.contract_id]
            )
            else "failed"
        )
        for contract in state.outcome_contracts
        if not contract.allow_partial
    }


def verify_input_artifacts(state: AgentState) -> bool:
    """Re-hash every input and reject paths that no longer stay in workspace."""

    workspace = Path(state.workspace).resolve() if state.workspace else None
    if workspace is None or not workspace.exists() or not workspace.is_dir():
        return False
    # An empty inventory is integrity-preserving even though it may later
    # produce a PARTIAL report for insufficient evidence.
    for artifact in state.input_artifacts:
        candidate = (workspace / artifact.relative_path).resolve()
        if len(artifact.sha256) != 64 or not candidate.is_relative_to(workspace) or not candidate.is_file():
            return False
        digest = hashlib.sha256()
        with candidate.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        if digest.hexdigest() != artifact.sha256.lower():
            return False
    return True


def build_task_capsule(state: AgentState) -> dict[str, object]:
    """Create the bounded task summary supplied to worker context packs."""

    contract = require_resolved_task_contract(state)
    input_hashes = sorted(item.sha256.lower() for item in state.input_artifacts)
    return {
        "objective": contract.objective,
        "task_spec": state.task_spec_ref.model_dump(mode="json") if state.task_spec_ref is not None else None,
        "resolved_contract_id": contract.contract_id,
        "resolved_contract_digest": contract.contract_digest,
        "target_scope": contract.authorized_scope,
        "constraints": contract.constraints,
        "expected_outputs": contract.expected_outputs,
        "autonomy_policy": contract.autonomy_policy,
        "input_artifact_count": len(input_hashes),
        "input_manifest_digest": contract.input_manifest_digest,
        "repository_index_digest": state.repository_index.digest if state.repository_index is not None else None,
    }


def select_context_items(state: AgentState, kind: str) -> list[ContextItemRef]:
    """Return one deterministic authority-ordered context partition."""

    return sorted(
        (item for item in state.context_items if item.kind == kind),
        key=lambda item: (int(item.authority_level), item.source, item.context_id),
    )
