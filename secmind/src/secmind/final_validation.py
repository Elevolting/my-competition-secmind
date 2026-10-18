"""Deterministic, model-independent terminal validation projection.

The semantic answer and its immutable receipt are separate concerns.  This
module does not claim that a language model's conclusion is true; it proves
the properties the runtime can actually verify without another provider call:
task-contract binding, typed-answer presence, reference closure, verifier-owned
evidence links and completion-obligation state.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

from pydantic import ValidationError

from secmind.investigation.contracts import (
    CompletionOutcome,
    CompletionReceipt,
    CompletionSnapshotV2,
    canonical_content_digest,
)
from secmind.orchestration.obligation_runtime import current_obligation_set
from secmind.schemas import AgentReport, AgentState, ClaimStatus, EvidenceRelation, RunStatus
from secmind.task_contract import canonical_digest

FINAL_VALIDATION_VERSION = "secmind-final-validation-v1"
EXACT_ANSWER_ATTESTATION_VERSION = "secmind-exact-answer-attestation-v1"
_SHA256_PATTERN = r"^[a-fA-F0-9]{64}$"
_MAX_REFERENCE_NODES = 4_096
_MAX_REFERENCE_ITEMS = 256
_MAX_RECEIPT_COLLECTION_ITEMS = 1_000
_EVIDENCE_REFERENCE_FIELDS = frozenset(
    {
        "evidence_id",
        "evidence_ids",
        "evidence_refs",
        "source_evidence_ids",
        "supporting_evidence_ids",
    }
)
_REQUIRED_CHECKS = frozenset(
    {
        "completion_contracts_parse",
        "completion_decision_complete",
        "completion_digests_valid",
        "completion_integrity_valid",
        "completion_obligations_bound",
        "completion_proof_valid",
        "completion_run_and_id_binding",
        "completion_snapshot_quiet",
        "critical_obligations_complete",
        "evidence_reference_closure",
        "required_evidence_verified",
        "resolved_task_contract_bound",
        "terminal_status_completed",
        "typed_answer_present",
        "verified_support_chain_present",
    }
)


def _evidence_references(
    value: Any,
    *,
    depth: int = 0,
    _budget: list[int] | None = None,
) -> set[str]:
    """Collect only explicitly named evidence references with hard bounds.

    ``answer_payload`` is provider-shaped ``dict[str, Any]`` data.  It must
    never be able to turn a prose field named ``evidence`` into a reference,
    nor make terminal validation spend unbounded time walking a cyclic or
    adversarially large JSON tree.
    """

    if _budget is None:
        _budget = [0]
    _budget[0] += 1
    if _budget[0] > _MAX_REFERENCE_NODES or depth > 12:
        return set()
    if isinstance(value, Mapping):
        mapping_references: set[str] = set()
        for key, item in list(value.items())[:_MAX_REFERENCE_ITEMS]:
            normalized = str(key).casefold()
            if normalized in _EVIDENCE_REFERENCE_FIELDS and isinstance(item, str) and item.strip():
                mapping_references.add(item.strip())
            elif (
                normalized in _EVIDENCE_REFERENCE_FIELDS
                and isinstance(item, Sequence)
                and not isinstance(item, (str, bytes, bytearray))
            ):
                mapping_references.update(
                    candidate.strip() for candidate in item if isinstance(candidate, str) and candidate.strip()
                )
            mapping_references.update(_evidence_references(item, depth=depth + 1, _budget=_budget))
        return mapping_references
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        sequence_references: set[str] = set()
        for item in value[:_MAX_REFERENCE_ITEMS]:
            sequence_references.update(_evidence_references(item, depth=depth + 1, _budget=_budget))
        return sequence_references
    return set()


def build_exact_answer_attestation(
    *,
    run_id: str,
    input_manifest_digest: str,
    evidence_id: str,
    value_sha256: str,
    artifact_sha256: str,
    locator: Mapping[str, Any],
) -> dict[str, Any] | None:
    """Create a value-free attestation for a deterministic exact observation.

    The attestation intentionally contains only digests and a bounded source
    locator.  It binds the answer exception to the run, immutable input
    manifest, evidence identity, source artifact and locator without copying
    the secret/exact token into metadata.  The caller must have obtained the
    evidence from the runtime verifier; this function is not an authority on
    its own.
    """

    if not all(isinstance(item, str) and item.strip() for item in (run_id, evidence_id)):
        return None
    if not all(
        isinstance(item, str) and re.fullmatch(_SHA256_PATTERN, item)
        for item in (input_manifest_digest, value_sha256, artifact_sha256)
    ):
        return None
    if not isinstance(locator, Mapping) or not locator:
        return None
    bounded_locator = {
        str(key): locator[key]
        for key in sorted(locator, key=lambda item: str(item))[:32]
        if isinstance(key, (str, int, float, bool))
    }
    if any(
        isinstance(item, (Mapping, Sequence)) and not isinstance(item, (str, bytes, bytearray))
        for item in bounded_locator.values()
    ):
        # A locator is deliberately flat.  Nested provider payloads would make
        # the digest ambiguous and create a covert storage channel.
        return None
    payload: dict[str, Any] = {
        "schema_version": EXACT_ANSWER_ATTESTATION_VERSION,
        "run_id": run_id.strip()[:200],
        "input_manifest_digest": input_manifest_digest.lower(),
        "evidence_id": evidence_id.strip()[:200],
        "value_sha256": value_sha256.lower(),
        "artifact_sha256": artifact_sha256.lower(),
        "locator": bounded_locator,
        "locator_digest": canonical_digest(bounded_locator),
    }
    payload["attestation_digest"] = canonical_digest(payload)
    return payload


def validate_exact_answer_attestation(
    value: Any,
    *,
    expected_run_id: str | None = None,
    expected_input_manifest_digest: str | None = None,
    expected_evidence_id: str | None = None,
    expected_value_sha256: str | None = None,
    expected_artifact_sha256: str | None = None,
    expected_locator: Mapping[str, Any] | None = None,
) -> bool:
    """Validate a value-free exact-answer attestation and all supplied binds."""

    if not isinstance(value, Mapping):
        return False
    expected_keys = {
        "schema_version",
        "run_id",
        "input_manifest_digest",
        "evidence_id",
        "value_sha256",
        "artifact_sha256",
        "locator",
        "locator_digest",
        "attestation_digest",
    }
    if set(value) != expected_keys:
        return False
    if value.get("schema_version") != EXACT_ANSWER_ATTESTATION_VERSION:
        return False
    scalar_text = value.get("run_id")
    if not isinstance(scalar_text, str) or not scalar_text or len(scalar_text) > 200:
        return False
    for key in ("input_manifest_digest", "value_sha256", "artifact_sha256"):
        item = value.get(key)
        if not isinstance(item, str) or re.fullmatch(_SHA256_PATTERN, item) is None:
            return False
    evidence_id = value.get("evidence_id")
    if not isinstance(evidence_id, str) or not evidence_id or len(evidence_id) > 200:
        return False
    locator = value.get("locator")
    if not isinstance(locator, Mapping) or not locator or len(locator) > 32:
        return False
    if value.get("locator_digest") != canonical_digest(dict(locator)):
        return False
    payload = dict(value)
    digest = payload.pop("attestation_digest", None)
    if not isinstance(digest, str) or digest != canonical_digest(payload):
        return False
    comparisons = (
        (expected_run_id, scalar_text),
        (expected_input_manifest_digest, value.get("input_manifest_digest")),
        (expected_evidence_id, evidence_id),
        (expected_value_sha256, value.get("value_sha256")),
        (expected_artifact_sha256, value.get("artifact_sha256")),
    )
    for expected, observed in comparisons:
        if expected is not None and (not isinstance(expected, str) or expected.lower() != str(observed).lower()):
            return False
    if expected_locator is not None and dict(expected_locator) != dict(locator):
        return False
    return True


def verified_evidence_claims(
    state: AgentState,
    report: AgentReport,
    *,
    require_report_claim_ids: bool = True,
    allowed_evidence_ids: set[str] | None = None,
) -> dict[str, tuple[str, ...]]:
    """Return report-visible evidence links proven by the durable verifier.

    ``allowed_evidence_ids`` is an optional runtime-owned integrity fence.  A
    terminal admission pass supplies the IDs that were successfully read and
    rehashed from the current CAS.  It is intentionally applied *after* the
    durable claim/link checks: a verifier claim alone can never turn a missing
    or tampered CAS object into trusted evidence.  ``None`` preserves the
    compatibility behavior for callers that do not have an admission rehash
    result (for example, pure validation fixtures).
    """

    report_claim_ids = set(report.claim_ids)
    verified_claim_ids = {
        claim.claim_id
        for claim in state.claims
        if (not require_report_claim_ids or claim.claim_id in report_claim_ids) and claim.status == ClaimStatus.VERIFIED
    }
    if not verified_claim_ids:
        return {}
    state_evidence = {item.evidence_id: item for item in state.evidence}
    report_evidence = {item.evidence_id: item for item in report.evidence}
    links: dict[str, set[str]] = {}
    for link in state.evidence_links:
        if (
            link.claim_id not in verified_claim_ids
            or link.relation != EvidenceRelation.SUPPORTS
            or link.verifier_status != ClaimStatus.VERIFIED
            or (allowed_evidence_ids is not None and link.evidence_id not in allowed_evidence_ids)
            or link.evidence_id not in state_evidence
            or link.evidence_id not in report_evidence
            or state_evidence[link.evidence_id].model_dump(mode="json")
            != report_evidence[link.evidence_id].model_dump(mode="json")
        ):
            continue
        links.setdefault(link.evidence_id, set()).add(link.claim_id)
    return {evidence_id: tuple(sorted(claim_ids)) for evidence_id, claim_ids in sorted(links.items())}


def _completion_proof(state: AgentState) -> tuple[bool, dict[str, bool]]:
    raw = state.audit_coverage.get("completion_proof")
    checks = {
        "completion_contracts_parse": False,
        "completion_run_and_id_binding": False,
        "completion_digests_valid": False,
        "completion_snapshot_quiet": False,
        "completion_integrity_valid": False,
        "completion_decision_complete": False,
        "completion_obligations_bound": False,
    }
    if not isinstance(raw, Mapping):
        return False, checks
    try:
        snapshot = CompletionSnapshotV2.model_validate(raw.get("snapshot"))
        receipt = CompletionReceipt.model_validate(raw.get("receipt"))
    except (TypeError, ValidationError):
        return False, checks
    checks["completion_contracts_parse"] = True
    checks["completion_run_and_id_binding"] = bool(
        snapshot.run_id == state.run_id
        and receipt.run_id == state.run_id
        and receipt.snapshot_id == snapshot.snapshot_id
        and state.completion_snapshot_id == snapshot.snapshot_id
        and state.completion_receipt_id == receipt.receipt_id
    )
    checks["completion_digests_valid"] = bool(
        canonical_content_digest(snapshot, exclude={"snapshot_digest"}) == snapshot.snapshot_digest
        and canonical_content_digest(receipt, exclude={"receipt_digest"}) == receipt.receipt_digest
    )
    checks["completion_snapshot_quiet"] = snapshot.is_quiet()
    checks["completion_integrity_valid"] = bool(
        snapshot.input_integrity
        and snapshot.artifact_integrity
        and snapshot.evidence_integrity
        and snapshot.ledger_integrity
    )
    checks["completion_decision_complete"] = bool(
        receipt.decision == CompletionOutcome.COMPLETE and not receipt.unsatisfied_obligation_ids
    )
    checks["completion_obligations_bound"] = set(snapshot.requirement_obligations).issubset(
        set(receipt.satisfied_obligation_ids)
    )
    return all(checks.values()), checks


def validate_final_validation_payload(value: Mapping[str, Any] | Any) -> tuple[bool, str | None]:
    """Validate the self-digest of a runtime-owned public receipt.

    The receipt deliberately proves structural and provenance properties only;
    it never claims independent semantic correctness.  This helper lets every
    public/replay boundary reject model-authored lookalikes and tampering.
    """

    if not isinstance(value, Mapping):
        return False, "validation receipt is missing"
    payload = dict(value)
    digest = payload.pop("validation_digest", None)
    if not isinstance(digest, str) or len(digest) != 64:
        return False, "validation digest is missing"
    if payload.get("schema_version") != FINAL_VALIDATION_VERSION:
        return False, "validation schema version is unsupported"
    if payload.get("validator_id") != "secmind-deterministic-contract-evidence-verifier":
        return False, "validation authority is not the runtime verifier"
    if payload.get("semantic_model_independence") is not False:
        return False, "validation receipt overstates semantic independence"
    if (
        payload.get("validator_kind") != "deterministic_contract_and_evidence"
        or payload.get("applied") is not True
        or payload.get("model_independent") is not True
    ):
        return False, "validation receipt is not a deterministic runtime projection"
    checks = payload.get("checks")
    if not isinstance(checks, Mapping) or not _REQUIRED_CHECKS.issubset(checks):
        return False, "validation receipt is missing required checks"
    if any(not isinstance(checks[key], bool) for key in _REQUIRED_CHECKS):
        return False, "validation receipt contains non-boolean checks"
    status = payload.get("status")
    if status not in {"passed", "partial"}:
        return False, "validation status is unsupported"
    if (status == "passed") != all(bool(checks[key]) for key in _REQUIRED_CHECKS):
        return False, "validation status conflicts with its checks"
    for key in (
        "required_evidence_ids",
        "missing_evidence_ids",
        "verified_evidence_ids",
        "verified_claim_ids",
        "limitations",
    ):
        if not isinstance(payload.get(key), list):
            return False, f"validation receipt has invalid {key}"
    input_manifest_digest = payload.get("input_manifest_digest")
    if input_manifest_digest is not None and (
        not isinstance(input_manifest_digest, str) or re.fullmatch(_SHA256_PATTERN, input_manifest_digest) is None
    ):
        return False, "validation receipt has invalid input_manifest_digest"
    # An unbound/partial fixture may legitimately have no resolved contract,
    # but a receipt that claims the contract is bound must carry the immutable
    # manifest identity used by exact-answer attestation.  This keeps old
    # non-exact compatibility projections readable while making the live
    # runtime path fail closed when its digest is missing or malformed.
    checks_mapping = payload.get("checks")
    if isinstance(checks_mapping, Mapping) and checks_mapping.get("resolved_task_contract_bound") is True:
        if not isinstance(input_manifest_digest, str) or re.fullmatch(_SHA256_PATTERN, input_manifest_digest) is None:
            return False, "validation receipt is missing input_manifest_digest"
    projection_overflow = payload.get("required_evidence_projection_overflow")
    if projection_overflow is not None and not isinstance(projection_overflow, bool):
        return False, "validation receipt has invalid required evidence projection status"
    if canonical_digest(payload) != digest:
        return False, "validation digest mismatch"
    return True, None


def build_final_validation(
    state: AgentState,
    report: AgentReport,
    *,
    rehashed_evidence_ids: set[str] | None = None,
) -> dict[str, Any]:
    """Return a bounded validation receipt suitable for the public report.

    When terminal Admission has an independent CAS rehash result, the same
    successful-ID set must constrain the receipt.  Otherwise a stale claim
    edge could remain verifier-valid after its backing artifact was deleted or
    modified, and the public exact-answer boundary could trust a value that
    was never re-read during this admission attempt.
    """

    contract = state.resolved_task_contract
    obligation_set = current_obligation_set(state)
    evidence_by_id = {item.evidence_id: item for item in report.evidence}
    answer_references = _evidence_references(report.answer_payload)
    finding_references = {
        evidence_id for finding in report.findings for evidence_id in finding.evidence_ids if evidence_id
    }
    required_references = sorted(answer_references | finding_references)
    required_reference_overflow = len(required_references) > _MAX_RECEIPT_COLLECTION_ITEMS
    missing_references = sorted(set(required_references) - set(evidence_by_id))
    verified_claim_ids = {claim.claim_id for claim in state.claims if claim.status == ClaimStatus.VERIFIED}
    verified_claim_refs = verified_evidence_claims(
        state,
        report,
        require_report_claim_ids=False,
        allowed_evidence_ids=rehashed_evidence_ids,
    )
    all_verified_evidence_ids = sorted(verified_claim_refs)
    required_verified_evidence_ids = sorted(set(required_references).intersection(verified_claim_refs))
    required_verified_evidence_set = set(required_verified_evidence_ids)
    verified_evidence_ids = [
        *required_verified_evidence_ids,
        *[item for item in all_verified_evidence_ids if item not in required_verified_evidence_set],
    ]
    all_verified_claim_ids = sorted(verified_claim_ids)
    required_verified_claim_ids = sorted(
        {
            claim_id
            for evidence_id in required_verified_evidence_ids
            for claim_id in verified_claim_refs.get(evidence_id, ())
        }
    )
    required_verified_claim_set = set(required_verified_claim_ids)
    verified_claim_ids_ordered = [
        *required_verified_claim_ids,
        *[item for item in all_verified_claim_ids if item not in required_verified_claim_set],
    ]
    required_evidence_projection_overflow = bool(
        required_reference_overflow
        or len(required_verified_evidence_ids) > _MAX_RECEIPT_COLLECTION_ITEMS
        or len(required_verified_claim_ids) > _MAX_RECEIPT_COLLECTION_ITEMS
    )
    verified_evidence_set = set(all_verified_evidence_ids)
    contract_bound = bool(
        contract is not None
        and contract.run_id == state.run_id
        and state.task_spec_ref is not None
        and contract.task_spec_id == state.task_spec_ref.task_spec_id
        and contract.task_spec_revision == state.task_spec_ref.revision
    )
    answer_present = bool(report.answer_type and report.answer_payload)
    closure_passed = not missing_references
    terminal_completed = state.status == RunStatus.COMPLETED and report.status == RunStatus.COMPLETED
    completion_proof_valid, completion_checks = _completion_proof(state)
    obligations_complete = bool(obligation_set is not None and obligation_set.complete)
    verified_support_present = bool(verified_claim_ids and verified_evidence_ids)
    required_references_verified = not required_evidence_projection_overflow and set(required_references).issubset(
        verified_evidence_set
    )
    passed = bool(
        contract_bound
        and answer_present
        and closure_passed
        and required_references_verified
        and verified_support_present
        and completion_proof_valid
        and obligations_complete
        and terminal_completed
        and not required_evidence_projection_overflow
    )
    checks = {
        "resolved_task_contract_bound": contract_bound,
        "typed_answer_present": answer_present,
        "evidence_reference_closure": closure_passed,
        "required_evidence_verified": required_references_verified,
        "verified_support_chain_present": verified_support_present,
        "completion_proof_valid": completion_proof_valid,
        "critical_obligations_complete": obligations_complete,
        "terminal_status_completed": terminal_completed,
        **completion_checks,
    }
    payload: dict[str, Any] = {
        "schema_version": FINAL_VALIDATION_VERSION,
        "validator_id": "secmind-deterministic-contract-evidence-verifier",
        "validator_kind": "deterministic_contract_and_evidence",
        "applied": True,
        "status": "passed" if passed else "partial",
        "model_independent": True,
        "semantic_model_independence": False,
        "semantic_scope": "contract, provenance, reference closure and verifier-owned evidence links",
        "checks": checks,
        "answer_type": report.answer_type,
        "input_manifest_digest": (contract.input_manifest_digest if contract is not None else None),
        "required_evidence_ids": required_references[:_MAX_RECEIPT_COLLECTION_ITEMS],
        "missing_evidence_ids": missing_references[:_MAX_RECEIPT_COLLECTION_ITEMS],
        "verified_evidence_ids": verified_evidence_ids[:_MAX_RECEIPT_COLLECTION_ITEMS],
        "verified_claim_ids": verified_claim_ids_ordered[:_MAX_RECEIPT_COLLECTION_ITEMS],
        "required_evidence_projection_overflow": required_evidence_projection_overflow,
        "completion_snapshot_id": state.completion_snapshot_id,
        "completion_receipt_id": state.completion_receipt_id,
        "obligation_set_digest": obligation_set.set_digest if obligation_set is not None else None,
        "obligation_status": (obligation_set.composite_status.value if obligation_set is not None else "missing"),
        "limitations": (
            []
            if passed
            else [
                "The deterministic verifier does not independently establish the semantic truth of model claims.",
                *(
                    ["One or more referenced evidence records are missing from the public closure."]
                    if missing_references
                    else []
                ),
                *(
                    ["No runtime-verified claim-to-evidence SUPPORTS chain is present in the public view."]
                    if not verified_support_present
                    else []
                ),
                *(
                    ["One or more required evidence references lack a runtime-verified SUPPORTS link."]
                    if not required_references_verified
                    else []
                ),
                *(
                    ["The digest-sealed completion snapshot and receipt did not validate as a quiet COMPLETE decision."]
                    if not completion_proof_valid
                    else []
                ),
                *(
                    [
                        "The required evidence verification closure exceeds the bounded public receipt capacity; "
                        "terminal validation is fail-closed."
                    ]
                    if required_evidence_projection_overflow
                    else []
                ),
            ]
        ),
    }
    payload["validation_digest"] = canonical_digest(payload)
    return payload


__all__ = [
    "EXACT_ANSWER_ATTESTATION_VERSION",
    "FINAL_VALIDATION_VERSION",
    "build_exact_answer_attestation",
    "build_final_validation",
    "validate_exact_answer_attestation",
    "validate_final_validation_payload",
    "verified_evidence_claims",
]
