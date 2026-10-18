"""Pure Test 3.0 contract translation for the v0.8.3 API bridge.

The evaluation platform owns process startup and input packaging.  SecMind owns
the semantic contract at its API boundary.  Keeping these functions pure makes
that boundary testable without importing the evaluation engine or copying its
large generic bridge into this repository.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass
from itertools import islice
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from pydantic import ValidationError

from secmind.domain_answers import TypedSemanticDelta
from secmind.final_validation import (
    validate_exact_answer_attestation,
    validate_final_validation_payload,
)
from secmind.secret_scrubber import REDACTED, TRUNCATED, scrub_artifact, scrub_text, scrub_value

INTEGRATION_VERSION = "secmind-test3-v0.8.6-2"
PROJECTION_SCHEMA_VERSION = "secmind-test3-projection-v0.8.6-2"
CURSOR_SCHEMA_VERSION = "secmind-test3-cursor-v1"
SCENARIO_SEMANTIC_DELTA_RECEIPT_VERSION = "secmind-scenario-semantic-delta-receipt-v1"
MAX_PUBLIC_EVIDENCE = 256
MAX_PUBLIC_FINDINGS = 100
MAX_PUBLIC_ITEMS_PER_FIELD = 64
MAX_CURSOR_BYTES = 2_048
MAX_TRUSTED_EXACT_CANDIDATES = 32
MAX_TRUSTED_EXACT_VALUE_CHARS = 4_096


class ProjectionCursorError(ValueError):
    """Raised for a tampered, stale or malformed projection cursor."""


@dataclass(frozen=True, slots=True)
class ProjectionPage:
    """One bounded page returned by :func:`read_projection_page`."""

    collection: str
    page: int
    page_size: int
    total_count: int
    items: tuple[Any, ...]
    next_cursor: str | None
    page_digest: str
    truncated: bool
    truncated_count: int
    dropped_ids: tuple[str, ...]
    duplicate_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": PROJECTION_SCHEMA_VERSION,
            "collection": self.collection,
            "page": self.page,
            "page_size": self.page_size,
            "parent": self.collection,
            "total": self.total_count,
            "total_count": self.total_count,
            "emitted": len(self.items),
            "emitted_count": len(self.items),
            "items": list(self.items),
            "next_cursor": self.next_cursor,
            "next": self.next_cursor,
            "page_digest": self.page_digest,
            "digest": self.page_digest,
            "truncated": self.truncated,
            "truncated_count": self.truncated_count,
            "dropped_count": self.truncated_count,
            "dropped_ids": list(self.dropped_ids),
            "duplicate_ids": list(self.duplicate_ids),
        }


class ProjectionPageStore:
    """Explicit caller-owned collection registry for the cursor read API."""

    def __init__(self) -> None:
        self._collections: dict[str, list[Any]] = {}

    def register(self, collection: str, values: Sequence[Any]) -> str:
        name = _collection_name(collection)
        copied = [deepcopy(item) for item in values]
        self._collections[name] = copied
        return _source_digest(name, copied)

    def read(
        self,
        collection: str,
        *,
        cursor: str | None = None,
        page_size: int = MAX_PUBLIC_ITEMS_PER_FIELD,
    ) -> dict[str, Any]:
        name = _collection_name(collection)
        if name not in self._collections:
            raise KeyError(name)
        return read_projection_page(self._collections[name], collection=name, cursor=cursor, page_size=page_size)

    read_page = read


class ProjectionPageReader:
    """Mapping-bound read API suitable for a bridge/artifact endpoint."""

    def __init__(self, collections: Mapping[str, Sequence[Any]]) -> None:
        self._store = ProjectionPageStore()
        for name, values in collections.items():
            if isinstance(values, Sequence) and not isinstance(values, (str, bytes, bytearray)):
                self._store.register(str(name), values)

    def read_page(
        self,
        collection: str,
        *,
        cursor: str | None = None,
        page_size: int = MAX_PUBLIC_ITEMS_PER_FIELD,
    ) -> dict[str, Any]:
        return self._store.read(collection, cursor=cursor, page_size=page_size)

    read = read_page


_TRUSTED_TASK_METADATA_KEYS = frozenset(
    {
        "task_id",
        "invocation_id",
        "case_id",
        "question_id",
        "benchmark_id",
        "task_version",
        "dataset_version",
        "category",
        "task_category",
        "task_family",
        "difficulty",
        "language",
        "primary_domain",
        "secondary_capabilities",
        "scoring_mode",
        "required_output",
        "execution_policy",
        "budget",
        "profile",
        "evaluation_profile",
        "config_profile",
        "prompt_profile",
        "rubric_version",
        "expected_outputs",
        "randomization_block",
        "block_id",
        "seed",
        "input_manifest_digest",
        "source_manifest_digest",
    }
)
_TRUSTED_METADATA_CONTAINERS = ("metadata", "evaluation_metadata", "task_metadata")
_EXPLICIT_EVIDENCE_REFERENCE_FIELDS = frozenset(
    {
        "evidence_id",
        "evidence_ids",
        "evidence_refs",
        "source_evidence_ids",
        "supporting_evidence_ids",
        "required_evidence_id",
        "required_evidence_ids",
        "required_evidence_refs",
    }
)

_SAFE_DIAGNOSTIC_KEYS = (
    "canonical_primary_attempted",
    "canonical_primary_status",
    "canonical_primary_provider_requests",
    "model_gateway_failure",
    "primary_route",
    "independent_scout",
    "tool_routing",
    "correlation",
    "tool_gain_gate_diagnostics",
    "tool_path_canonicalization",
    "accepted_delta_count",
    "typed_delta_count",
    "admitted_finding_count",
    "rejected_finding_count",
    "scenario_projection",
    "deterministic_primary_skip_diagnostics",
)


def build_trusted_task_payload(
    base_payload: Mapping[str, Any],
    task: Mapping[str, Any],
) -> dict[str, Any]:
    """Add evaluator-owned task semantics to a generic SecMind request.

    These fields influence answer routing, never authorization or target scope.
    The bridge executes a non-interactive benchmark, so asking a human to clarify
    an answerable task is a product failure rather than a safe interaction mode.
    """

    payload = deepcopy(dict(base_payload))
    required = task.get("required_output")
    output_contract = (
        _hard_scrub(deepcopy(required), max_depth=8, max_items=MAX_PUBLIC_ITEMS_PER_FIELD)
        if isinstance(required, Mapping)
        else {}
    )
    capabilities = task.get("secondary_capabilities")
    payload.update(
        {
            "interaction_mode": "unattended",
            "autonomy_policy": "automatic",
            "primary_domain": _optional_text(task.get("primary_domain")),
            "secondary_capabilities": _text_list(capabilities),
            "scoring_mode": _optional_text(output_contract.get("scoring_mode")),
            "output_contract": output_contract,
        }
    )
    required_fields = output_contract.get("required_fields")
    if isinstance(required_fields, list):
        payload["expected_outputs"] = [
            str(item).strip()
            for item in required_fields
            if isinstance(item, str) and item.strip() and item != "[TRUNCATED]"
        ]
    trusted_metadata = _trusted_task_metadata(task)
    if trusted_metadata:
        # Keep evaluator-owned metadata in a clearly separate namespace.  The
        # generic bridge may copy the task payload into an API request, so only
        # this explicit allowlist is allowed to cross the trust boundary.
        payload["evaluation_metadata"] = trusted_metadata
        payload["task_metadata"] = deepcopy(trusted_metadata)
        payload["evaluation_contract_digest"] = _canonical_digest(trusted_metadata)
    # This payload stays on the loopback control plane and is consumed as
    # untrusted task data.  It must not pass through the output/log scrubber:
    # high-entropy but non-secret identifiers (notably upload UUIDs) can be
    # rewritten to ``[REDACTED]`` and break referential integrity.  Evaluator
    # metadata above is separately allowlisted and scrubbed; public results,
    # diagnostics and ledgers retain their existing mandatory scrub gates.
    return payload


def _validated_process_receipt(
    answer: Mapping[str, Any],
    report: Mapping[str, Any],
) -> dict[str, Any] | None:
    """Return only a runtime-bound deterministic semantic-delta receipt.

    A provider can emit similarly named dictionaries, so a field name alone
    is not authority.  The accepted object must satisfy the strict delta
    contract, reproduce its semantic digest, belong to this run, and close
    over evidence and immutable raw-input digests present in the report.
    """

    raw_delta = _find_named_mapping(answer, "semantic_delta")
    if raw_delta is None:
        return None
    try:
        delta = TypedSemanticDelta.model_validate(raw_delta)
    except (TypeError, ValidationError):
        return None
    coverage = report.get("coverage")
    runtime_receipt = coverage.get("scenario_semantic_delta_receipt") if isinstance(coverage, Mapping) else None
    if not isinstance(runtime_receipt, Mapping) or not _valid_scenario_semantic_delta_receipt(runtime_receipt, delta):
        return None
    if (
        delta.run_id != _optional_text(report.get("run_id"))
        or delta.source_content_trust != "deterministic_projection"
        or not delta.anchor_preserved
        or not delta.evidence_closure.complete
        or not delta.admission_ready
        or delta.disposition != "accepted"
        or delta.process_provenance.process_id != "secmind.deterministic-scenario-analyzer"
        or delta.process_provenance.network_access_performed
        or delta.process_provenance.model_calls != 0
    ):
        return None
    semantic_material = {
        "run_id": delta.run_id,
        "scenario": delta.scenario,
        "answer_kind": delta.answer_kind,
        "action": delta.action,
        "disposition": delta.disposition,
        "evidence_ids": list(delta.evidence_ids),
        "finding_ids": list(delta.finding_ids),
        "facts": list(delta.facts),
        "unknowns": list(delta.unknowns),
        "conflicts": list(delta.conflicts),
        "record_locators": [item.model_dump(mode="json") for item in delta.record_locators],
        "endpoint_graph": delta.endpoint_graph,
        "policy_decisions": list(delta.policy_decisions),
        "raw_artifact_digests": list(delta.raw_artifact_digests),
        "derived_artifact_digests": list(delta.derived_artifact_digests),
        "process_provenance": delta.process_provenance.model_dump(mode="json"),
        "evidence_closure": delta.evidence_closure.model_dump(mode="json"),
        "anchor_semantic_digest": delta.anchor_semantic_digest,
    }
    semantic_digest = hashlib.sha256(
        json.dumps(
            semantic_material,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    if semantic_digest != delta.semantic_digest.lower():
        return None
    evidence_ids: set[str] = set()
    referenced_evidence_digests: set[str] = set()
    required_evidence_ids = set(delta.evidence_ids)
    report_evidence = report.get("evidence")
    if isinstance(report_evidence, list):
        for index, row in enumerate(report_evidence):
            if not isinstance(row, Mapping):
                continue
            evidence_id = _collection_id(dict(row), index, prefix="evidence")
            evidence_ids.add(evidence_id)
            metadata = row.get("metadata")
            metadata = metadata if isinstance(metadata, Mapping) else {}
            for candidate in (
                row.get("sha256"),
                row.get("file_sha256"),
                row.get("artifact_ref"),
                metadata.get("source_artifact_sha256"),
                metadata.get("file_sha256"),
            ):
                if isinstance(candidate, str) and _is_sha256(candidate):
                    digest = candidate.lower()
                    if evidence_id in required_evidence_ids:
                        referenced_evidence_digests.add(digest)
    if not required_evidence_ids.issubset(evidence_ids):
        return None
    raw_digests = set(delta.evidence_closure.raw_artifact_digests)
    if not raw_digests or not referenced_evidence_digests or not referenced_evidence_digests.issubset(raw_digests):
        return None
    if not set(delta.process_provenance.input_artifact_digests).issubset(raw_digests):
        return None
    if not set(delta.process_provenance.output_artifact_digests).issubset(
        set(delta.evidence_closure.derived_artifact_digests)
    ):
        return None
    return {
        **delta.process_provenance.model_dump(mode="json"),
        "run_id": delta.run_id,
        "delta_id": delta.delta_id,
        "delta_digest": runtime_receipt["delta_digest"],
        "semantic_digest": delta.semantic_digest,
        "process_digest": runtime_receipt["process_digest"],
        "evidence_closure_complete": True,
        "evidence_count": len(delta.evidence_ids),
        "runtime_bound": True,
        "receipt_digest": runtime_receipt["receipt_digest"],
        "admission_ready": True,
        "disposition": "accepted",
    }


def _restore_runtime_process_receipt(result: dict[str, Any], receipt: Mapping[str, Any] | None) -> None:
    """Keep validated receipt identities intact through the generic scrub gate."""

    if not isinstance(receipt, Mapping):
        return
    decision = result.get("decision_summary")
    projected = decision.get("process_receipt") if isinstance(decision, dict) else None
    if not isinstance(projected, dict):
        return
    # These are runtime-created identities/digests, not provider text.  The
    # generic high-entropy scrubber cannot know that distinction and can turn
    # ``scenario-delta-<digest>`` into ``[REDACTED]``; restoring only the
    # validated receipt fields preserves the public binding without reopening
    # arbitrary evidence or provenance payloads.
    for key in (
        "run_id",
        "delta_id",
        "delta_digest",
        "semantic_digest",
        "process_id",
        "process_version",
        "operation",
        "process_digest",
        "receipt_digest",
        "admission_ready",
        "disposition",
        "runtime_bound",
    ):
        if key in receipt:
            projected[key] = deepcopy(receipt[key])


def _valid_scenario_semantic_delta_receipt(value: Any, delta: TypedSemanticDelta) -> bool:
    """Validate the runtime-owned receipt before accepting a process claim."""

    if not isinstance(value, Mapping):
        return False
    process = delta.process_provenance.model_dump(mode="json")
    expected: dict[str, Any] = {
        "schema_version": SCENARIO_SEMANTIC_DELTA_RECEIPT_VERSION,
        "delta_schema_version": delta.schema_version,
        "run_id": delta.run_id,
        "delta_id": delta.delta_id,
        "delta_digest": _canonical_digest(delta.model_dump(mode="json")),
        "semantic_digest": delta.semantic_digest.lower(),
        "process_id": process.get("process_id"),
        "process_version": process.get("process_version"),
        "operation": process.get("operation"),
        "process_digest": _canonical_digest(process),
        "process_provenance": process,
        "admission_ready": True,
        "disposition": "accepted",
        "anchor_preserved": True,
        "source_content_trust": "deterministic_projection",
    }
    expected["receipt_digest"] = _canonical_digest(expected)
    receipt = dict(value)
    if receipt.get("projection") == "summary":
        supplied_projection_digest = receipt.get("sha256")
        if supplied_projection_digest != _public_projection_digest(expected):
            return False
        return all(receipt.get(key) == item for key, item in expected.items() if key != "process_provenance")
    return receipt == expected


@dataclass(frozen=True, slots=True)
class _DecisionProjection:
    field_provenance: dict[str, Any]
    decision_projection: dict[str, Any]
    coverage: Any
    process_receipt: dict[str, Any] | None


@dataclass(frozen=True, slots=True)
class _EvidenceProjection:
    answer_obj: dict[str, Any]
    findings_origin: str
    evidence_origin: str
    finding_ids: list[str]
    finding_to_evidence: dict[str, list[str]]
    evidence_ids: list[str]
    evidence_to_findings: dict[str, list[str]]
    emitted_finding_ids: set[str]
    required_evidence_ids: set[str]
    unverified_evidence_ids: set[str]
    finding_info: dict[str, Any]
    evidence_info: dict[str, Any]
    limitation_info: dict[str, Any]
    answer_projection: dict[str, Any]


def _project_decision_summary(
    result: dict[str, Any],
    report_obj: dict[str, Any],
    answer_obj: dict[str, Any],
    *,
    summary: Mapping[str, Any] | None,
    task: Mapping[str, Any] | None,
) -> _DecisionProjection:
    """Project plan, validation, retry and process fields in source order."""

    decision = result.get("decision_summary")
    decision_obj = dict(decision) if isinstance(decision, dict) else {}
    plan_source: str | None = None
    steps: list[Any] = []
    for key in ("plan", "steps", "plan_or_steps"):
        candidate = decision_obj.get(key)
        if isinstance(candidate, list):
            steps = deepcopy(candidate)
            plan_source = f"decision_summary.{key}"
            break
    if plan_source is None:
        run_summary = dict(summary or {})
        raw_plan = run_summary.get("plan")
        if isinstance(raw_plan, list):
            steps = deepcopy(raw_plan)
            plan_source = "summary.plan"
    plan_kind = "native" if plan_source is not None else "derived"
    derived_from: str | None = None
    if not steps:
        decisions = decision_obj.get("decisions")
        if not isinstance(decisions, list):
            decisions = report_obj.get("decisions")
        if isinstance(decisions, list):
            steps = [
                {
                    "step_id": f"observed-{index:02d}",
                    "objective": str(item.get("decision", item.get("objective", "governed analysis step"))),
                    # A decision observation is not evidence that the step
                    # completed.  This prevents a derived projection from
                    # manufacturing success criteria or execution state.
                    "status": "observed",
                    "provenance": {"kind": "derived", "source": "decisions"},
                }
                for index, item in enumerate(decisions[:12], start=1)
                if isinstance(item, dict)
            ]
            derived_from = (
                "decision_summary.decisions" if isinstance(decision_obj.get("decisions"), list) else "report.decisions"
            )
            plan_kind = "derived"
    if not steps:
        plan_kind = "derived"
        derived_from = derived_from or "empty_plan"
    existing_provenance = decision_obj.get("field_provenance")
    field_provenance = (
        {str(key): value for key, value in existing_provenance.items()}
        if isinstance(existing_provenance, Mapping)
        else {}
    )
    field_provenance.update(
        {
            "plan_or_steps": {
                "origin": plan_kind,
                "source": plan_source or derived_from,
            },
            "plan": {"origin": "alias", "alias_of": "plan_or_steps"},
            "steps": {"origin": "alias", "alias_of": "plan_or_steps"},
        }
    )
    # Test 3.0 scorers have historically accepted either spelling.  Publishing
    # both aliases prevents an adapter revision from silently erasing the plan.
    decision_obj["plan_or_steps"] = deepcopy(steps)
    decision_obj["plan"] = deepcopy(steps)
    decision_obj["steps"] = deepcopy(steps)
    decision_obj["plan_contract"] = {
        "schema_version": PROJECTION_SCHEMA_VERSION,
        "origin": plan_kind,
        "source": plan_source or derived_from,
        "aliases": ["plan_or_steps", "plan", "steps"],
        "derived_step_status": "observed" if plan_kind == "derived" else None,
    }
    if not decision_obj.get("success_criteria"):
        required = dict(task or {}).get("required_output")
        required_fields = required.get("required_fields") if isinstance(required, dict) else None
        if isinstance(required_fields, list):
            decision_obj["success_criteria"] = [
                f"publish schema-valid {item}" for item in required_fields if isinstance(item, str) and item.strip()
            ]
            field_provenance["success_criteria"] = {
                "origin": "derived",
                "source": "task.required_output.required_fields",
            }
    elif "success_criteria" not in field_provenance:
        field_provenance["success_criteria"] = {"origin": "native"}
    # Only the runtime-owned, self-digested receipt may occupy the public
    # validation slot.  A model-authored ``answer.validation`` or a caller's
    # pre-existing decision field is untrusted task output, not verifier proof.
    for field in ("final_validation", "validation", "verification"):
        decision_obj.pop(field, None)
    coverage = report_obj.get("coverage")
    runtime_validation = report_obj.get("verification_summary")
    validation_valid, _validation_reason = validate_final_validation_payload(runtime_validation)
    coverage_validation_digest = (
        coverage.get("final_validation_receipt_digest") if isinstance(coverage, Mapping) else None
    )
    coverage_validator_id = coverage.get("final_validation_validator_id") if isinstance(coverage, Mapping) else None
    validation_bound = bool(
        isinstance(coverage, Mapping)
        and coverage.get("final_validation_required") is True
        and isinstance(coverage_validation_digest, str)
        and isinstance(coverage_validator_id, str)
        and isinstance(runtime_validation, Mapping)
        and runtime_validation.get("validation_digest") == coverage_validation_digest
        and runtime_validation.get("validator_id") == coverage_validator_id
    )
    if validation_valid and validation_bound:
        decision_obj["final_validation"] = deepcopy(runtime_validation)
        field_provenance["final_validation"] = {
            "origin": "native",
            "source": "report.verification_summary",
        }
    validation = decision_obj.get("final_validation")
    if isinstance(validation, dict):
        decision_obj["validation"] = deepcopy(validation)
        decision_obj["verification"] = deepcopy(validation)
        field_provenance.setdefault("validation", {"origin": "alias", "alias_of": "final_validation"})
        field_provenance.setdefault("verification", {"origin": "alias", "alias_of": "final_validation"})
    unknowns = decision_obj.get("confidence_or_unknowns")
    if isinstance(unknowns, list):
        decision_obj["unknowns"] = deepcopy(unknowns)
        field_provenance.setdefault("unknowns", {"origin": "alias", "alias_of": "confidence_or_unknowns"})
    if isinstance(coverage, dict) and "bounded_retries" not in decision_obj:
        decision_obj["bounded_retries"] = {
            "policy": "one_primary_plus_one_bounded_fallback",
            "primary_attempted": bool(coverage.get("canonical_primary_attempted")),
            "primary_status": coverage.get("canonical_primary_status", "not_recorded"),
        }
        field_provenance["bounded_retries"] = {"origin": "derived", "source": "report.coverage"}
    # ``bounded_retries`` documents policy only.  Publish a retry receipt only
    # when the runtime retained actual, sanitized provider-attempt telemetry.
    decision_obj.pop("retry_summary", None)
    attempt_summary = coverage.get("canonical_primary_attempt_summary") if isinstance(coverage, dict) else None
    if isinstance(attempt_summary, dict) and isinstance(attempt_summary.get("attempts"), list):
        decision_obj["retry_summary"] = deepcopy(attempt_summary)
        field_provenance["retry_summary"] = {
            "origin": "native",
            "source": "report.coverage.canonical_primary_attempt_summary",
        }
    process_receipt = _validated_process_receipt(answer_obj, report_obj)
    if process_receipt:
        decision_obj.setdefault("process_receipt", deepcopy(process_receipt))
        field_provenance.setdefault(
            "process_receipt",
            {"origin": "native", "source": "answer.process_provenance"},
        )
        if not decision_obj.get("tools"):
            process_name = _first_text(
                process_receipt.get("parser_id"),
                process_receipt.get("process_id"),
                process_receipt.get("producer"),
                "domain-evidence-compiler",
            )
            decision_obj["tools"] = [f"deterministic:{process_name}"]
            field_provenance["tools"] = {"origin": "native", "source": "answer.process_provenance"}
    if not decision_obj.get("tools") and isinstance(coverage, dict):
        scenario_projection = coverage.get("scenario_projection")
        if not isinstance(scenario_projection, dict):
            scenario_projection = coverage.get("pre_primary_scenario_projection")
        if isinstance(scenario_projection, dict) and scenario_projection.get("scenario"):
            decision_obj["tools"] = [f"deterministic:{scenario_projection['scenario']}"]
            field_provenance["tools"] = {"origin": "derived", "source": "report.coverage.scenario_projection"}
    decision_obj["native_fields"] = sorted(
        key for key, value in field_provenance.items() if isinstance(value, dict) and value.get("origin") == "native"
    )
    decision_obj["derived_fields"] = sorted(
        key for key, value in field_provenance.items() if isinstance(value, dict) and value.get("origin") == "derived"
    )
    decision_obj["alias_fields"] = sorted(
        key for key, value in field_provenance.items() if isinstance(value, dict) and value.get("origin") == "alias"
    )
    decision_obj["field_provenance"] = field_provenance
    decision_projection = _list_projection_metadata(decision_obj, prefix="decision")
    result["decision_summary"] = _hard_scrub(
        decision_obj,
        max_depth=10,
        max_items=MAX_PUBLIC_ITEMS_PER_FIELD,
    )
    return _DecisionProjection(field_provenance, decision_projection, coverage, process_receipt)


def _project_evidence_collections(
    result: dict[str, Any],
    answer_obj: dict[str, Any],
    *,
    task: Mapping[str, Any] | None,
    trusted_claim_refs: Mapping[str, Sequence[str]] | None = None,
    trusted_exact_answers: frozenset[str] = frozenset(),
) -> _EvidenceProjection:
    """Project bounded findings/evidence while retaining reference closure."""

    raw_findings = result.get("findings")
    findings_origin = "result.findings"
    if (not isinstance(raw_findings, list) or not raw_findings) and isinstance(answer_obj.get("findings"), list):
        raw_findings = answer_obj["findings"]
        findings_origin = "answer.findings"
    findings = _prepare_collection(raw_findings if isinstance(raw_findings, list) else [], "finding")
    finding_ids, finding_to_evidence = _finding_reference_index(findings)
    required_ids = _required_reference_ids(task or {})
    raw_evidence = result.get("evidence")
    evidence_origin = "result.evidence"
    typed_evidence = _typed_answer_evidence(answer_obj)
    if not isinstance(raw_evidence, list) or not raw_evidence:
        if typed_evidence:
            raw_evidence = typed_evidence
            evidence_origin = "answer.typed_evidence"
    elif typed_evidence:
        existing_ids = {_collection_id(item, index, prefix="evidence") for index, item in enumerate(raw_evidence)}
        raw_evidence = [
            *raw_evidence,
            *[
                item
                for index, item in enumerate(typed_evidence)
                if _collection_id(item, index, prefix="evidence") not in existing_ids
            ],
        ]
        evidence_origin = "result.evidence+answer.typed_evidence"
    evidence = _prepare_collection(raw_evidence if isinstance(raw_evidence, list) else [], "evidence")
    answer_obj = _remap_answer_evidence_aliases(answer_obj, evidence)
    answer_evidence_ids = _answer_evidence_references(answer_obj)
    if answer_obj.get("answer_kind") == "exact" and answer_evidence_ids:
        referenced_evidence = [
            item
            for index, item in enumerate(evidence)
            if _collection_id(item, index, prefix="evidence") in answer_evidence_ids
        ]
        if referenced_evidence:
            evidence = referenced_evidence
            evidence_origin += ".answer_reference_closure"
    evidence_ids: list[str] = []
    evidence_to_findings: dict[str, list[str]] = {}
    unverified_evidence_ids: set[str] = set()
    trusted_claim_refs = trusted_claim_refs or {}
    for index, item in enumerate(evidence):
        evidence_id = _collection_id(item, index, prefix="evidence")
        evidence_ids.append(evidence_id)
        if isinstance(item, dict):
            if not isinstance(item, dict):
                continue
            metadata = item.get("metadata")
            provider_claimed = _is_provider_claimed_evidence(item)
            if provider_claimed:
                unverified_evidence_ids.add(evidence_id)
            locator = item.get("source_locator") if isinstance(item.get("source_locator"), Mapping) else None
            if locator is None:
                locator = item.get("record_locator") if isinstance(item.get("record_locator"), Mapping) else None
            if locator is None and isinstance(metadata, dict):
                locator = metadata.get("source_locator")
            if locator is None and isinstance(metadata, dict):
                locator = metadata.get("record_locator")
            locator = locator if isinstance(locator, dict) else {}
            path = _first_text(
                item.get("path"),
                item.get("file"),
                item.get("file_path"),
                metadata.get("path") if isinstance(metadata, dict) else None,
                locator.get("path"),
                locator.get("source_path"),
                locator.get("record_path"),
                locator.get("source_ref"),
            )
            if path:
                item.pop("path", None)
                item.pop("file", None)
                public_path = _public_input_path(path)
                if public_path is not None:
                    item["path"] = public_path
                else:
                    metadata_obj = dict(metadata) if isinstance(metadata, dict) else {}
                    metadata_obj["path_projection_status"] = "unresolved_unsafe_or_nonrelative_path"
                    metadata = metadata_obj
                    item["metadata"] = metadata_obj
            source_sha = _first_text(
                item.get("file_sha256"),
                item.get("sha256"),
                metadata.get("source_artifact_sha256") if isinstance(metadata, dict) else None,
                metadata.get("file_sha256") if isinstance(metadata, dict) else None,
                locator.get("file_sha256"),
                locator.get("source_artifact_sha256"),
                locator.get("artifact_sha256"),
                locator.get("sha256"),
            )
            if source_sha and not provider_claimed:
                normalized_sha = source_sha.lower() if _is_sha256(source_sha) else source_sha
                item["file_sha256"] = normalized_sha
                item["sha256"] = normalized_sha
            source_ref = _first_text(
                item.get("source_ref"),
                item.get("record_locator"),
                locator.get("source_ref"),
                locator.get("record_locator"),
            )
            if source_ref:
                item["source_ref"] = source_ref
            line = _first_positive_int(
                item.get("line"),
                item.get("line_number"),
                item.get("line_start"),
                _line_range_start(item.get("line_range")),
                metadata.get("line") if isinstance(metadata, dict) else None,
                locator.get("line_number"),
                locator.get("line"),
                locator.get("record_line"),
            )
            if line is not None and not provider_claimed:
                item["line"] = line
            offset = _first_nonnegative_int(
                item.get("byte_offset"),
                item.get("offset"),
                locator.get("byte_offset"),
                locator.get("offset"),
            )
            if offset is not None and not provider_claimed:
                item["byte_offset"] = offset
                item["offset"] = offset
            if (
                evidence_id in answer_evidence_ids
                and isinstance(metadata, Mapping)
                and metadata.get("evidence_type") == "exact_value_observation"
                and str(item.get("source", "")) == "deterministic_exact_source@1.0"
                and source_sha
                and offset is not None
            ):
                item["extraction"] = {
                    "method": "bounded_immutable_source_match",
                    "producer": "deterministic_exact_source@1.0",
                    "source_sha256": source_sha.lower() if _is_sha256(source_sha) else source_sha,
                    "byte_offset": offset,
                }
            timestamp = _first_text(
                item.get("timestamp"),
                metadata.get("timestamp") if isinstance(metadata, dict) else None,
                locator.get("timestamp"),
            )
            if timestamp and not provider_claimed:
                item["timestamp"] = timestamp
            packet = _first_nonnegative_int(
                item.get("packet"),
                item.get("packet_number"),
                locator.get("packet"),
                locator.get("packet_number"),
            )
            if packet is not None and not provider_claimed:
                item["packet"] = packet
            if provider_claimed:
                # Provider assertions remain visible for audit, but never
                # become scorer-valid support merely because a locator or
                # digest was copied into the answer projection.
                for key in (
                    "path",
                    "file",
                    "file_path",
                    "source_ref",
                    "record_locator",
                    "source_locator",
                    "line",
                    "line_number",
                    "line_start",
                    "line_range",
                    "byte_offset",
                    "offset",
                    "timestamp",
                    "packet",
                    "packet_number",
                    "event_id",
                    "artifact_ref",
                    "sha256",
                    "file_sha256",
                    "claim_id",
                    "claim_refs",
                    "claim_ids",
                    "finding_id",
                    "finding_ids",
                ):
                    item.pop(key, None)
                metadata_obj = dict(metadata) if isinstance(metadata, dict) else {}
                # Provider evidence is audit-only.  Remove both top-level and
                # nested claim/attestation markers so a copied locator cannot
                # look like a verifier-owned support edge.
                for key in (
                    "claim_id",
                    "claim_ids",
                    "claim_refs",
                    "verification_status",
                    "exact_answer_attestation",
                ):
                    metadata_obj.pop(key, None)
                metadata_obj["verification_status"] = "unverified_provider_claim"
                metadata_obj["unverified_evidence_id"] = evidence_id
                item["metadata"] = metadata_obj
                continue
            verified_refs = _unique_text(list(trusted_claim_refs.get(evidence_id, ())))
            if verified_refs:
                item["claim_refs"] = verified_refs
                item["claim_id"] = verified_refs[0]
                metadata_obj = dict(metadata) if isinstance(metadata, dict) else {}
                metadata_obj["verification_status"] = "verified_support"
                metadata_obj["claim_refs"] = verified_refs
                metadata_obj["claim_id"] = verified_refs[0]
                item["metadata"] = metadata_obj
            linked = _text_list(item.get("finding_ids"))
            finding_id = _first_text(
                item.get("finding_id"),
                metadata.get("finding_id") if isinstance(metadata, dict) else None,
                locator.get("finding_id"),
            )
            if finding_id:
                linked.insert(0, finding_id)
            linked.extend(
                finding_id
                for finding_id, references in finding_to_evidence.items()
                if evidence_id in references and finding_id not in linked
            )
            linked = _unique_text(linked)
            if linked:
                item["finding_id"] = linked[0]
                if len(linked) > 1:
                    item["finding_ids"] = linked
                evidence_to_findings[evidence_id] = linked
            if evidence_id in answer_evidence_ids and not item.get("claim_id"):
                answer_kind = _optional_text(answer_obj.get("answer_kind")) or "domain"
                item["claim_id"] = f"answer-{answer_kind}-primary-claim"
    evidence.sort(key=_public_evidence_priority)
    finding_projection, finding_info = _bounded_collection(
        findings,
        MAX_PUBLIC_FINDINGS,
        prefix="finding",
        required_ids=required_ids.get("finding", set()),
    )
    if isinstance(raw_findings, list):
        result["findings"] = _hard_scrub(
            finding_projection,
            max_depth=10,
            max_items=MAX_PUBLIC_FINDINGS,
        )
    emitted_finding_ids = {
        _collection_id(item, index, prefix="finding") for index, item in enumerate(finding_projection)
    }
    # Evidence may retain provenance for a candidate that Admission rejected.
    # Keep that history, but never expose the rejected ID as an active finding
    # relation in the public reference graph.
    for index, item in enumerate(evidence):
        if not isinstance(item, dict):
            continue
        evidence_id = _collection_id(item, index, prefix="evidence")
        if evidence_id in unverified_evidence_ids:
            item.pop("finding_id", None)
            item.pop("finding_ids", None)
            evidence_to_findings.pop(evidence_id, None)
            continue
        linked = evidence_to_findings.get(evidence_id, [])
        active = [finding_id for finding_id in linked if finding_id in emitted_finding_ids]
        rejected = [finding_id for finding_id in linked if finding_id not in emitted_finding_ids]
        if rejected:
            metadata = item.get("metadata")
            metadata_obj = dict(metadata) if isinstance(metadata, dict) else {}
            metadata_obj["provenance_finding_ids"] = rejected
            item["metadata"] = metadata_obj
        item.pop("finding_id", None)
        item.pop("finding_ids", None)
        if active:
            item["finding_id"] = active[0]
            if len(active) > 1:
                item["finding_ids"] = active
            evidence_to_findings[evidence_id] = active
        else:
            evidence_to_findings.pop(evidence_id, None)
    evidence.sort(key=_public_evidence_priority)
    required_evidence_ids = {
        evidence_id for finding_id in emitted_finding_ids for evidence_id in finding_to_evidence.get(finding_id, [])
    }
    required_evidence_ids.update(answer_evidence_ids)
    required_evidence_ids.update(required_ids.get("evidence", set()))
    # Provider-claimed rows are never trusted support.  Keep them in the
    # bounded projection for audit, but make their presence explicit in the
    # closure so the public receipt cannot report a complete support graph.
    required_evidence_ids.update(unverified_evidence_ids)
    evidence_projection, evidence_info = _bounded_collection(
        evidence,
        MAX_PUBLIC_EVIDENCE,
        prefix="evidence",
        required_ids=required_evidence_ids,
    )
    if isinstance(raw_evidence, list):
        result["evidence"] = _hard_scrub(
            evidence_projection,
            max_depth=10,
            max_items=MAX_PUBLIC_EVIDENCE,
        )
    limitations = result.get("limitations")
    limitation_info: dict[str, Any] = {}
    if isinstance(limitations, list):
        limitations_projection, limitation_info = _bounded_collection(
            limitations,
            MAX_PUBLIC_ITEMS_PER_FIELD,
            prefix="limitation",
        )
        result["limitations"] = _hard_scrub(
            limitations_projection,
            max_depth=4,
            max_items=MAX_PUBLIC_ITEMS_PER_FIELD,
        )
    answer_projection = _list_projection_metadata(answer_obj, prefix="answer")
    answer_boundary: Any = {"answer": answer_obj} if trusted_exact_answers else answer_obj
    bounded_answer = _hard_scrub(
        answer_boundary,
        max_depth=10,
        max_items=MAX_PUBLIC_ITEMS_PER_FIELD,
        trusted_exact_answers=trusted_exact_answers,
    )
    if trusted_exact_answers and isinstance(bounded_answer, Mapping):
        bounded_answer = bounded_answer.get("answer")
    if isinstance(bounded_answer, dict):
        answer_obj = bounded_answer
        result["answer"] = answer_obj
    return _EvidenceProjection(
        answer_obj=answer_obj,
        findings_origin=findings_origin,
        evidence_origin=evidence_origin,
        finding_ids=finding_ids,
        finding_to_evidence=finding_to_evidence,
        evidence_ids=evidence_ids,
        evidence_to_findings=evidence_to_findings,
        emitted_finding_ids=emitted_finding_ids,
        required_evidence_ids=required_evidence_ids,
        unverified_evidence_ids=unverified_evidence_ids,
        finding_info=finding_info,
        evidence_info=evidence_info,
        limitation_info=limitation_info,
        answer_projection=answer_projection,
    )


def project_domain_result(
    base_result: Mapping[str, Any],
    report: Mapping[str, Any] | None,
    *,
    summary: Mapping[str, Any] | None = None,
    task: Mapping[str, Any] | None = None,
    raw_report_for_trust: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Preserve the sealed typed answer and publish scorer-compatible aliases.

    ``base_result`` may already be a scrubbed compatibility projection.  The
    bridge can therefore provide the direct server report as
    ``raw_report_for_trust`` for the one narrow exact-answer decision.  Trust
    is still recomputed by :func:`trusted_exact_answer_values` from that
    server-owned evidence and attestation; this parameter never accepts a
    caller-supplied trusted-value set and must not contain a post-scrub
    projection whose locator digests may have changed.
    """

    result = deepcopy(dict(base_result))
    native_status = result.get("status")
    native_status_text = _optional_text(native_status)
    report_obj = dict(report or {})
    answer = result.get("answer")
    answer_obj = dict(answer) if isinstance(answer, dict) else {}
    typed = report_obj.get("answer_payload")
    if isinstance(typed, dict):
        # Typed fields are already part of the immutable Primary baseline.  The
        # generic summary stays authoritative for its own key.
        preserved_summary = answer_obj.get("summary")
        answer_obj.update(deepcopy(typed))
        if preserved_summary:
            answer_obj["summary"] = preserved_summary
    # Publish lossless compatibility aliases consumed by older and newer
    # scorer revisions. These are projections of already sealed typed fields,
    # never new semantic content.
    if answer_obj.get("answer_kind") == "timeline" and isinstance(answer_obj.get("events"), list):
        answer_obj.setdefault("timeline", deepcopy(answer_obj["events"]))
    if answer_obj.get("answer_kind") == "exact" and "answer" not in answer_obj:
        values = answer_obj.get("values")
        if isinstance(values, list) and len(values) == 1:
            answer_obj["answer"] = deepcopy(values[0])
        elif values not in (None, [], {}, ""):
            answer_obj["answer"] = deepcopy(values)
    if "uncertainty" not in answer_obj:
        uncertainty = answer_obj.get("unknown_fields") or answer_obj.get("unknowns")
        if isinstance(uncertainty, list) and uncertainty:
            answer_obj["uncertainty"] = deepcopy(uncertainty)
    if "confidence" not in answer_obj:
        epistemic_status = _optional_text(answer_obj.get("epistemic_status"))
        if epistemic_status:
            answer_obj["confidence"] = epistemic_status
    # Internal anchor/enhancement snapshots remain in the durable report and
    # run proof. Repeating them inside the semantic answer can multiply the
    # payload to several MiB without adding a single user-facing fact.
    answer_obj.pop("coverage", None)
    answer_obj.pop("usage", None)
    answer_type = report_obj.get("answer_type")
    if isinstance(answer_type, str) and answer_type:
        answer_obj["answer_type"] = answer_type
    result["answer"] = answer_obj

    decision_projection_state = _project_decision_summary(
        result,
        report_obj,
        answer_obj,
        summary=summary,
        task=task,
    )
    field_provenance = decision_projection_state.field_provenance
    decision_projection = decision_projection_state.decision_projection
    coverage = decision_projection_state.coverage
    process_receipt = decision_projection_state.process_receipt
    trust_source = raw_report_for_trust if isinstance(raw_report_for_trust, Mapping) else result
    trusted_exact_answers = trusted_exact_answer_values(answer_obj, trust_source, task, report=report_obj)
    trusted_claim_refs = _runtime_verified_evidence_claims(report_obj)
    evidence_projection_state = _project_evidence_collections(
        result,
        answer_obj,
        task=task,
        trusted_claim_refs=trusted_claim_refs,
        trusted_exact_answers=trusted_exact_answers,
    )
    answer_obj = evidence_projection_state.answer_obj
    findings_origin = evidence_projection_state.findings_origin
    evidence_origin = evidence_projection_state.evidence_origin
    finding_ids = evidence_projection_state.finding_ids
    finding_to_evidence = evidence_projection_state.finding_to_evidence
    evidence_ids = evidence_projection_state.evidence_ids
    evidence_to_findings = evidence_projection_state.evidence_to_findings
    emitted_finding_ids = evidence_projection_state.emitted_finding_ids
    required_evidence_ids = evidence_projection_state.required_evidence_ids
    unverified_evidence_ids = evidence_projection_state.unverified_evidence_ids
    finding_info = evidence_projection_state.finding_info
    evidence_info = evidence_projection_state.evidence_info
    limitation_info = evidence_projection_state.limitation_info
    answer_projection = evidence_projection_state.answer_projection
    evidence_projection = result.get("evidence")
    if not isinstance(evidence_projection, list):
        evidence_projection = []
    proof = result.get("run_proof")
    proof_obj = dict(proof) if isinstance(proof, dict) else {}
    proof_obj["secmind_integration_version"] = INTEGRATION_VERSION
    proof_obj["native_status"] = native_status_text
    proof_obj["mapped_status"] = _optional_text(result.get("status"))
    proof_obj["status_mapping"] = {
        "rule": "preserve-native-status-v1",
        "native_status_promoted": False,
        "native_status": native_status_text,
        "mapped_status": _optional_text(result.get("status")),
    }
    proof_obj["field_provenance"] = {
        "decision_summary": field_provenance,
        "native_status": "native",
        "answer_payload": "native" if isinstance(typed, dict) else "base",
        "findings": findings_origin,
        "evidence": evidence_origin,
    }
    proof_obj["unverified_evidence_ids"] = sorted(unverified_evidence_ids)
    if task:
        trusted_metadata = _trusted_task_metadata(task)
        if trusted_metadata:
            proof_obj["task_metadata_digest"] = _canonical_digest(trusted_metadata)
    closure = _reference_closure(
        finding_ids=finding_ids,
        evidence_ids=evidence_ids,
        finding_to_evidence=finding_to_evidence,
        evidence_to_findings=evidence_to_findings,
        emitted_finding_ids=emitted_finding_ids,
        emitted_evidence_ids={
            _collection_id(item, index, prefix="evidence") for index, item in enumerate(evidence_projection)
        },
        required_evidence_ids=required_evidence_ids,
        required_reference_overflow=(
            finding_info.get("required_overflow_ids", []) + evidence_info.get("required_overflow_ids", [])
        ),
        duplicate_ids=(finding_info.get("duplicate_ids", []) + evidence_info.get("duplicate_ids", [])),
        projection_truncated=bool(finding_info.get("truncated") or evidence_info.get("truncated")),
        unverified_evidence_ids=sorted(unverified_evidence_ids),
    )
    proof_obj["projection"] = {
        "schema_version": PROJECTION_SCHEMA_VERSION,
        "hard_limits": {
            "findings": MAX_PUBLIC_FINDINGS,
            "evidence": MAX_PUBLIC_EVIDENCE,
            "nested": MAX_PUBLIC_ITEMS_PER_FIELD,
        },
        "collections": {
            "findings": finding_info,
            "evidence": evidence_info,
            "limitations": limitation_info,
            "decision": decision_projection,
            "answer": answer_projection,
        },
        "reference_closure": closure,
        "unverified_evidence_ids": sorted(unverified_evidence_ids),
        "page_api": {
            "cursor_schema": CURSOR_SCHEMA_VERSION,
            "read": "secmind.integrations.test3.read_projection_page",
            "read_method": "ProjectionPageReader.read_page",
        },
    }
    if isinstance(coverage, dict):
        # The platform deletes the per-task temporary DB/CAS after projection.
        # Preserve only bounded, already-scrubbed control-plane diagnostics so
        # provider and tool failures remain attributable without exposing raw
        # prompts, responses, workspace paths or credentials.
        safe_diagnostics = {key: deepcopy(coverage[key]) for key in _SAFE_DIAGNOSTIC_KEYS if key in coverage}
        proof_obj["agent_diagnostics"] = _hard_scrub(safe_diagnostics, max_depth=10, max_items=256)
    if summary:
        last_error = summary.get("last_error")
        if isinstance(last_error, str) and last_error:
            proof_obj["safe_failure_summary"] = scrub_text(last_error)[:512]
    # Older score adapters read policy fields at the answer root while newer
    # ones read the typed nested payload. Publish both views byte-equivalently.
    for key in ("decision", "safe_actions", "blocked_actions"):
        if key in answer_obj:
            result[key] = deepcopy(answer_obj[key])
    result["run_proof"] = _hard_scrub(proof_obj, max_depth=12, max_items=256)
    # Last-line gate: generic platform envelope fields are also tainted. Known
    # collections are already bounded; unknown fields receive a conservative
    # cap and are then checked by the complete artifact scrubber.
    for key, value in list(result.items()):
        if key in {"answer", "decision_summary", "findings", "evidence", "limitations", "run_proof"}:
            continue
        result[key] = _hard_scrub(value, max_depth=8, max_items=64)
    try:
        scrubbed_result = scrub_artifact(
            result,
            max_depth=12,
            max_items=256,
            trusted_exact_answers=trusted_exact_answers,
        )
        _restore_runtime_process_receipt(scrubbed_result, process_receipt)
        return scrubbed_result
    except Exception as exc:
        # Do not let a detector implementation turn a result into a raw
        # failure with the offending artifact attached.
        raise RuntimeError("Test 3.0 public artifact failed the secret-scrub gate") from exc


def _prepare_collection(values: list[Any], prefix: str) -> list[Any]:
    """Copy collection rows and give every row a stable public identity."""

    output: list[Any] = []
    for index, value in enumerate(values):
        item = deepcopy(value)
        if isinstance(item, dict):
            item.setdefault(f"{prefix}_id", _collection_id(item, index, prefix=prefix))
        output.append(item)
    return output


def _required_reference_ids(task: Mapping[str, Any]) -> dict[str, set[str]]:
    output: dict[str, set[str]] = {"finding": set(), "evidence": set()}
    required = task.get("required_output")
    if not isinstance(required, Mapping):
        required = task.get("output_contract") if isinstance(task.get("output_contract"), Mapping) else {}
    _collect_required_refs(required, output)
    return output


def _collect_required_refs(value: object, output: dict[str, set[str]], parent: str = "") -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            folded = str(key).casefold()
            target = (
                "evidence"
                if folded in _EXPLICIT_EVIDENCE_REFERENCE_FIELDS
                else "finding"
                if folded in {"finding_id", "finding_ids", "finding_refs", "source_finding_ids"}
                else parent
            )
            # Bare ``evidence``/``supporting_evidence`` is often a prose
            # output requirement, not an evidence identifier.  Only explicit
            # *_id/*_ids/*_refs fields may contribute a required ID.
            is_explicit_evidence_field = folded in _EXPLICIT_EVIDENCE_REFERENCE_FIELDS
            if target in output and is_explicit_evidence_field and isinstance(item, str) and item.strip():
                safe_id = _safe_identifier(item, f"{target}_id")
                if safe_id:
                    output[target].add(safe_id)
            elif (
                target in output
                and is_explicit_evidence_field
                and isinstance(item, Sequence)
                and not isinstance(item, (str, bytes, bytearray))
            ):
                for entry in item:
                    if isinstance(entry, str) and entry.strip():
                        safe_id = _safe_identifier(entry, f"{target}_id")
                        if safe_id:
                            output[target].add(safe_id)
            _collect_required_refs(item, output, target)
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for item in value:
            _collect_required_refs(item, output, parent)


def _hard_scrub(
    value: Any,
    *,
    max_depth: int,
    max_items: int,
    trusted_exact_answers: set[str] | frozenset[str] = frozenset(),
) -> Any:
    """Scrub while making list/dict limits hard (no sentinel overrun)."""

    return _remove_truncation_markers(
        scrub_value(
            value,
            max_depth=max_depth,
            max_items=max(1, max_items),
            trusted_exact_answers=trusted_exact_answers,
        ),
        max_items=max(1, max_items),
    )


def trusted_exact_answer_values(
    answer: Mapping[str, Any],
    result: Mapping[str, Any],
    task: Mapping[str, Any] | None,
    *,
    report: Mapping[str, Any] | None = None,
) -> frozenset[str]:
    """Return exact values safe to retain at the public answer boundary.

    The ordinary scrubber must redact unlabeled high-entropy strings because
    they may be credentials.  A benchmark exact answer is a much narrower
    case: the evaluator-owned envelope must select an exact-answer scoring
    mode, the typed answer must explicitly identify an exact answer, and the
    same candidate must occur in a non-provider-claimed evidence row carrying
    a source locator.  Values that merely appear in prose or in an unverified
    provider row never enter the exception set.
    """

    if not _task_allows_exact_answer(task):
        return frozenset()
    if _optional_text(answer.get("answer_kind")) not in {"exact", "exact_answer"}:
        return frozenset()
    answer_type = _optional_text(answer.get("answer_type"))
    if answer_type and answer_type not in {"exact", "exact_answer"}:
        return frozenset()

    candidates: set[str] = set()

    def add_candidate(value: Any) -> None:
        if (
            isinstance(value, str)
            and value
            and len(value) <= MAX_TRUSTED_EXACT_VALUE_CHARS
            and len(candidates) < MAX_TRUSTED_EXACT_CANDIDATES
        ):
            candidates.add(value)

    raw_values = answer.get("values")
    if isinstance(raw_values, Sequence) and not isinstance(raw_values, (str, bytes, bytearray)):
        for item in islice(raw_values, MAX_TRUSTED_EXACT_CANDIDATES):
            add_candidate(item)
    elif isinstance(raw_values, str):
        add_candidate(raw_values)
    direct = answer.get("answer")
    add_candidate(direct)
    if not candidates:
        return frozenset()

    root_refs = {
        *_text_list(answer.get("evidence_ids")),
        *_text_list(answer.get("evidence_refs")),
        *_text_list(answer.get("supporting_evidence_ids")),
    }
    runtime_verified_evidence_ids = _runtime_verified_evidence_ids(report)
    runtime_verified_claims = _runtime_verified_evidence_claims(report)
    expected_run_id = _optional_text(report.get("run_id")) if isinstance(report, Mapping) else None
    expected_manifest_digest = _task_input_manifest_digest(task) or _report_input_manifest_digest(report)
    require_runtime_attestation = runtime_verified_evidence_ids is not None
    if require_runtime_attestation and expected_manifest_digest is None:
        return frozenset()
    raw_evidence = result.get("evidence")
    if not isinstance(raw_evidence, list) or not raw_evidence:
        raw_evidence = _typed_answer_evidence(answer)
    evidence_by_id = {
        _collection_id(dict(row), index, prefix="evidence"): row
        for index, row in enumerate(raw_evidence)
        if isinstance(row, Mapping)
    }

    candidate_refs: dict[str, set[str]] = {candidate: set(root_refs) for candidate in candidates}
    # Some deterministic domain compilers keep the exact token in a typed
    # ``items`` row while the promoted public evidence intentionally stores
    # only a value digest.  Never trust the row's claimed locator on its own:
    # it must resolve to a system-produced evidence row whose value digest and
    # source locator both verify the candidate.
    for row in _typed_answer_rows(answer):
        row_refs = {
            *_text_list(row.get("evidence_ids")),
            *_text_list(row.get("evidence_refs")),
            *_text_list(row.get("supporting_evidence_ids")),
        }
        if not row_refs:
            continue
        row_values = _evidence_value_strings(row)
        for candidate in candidates.intersection(row_values):
            candidate_refs[candidate].update(row_refs)

    trusted = {
        candidate
        for candidate, references in candidate_refs.items()
        if any(
            (
                runtime_verified_evidence_ids is None
                or (reference in runtime_verified_evidence_ids and reference in runtime_verified_claims)
            )
            and _deterministic_exact_evidence_binds(
                evidence_by_id.get(reference),
                candidate,
                expected_run_id=expected_run_id,
                expected_input_manifest_digest=expected_manifest_digest,
                require_attestation=require_runtime_attestation,
            )
            for reference in references
        )
    }
    return frozenset(trusted)


def _runtime_verified_evidence_ids(report: Mapping[str, Any] | None) -> set[str] | None:
    """Return verifier-owned evidence IDs, or ``None`` for legacy local calls.

    A report that declares terminal validation is treated fail-closed: an
    invalid/missing receipt yields an empty set rather than falling back to a
    model-authored evidence row.  Unit-level pure projection callers that do
    not carry a report retain the historical deterministic-only behavior.
    """

    if not isinstance(report, Mapping):
        return None
    coverage = report.get("coverage")
    if not isinstance(coverage, Mapping) or coverage.get("final_validation_required") is not True:
        return None
    validation = report.get("verification_summary")
    valid, _reason = validate_final_validation_payload(validation)
    if not valid or not isinstance(validation, Mapping):
        return set()
    if coverage.get("final_validation_receipt_digest") != validation.get("validation_digest") or coverage.get(
        "final_validation_validator_id"
    ) != validation.get("validator_id"):
        return set()
    values = validation.get("verified_evidence_ids")
    if not isinstance(values, list):
        return set()
    return {item for item in values if isinstance(item, str) and item}


def _runtime_verified_evidence_claims(report: Mapping[str, Any] | None) -> dict[str, tuple[str, ...]]:
    """Project only server-marked claim links from a valid terminal receipt."""

    verified_evidence_ids = _runtime_verified_evidence_ids(report)
    if verified_evidence_ids is None or not isinstance(report, Mapping):
        return {}
    validation = report.get("verification_summary")
    verified_claim_ids = (
        {item for item in validation.get("verified_claim_ids", []) if isinstance(item, str) and item}
        if isinstance(validation, Mapping)
        else set()
    )
    output: dict[str, tuple[str, ...]] = {}
    rows = report.get("evidence")
    if not isinstance(rows, list):
        return output
    for index, row in enumerate(rows):
        if not isinstance(row, Mapping):
            continue
        evidence_id = _collection_id(dict(row), index, prefix="evidence")
        if evidence_id not in verified_evidence_ids:
            continue
        metadata = row.get("metadata")
        if not isinstance(metadata, Mapping) or metadata.get("verification_status") != "verified_support":
            continue
        refs = _unique_text(
            [
                item
                for item in (_text_list(metadata.get("claim_refs")) + [_optional_text(metadata.get("claim_id")) or ""])
                if item
            ]
        )
        if refs and set(refs).issubset(verified_claim_ids):
            output[evidence_id] = tuple(refs)
    return output


def _task_input_manifest_digest(task: Mapping[str, Any] | None) -> str | None:
    if not isinstance(task, Mapping):
        return None
    for container in (task, task.get("evaluation_metadata"), task.get("task_metadata")):
        if not isinstance(container, Mapping):
            continue
        candidate = container.get("input_manifest_digest")
        if isinstance(candidate, str) and _is_sha256(candidate):
            return candidate.lower()
    return None


def _report_input_manifest_digest(report: Mapping[str, Any] | None) -> str | None:
    """Read the verifier's immutable input digest from bounded report metadata."""

    if not isinstance(report, Mapping):
        return None
    for container_name in ("coverage", "verification_summary"):
        container = report.get(container_name)
        if isinstance(container, Mapping):
            candidate = container.get("input_manifest_digest")
            if isinstance(candidate, str) and _is_sha256(candidate):
                return candidate.lower()
    return None


def _typed_answer_rows(answer: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """Return bounded typed rows that can carry exact values and locators."""

    rows: list[Mapping[str, Any]] = []
    for collection in ("items", "facts", "events", "inferences", "actors", "iocs", "techniques"):
        values = answer.get(collection)
        if not isinstance(values, list):
            continue
        rows.extend(item for item in values[:MAX_PUBLIC_ITEMS_PER_FIELD] if isinstance(item, Mapping))
    return rows


def _task_allows_exact_answer(task: Mapping[str, Any] | None) -> bool:
    if not isinstance(task, Mapping):
        return False
    contract = task.get("required_output")
    if not isinstance(contract, Mapping):
        contract = task.get("output_contract")
    if not isinstance(contract, Mapping):
        return False
    return _optional_text(contract.get("scoring_mode")) in {
        "exact_answer",
        "exact_answer_with_evidence",
    }


def _has_input_locator(row: Mapping[str, Any]) -> bool:
    """Require a bounded source locator before treating a value as input-derived."""

    locator: Mapping[str, Any] = {}
    for key in ("source_locator", "record_locator", "locator"):
        candidate = row.get(key)
        if isinstance(candidate, Mapping):
            locator = candidate
            break
    if not locator:
        metadata = row.get("metadata")
        if isinstance(metadata, Mapping):
            for key in ("source_locator", "record_locator", "locator"):
                candidate = metadata.get(key)
                if isinstance(candidate, Mapping):
                    locator = candidate
                    break
    path_values = [row.get(key) for key in ("path", "file", "file_path", "source_ref")]
    locator_path_values = [locator.get(key) for key in ("path", "source_path", "source_ref", "record_path")]
    path_present = any(_is_public_locator_text(value) for value in path_values) or any(
        _is_public_locator_text(value) for value in locator_path_values
    )
    position_values = [row.get(key) for key in ("line", "line_number", "byte_offset", "offset", "packet")]
    locator_position_values = [locator.get(key) for key in ("line", "line_number", "byte_offset", "offset", "packet")]
    position_present = any(isinstance(value, (int, float)) and value >= 0 for value in position_values) or any(
        isinstance(value, (int, float)) and value >= 0 for value in locator_position_values
    )
    digest_present = any(
        isinstance(row.get(key), str) and _is_sha256(row[key]) for key in ("sha256", "file_sha256", "artifact_ref")
    ) or any(
        isinstance(locator.get(key), str) and _is_sha256(locator[key])
        for key in ("sha256", "file_sha256", "artifact_sha256")
    )
    return path_present and (position_present or digest_present)


def _is_public_locator_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip()) and value not in {REDACTED, TRUNCATED}


def _deterministic_exact_evidence_binds(
    row: Any,
    candidate: str,
    *,
    expected_run_id: str | None = None,
    expected_input_manifest_digest: str | None = None,
    require_attestation: bool = False,
) -> bool:
    """Verify an exact value against a system-produced input observation."""

    if not isinstance(row, Mapping) or _is_provider_claimed_evidence(row) or not _has_input_locator(row):
        return False
    metadata = row.get("metadata")
    metadata = metadata if isinstance(metadata, Mapping) else {}
    source = _optional_text(row.get("source")) or _optional_text(metadata.get("source")) or ""
    evidence_type = _optional_text(metadata.get("evidence_type")) or _optional_text(row.get("evidence_type"))
    if evidence_type != "exact_value_observation" or source != "deterministic_exact_source@1.0":
        return False
    value_digest = _optional_text(metadata.get("value_sha256"))
    if not value_digest or value_digest != hashlib.sha256(candidate.encode("utf-8")).hexdigest():
        return False

    source_digest = _optional_text(metadata.get("source_artifact_sha256"))
    if not source_digest or not _is_sha256(source_digest):
        return False
    source_digest = source_digest.lower()
    public_digests = {
        str(row[key]).lower()
        for key in ("sha256", "file_sha256", "artifact_ref")
        if isinstance(row.get(key), str) and _is_sha256(row[key])
    }
    if source_digest not in public_digests:
        return False
    native_artifact_id = _optional_text(metadata.get("native_artifact_id"))
    if native_artifact_id is not None and native_artifact_id.lower() != source_digest:
        return False

    locator: Mapping[str, Any] = {}
    for key in ("source_locator", "record_locator", "locator"):
        value = row.get(key)
        if isinstance(value, Mapping):
            locator = value
            break
        value = metadata.get(key)
        if isinstance(value, Mapping):
            locator = value
            break
    byte_offset = row.get("byte_offset")
    if not isinstance(byte_offset, int) or byte_offset < 0:
        byte_offset = locator.get("byte_offset")
    if not isinstance(byte_offset, int) or byte_offset < 0:
        return False
    evidence_id = _optional_text(row.get("evidence_id"))
    if evidence_id is None:
        return False
    if expected_input_manifest_digest is not None:
        observed_manifest = _optional_text(metadata.get("input_manifest_digest"))
        if observed_manifest != expected_input_manifest_digest:
            return False
    if expected_run_id is not None and _optional_text(metadata.get("run_id")) not in {None, expected_run_id}:
        return False
    locator = dict(locator)
    attestation = metadata.get("exact_answer_attestation")
    if require_attestation and not isinstance(attestation, Mapping):
        return False
    if require_attestation and metadata.get("verification_status") != "verified_support":
        return False
    if (
        require_attestation
        and not _text_list(metadata.get("claim_refs"))
        and not _optional_text(metadata.get("claim_id"))
    ):
        return False
    if isinstance(attestation, Mapping):
        if not validate_exact_answer_attestation(
            attestation,
            expected_run_id=expected_run_id,
            expected_input_manifest_digest=expected_input_manifest_digest
            or _optional_text(metadata.get("input_manifest_digest")),
            expected_evidence_id=evidence_id,
            expected_value_sha256=value_digest,
            expected_artifact_sha256=source_digest,
            expected_locator=locator,
        ):
            return False
    expected_id = str(
        uuid5(
            NAMESPACE_URL,
            f"secmind:exact-source:{source_digest}:{byte_offset}:{candidate}",
        )
    )
    return evidence_id == expected_id


def _evidence_value_strings(row: Mapping[str, Any]) -> set[str]:
    """Collect bounded, semantically named evidence values only."""

    values: set[str] = set()
    pending: list[Any] = [row]
    visited = 0
    while pending and visited < 256:
        current = pending.pop()
        visited += 1
        if isinstance(current, Mapping):
            for key, item in islice(current.items(), 64):
                if str(key).casefold() in {"value", "exact_value", "flag", "answer"} and isinstance(item, str):
                    values.add(item)
                if isinstance(item, (Mapping, list)):
                    pending.append(item)
        elif isinstance(current, list):
            pending.extend(current[:64])
    return values


def _remove_truncation_markers(value: Any, *, max_items: int) -> Any:
    if isinstance(value, list):
        return [_remove_truncation_markers(item, max_items=max_items) for item in value if item != "[TRUNCATED]"][
            :max_items
        ]
    if isinstance(value, dict):
        return {
            key: _remove_truncation_markers(item, max_items=max_items)
            for key, item in list(value.items())[:max_items]
            if key != "scrubber.truncated"
        }
    return value


def _answer_evidence_references(answer: Mapping[str, Any]) -> set[str]:
    """Collect explicit evidence references from bounded typed answer fields."""

    references: set[str] = _collect_explicit_evidence_references(answer)
    pending: list[object] = [
        answer.get(name)
        for name in (
            "evidence_id",
            "evidence_ids",
            "evidence_refs",
            "source_evidence_ids",
            "supporting_evidence_ids",
            "findings",
            "facts",
            "events",
            "inferences",
            "actors",
            "iocs",
            "techniques",
            "items",
            "derivation",
            "source_offsets",
            "validation",
        )
    ]
    visited = 0
    while pending and visited < 10_000:
        current = pending.pop()
        visited += 1
        if isinstance(current, dict):
            evidence_id = _optional_text(current.get("evidence_id"))
            if evidence_id:
                references.add(evidence_id)
            references.update(_text_list(current.get("evidence_ids")))
            pending.extend(current.values())
        elif isinstance(current, list):
            pending.extend(current)
    return references


def _collect_explicit_evidence_references(
    value: Any,
    *,
    field_name: str | None = None,
    depth: int = 0,
    _budget: list[int] | None = None,
) -> set[str]:
    """Collect every non-empty string in named reference fields.

    The field name, rather than an ID prefix or punctuation heuristic, is the
    authority.  A prose string supplied under an explicit reference member is
    therefore a missing reference and makes the closure fail closed.
    """

    if _budget is None:
        _budget = [0]
    _budget[0] += 1
    if _budget[0] > 4_096 or depth > 16:
        return set()
    references: set[str] = set()
    if isinstance(value, str):
        if field_name in _EXPLICIT_EVIDENCE_REFERENCE_FIELDS and value.strip():
            references.add(value.strip())
        return references
    if isinstance(value, Mapping):
        for key, item in list(value.items())[:256]:
            normalized = str(key).casefold()
            references.update(
                _collect_explicit_evidence_references(
                    item,
                    field_name=normalized,
                    depth=depth + 1,
                    _budget=_budget,
                )
            )
        return references
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for item in value[:256]:
            references.update(
                _collect_explicit_evidence_references(
                    item,
                    field_name=field_name,
                    depth=depth + 1,
                    _budget=_budget,
                )
            )
        return references
    return references


def _remap_answer_evidence_aliases(
    answer: Mapping[str, Any],
    evidence: Sequence[Any],
) -> dict[str, Any]:
    """Resolve unique provider-local evidence IDs to canonical public IDs."""

    targets: dict[str, set[str]] = {}
    for index, item in enumerate(evidence):
        if not isinstance(item, Mapping):
            continue
        metadata = item.get("metadata")
        raw_aliases = metadata.get("provider_evidence_ids") if isinstance(metadata, Mapping) else None
        if not isinstance(raw_aliases, list):
            continue
        canonical_id = _collection_id(dict(item), index, prefix="evidence")
        for alias in raw_aliases:
            safe_alias = _optional_text(alias)
            if safe_alias:
                targets.setdefault(safe_alias, set()).add(canonical_id)
    aliases = {alias: next(iter(values)) for alias, values in targets.items() if len(values) == 1}
    if not aliases:
        return deepcopy(dict(answer))

    visited = 0

    def remap(value: Any, *, field_name: str | None = None, depth: int = 0) -> Any:
        nonlocal visited
        visited += 1
        if visited > 20_000 or depth > 16:
            return deepcopy(value)
        if isinstance(value, Mapping):
            return {str(key): remap(item, field_name=str(key), depth=depth + 1) for key, item in value.items()}
        if isinstance(value, list):
            return [remap(item, field_name=field_name, depth=depth + 1) for item in value]
        if isinstance(value, str) and field_name in _EXPLICIT_EVIDENCE_REFERENCE_FIELDS:
            return aliases.get(value, value)
        return deepcopy(value)

    remapped = remap(answer)
    return remapped if isinstance(remapped, dict) else deepcopy(dict(answer))


def _find_named_mapping(value: Mapping[str, Any], field_name: str) -> dict[str, Any] | None:
    """Find one bounded typed mapping without harvesting arbitrary prose."""

    pending: list[Any] = [value]
    visited = 0
    while pending and visited < 5_000:
        current = pending.pop()
        visited += 1
        if isinstance(current, Mapping):
            candidate = current.get(field_name)
            if isinstance(candidate, Mapping) and candidate:
                return dict(candidate)
            pending.extend(current.values())
        elif isinstance(current, list):
            pending.extend(current)
    return None


def _typed_answer_evidence(answer: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Project only explicit typed evidence into the scorer collection.

    Domain answer schemas historically carried evidence under ``answer`` while
    the public envelope and scorer consume the top-level collection.  This is a
    lossless shape adapter: it never treats arbitrary prose as evidence and it
    records provider-claimed provenance until the runtime supplies a verified
    Evidence object for the same source.
    """

    output: list[dict[str, Any]] = []
    direct = answer.get("evidence")
    if isinstance(direct, list):
        answer_kind = _optional_text(answer.get("answer_kind")) or "domain"
        for item in direct:
            if not isinstance(item, dict):
                continue
            promoted = deepcopy(item)
            promoted.setdefault("claim_id", f"answer-{answer_kind}-primary-claim")
            output.append(promoted)

    # Timeline and investigation answers bind a small evidence object to each
    # typed row.  Only these named collections and the explicit ``evidence``
    # member are eligible; recursive string harvesting is intentionally banned.
    for collection_name in ("facts", "events", "inferences", "actors", "iocs", "techniques"):
        rows = answer.get(collection_name)
        if not isinstance(rows, list):
            continue
        for row_index, row in enumerate(rows):
            if not isinstance(row, dict):
                continue
            embedded = row.get("evidence")
            if not isinstance(embedded, dict):
                continue
            item = deepcopy(embedded)
            statement = _first_text(
                row.get("statement"),
                row.get("description"),
                row.get("event_type"),
                row.get("value"),
            )
            if statement:
                item.setdefault("summary", statement)
            item.setdefault(
                "evidence_id",
                "typed-" + _canonical_digest([collection_name, row_index, item, statement])[:32],
            )
            metadata = item.get("metadata")
            metadata_obj = dict(metadata) if isinstance(metadata, dict) else {}
            metadata_obj.setdefault("projection_origin", f"answer.{collection_name}[{row_index}].evidence")
            metadata_obj.setdefault("assurance", "provider_claimed")
            item["metadata"] = metadata_obj
            output.append(item)

    deduped: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, item in enumerate(output):
        item.setdefault("evidence_id", "typed-" + _canonical_digest(["typed-evidence", index, item])[:32])
        metadata = item.get("metadata")
        metadata_obj = dict(metadata) if isinstance(metadata, dict) else {}
        metadata_obj.setdefault("projection_origin", "answer.evidence")
        metadata_obj.setdefault("assurance", "provider_claimed")
        item["metadata"] = metadata_obj
        digest = _canonical_digest(item)
        if digest in seen:
            continue
        seen.add(digest)
        deduped.append(item)
    return deduped


def _is_provider_claimed_evidence(item: Mapping[str, Any]) -> bool:
    """Identify evidence whose authority is only the provider response."""

    metadata = item.get("metadata")
    metadata = metadata if isinstance(metadata, Mapping) else {}
    assurance = _optional_text(item.get("assurance")) or _optional_text(metadata.get("assurance"))
    trust = _optional_text(item.get("source_content_trust")) or _optional_text(metadata.get("source_content_trust"))
    origin = _optional_text(metadata.get("projection_origin")) or ""
    return assurance == "provider_claimed" or trust == "untrusted_data" or origin.startswith("answer.")


def _trusted_task_metadata(task: Mapping[str, Any]) -> dict[str, Any]:
    """Return bounded evaluator metadata without copying workspace controls."""

    metadata: dict[str, Any] = {}
    for key in _TRUSTED_TASK_METADATA_KEYS:
        if key in task:
            metadata[key] = scrub_value(deepcopy(task[key]), max_depth=6, max_items=MAX_PUBLIC_ITEMS_PER_FIELD)
    for container in _TRUSTED_METADATA_CONTAINERS:
        nested = task.get(container)
        if not isinstance(nested, Mapping):
            continue
        for key in _TRUSTED_TASK_METADATA_KEYS:
            if key in nested and key not in metadata:
                metadata[key] = scrub_value(deepcopy(nested[key]), max_depth=6, max_items=MAX_PUBLIC_ITEMS_PER_FIELD)
    return metadata


def _canonical_digest(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _public_projection_digest(value: Any) -> str:
    """Match ``public_coverage``'s UTF-8 digest for an opaque value."""

    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _collection_id(value: object, index: int, *, prefix: str) -> str:
    if isinstance(value, dict):
        for key in ("evidence_id", "finding_id", "id", "limitation_id", "step_id"):
            candidate = _optional_text(value.get(key))
            if candidate:
                safe_id = _safe_identifier(candidate, key)
                if safe_id:
                    return safe_id
    return f"{prefix}-{index + 1:04d}"


def _safe_identifier(value: object, field: str) -> str | None:
    """Scrub an ID with its schema context so digest-backed IDs remain stable."""

    candidate = _optional_text(value)
    if not candidate:
        return None
    projected = scrub_value({field: candidate}, max_depth=2, max_items=2)
    safe = projected.get(field) if isinstance(projected, Mapping) else None
    if isinstance(safe, str) and safe not in {"[REDACTED]", "[TRUNCATED]"}:
        return safe[:160]
    return scrub_text(candidate)[:160]


def _bounded_collection(
    values: list[Any],
    limit: int,
    *,
    prefix: str,
    required_ids: set[str] | None = None,
) -> tuple[list[Any], dict[str, Any]]:
    required = set(required_ids or ())
    ids = [_collection_id(value, index, prefix=prefix) for index, value in enumerate(values)]
    required_indices = [index for index, identifier in enumerate(ids) if identifier in required]
    # A hard cap applies even when the contract asks for more required rows.
    # Required overflow is explicit and makes reference closure fail closed.
    selected_indices: list[int] = required_indices[:limit]
    for index in range(len(values)):
        if len(selected_indices) >= limit:
            break
        if index not in selected_indices:
            selected_indices.append(index)
    selected_indices.sort()
    emitted = [values[index] for index in selected_indices]
    emitted_ids = [ids[index] for index in selected_indices]
    dropped_ids = [identifier for index, identifier in enumerate(ids) if index not in selected_indices]
    counts: dict[str, int] = {}
    for identifier in ids:
        counts[identifier] = counts.get(identifier, 0) + 1
    duplicate_ids = sorted(identifier for identifier, count in counts.items() if count > 1)
    required_overflow_ids = [
        identifier
        for identifier in sorted(required)
        if identifier not in ids or ids.index(identifier) not in selected_indices
    ]
    page_count = max(1, (len(values) + limit - 1) // limit) if values else 1
    return emitted, {
        "total_count": len(values),
        "emitted_count": len(emitted),
        "truncated_count": len(dropped_ids),
        "dropped_count": len(dropped_ids),
        "truncated": bool(dropped_ids),
        "page": 1,
        "page_size": limit,
        "page_count": page_count,
        "next_cursor": _encode_cursor(
            {
                "collection": prefix,
                "offset": limit,
                "page_size": limit,
                "source_digest": _source_digest(prefix, values),
            }
        )
        if len(values) > limit
        else None,
        "emitted_ids": emitted_ids,
        "dropped_ids": dropped_ids,
        "required_ids": sorted(required),
        "required_overflow_ids": required_overflow_ids,
        "duplicate_ids": duplicate_ids,
        "all_ids_digest": _canonical_digest(ids),
    }


def _list_projection_metadata(value: Mapping[str, Any], *, prefix: str) -> dict[str, Any]:
    collections: dict[str, Any] = {}
    for key, item in value.items():
        if isinstance(item, list):
            _, info = _bounded_collection(item, MAX_PUBLIC_ITEMS_PER_FIELD, prefix=f"{prefix}.{key}")
            if info["truncated"]:
                collections[str(key)] = info
    return collections


def _finding_reference_index(values: list[Any]) -> tuple[list[str], dict[str, list[str]]]:
    finding_ids: list[str] = []
    finding_to_evidence: dict[str, list[str]] = {}
    for index, item in enumerate(values):
        finding_id = _collection_id(item, index, prefix="finding")
        finding_ids.append(finding_id)
        if not isinstance(item, dict):
            continue
        refs: list[str] = []
        for key in ("evidence_ids", "evidence_refs", "source_evidence_ids", "supporting_evidence_ids"):
            refs.extend(_reference_ids(item.get(key)))
        finding_to_evidence[finding_id] = _unique_text(refs)
    return finding_ids, finding_to_evidence


def _reference_ids(value: object) -> list[str]:
    if isinstance(value, str):
        safe_id = _safe_identifier(value, "evidence_id")
        return [safe_id] if safe_id else []
    if isinstance(value, Mapping):
        for key in ("evidence_id", "id", "ref", "evidence_ref"):
            candidate = _optional_text(value.get(key))
            if candidate:
                safe_id = _safe_identifier(candidate, "evidence_id")
                return [safe_id] if safe_id else []
        return []
    if not isinstance(value, list):
        return []
    references: list[str] = []
    for item in value:
        if isinstance(item, str) and item.strip():
            safe_id = _safe_identifier(item, "evidence_id")
            if safe_id:
                references.append(safe_id)
        elif isinstance(item, dict):
            for key in ("evidence_id", "id", "ref", "evidence_ref"):
                candidate = _optional_text(item.get(key))
                if candidate:
                    safe_id = _safe_identifier(candidate, "evidence_id")
                    if safe_id:
                        references.append(safe_id)
                    break
    return references


def _reference_closure(
    *,
    finding_ids: list[str],
    evidence_ids: list[str],
    finding_to_evidence: Mapping[str, list[str]],
    evidence_to_findings: Mapping[str, list[str]],
    emitted_finding_ids: set[str],
    emitted_evidence_ids: set[str],
    required_evidence_ids: set[str] | None = None,
    required_reference_overflow: Sequence[str] = (),
    duplicate_ids: Sequence[str] = (),
    projection_truncated: bool = False,
    unverified_evidence_ids: Sequence[str] = (),
) -> dict[str, Any]:
    known_findings = set(finding_ids)
    known_evidence = set(evidence_ids)
    referenced_evidence = {ref for refs in finding_to_evidence.values() for ref in refs}
    referenced_findings = {ref for refs in evidence_to_findings.values() for ref in refs}
    emitted_required_evidence = {
        ref for finding_id in emitted_finding_ids for ref in finding_to_evidence.get(finding_id, [])
    }
    emitted_required_evidence.update(required_evidence_ids or ())
    emitted_missing_evidence = sorted(emitted_required_evidence - emitted_evidence_ids)
    unverified = set(unverified_evidence_ids)
    unverified_references = sorted(unverified & (referenced_evidence | emitted_required_evidence))
    return {
        "closed": not (
            referenced_evidence - known_evidence
            or referenced_findings - known_findings
            or emitted_missing_evidence
            or required_reference_overflow
            or duplicate_ids
            or projection_truncated
            or unverified_references
        ),
        "missing_evidence_ids": sorted(referenced_evidence - known_evidence),
        "missing_finding_ids": sorted(referenced_findings - known_findings),
        "emitted_required_evidence_ids": sorted(emitted_required_evidence),
        "emitted_missing_evidence_ids": emitted_missing_evidence,
        "dropped_finding_ids": sorted(known_findings - emitted_finding_ids),
        "dropped_evidence_ids": sorted(known_evidence - emitted_evidence_ids),
        "required_overflow_ids": sorted(set(required_reference_overflow)),
        "duplicate_ids": sorted(set(duplicate_ids)),
        "projection_truncated": bool(projection_truncated),
        "unverified_evidence_ids": sorted(unverified),
        "unverified_referenced_evidence_ids": unverified_references,
    }


def read_projection_page(
    source: Sequence[Any] | Mapping[str, Any] | ProjectionPageStore,
    *,
    collection: str = "items",
    cursor: str | None = None,
    page_size: int = MAX_PUBLIC_ITEMS_PER_FIELD,
) -> dict[str, Any]:
    """Read a stateless, integrity-checked page from a projection collection.

    The source digest is embedded in the cursor, so a caller cannot reuse a
    cursor after the underlying artifact changes.  Every page reports all IDs
    outside that page; no slice is silently discarded.
    """

    if isinstance(source, ProjectionPageStore):
        return source.read(collection, cursor=cursor, page_size=page_size)
    name = _collection_name(collection)
    values: Sequence[Any] | None = None
    if isinstance(source, Mapping):
        candidate = source.get(name)
        if not isinstance(candidate, Sequence) or isinstance(candidate, (str, bytes, bytearray)):
            candidate = source.get(collection)
        if not isinstance(candidate, Sequence) or isinstance(candidate, (str, bytes, bytearray)):
            aliases = {name[:-1]} if name.endswith("s") else {name + "s"}
            candidate = next((source.get(alias) for alias in aliases if alias in source), None)
        if isinstance(candidate, Sequence) and not isinstance(candidate, (str, bytes, bytearray)):
            values = candidate
    elif isinstance(source, Sequence) and not isinstance(source, (str, bytes, bytearray)):
        values = source
    if values is None:
        raise KeyError(name)
    if isinstance(page_size, bool) or not isinstance(page_size, int) or page_size < 1:
        raise ProjectionCursorError("page_size must be a positive integer")
    cap = (
        MAX_PUBLIC_EVIDENCE
        if name == "evidence"
        else MAX_PUBLIC_FINDINGS
        if name == "findings"
        else MAX_PUBLIC_ITEMS_PER_FIELD
    )
    page_size = min(page_size, cap)
    copied = [deepcopy(item) for item in values]
    source_digest = _source_digest(name, copied)
    offset = 0
    if cursor:
        state = _decode_cursor(cursor)
        if state.get("collection") != name or state.get("source_digest") != source_digest:
            raise ProjectionCursorError("cursor does not match the projection source")
        offset = state.get("offset", -1)
        if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0 or offset > len(copied):
            raise ProjectionCursorError("cursor offset is outside the projection")
        stored_size = state.get("page_size", page_size)
        if isinstance(stored_size, bool) or not isinstance(stored_size, int) or stored_size < 1:
            raise ProjectionCursorError("cursor page size is invalid")
        # Cursor state owns the page width.  Ignoring a later caller width
        # prevents a smaller retry from skipping rows by changing the offset
        # denominator between pages.
        page_size = min(stored_size, cap)
    page_number = offset // page_size + 1
    items = copied[offset : offset + page_size]
    next_offset = offset + len(items)
    next_cursor = (
        _encode_cursor(
            {
                "collection": name,
                "source_digest": source_digest,
                "offset": next_offset,
                "page_size": page_size,
            }
        )
        if next_offset < len(copied)
        else None
    )
    prefix = (
        "finding"
        if name in {"findings", "finding"}
        else "evidence"
        if name in {"evidence", "evidences"}
        else name.rstrip("s") or "item"
    )
    ids = [_collection_id(item, index, prefix=prefix) for index, item in enumerate(copied)]
    counts: dict[str, int] = {}
    for identifier in ids:
        counts[identifier] = counts.get(identifier, 0) + 1
    duplicate_ids = tuple(sorted(identifier for identifier, count in counts.items() if count > 1))
    emitted_ids = ids[offset:next_offset]
    dropped_ids = ids[:offset] + ids[next_offset:]
    safe_items = tuple(_hard_scrub(items, max_depth=10, max_items=page_size))
    page = ProjectionPage(
        collection=name,
        page=page_number,
        page_size=page_size,
        total_count=len(copied),
        items=safe_items,
        next_cursor=next_cursor,
        page_digest=_canonical_digest(
            {"collection": name, "page": page_number, "ids": emitted_ids, "items": safe_items}
        ),
        truncated=bool(dropped_ids),
        truncated_count=len(dropped_ids),
        dropped_ids=tuple(dropped_ids),
        duplicate_ids=duplicate_ids,
    )
    return page.to_dict()


def _collection_name(value: object) -> str:
    name = scrub_text(str(value)).strip()
    if not name or len(name) > 128 or any(char in name for char in "/\\\x00"):
        raise ProjectionCursorError("invalid projection collection")
    return name


def _source_digest(collection: str, values: Sequence[Any]) -> str:
    return _canonical_digest({"collection": collection, "values": list(values)})


def _encode_cursor(payload: Mapping[str, Any]) -> str:
    body = {"schema_version": CURSOR_SCHEMA_VERSION, **dict(payload)}
    raw = json.dumps(body, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest = hashlib.sha256(raw).hexdigest()[:32].encode("ascii")
    encoded = base64.urlsafe_b64encode(raw + b"." + digest).decode("ascii").rstrip("=")
    if len(encoded) > MAX_CURSOR_BYTES:
        raise ProjectionCursorError("projection cursor exceeds the size limit")
    return encoded


def _decode_cursor(cursor: str) -> dict[str, Any]:
    if not isinstance(cursor, str) or not cursor or len(cursor) > MAX_CURSOR_BYTES:
        raise ProjectionCursorError("invalid projection cursor")
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
        raw, separator, digest = decoded.rpartition(b".")
        if separator != b"." or hashlib.sha256(raw).hexdigest()[:32].encode("ascii") != digest:
            raise ProjectionCursorError("projection cursor integrity check failed")
        payload = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError, binascii.Error, json.JSONDecodeError) as exc:
        raise ProjectionCursorError("invalid projection cursor") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != CURSOR_SCHEMA_VERSION:
        raise ProjectionCursorError("unsupported projection cursor")
    return payload


def _first_text(*values: object) -> str | None:
    for value in values:
        text = _optional_text(value)
        if text:
            return text
    return None


def _line_range_start(value: object) -> int | None:
    if isinstance(value, (list, tuple)) and value:
        first = value[0]
        if isinstance(first, int) and not isinstance(first, bool) and first > 0:
            return first
    return None


def _first_positive_int(*values: object) -> int | None:
    for value in values:
        if isinstance(value, int) and not isinstance(value, bool) and value > 0:
            return value
    return None


def _first_nonnegative_int(*values: object) -> int | None:
    for value in values:
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            return value
    return None


def _is_sha256(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdefABCDEF" for character in value)


def _unique_text(values: list[str]) -> list[str]:
    output: list[str] = []
    for value in values:
        if value and value not in output:
            output.append(value)
    return output


def _public_input_path(value: str) -> str | None:
    normalized = value.strip().replace("\\", "/")
    parts = normalized.split("/")
    for index, part in enumerate(parts):
        if part.endswith("-evaluation-input") and index + 1 < len(parts):
            normalized = "/".join(parts[index + 1 :])
            parts = normalized.split("/")
            break
    if (
        not normalized
        or normalized.startswith("/")
        or re.match(r"^[A-Za-z]:", normalized)
        or "[REDACTED]" in normalized
        or any(not part or part in {".", ".."} for part in parts)
    ):
        return None
    return normalized


def _public_evidence_priority(item: object) -> tuple[int, str]:
    if not isinstance(item, dict):
        return (5, "")
    source = str(item.get("source", ""))
    metadata = item.get("metadata")
    locator = metadata.get("source_locator") if isinstance(metadata, dict) else None
    if item.get("finding_id"):
        rank = 0
    elif source.startswith("secmind:canonical-primary"):
        rank = 1
    elif item.get("path") or isinstance(locator, dict):
        rank = 2
    else:
        rank = 3
    return (rank, str(item.get("evidence_id", "")))


def _optional_text(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _text_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item.strip() for item in value if isinstance(item, str) and item.strip()]


# Short public spelling for API callers that expose a generic ``read`` route.
read_page = read_projection_page


__all__ = [
    "CURSOR_SCHEMA_VERSION",
    "INTEGRATION_VERSION",
    "MAX_PUBLIC_EVIDENCE",
    "MAX_PUBLIC_FINDINGS",
    "MAX_PUBLIC_ITEMS_PER_FIELD",
    "PROJECTION_SCHEMA_VERSION",
    "SCENARIO_SEMANTIC_DELTA_RECEIPT_VERSION",
    "ProjectionCursorError",
    "ProjectionPage",
    "ProjectionPageReader",
    "ProjectionPageStore",
    "build_trusted_task_payload",
    "project_domain_result",
    "read_page",
    "read_projection_page",
    "trusted_exact_answer_values",
]
