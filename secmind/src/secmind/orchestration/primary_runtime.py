"""Primary-side deterministic projections kept outside the graph coordinator.

These helpers only merge immutable scenario facts and advisory context.  They
do not route nodes, invoke tools, or decide policy; the orchestrator remains
the owner of those boundaries.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from secmind.direct_anchor_pipeline import stable_digest
from secmind.orchestration.evidence_projection import deterministic_scenario_primary_skip_diagnostics
from secmind.orchestration.obligation_runtime import current_obligation_set, refresh_obligation_set
from secmind.schemas import AgentState, ClaimStatus, DecisionRecord, EvidenceRelation


async def checkpoint_deterministic_primary_skip(host: Any, state: AgentState) -> Any | None:
    """Persist a fail-closed provider skip after deterministic completion."""

    diagnostics = deterministic_scenario_primary_skip_diagnostics(state)
    state.audit_coverage["deterministic_primary_skip_diagnostics"] = diagnostics
    if state.report is not None:
        state.report = state.report.model_copy(update={"coverage": dict(state.audit_coverage)})
    if not diagnostics["eligible"]:
        return None
    delta = state.audit_coverage["scenario_semantic_delta"]
    delta_receipt = state.audit_coverage["scenario_semantic_delta_receipt"]
    authority = current_obligation_set(state)
    if not isinstance(delta, Mapping) or not isinstance(delta_receipt, Mapping) or authority is None:
        raise RuntimeError("eligible deterministic Primary skip lost its sealed prerequisites")
    evidence_ids = sorted(str(item) for item in delta.get("evidence_ids", []))
    partial_exact = state.status.value == "partial" and delta.get("answer_kind") == "exact"
    reason = (
        "deterministic exact answer satisfied its contract obligations and verified evidence closure; "
        "unrelated parser coverage remains partial"
        if partial_exact
        else "deterministic typed answer satisfied critical obligations and verified evidence closure"
    )
    event_payload = {
        "semantic_delta_receipt_digest": delta_receipt.get("receipt_digest"),
        "obligation_set_digest": authority.set_digest,
        "verified_evidence_ids": evidence_ids,
        "preserved_run_status": state.status.value,
        "skip_scope": "exact_contract" if partial_exact else "complete_scenario",
        "reason": reason,
    }
    state.audit_coverage.update(
        {
            "canonical_primary_attempted": False,
            "canonical_primary_provider_requests": 0,
            "canonical_primary_status": "skipped_deterministic_scenario",
            "canonical_primary_skip_reason": reason,
        }
    )
    state.decisions.append(
        DecisionRecord(
            decision="canonical_primary_skipped_after_verified_scenario_completion",
            rationale_summary=reason,
            evidence_ids=evidence_ids,
            policy_ids=[
                "DETERMINISTIC-SCENARIO-PRIMARY-SKIP-V1",
                "EXACT-CONTRACT-PRIMARY-SKIP-V1" if partial_exact else "SCENARIO-COMPLETE-PRIMARY-SKIP-V1",
                "EVIDENCE-REQUIRED-V1",
            ],
            model_id="deterministic-scenario-completion-gate",
            prompt_version="none",
            confidence=1.0,
        )
    )
    if state.report is not None:
        state.report = state.report.model_copy(
            update={"decisions": list(state.decisions), "coverage": dict(state.audit_coverage)}
        )
    return await host._checkpoint(state, "canonical_primary.skipped_deterministic_scenario", event_payload)


def record_pre_primary_scenario_result(state: AgentState) -> dict[str, Any] | None:
    """Publish one typed scenario read model and evaluate its obligations."""

    report = state.report
    if report is None:
        return None
    coverage = dict(report.coverage)
    state.audit_coverage.update(coverage)
    semantic_delta = state.audit_coverage.get("scenario_semantic_delta")
    scenario = semantic_delta.get("scenario") if isinstance(semantic_delta, Mapping) else None
    projection = {
        "scenario": scenario or state.scenario.value,
        "status": state.status.value,
        "answer_type": report.answer_type,
        "answer_payload": report.answer_payload,
        "executive_summary": report.executive_summary,
        "finding_ids": [item.finding_id for item in report.findings],
        "evidence_ids": [item.evidence_id for item in report.evidence],
        "limitations": list(report.limitations),
        "coverage": coverage,
    }
    state.audit_coverage["pre_primary_scenario_projection"] = projection
    state.audit_coverage["pre_primary_scenario_executed"] = True
    verified_claims = {item.claim_id for item in state.claims if item.status == ClaimStatus.VERIFIED}
    verified_evidence = sorted(
        item.evidence_id
        for item in state.evidence_links
        if item.claim_id in verified_claims
        and item.relation == EvidenceRelation.SUPPORTS
        and item.verifier_status == ClaimStatus.VERIFIED
    )
    refresh_obligation_set(state, report.answer_payload, evidence_ids=verified_evidence)
    state.report = report.model_copy(update={"coverage": dict(state.audit_coverage)})
    return projection


def fuse_pre_primary_scenario_answer(state: AgentState, typed_answer: Any) -> Any:
    """Fuse verified deterministic domain fields without replacing model semantics."""

    projection = state.audit_coverage.get("pre_primary_scenario_projection")
    scenario_payload = projection.get("answer_payload") if isinstance(projection, dict) else None
    if not isinstance(scenario_payload, dict):
        return typed_answer
    model_payload = typed_answer.model_dump(mode="json")
    if scenario_payload.get("answer_kind") != model_payload.get("answer_kind"):
        return typed_answer

    def merged_rows(name: str, maximum: int, *, deterministic_only: bool = False) -> list[Any]:
        deterministic = scenario_payload.get(name)
        model_values = model_payload.get(name)
        left = list(deterministic) if isinstance(deterministic, list) else []
        right = [] if deterministic_only else (list(model_values) if isinstance(model_values, list) else [])
        output: list[Any] = []
        seen: set[str] = set()
        for item in [*left, *right]:
            digest = stable_digest(item)
            if digest in seen:
                continue
            seen.add(digest)
            output.append(item)
            if len(output) >= maximum:
                break
        return output

    def merge_extensions() -> None:
        """Carry parser receipts into the public typed answer.

        The pre-Primary scenario report is intentionally stored as an
        immutable projection in ``audit_coverage``.  Previously the
        fusion routine copied only a few top-level list fields, which
        meant that the semantic graph, parser lineage and IR policy rows
        disappeared when the Primary answer was revalidated.  That made
        the parser useful for prompting, but invisible in the active
        answer.  Deterministic scenario extensions are source-bound and
        therefore win on collisions; provider-only annotations remain
        auditable alongside them.
        """

        scenario_extensions = scenario_payload.get("extensions")
        model_extensions = model_payload.get("extensions")
        if not isinstance(scenario_extensions, dict):
            scenario_extensions = {}
        if not isinstance(model_extensions, dict):
            model_extensions = {}
        merged = dict(model_extensions)
        # These fields describe parser output, CAS lineage, and the
        # safety decision.  They must not be replaced by provider text.
        deterministic_keys = {
            "coverage",
            "endpoint_graph",
            "policy_actions",
            "policy_decisions",
            "alternatives",
            "hypotheses",
            "timeline_artifact_ids",
            "raw_artifact_digests",
            "derived_artifact_digests",
            "source_format",
            "mode",
            "executed_action_count",
            "process_provenance",
        }
        for key, value in scenario_extensions.items():
            if key in deterministic_keys or key not in merged:
                merged[key] = value
                continue
            current = merged[key]
            if isinstance(value, list) and isinstance(current, list):
                merged[key] = merged_rows_from_values(value, current, 2_000)
            elif isinstance(value, dict) and isinstance(current, dict):
                merged[key] = {**current, **value}
        model_payload["extensions"] = merged

    def merged_rows_from_values(left: list[Any], right: list[Any], maximum: int) -> list[Any]:
        """Stable, digest-based union used for extension arrays."""

        output: list[Any] = []
        seen: set[str] = set()
        for item in [*left, *right]:
            digest = stable_digest(item)
            if digest in seen:
                continue
            seen.add(digest)
            output.append(item)
            if len(output) >= maximum:
                break
        return output

    kind = str(model_payload.get("answer_kind") or "")
    if kind == "timeline":
        # Deterministic events carry source locators/evidence IDs; provider
        # events remain in the immutable receipt but cannot replace those
        # evidence-bound rows in the public timeline.
        model_payload.update(
            {
                "events": merged_rows("events", 1_000, deterministic_only=True),
                "facts": merged_rows("facts", 500),
                "inferences": merged_rows("inferences", 500),
                "actors": merged_rows("actors", 200),
                "iocs": merged_rows("iocs", 500),
                "techniques": merged_rows("techniques", 200),
                "tactics": merged_rows("tactics", 50, deterministic_only=True),
                "gaps": merged_rows("gaps", 200),
            }
        )
        # ``TimelineAnswer`` hydrates its incident-response graph from
        # these extensions.  Preserve the deterministic dry-run action,
        # hypothesis and rollback rows even when the model emits none.
        merge_extensions()
    elif kind == "exact":
        deterministic_values = scenario_payload.get("values")
        if deterministic_values not in (None, [], {}, ""):
            model_payload["values"] = deterministic_values
        model_payload["items"] = merged_rows("items", 1_000)
        model_payload["source_offsets"] = merged_rows("source_offsets", 1_000)
        derivation = scenario_payload.get("derivation")
        if isinstance(derivation, list):
            model_payload["derivation"] = merged_rows("derivation", 1_000)
        model_mapping = model_payload.get("mapping")
        scenario_mapping = scenario_payload.get("mapping")
        if isinstance(model_mapping, dict) and isinstance(scenario_mapping, dict):
            model_payload["mapping"] = {**model_mapping, **scenario_mapping}
        model_validation = model_payload.get("validation")
        scenario_validation = scenario_payload.get("validation")
        if isinstance(model_validation, dict) and isinstance(scenario_validation, dict):
            model_payload["validation"] = {**model_validation, **scenario_validation}
        merge_extensions()
    elif kind == "evidence_gap":
        # Incident-response gap tasks use the same evidence-bound action
        # compiler as forensic tasks but publish the stricter gap schema.
        # Without this branch, a valid parser result remained trapped in
        # the pre-Primary receipt and the active answer contained only
        # the provider's generic unknowns.
        model_payload.update(
            {
                "observations": merged_rows("observations", 500),
                "known": merged_rows("known", 500),
                "unknown_fields": merged_rows("unknown_fields", 500),
                "conflicts": merged_rows("conflicts", 200),
                "blocked_claims": merged_rows("blocked_claims", 200),
                "next_evidence": merged_rows("next_evidence", 200),
            }
        )
        merge_extensions()
    elif kind == "reverse_behavior":
        model_payload.update(
            {
                "behaviors": merged_rows("behaviors", 500),
                "persistence": merged_rows("persistence", 200),
                "injection": merged_rows("injection", 200),
                "evasion": merged_rows("evasion", 200),
                "mitre_attack": merged_rows("mitre_attack", 200),
                "unknowns": merged_rows("unknowns", 500),
            }
        )
        if model_payload.get("c2") in (None, "", []):
            model_payload["c2"] = scenario_payload.get("c2")
        if model_payload.get("protocol") in (None, ""):
            model_payload["protocol"] = scenario_payload.get("protocol")
        merge_extensions()
    else:
        return typed_answer

    # SemanticOutput/TypedSemanticDelta carry the public process
    # provenance, EvidenceClosure and graph projections.  They are part
    # of the already validated DomainAnswer contract, not a second
    # authority.  Copying the deterministic values here is what makes
    # parser facts and their source locators survive publication and
    # EIRS/replay projection.
    for field_name in ("semantic_output", "semantic_delta", "timeline_graph", "api_graph", "incident_response"):
        value = scenario_payload.get(field_name)
        if value is not None:
            model_payload[field_name] = value

    # A parser is a core source boundary for these domains.  If it could
    # not establish complete coverage, a provider cannot erase that fact
    # by returning ``completed`` from its generic envelope.  Keep the
    # answer executable (the report may still contain useful Primary
    # analysis), but expose the epistemic result as partial/insufficient.
    parser_execution = str(scenario_payload.get("execution_status") or "").casefold()
    if parser_execution in {"partial", "unknown"}:
        model_payload["execution_status"] = "partial"
        if model_payload.get("epistemic_status") == "conclusive":
            model_payload["epistemic_status"] = "insufficient_evidence"
    scenario_limitations = scenario_payload.get("limitations")
    model_limitations = model_payload.get("limitations")
    if isinstance(scenario_limitations, list):
        existing_limitations = model_limitations if isinstance(model_limitations, list) else []
        model_payload["limitations"] = list(
            dict.fromkeys([str(item) for item in [*existing_limitations, *scenario_limitations] if str(item)])
        )[:100]

    state.audit_coverage["domain_answer_fusion"] = {
        "scenario": projection.get("scenario") if isinstance(projection, dict) else None,
        "answer_kind": kind,
        "deterministic_fields_preserved": True,
        "model_summary_preserved": True,
    }
    return type(typed_answer).model_validate(model_payload)


def primary_advisory_context(host: Any, state: AgentState) -> list[dict[str, Any]]:
    """Materialize a small, provenance-bearing pre-Primary method pack."""

    total_budget = host.settings.primary_advisory_context_bytes
    remaining = total_budget
    selected: list[dict[str, Any]] = []
    scenario_projection = state.audit_coverage.get("pre_primary_scenario_projection")
    if isinstance(scenario_projection, Mapping):
        raw_delta = state.audit_coverage.get("scenario_semantic_delta")
        delta = raw_delta if isinstance(raw_delta, Mapping) else {}
        answer_kind = str(delta.get("answer_kind") or scenario_projection.get("answer_type") or "")
        scenario_answer = scenario_projection.get("answer_payload")
        scenario_answer = scenario_answer if isinstance(scenario_answer, Mapping) else {}
        if answer_kind == "reverse_behavior" and not any(
            isinstance(scenario_answer.get(field), list) and scenario_answer.get(field)
            for field in ("behaviors", "injection", "evasion", "mitre_attack")
        ):
            # A bounded signature set cannot establish that an unmatched
            # sample has no behavior.  Do not prime the semantic reviewer
            # with a negative result merely because no known complete chain
            # matched; the immutable receipt remains available after Primary.
            state.audit_coverage["primary_advisory_context"] = {
                "count": 0,
                "context_ids": [],
                "bytes": 0,
                "authorization_effect": "none",
                "scope": "reverse_no_positive_signal",
            }
            return []
        closure = delta.get("evidence_closure")
        closure = closure if isinstance(closure, Mapping) else {}
        authority = current_obligation_set(state)
        unresolved = [
            item.obligation_id
            for item in (authority.obligations if authority is not None else ())
            if item.critical and item.status.value not in {"satisfied", "waived"}
        ][:100]
        capsule = {
            "scenario": scenario_projection.get("scenario"),
            "answer_kind": answer_kind,
            "closure_missing": list(closure.get("missing") or [])[:100],
            "unknowns": list(delta.get("unknowns") or [])[:100],
            "unresolved_obligation_ids": unresolved,
            "limitations": list(scenario_projection.get("limitations") or [])[:100],
            "instruction": "Resolve only listed gaps; preserve deterministic evidence-bound fields.",
        }
        full_capsule = json.dumps(capsule, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        encoded_capsule = full_capsule[:remaining]
        if encoded_capsule:
            digest = stable_digest(capsule)
            selected.append(
                {
                    "context_id": digest,
                    "kind": "unresolved_scenario_gap",
                    "source": "secmind.deterministic-scenario-completion-gate",
                    "authority_level": "verified_runtime_receipt",
                    "taint": "untrusted",
                    "content_sha256": digest,
                    "content": encoded_capsule.decode("utf-8", errors="ignore"),
                    "truncated": len(encoded_capsule) < len(full_capsule),
                    "may_guide_analysis_only": True,
                }
            )
        state.audit_coverage["primary_advisory_context"] = {
            "count": len(selected),
            "context_ids": [item["context_id"] for item in selected],
            "bytes": len(encoded_capsule),
            "authorization_effect": "none",
            "scope": "unresolved_scenario_gap_only",
        }
        return selected
    if state.evidence_compiler_receipt is not None:
        payload = json.dumps(
            state.evidence_compiler_receipt.model_dump(mode="json"),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")[:remaining]
        if payload:
            selected.append(
                {
                    "context_id": state.evidence_compiler_receipt.output_digest,
                    "kind": "compiled_evidence",
                    "source": state.evidence_compiler_receipt.compiler_id,
                    "authority_level": "repository_content",
                    "taint": "untrusted",
                    "content_sha256": state.evidence_compiler_receipt.output_digest,
                    "content": payload.decode("utf-8", errors="ignore"),
                    "truncated": len(payload)
                    < len(
                        json.dumps(
                            state.evidence_compiler_receipt.model_dump(mode="json"),
                            ensure_ascii=False,
                            sort_keys=True,
                            separators=(",", ":"),
                        ).encode("utf-8")
                    ),
                    "may_guide_analysis_only": True,
                }
            )
            remaining -= len(payload)
    references = sorted(
        (item for item in state.context_items if item.kind in {"audit_skill", "knowledge"}),
        key=lambda item: (0 if item.kind == "audit_skill" else 1, item.source, item.context_id),
    )
    for reference in references[:12]:
        if remaining <= 0:
            break
        try:
            content = host.context_item_store.read_text(reference, run_id=state.run_id)
        except (OSError, ValueError):
            continue
        encoded = content.encode("utf-8")[:remaining]
        bounded = encoded.decode("utf-8", errors="ignore")
        if not bounded:
            continue
        selected.append(
            {
                "context_id": reference.context_id,
                "kind": reference.kind,
                "source": reference.source,
                "authority_level": reference.authority_level.value,
                "taint": reference.taint.value,
                "content_sha256": reference.content_hash,
                "content": bounded,
                "truncated": len(encoded) < len(content.encode("utf-8")),
                "may_guide_analysis_only": True,
            }
        )
        remaining -= len(encoded)
    state.audit_coverage["primary_advisory_context"] = {
        "count": len(selected),
        "context_ids": [item["context_id"] for item in selected],
        "bytes": total_budget - remaining,
        "authorization_effect": "none",
    }
    return selected


def account_failed_primary_attempts(host: Any, state: AgentState) -> int:
    attempts = host.gateway.provider_attempts_for(state.run_id)
    state.budget.usage.provider_requests += len(attempts)
    state.budget.usage.input_tokens += sum(item.usage.input_tokens for item in attempts)
    state.budget.usage.output_tokens += sum(item.usage.output_tokens for item in attempts)
    state.budget.usage.cache_hit_input_tokens += sum(item.usage.cache_hit_input_tokens for item in attempts)
    state.budget.usage.cache_miss_input_tokens += sum(item.usage.cache_miss_input_tokens for item in attempts)
    state.budget.usage.cost_units += sum(item.usage.cost_units for item in attempts)
    return len(attempts)


__all__ = [
    "account_failed_primary_attempts",
    "checkpoint_deterministic_primary_skip",
    "fuse_pre_primary_scenario_answer",
    "primary_advisory_context",
    "record_pre_primary_scenario_result",
]
