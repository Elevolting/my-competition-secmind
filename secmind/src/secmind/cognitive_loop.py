"""Bounded evidence-to-belief update for the v0.8.4 supervisor.

This module deliberately contains no provider calls and no control-plane side
effects.  It turns the current verified evidence graph, typed deltas and
answer obligations into a replay-stable belief revision.  The supervisor may
then schedule a bounded observation or render the active answer revision; it
never treats the immutable provider receipt as the final truth.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Any

from secmind.direct_anchor_pipeline import DeltaDisposition, TypedDelta, stable_digest
from secmind.schemas import AgentState, ClaimStatus
from secmind.task_contract import BeliefState, ObligationStatus

COGNITIVE_LOOP_VERSION = "eirs-deterministic-1.1"

# BeliefState intentionally has bounded lists.  The evidence graph itself can
# be much larger (for example a packet index can produce thousands of
# verified, independently addressable observations), so this boundary must be
# enforced before constructing the Pydantic model.  Keeping the limits here,
# next to the projection code, prevents an optional cognition pass from
# turning a valid Primary result into a worker-level ValidationError.
_BELIEF_LIST_LIMITS = {
    "known_facts": 2_000,
    "unknowns": 2_000,
    "contradictions": 2_000,
    "support_evidence_ids": 10_000,
    "refute_evidence_ids": 10_000,
    "open_obligation_ids": 1_000,
}


def _bounded_ids(
    values: Sequence[str],
    *,
    limit: int,
) -> tuple[list[str], dict[str, Any]]:
    """Return a stable bounded projection and its lossless overflow receipt.

    The full ID set remains represented by a digest in the audit projection;
    only the bounded cognitive convenience list is truncated.  Sorting and
    deduplicating before slicing makes replay independent of graph/worker
    completion order.  The receipt deliberately contains IDs only as hashes,
    so it does not duplicate potentially sensitive evidence metadata.
    """

    normalized = sorted({str(item) for item in values if str(item)})
    retained = normalized[:limit]
    dropped = normalized[limit:]
    return retained, {
        "total": len(normalized),
        "retained": len(retained),
        "dropped": len(dropped),
        "full_set_digest": stable_digest(normalized),
        "dropped_set_digest": stable_digest(dropped) if dropped else None,
        "limit": limit,
        "truncated": bool(dropped),
    }


def _record_projection_bounds(state: AgentState, bounds: dict[str, dict[str, Any]]) -> None:
    """Expose bounded-cognition accounting without enlarging BeliefState."""

    state.audit_coverage["cognitive_projection"] = {
        "schema_version": "cognitive-projection-bounds-v1",
        "overflow": any(item["truncated"] for item in bounds.values()),
        "fields": bounds,
    }


def update_belief(state: AgentState) -> BeliefState:
    """Return the next bounded, content-addressed belief revision."""

    previous = state.belief_state or BeliefState()
    verified_claims = [item.claim_id for item in state.claims if item.status == ClaimStatus.VERIFIED]
    refuted_claims = [item.claim_id for item in state.claims if item.status == ClaimStatus.REJECTED]
    verified_claim_ids = set(verified_claims)
    refuted_claim_ids = set(refuted_claims)
    support_evidence = [link.evidence_id for link in state.evidence_links if link.claim_id in verified_claim_ids]
    refute_evidence = [link.evidence_id for link in state.evidence_links if link.claim_id in refuted_claim_ids]
    open_obligations = [
        item.obligation_id
        for item in state.obligation_status
        if item.critical and item.status not in {ObligationStatus.SATISFIED, ObligationStatus.WAIVED}
    ]
    accepted_deltas = _accepted_delta_ids(state.audit_coverage.get("typed_deltas", []))
    contradictions = [*refuted_claims, *accepted_deltas]

    bounded: dict[str, list[str]] = {}
    bounds: dict[str, dict[str, Any]] = {}
    for field, values in {
        "known_facts": verified_claims,
        "unknowns": open_obligations,
        "contradictions": contradictions,
        "support_evidence_ids": support_evidence,
        "refute_evidence_ids": refute_evidence,
        "open_obligation_ids": open_obligations,
    }.items():
        bounded[field], bounds[field] = _bounded_ids(
            values,
            limit=_BELIEF_LIST_LIMITS[field],
        )
    _record_projection_bounds(state, bounds)

    bounded_known_facts = bounded["known_facts"]
    bounded_unknowns = bounded["unknowns"]
    bounded_contradictions = bounded["contradictions"]
    bounded_support_evidence = bounded["support_evidence_ids"]
    bounded_refute_evidence = bounded["refute_evidence_ids"]
    bounded_open_obligations = bounded["open_obligation_ids"]
    changed = (
        previous.known_facts != bounded_known_facts
        or previous.unknowns != bounded_unknowns
        or previous.contradictions != bounded_contradictions
        or previous.support_evidence_ids != bounded_support_evidence
        or previous.refute_evidence_ids != bounded_refute_evidence
        or previous.open_obligation_ids != bounded_open_obligations
    )
    payload = {
        "revision": min(8, previous.revision + (1 if changed else 0)),
        "base_answer_digest": previous.base_answer_digest,
        "known_facts": bounded_known_facts,
        "unknowns": bounded_unknowns,
        "contradictions": bounded_contradictions,
        "support_evidence_ids": bounded_support_evidence,
        "refute_evidence_ids": bounded_refute_evidence,
        "open_obligation_ids": bounded_open_obligations,
        "stagnation_count": min(3, 0 if changed else previous.stagnation_count + 1),
    }
    payload["belief_digest"] = stable_digest(payload)
    return BeliefState.model_validate(payload)


def _accepted_delta_ids(raw_deltas: Iterable[object]) -> list[str]:
    accepted: list[str] = []
    for raw in raw_deltas:
        try:
            delta = TypedDelta.model_validate(raw)
        except (TypeError, ValueError):
            continue
        if delta.disposition == DeltaDisposition.ACCEPTED:
            accepted.append(delta.delta_id)
    return sorted(set(accepted))


__all__ = ["COGNITIVE_LOOP_VERSION", "update_belief"]
