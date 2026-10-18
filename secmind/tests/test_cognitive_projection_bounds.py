from __future__ import annotations

from secmind.cognitive_loop import update_belief
from secmind.schemas import AgentState, Claim, ClaimStatus, TaskRequest


def test_belief_projection_bounds_large_verified_claim_set_without_recovery_error() -> None:
    state = AgentState(run_id="run-cognitive-overflow", task=TaskRequest(objective="bound claims"))
    state.claims = [
        Claim(
            claim_id=f"claim-{index:04d}",
            claim_type="scenario.observation",
            statement="verified observation",
            subject_ref=f"subject-{index:04d}",
            status=ClaimStatus.VERIFIED,
            producer="deterministic-scenario-analyzer",
        )
        for index in range(2_001)
    ]

    belief = update_belief(state)

    assert len(belief.known_facts) == 2_000
    receipt = state.audit_coverage["cognitive_projection"]
    assert receipt["schema_version"] == "cognitive-projection-bounds-v1"
    assert receipt["overflow"] is True
    assert receipt["fields"]["known_facts"]["total"] == 2_001
    assert receipt["fields"]["known_facts"]["retained"] == 2_000
    assert receipt["fields"]["known_facts"]["dropped"] == 1
    assert receipt["fields"]["known_facts"]["dropped_set_digest"]

    replay = update_belief(state)
    assert replay == belief
    assert replay.belief_digest == belief.belief_digest
