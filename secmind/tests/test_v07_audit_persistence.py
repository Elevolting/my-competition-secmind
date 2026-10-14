from __future__ import annotations

import hashlib

import pytest

from secmind.audit_kernel.contracts import (
    GainAction,
    PrimaryVerdict,
    ReviewVerdict,
    UnitDecision,
)
from secmind.audit_kernel.persistence import (
    AuditLane,
    AuditPersistence,
    AuditPersistenceConflict,
    ReviewShardReceipt,
    ShardStatus,
)
from secmind.investigation.store import InvestigationStore


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _unit(label: str) -> str:
    return f"unit-{_digest(label)}"


def _primary(unit_id: str, *, receipt_id: str = "receipt-primary") -> PrimaryVerdict:
    return PrimaryVerdict(
        unit_id=unit_id,
        verdict=ReviewVerdict.NOT_VULNERABLE,
        confidence=0.91,
        reason_codes=("NO_REACHABLE_SINK",),
        receipt_id=receipt_id,
        evidence_ids=("evidence-1",),
    )


def test_primary_verdict_is_lane_scoped_idempotent_and_crash_reusable() -> None:
    store = InvestigationStore("sqlite:///:memory:")
    try:
        first_adapter = AuditPersistence(store)
        unit_id = _unit("one")
        verdict = _primary(unit_id)

        first = first_adapter.commit_primary_verdict(run_id="run-a", lane=AuditLane.BASELINE, verdict=verdict)
        replay = first_adapter.commit_primary_verdict(run_id="run-a", lane=AuditLane.BASELINE, verdict=verdict)
        first_adapter.commit_primary_verdict(run_id="run-a", lane=AuditLane.SHADOW, verdict=verdict)

        assert replay == first
        assert len(first_adapter.load_primary_verdicts(run_id="run-a")) == 2

        # A new adapter models a process restart and reconstructs solely from
        # investigation_objects.
        recovered = AuditPersistence(store).load_primary_verdict(
            run_id="run-a", lane=AuditLane.BASELINE, unit_id=unit_id
        )
        assert recovered == verdict

        with pytest.raises(AuditPersistenceConflict):
            first_adapter.commit_primary_verdict(
                run_id="run-a",
                lane=AuditLane.BASELINE,
                verdict=_primary(unit_id, receipt_id="conflicting-receipt"),
            )
    finally:
        store.close()


def test_records_are_isolated_by_run_and_lane() -> None:
    store = InvestigationStore("sqlite:///:memory:")
    try:
        persistence = AuditPersistence(store)
        unit_id = _unit("shared")
        persistence.commit_primary_verdict(
            run_id="run-a",
            lane=AuditLane.BASELINE,
            verdict=_primary(unit_id, receipt_id="a"),
        )
        persistence.commit_primary_verdict(
            run_id="run-b",
            lane=AuditLane.BASELINE,
            verdict=_primary(unit_id, receipt_id="b"),
        )
        persistence.commit_primary_verdict(
            run_id="run-a",
            lane=AuditLane.FINAL,
            verdict=_primary(unit_id, receipt_id="final"),
        )

        run_a = persistence.load_primary_verdicts(run_id="run-a")
        assert [(record.lane, record.verdict.receipt_id) for record in run_a] == [
            (AuditLane.BASELINE, "a"),
            (AuditLane.FINAL, "final"),
        ]
        assert persistence.load_primary_verdicts(run_id="run-b")[0].verdict.receipt_id == "b"
    finally:
        store.close()


def test_unit_decision_commits_independently_per_legal_item() -> None:
    store = InvestigationStore("sqlite:///:memory:")
    try:
        persistence = AuditPersistence(store)
        unit_id = _unit("decision")
        decision = UnitDecision.create(
            unit_id=unit_id,
            action=GainAction.KEEP_BASELINE,
            baseline_verdict=ReviewVerdict.NOT_VULNERABLE,
            final_verdict=ReviewVerdict.NOT_VULNERABLE,
            baseline_receipt_id="receipt-primary",
            reason_codes=("BASELINE_PRESERVED",),
        )

        persistence.commit_unit_decision(run_id="run-decision", lane=AuditLane.FINAL, decision=decision)

        assert (
            AuditPersistence(store).load_unit_decision(run_id="run-decision", lane=AuditLane.FINAL, unit_id=unit_id)
            == decision
        )
    finally:
        store.close()


def test_shard_receipts_are_minimal_attempt_scoped_and_conflict_safe() -> None:
    store = InvestigationStore("sqlite:///:memory:")
    try:
        persistence = AuditPersistence(store)
        units = [_unit("one"), _unit("two")]
        common = {
            "run_id": "run-shard",
            "lane": AuditLane.BASELINE,
            "unit_ids": units,
            "input_digest": _digest("input"),
            "profile_digest": _digest("profile"),
            "prompt_digest": _digest("prompt"),
        }
        partial = ReviewShardReceipt.create(
            **common,
            status=ShardStatus.PARTIAL,
            completed_unit_ids=[units[0]],
            error_type="SourceReviewError",
        )
        persistence.commit_shard_receipt(partial)
        persistence.commit_shard_receipt(partial)

        conflicting = ReviewShardReceipt.create(
            **common,
            status=ShardStatus.FAILED,
            error_type="ModelGatewayError",
        )
        with pytest.raises(AuditPersistenceConflict):
            persistence.commit_shard_receipt(conflicting)

        succeeded = ReviewShardReceipt.create(
            **common,
            attempt=2,
            status=ShardStatus.SUCCEEDED,
            completed_unit_ids=units,
        )
        persistence.commit_shard_receipt(succeeded)

        latest = AuditPersistence(store).load_shard_receipt(
            run_id="run-shard",
            lane=AuditLane.BASELINE,
            shard_key=partial.shard_key,
        )
        assert latest == succeeded
        assert len(persistence.load_shard_receipts(run_id="run-shard")) == 2
        serialized = succeeded.model_dump_json()
        assert "source" not in serialized.casefold()
        assert "input_digest" in serialized
        assert "profile_digest" in serialized
        assert "prompt_digest" in serialized
    finally:
        store.close()
