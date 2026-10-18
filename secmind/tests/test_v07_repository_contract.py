from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect

from secmind.audit_kernel.contracts import (
    AuditUnit,
    GainAction,
    PrimaryVerdict,
    ReviewVerdict,
    UnitDecision,
)
from secmind.audit_kernel.patch_release import (
    PatchIdentity,
    PatchReleaseRecord,
    PatchReleaseStatus,
)
from secmind.audit_kernel.repository import (
    AuditRepository,
    AuditRepositoryConflict,
    AuditUnitStatus,
    DecisionLane,
    ProviderReceipt,
)
from secmind.investigation.store import InvestigationStore
from secmind.schemas import ModelUsage


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _unit(run_id: str = "run-v07") -> AuditUnit:
    return AuditUnit.create(
        run_id=run_id,
        input_manifest_digest=_digest("manifest"),
        profile_digest=_digest("profile"),
        primary_path="src/Example.java",
        source_sha256=_digest("class Example {}"),
        target_cwes=(22, 78, 79, 89),
        support_paths=("src/Support.java",),
    )


def _provider(run_id: str = "run-v07", **updates: object) -> ProviderReceipt:
    values: dict[str, object] = {
        "run_id": run_id,
        "logical_call_id": "primary-shard-1",
        "provider_request_id": "provider-request-1",
        "pair_digest": _digest("pair"),
        "unit_ids": (_unit(run_id).unit_id,),
        "model_id": "mock-5.4",
        "prompt_version": "secmind-v0.7-primary-v2",
        "request_digest": _digest("request"),
        "response_digest": _digest("response"),
        "response_schema_digest": _digest("schema"),
        "parsed_response": {"verdicts": []},
        "usage": ModelUsage(
            provider_requests=1,
            input_tokens=100,
            output_tokens=10,
            cost_units=0.001,
        ),
        "latency_ms": 10,
        "attempt_count": 1,
        "created_at": datetime(2026, 7, 19, tzinfo=UTC),
    }
    values.update(updates)
    return ProviderReceipt.create(**values)


def _baseline(unit: AuditUnit, *, verdict: ReviewVerdict = ReviewVerdict.NOT_VULNERABLE) -> PrimaryVerdict:
    positive = verdict == ReviewVerdict.VULNERABLE
    return PrimaryVerdict(
        unit_id=unit.unit_id,
        verdict=verdict,
        cwe=89 if positive else None,
        sink_line=7 if positive else None,
        source_node_id="source" if positive else None,
        sink_node_id="sink" if positive else None,
        confidence=0.9,
        reason_codes=("bounded-primary",),
        receipt_id=_provider(unit.run_id).receipt_id,
        evidence_ids=("primary-evidence",),
    )


def _keep_decision(baseline: PrimaryVerdict, *, reason: str = "baseline_locked") -> UnitDecision:
    return UnitDecision.create(
        unit_id=baseline.unit_id,
        action=GainAction.KEEP_BASELINE,
        baseline_verdict=baseline.verdict,
        final_verdict=baseline.verdict,
        baseline_cwe=baseline.cwe,
        final_cwe=baseline.cwe,
        baseline_receipt_id=baseline.receipt_id,
        evidence_ids=baseline.evidence_ids,
        reason_codes=(reason,),
    )


def _enhancement(
    baseline: PrimaryVerdict,
    *,
    reason: str = "accepted",
    patch_release_id: str | None = None,
) -> UnitDecision:
    return UnitDecision.create(
        unit_id=baseline.unit_id,
        action=GainAction.ACCEPT_ENHANCEMENT,
        baseline_verdict=ReviewVerdict.NOT_VULNERABLE,
        final_verdict=ReviewVerdict.VULNERABLE,
        final_cwe=89,
        baseline_receipt_id=baseline.receipt_id,
        accepted_flow_id="flow-" + "a" * 64,
        patch_release_id=patch_release_id,
        critic_receipt_id="critic-receipt",
        semantic_certificate_digest="b" * 64,
        policy_digest="c" * 64,
        evidence_ids=("flow-evidence", "critic-evidence"),
        reason_codes=(reason,),
    )


def _release(**identity_updates: object) -> PatchReleaseRecord:
    identity_values: dict[str, object] = {
        "target_profile_digest": _digest("profile"),
        "cwe": 89,
        "patch_kind": "java-flow-negative-to-positive",
        "tool_name": "java-flow",
        "tool_version": "2026.07.1",
        "rule_bundle_digest": _digest("rules"),
        "parser_name": "java-parser",
        "parser_digest": _digest("parser"),
        "critic_prompt_version": "v07-critic-v1",
        "critic_model_policy_digest": _digest("policy"),
    }
    identity_values.update(identity_updates)
    identity = PatchIdentity.create(**identity_values)
    return PatchReleaseRecord.create(
        identity=identity,
        status=PatchReleaseStatus.AUTHORITATIVE,
        evaluation_dataset_digest=_digest("dataset"),
        baseline_arm_digest=_digest("baseline"),
        candidate_arm_digest=_digest("candidate"),
        sample_size=120,
        precision=0.95,
        recall=0.94,
        f1_delta=0.04,
        coverage_delta=0.0,
        paired_bootstrap_ci_low=0.01,
        paired_bootstrap_ci_high=0.07,
        mcnemar_p=0.01,
        approved_by="operator",
        expires_at=datetime.now(UTC) + timedelta(days=30),
    )


def _repository() -> tuple[InvestigationStore, AuditRepository]:
    store = InvestigationStore("sqlite:///:memory:")
    return store, AuditRepository(store, initialize_schema=True)


def test_v07_migration_creates_direct_anchor_tables_and_cas_columns(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("SECMIND_DATABASE_URL", raising=False)
    database = tmp_path / "v07-migration.db"
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database.as_posix()}")

    command.upgrade(config, "head")
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    schema = inspect(engine)
    try:
        assert {
            "audit_units",
            "provider_receipts",
            "baseline_verdicts",
            "unit_decisions",
            "patch_releases",
        } <= set(schema.get_table_names())
        audit_columns = {column["name"] for column in schema.get_columns("audit_units")}
        release_columns = {column["name"] for column in schema.get_columns("patch_releases")}
        assert {"state_version", "run_fence", "payload_digest"} <= audit_columns
        assert {"state_version", "status", "revoked_at"} <= release_columns
        decision_uniques = {tuple(item["column_names"]) for item in schema.get_unique_constraints("unit_decisions")}
        assert ("run_id", "unit_id", "lane", "revision") in decision_uniques
    finally:
        engine.dispose()

    command.downgrade(config, "0011_v06_usage_execution")
    downgraded = inspect(create_engine(f"sqlite:///{database.as_posix()}"))
    assert {
        "audit_units",
        "provider_receipts",
        "baseline_verdicts",
        "unit_decisions",
        "patch_releases",
    }.isdisjoint(downgraded.get_table_names())


def test_audit_unit_registration_is_idempotent_and_status_uses_cas() -> None:
    store, repository = _repository()
    try:
        unit = _unit()
        first = repository.register_unit(unit, run_fence=4)
        replay = repository.register_unit(unit, run_fence=99)
        assert replay == first
        assert first.status == AuditUnitStatus.PENDING
        assert first.state_version == 1
        assert first.run_fence == 4

        reviewing = repository.compare_and_set_unit(
            unit.run_id,
            unit.unit_id,
            expected_version=1,
            status=AuditUnitStatus.REVIEWING,
            run_fence=5,
        )
        assert reviewing.status == AuditUnitStatus.REVIEWING
        assert reviewing.state_version == 2
        assert reviewing.run_fence == 5

        with pytest.raises(AuditRepositoryConflict, match="compare-and-swap"):
            repository.compare_and_set_unit(
                unit.run_id,
                unit.unit_id,
                expected_version=1,
                status=AuditUnitStatus.FAILED,
            )
        with pytest.raises(AuditRepositoryConflict, match="backwards"):
            repository.compare_and_set_unit(
                unit.run_id,
                unit.unit_id,
                expected_version=2,
                status=AuditUnitStatus.FINALIZED,
                run_fence=3,
            )

        conflicting = unit.model_copy(update={"primary_path": "src/Other.java"})
        with pytest.raises(AuditRepositoryConflict, match="different content"):
            repository.register_unit(conflicting)
    finally:
        store.close()


def test_provider_and_baseline_rows_are_append_only_and_idempotent() -> None:
    store, repository = _repository()
    try:
        unit = _unit()
        repository.register_unit(unit)
        receipt = _provider()
        assert repository.record_provider_receipt(receipt) == receipt
        assert repository.record_provider_receipt(receipt) == receipt
        # Receipt ids derived from deterministic response hashes are scoped by
        # run and may legitimately repeat across independent tasks.
        other_run_receipt = _provider("run-v07-other")
        assert repository.record_provider_receipt(other_run_receipt) == other_run_receipt

        conflicting_receipt = _provider(response_digest=_digest("different-response"))
        with pytest.raises(AuditRepositoryConflict, match="different content"):
            repository.record_provider_receipt(conflicting_receipt)

        baseline = _baseline(unit)
        first = repository.append_baseline(unit.run_id, baseline, provider_receipt_id=receipt.receipt_id)
        replay = repository.append_baseline(unit.run_id, baseline, provider_receipt_id=receipt.receipt_id)
        assert replay == first
        assert first.verdict == baseline

        with pytest.raises(AuditRepositoryConflict, match="immutable"):
            repository.append_baseline(
                unit.run_id,
                _baseline(unit, verdict=ReviewVerdict.VULNERABLE),
                provider_receipt_id=receipt.receipt_id,
            )
    finally:
        store.close()


def test_final_decision_requires_active_release_and_revisions_are_append_only() -> None:
    store, repository = _repository()
    try:
        unit = _unit()
        baseline = _baseline(unit)
        repository.register_unit(unit)
        repository.record_provider_receipt(_provider())
        repository.append_baseline(unit.run_id, baseline, provider_receipt_id=baseline.receipt_id)

        keep = _keep_decision(baseline)
        first = repository.append_decision(unit.run_id, keep, lane=DecisionLane.FINAL)
        assert repository.append_decision(unit.run_id, keep, lane=DecisionLane.FINAL) == first
        with pytest.raises(AuditRepositoryConflict, match="append-only"):
            repository.append_decision(
                unit.run_id,
                _keep_decision(baseline, reason="different"),
                lane=DecisionLane.FINAL,
            )

        enhancement = _enhancement(baseline)
        with pytest.raises(AuditRepositoryConflict, match="authoritative patch release"):
            repository.append_decision(
                unit.run_id,
                enhancement,
                lane=DecisionLane.FINAL,
                revision=2,
            )

        release = _release()
        published = repository.publish_release(unit.run_id, release)
        assert published.status == PatchReleaseStatus.AUTHORITATIVE
        enhancement = _enhancement(
            baseline,
            patch_release_id=release.patch_release_id,
        )
        accepted = repository.append_decision(
            unit.run_id,
            enhancement,
            lane=DecisionLane.FINAL,
            revision=2,
            release_id=release.patch_release_id,
        )
        assert accepted.release_id == release.patch_release_id

        revoked = repository.revoke_release(
            release.patch_release_id,
            expected_version=1,
            reason="negative paired window",
        )
        assert revoked.status == PatchReleaseStatus.REVOKED
        assert revoked.state_version == 2
        assert (
            repository.revoke_release(
                release.patch_release_id,
                expected_version=1,
                reason="negative paired window",
            )
            == revoked
        )
        with pytest.raises(AuditRepositoryConflict, match="different payload"):
            repository.revoke_release(
                release.patch_release_id,
                expected_version=2,
                reason="different reason",
            )
        with pytest.raises(AuditRepositoryConflict, match="not authoritative"):
            repository.append_decision(
                unit.run_id,
                _enhancement(
                    baseline,
                    reason="later",
                    patch_release_id=release.patch_release_id,
                ),
                lane=DecisionLane.FINAL,
                revision=3,
                release_id=release.patch_release_id,
            )
    finally:
        store.close()


def test_content_addressed_patch_release_identities_coexist() -> None:
    store, repository = _repository()
    try:
        release = _release()
        first = repository.publish_release("run-v07", release)
        assert repository.publish_release("run-v07", release) == first

        other_identity = _release(critic_model_policy_digest=_digest("other-policy"))
        other = repository.publish_release("run-v07", other_identity)
        assert other.release.patch_release_id != first.release.patch_release_id
    finally:
        store.close()
