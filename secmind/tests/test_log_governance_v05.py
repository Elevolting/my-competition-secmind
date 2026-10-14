from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from secmind.log_governance import (
    LAYER_POLICIES,
    DataView,
    LogLayer,
    RetainedObject,
    RetentionDisposition,
    RetentionEvaluator,
    RetentionHold,
    RetentionPolicyError,
    RetentionProfile,
    authorize_data_view,
)
from secmind.secret_scrubber import REDACTED

NOW = datetime(2026, 7, 14, tzinfo=UTC)


def _retained(layer: LogLayer, *, age_days: int, object_id: str = "object") -> RetainedObject:
    return RetainedObject(
        object_id=object_id,
        run_id="run-1",
        layer=layer,
        view=LAYER_POLICIES[layer].view,
        created_at=NOW - timedelta(days=age_days),
        size_bytes=128,
    )


def test_default_profile_covers_all_six_layers_with_frozen_digest() -> None:
    profile = RetentionProfile()

    assert {layer.value: profile.ttl_days[layer] for layer in LogLayer} == {
        "L1": 180,
        "L2": 30,
        "L3": 30,
        "L4": 14,
        "L5": 30,
        "L6": 30,
    }
    assert len(profile.profile_digest) == 64
    with pytest.raises(TypeError):
        profile.ttl_days[LogLayer.RUNTIME] = 1  # type: ignore[index]


def test_expired_deletable_log_is_only_marked_eligible() -> None:
    decision = RetentionEvaluator(RetentionProfile()).evaluate(
        _retained(LogLayer.TOOL, age_days=15),
        now=NOW,
    )

    assert decision.disposition == RetentionDisposition.DELETE_ELIGIBLE
    assert decision.reason_codes == ("RETENTION_TTL_EXPIRED", "DELETE_REQUIRES_AUDIT_EVENT")


def test_unexpired_log_is_retained() -> None:
    decision = RetentionEvaluator(RetentionProfile()).evaluate(
        _retained(LogLayer.RUNTIME, age_days=1),
        now=NOW,
    )

    assert decision.disposition == RetentionDisposition.RETAIN
    assert decision.reason_codes == ("RETENTION_TTL_ACTIVE",)


def test_append_only_ledger_is_never_automatically_deleted_after_ttl() -> None:
    decision = RetentionEvaluator(RetentionProfile()).evaluate(
        _retained(LogLayer.DECISION_AUDIT, age_days=365),
        now=NOW,
    )

    assert decision.disposition == RetentionDisposition.PROTECTED
    assert "APPEND_ONLY_HISTORY_PROTECTED" in decision.reason_codes


def test_active_hold_extends_retention_but_cannot_bypass_quota() -> None:
    retained = _retained(LogLayer.RAW_SECURITY, age_days=60)
    hold = RetentionHold(
        hold_id="competition-review",
        run_id=retained.run_id,
        object_ids=frozenset({retained.object_id}),
        starts_at=NOW - timedelta(days=1),
        expires_at=NOW + timedelta(days=10),
        reserved_bytes=retained.size_bytes,
    )
    evaluator = RetentionEvaluator(RetentionProfile(hold_quota_bytes=128))

    decision = evaluator.evaluate(retained, holds=(hold,), now=NOW)

    assert decision.disposition == RetentionDisposition.HELD
    assert decision.active_hold_ids == (hold.hold_id,)

    oversized = RetentionHold(
        hold_id="over-quota",
        run_id=retained.run_id,
        object_ids=frozenset({retained.object_id}),
        starts_at=NOW - timedelta(seconds=1),
        expires_at=NOW + timedelta(days=1),
        reserved_bytes=129,
    )
    with pytest.raises(RetentionPolicyError, match="quota"):
        evaluator.evaluate(retained, holds=(oversized,), now=NOW)


def test_layer_view_mismatch_and_naive_times_fail_closed() -> None:
    with pytest.raises(RetentionPolicyError, match="raw_restricted"):
        RetainedObject(
            object_id="raw",
            run_id="run",
            layer=LogLayer.RAW_SECURITY,
            view=DataView.OBSERVABLE,
            created_at=NOW,
            size_bytes=1,
        )


@pytest.mark.parametrize(
    "kwargs",
    [
        {"profile_id": ""},
        {"ttl_days": {layer: 0 for layer in LogLayer}},
        {"ttl_days": {LogLayer.RUNTIME: 30}},
        {"hold_quota_bytes": 0},
    ],
)
def test_invalid_retention_profiles_fail_closed(kwargs) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(RetentionPolicyError):
        RetentionProfile(**kwargs)


@pytest.mark.parametrize(
    "changes",
    [
        {"hold_id": ""},
        {"starts_at": datetime(2026, 7, 14), "expires_at": NOW + timedelta(days=1)},
        {"expires_at": NOW - timedelta(days=2)},
        {"reserved_bytes": 0},
    ],
)
def test_invalid_retention_holds_fail_closed(changes) -> None:  # type: ignore[no-untyped-def]
    values = {
        "hold_id": "hold",
        "run_id": "run-1",
        "object_ids": frozenset({"object"}),
        "starts_at": NOW - timedelta(days=1),
        "expires_at": NOW + timedelta(days=1),
        "reserved_bytes": 1,
    }
    values.update(changes)
    with pytest.raises(RetentionPolicyError):
        RetentionHold(**values)
    with pytest.raises(RetentionPolicyError, match="timezone-aware"):
        _retained(LogLayer.RUNTIME, age_days=1).__class__(
            object_id="runtime",
            run_id="run",
            layer=LogLayer.RUNTIME,
            view=DataView.OBSERVABLE,
            created_at=datetime(2026, 7, 14),
            size_bytes=1,
        )


def test_raw_access_requires_role_and_explicit_run_binding_and_scrubs_audit() -> None:
    secret = "ghp_abcdefghijklmnopqrstuvwxyz123456"  # noqa: S105 - synthetic scrubber fixture
    denied = authorize_data_view(
        run_id="run-1",
        requested_view=DataView.RAW_RESTRICTED,
        actor_id="analyst-1",
        actor_role="analyst",
        bound_run_ids=frozenset({"run-1"}),
        details={"authorization": secret},
    )
    cross_run = authorize_data_view(
        run_id="run-2",
        requested_view=DataView.OBSERVABLE,
        actor_id="operator-1",
        actor_role="operator",
        bound_run_ids=frozenset({"run-1"}),
    )
    allowed = authorize_data_view(
        run_id="run-1",
        requested_view=DataView.RAW_RESTRICTED,
        actor_id="operator-1",
        actor_role="operator",
        bound_run_ids=frozenset({"run-1"}),
        details={"authorization": secret},
    )

    assert denied.allowed is False and denied.reason_code == "RAW_RESTRICTED_ROLE_DENIED"
    assert cross_run.allowed is False and cross_run.reason_code == "CROSS_RUN_ACCESS_DENIED"
    assert allowed.allowed is True
    assert allowed.audit_payload["details"] == {"authorization": REDACTED}
    assert secret not in repr(allowed.audit_payload)
    assert len(allowed.payload_digest) == 64


def test_access_requires_actor_and_observable_role() -> None:
    missing_actor = authorize_data_view(
        run_id="run-1",
        requested_view=DataView.PUBLIC_REPORT,
        actor_id="",
        actor_role="operator",
        bound_run_ids=frozenset({"run-1"}),
    )
    wrong_role = authorize_data_view(
        run_id="run-1",
        requested_view=DataView.OBSERVABLE,
        actor_id="guest",
        actor_role="guest",
        bound_run_ids=frozenset({"run-1"}),
    )

    assert missing_actor.reason_code == "ACTOR_ID_REQUIRED"
    assert wrong_role.reason_code == "OBSERVABLE_ROLE_DENIED"
