from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from types import MappingProxyType
from typing import Any

from secmind.ledger import canonical_json
from secmind.schemas import DataView, LogLayer
from secmind.secret_scrubber import scrub_value


class RetentionPolicyError(ValueError):
    """Retention input is ambiguous or would weaken a governance boundary."""


class RetentionDisposition(StrEnum):
    RETAIN = "retain"
    HELD = "held"
    DELETE_ELIGIBLE = "delete_eligible"
    PROTECTED = "protected"


@dataclass(frozen=True)
class LogLayerPolicy:
    layer: LogLayer
    storage: str
    default_ttl_days: int
    view: DataView
    automatically_deletable: bool


LAYER_POLICIES: Mapping[LogLayer, LogLayerPolicy] = MappingProxyType(
    {
        LogLayer.DECISION_AUDIT: LogLayerPolicy(
            LogLayer.DECISION_AUDIT,
            "postgresql_append_only_ledger",
            180,
            DataView.OBSERVABLE,
            False,
        ),
        LogLayer.RUNTIME: LogLayerPolicy(
            LogLayer.RUNTIME,
            "structured_log_store",
            30,
            DataView.OBSERVABLE,
            True,
        ),
        LogLayer.MODEL: LogLayerPolicy(
            LogLayer.MODEL,
            "postgresql",
            30,
            DataView.OBSERVABLE,
            True,
        ),
        LogLayer.TOOL: LogLayerPolicy(
            LogLayer.TOOL,
            "artifact_store_and_metadata",
            14,
            DataView.OBSERVABLE,
            True,
        ),
        LogLayer.RAW_SECURITY: LogLayerPolicy(
            LogLayer.RAW_SECURITY,
            "restricted_artifact_store",
            30,
            DataView.RAW_RESTRICTED,
            True,
        ),
        LogLayer.NORMALIZED_SECURITY: LogLayerPolicy(
            LogLayer.NORMALIZED_SECURITY,
            "postgresql_partition_or_artifact",
            30,
            DataView.OBSERVABLE,
            True,
        ),
    }
)


@dataclass(frozen=True)
class RetentionProfile:
    """Immutable internal retention policy used before public Schema integration.

    A TTL makes an object eligible for a governed cleanup; it never performs the
    deletion itself. L1 remains protected because append-only ledger history may
    not be silently mutated after its review horizon.
    """

    profile_id: str = "competition-default-v1"
    ttl_days: Mapping[LogLayer, int] = field(
        default_factory=lambda: {layer: policy.default_ttl_days for layer, policy in LAYER_POLICIES.items()}
    )
    hold_quota_bytes: int = 512 * 1024 * 1024

    def __post_init__(self) -> None:
        if not self.profile_id.strip():
            raise RetentionPolicyError("retention profile id is required")
        normalized: dict[LogLayer, int] = {}
        for layer in LogLayer:
            value = self.ttl_days.get(layer)
            if not isinstance(value, int) or isinstance(value, bool) or value < 1 or value > 3_650:
                raise RetentionPolicyError(f"invalid TTL for {layer.value}")
            normalized[layer] = value
        if set(self.ttl_days) != set(LogLayer):
            raise RetentionPolicyError("retention profile must define exactly L1-L6")
        if self.hold_quota_bytes < 1:
            raise RetentionPolicyError("hold quota must be positive")
        object.__setattr__(self, "ttl_days", MappingProxyType(normalized))

    @property
    def profile_digest(self) -> str:
        material = {
            "hold_quota_bytes": self.hold_quota_bytes,
            "profile_id": self.profile_id,
            "ttl_days": {layer.value: self.ttl_days[layer] for layer in LogLayer},
        }
        return hashlib.sha256(canonical_json(material).encode()).hexdigest()


@dataclass(frozen=True)
class RetainedObject:
    object_id: str
    run_id: str
    layer: LogLayer
    view: DataView
    created_at: datetime
    size_bytes: int

    def __post_init__(self) -> None:
        if not self.object_id or not self.run_id:
            raise RetentionPolicyError("retained object identity is required")
        if self.created_at.tzinfo is None:
            raise RetentionPolicyError("retained object time must be timezone-aware")
        if self.size_bytes < 0:
            raise RetentionPolicyError("retained object size cannot be negative")
        expected_view = LAYER_POLICIES[self.layer].view
        if self.view != expected_view:
            raise RetentionPolicyError(f"{self.layer.value} must use the {expected_view.value} view")


@dataclass(frozen=True)
class RetentionHold:
    hold_id: str
    run_id: str
    object_ids: frozenset[str]
    starts_at: datetime
    expires_at: datetime
    reserved_bytes: int

    def __post_init__(self) -> None:
        if not self.hold_id or not self.run_id or not self.object_ids:
            raise RetentionPolicyError("hold identity, run and object bindings are required")
        if self.starts_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise RetentionPolicyError("hold times must be timezone-aware")
        if self.expires_at <= self.starts_at:
            raise RetentionPolicyError("hold expiry must be after its start")
        if self.reserved_bytes < 1:
            raise RetentionPolicyError("hold quota reservation must be positive")


@dataclass(frozen=True)
class RetentionDecision:
    object_id: str
    disposition: RetentionDisposition
    expires_at: datetime
    reason_codes: tuple[str, ...]
    active_hold_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class DataAccessDecision:
    allowed: bool
    reason_code: str
    audit_payload: Mapping[str, Any]
    payload_digest: str


class RetentionEvaluator:
    def __init__(self, profile: RetentionProfile) -> None:
        self.profile = profile

    def evaluate(
        self,
        retained: RetainedObject,
        *,
        holds: tuple[RetentionHold, ...] = (),
        now: datetime | None = None,
    ) -> RetentionDecision:
        checked_at = now or datetime.now(UTC)
        if checked_at.tzinfo is None:
            raise RetentionPolicyError("retention evaluation time must be timezone-aware")
        active_holds = tuple(
            sorted(
                (
                    hold
                    for hold in holds
                    if hold.run_id == retained.run_id
                    and retained.object_id in hold.object_ids
                    and hold.starts_at <= checked_at < hold.expires_at
                ),
                key=lambda item: item.hold_id,
            )
        )
        all_active = tuple(hold for hold in holds if hold.starts_at <= checked_at < hold.expires_at)
        if sum(hold.reserved_bytes for hold in all_active) > self.profile.hold_quota_bytes:
            raise RetentionPolicyError("active retention holds exceed the configured quota")
        expires_at = retained.created_at + timedelta(days=self.profile.ttl_days[retained.layer])
        if active_holds:
            return RetentionDecision(
                object_id=retained.object_id,
                disposition=RetentionDisposition.HELD,
                expires_at=max(expires_at, *(hold.expires_at for hold in active_holds)),
                reason_codes=("RETENTION_HOLD_ACTIVE",),
                active_hold_ids=tuple(hold.hold_id for hold in active_holds),
            )
        if checked_at < expires_at:
            return RetentionDecision(
                retained.object_id,
                RetentionDisposition.RETAIN,
                expires_at,
                ("RETENTION_TTL_ACTIVE",),
            )
        if not LAYER_POLICIES[retained.layer].automatically_deletable:
            return RetentionDecision(
                retained.object_id,
                RetentionDisposition.PROTECTED,
                expires_at,
                ("APPEND_ONLY_HISTORY_PROTECTED", "RETENTION_REVIEW_DUE"),
            )
        return RetentionDecision(
            retained.object_id,
            RetentionDisposition.DELETE_ELIGIBLE,
            expires_at,
            ("RETENTION_TTL_EXPIRED", "DELETE_REQUIRES_AUDIT_EVENT"),
        )


def authorize_data_view(
    *,
    run_id: str,
    requested_view: DataView,
    actor_id: str,
    actor_role: str,
    bound_run_ids: frozenset[str],
    details: Mapping[str, Any] | None = None,
) -> DataAccessDecision:
    """Return a scrubbed, deterministic access decision for later audit commit."""

    normalized_role = actor_role.strip().lower()
    if not actor_id.strip():
        allowed, reason = False, "ACTOR_ID_REQUIRED"
    elif run_id not in bound_run_ids:
        allowed, reason = False, "CROSS_RUN_ACCESS_DENIED"
    elif requested_view == DataView.RAW_RESTRICTED and normalized_role not in {"operator", "auditor"}:
        allowed, reason = False, "RAW_RESTRICTED_ROLE_DENIED"
    elif requested_view == DataView.OBSERVABLE and normalized_role not in {
        "operator",
        "auditor",
        "analyst",
        "verifier",
        "system",
    }:
        allowed, reason = False, "OBSERVABLE_ROLE_DENIED"
    else:
        allowed, reason = True, "ACCESS_ALLOWED"
    safe_details = scrub_value(dict(details or {}))
    payload = {
        "actor_id": actor_id,
        "actor_role": normalized_role,
        "allowed": allowed,
        "details": safe_details if isinstance(safe_details, dict) else {},
        "reason_code": reason,
        "requested_view": requested_view.value,
        "run_id": run_id,
    }
    digest = hashlib.sha256(canonical_json(payload).encode()).hexdigest()
    return DataAccessDecision(allowed, reason, MappingProxyType(payload), digest)


__all__ = [
    "DataAccessDecision",
    "DataView",
    "LAYER_POLICIES",
    "LogLayer",
    "LogLayerPolicy",
    "RetainedObject",
    "RetentionDecision",
    "RetentionDisposition",
    "RetentionEvaluator",
    "RetentionHold",
    "RetentionPolicyError",
    "RetentionProfile",
    "authorize_data_view",
]
