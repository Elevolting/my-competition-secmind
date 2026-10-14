from __future__ import annotations

import hashlib
import re
from collections.abc import Callable
from enum import StrEnum
from typing import Any, Self

from pydantic import Field, field_validator, model_validator

from secmind.audit_kernel.contracts import (
    SHA256_PATTERN,
    AuditContract,
    AuditUnit,
    PrimaryVerdict,
    UnitDecision,
    content_digest,
)
from secmind.audit_kernel.patch_release import PatchReleaseRecord
from secmind.audit_kernel.receipts import ProviderReceipt
from secmind.audit_kernel.repository import (
    AuditRepository,
    AuditUnitStatus,
    DecisionLane,
)
from secmind.investigation.contracts import RunAuthority
from secmind.investigation.store import InvestigationConflict, InvestigationStore

_PRIMARY_OBJECT_TYPE = "v07.audit.primary_verdict"
_DECISION_OBJECT_TYPE = "v07.audit.unit_decision"
_SHARD_OBJECT_TYPE = "v07.audit.shard_receipt"
_PROVIDER_RECEIPT_OBJECT_TYPE = "v07.audit.provider_receipt"
_UNIT_ID_PATTERN = r"^unit-[a-f0-9]{64}$"
_SHARD_KEY_PATTERN = r"^shard-[a-f0-9]{64}$"


class AuditPersistenceConflict(RuntimeError):
    """A stable audit identity was reused with different immutable content."""


class AuditLane(StrEnum):
    BASELINE = "baseline"
    FINAL = "final"
    SHADOW = "shadow"


class ShardStatus(StrEnum):
    SUCCEEDED = "succeeded"
    PARTIAL = "partial"
    FAILED = "failed"


class PersistReceipt(AuditContract):
    object_id: str = Field(min_length=1, max_length=200)
    run_id: str = Field(min_length=1, max_length=128)
    lane: AuditLane
    object_type: str = Field(min_length=1, max_length=100)
    logical_key: str = Field(min_length=1, max_length=200)
    version: int = Field(ge=1)
    content_digest: str = Field(pattern=SHA256_PATTERN)


class LanePrimaryVerdict(AuditContract):
    run_id: str = Field(min_length=1, max_length=128)
    lane: AuditLane
    verdict: PrimaryVerdict
    record_digest: str = Field(pattern=SHA256_PATTERN)

    @property
    def unit_id(self) -> str:
        return self.verdict.unit_id

    @model_validator(mode="after")
    def validate_digest(self) -> Self:
        expected = content_digest(self.model_dump(mode="json", exclude={"record_digest"}))
        if self.record_digest != expected:
            raise ValueError("primary verdict record digest is invalid")
        return self

    @classmethod
    def create(cls, *, run_id: str, lane: AuditLane, verdict: PrimaryVerdict) -> Self:
        payload = {
            "run_id": run_id,
            "lane": lane.value,
            "verdict": verdict.model_dump(mode="json"),
        }
        return cls.model_validate({**payload, "record_digest": content_digest(payload)})


class LaneUnitDecision(AuditContract):
    run_id: str = Field(min_length=1, max_length=128)
    lane: AuditLane
    decision: UnitDecision
    record_digest: str = Field(pattern=SHA256_PATTERN)

    @property
    def unit_id(self) -> str:
        return self.decision.unit_id

    @model_validator(mode="after")
    def validate_digest(self) -> Self:
        if not self.decision.digest_valid():
            raise ValueError("unit decision digest is invalid")
        expected = content_digest(self.model_dump(mode="json", exclude={"record_digest"}))
        if self.record_digest != expected:
            raise ValueError("unit decision record digest is invalid")
        return self

    @classmethod
    def create(cls, *, run_id: str, lane: AuditLane, decision: UnitDecision) -> Self:
        if not decision.digest_valid():
            raise ValueError("unit decision digest is invalid")
        payload = {
            "run_id": run_id,
            "lane": lane.value,
            "decision": decision.model_dump(mode="json"),
        }
        return cls.model_validate({**payload, "record_digest": content_digest(payload)})


class ReviewShardReceipt(AuditContract):
    run_id: str = Field(min_length=1, max_length=128)
    lane: AuditLane
    shard_key: str = Field(pattern=_SHARD_KEY_PATTERN)
    attempt: int = Field(default=1, ge=1)
    unit_ids: tuple[str, ...] = Field(min_length=1)
    completed_unit_ids: tuple[str, ...] = ()
    input_digest: str = Field(pattern=SHA256_PATTERN)
    profile_digest: str = Field(pattern=SHA256_PATTERN)
    prompt_digest: str = Field(pattern=SHA256_PATTERN)
    response_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    status: ShardStatus
    error_type: str | None = Field(default=None, max_length=128)
    receipt_digest: str = Field(pattern=SHA256_PATTERN)

    @field_validator("unit_ids", "completed_unit_ids")
    @classmethod
    def normalize_unit_ids(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(sorted(set(values)))
        if any(not re.fullmatch(_UNIT_ID_PATTERN, value) for value in normalized):
            raise ValueError("shard receipt contains an invalid unit id")
        return normalized

    @field_validator("error_type")
    @classmethod
    def validate_error_type(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized or any(not (character.isalnum() or character in "_.:-") for character in normalized):
            raise ValueError("error_type must be a type identifier, not an error message")
        return normalized

    @model_validator(mode="after")
    def validate_receipt(self) -> Self:
        completed = set(self.completed_unit_ids)
        units = set(self.unit_ids)
        if not completed.issubset(units):
            raise ValueError("completed shard units must belong to the shard")
        if self.status == ShardStatus.SUCCEEDED and (completed != units or self.error_type is not None):
            raise ValueError("successful shard receipts require every unit and no error")
        if self.status == ShardStatus.PARTIAL and (not completed or completed == units or self.error_type is None):
            raise ValueError("partial shard receipts require a proper completed subset and error type")
        if self.status == ShardStatus.FAILED and (completed or self.error_type is None):
            raise ValueError("failed shard receipts require no completed units and an error type")
        expected_key = self.stable_key(
            unit_ids=self.unit_ids,
            input_digest=self.input_digest,
            profile_digest=self.profile_digest,
            prompt_digest=self.prompt_digest,
        )
        if self.shard_key != expected_key:
            raise ValueError("shard key does not match its immutable inputs")
        expected_digest = content_digest(self.model_dump(mode="json", exclude={"receipt_digest"}))
        if self.receipt_digest != expected_digest:
            raise ValueError("shard receipt digest is invalid")
        return self

    @staticmethod
    def stable_key(
        *,
        unit_ids: tuple[str, ...] | list[str],
        input_digest: str,
        profile_digest: str,
        prompt_digest: str,
    ) -> str:
        return "shard-" + content_digest(
            {
                "unit_ids": sorted(set(unit_ids)),
                "input_digest": input_digest,
                "profile_digest": profile_digest,
                "prompt_digest": prompt_digest,
            }
        )

    @classmethod
    def create(
        cls,
        *,
        run_id: str,
        lane: AuditLane | str,
        unit_ids: tuple[str, ...] | list[str],
        input_digest: str,
        profile_digest: str,
        prompt_digest: str,
        status: ShardStatus | str,
        response_sha256: str | None = None,
        attempt: int = 1,
        completed_unit_ids: tuple[str, ...] | list[str] = (),
        error_type: str | None = None,
    ) -> Self:
        normalized_units = tuple(sorted(set(unit_ids)))
        payload: dict[str, Any] = {
            "run_id": run_id,
            "lane": AuditLane(lane),
            "shard_key": cls.stable_key(
                unit_ids=normalized_units,
                input_digest=input_digest,
                profile_digest=profile_digest,
                prompt_digest=prompt_digest,
            ),
            "attempt": attempt,
            "unit_ids": normalized_units,
            "completed_unit_ids": tuple(sorted(set(completed_unit_ids))),
            "input_digest": input_digest,
            "profile_digest": profile_digest,
            "prompt_digest": prompt_digest,
            "status": ShardStatus(status),
            "response_sha256": response_sha256,
            "error_type": error_type,
        }
        return cls.model_validate({**payload, "receipt_digest": content_digest(payload)})


class AuditPersistence:
    """Small v0.7 adapter over the append-only investigation object store.

    Every legal item is committed independently.  A process can therefore load
    and reuse a verdict immediately after a crash without replaying source text
    or a paid provider call.  Raw source is intentionally absent from every
    persistence contract in this module.
    """

    def __init__(
        self,
        store: InvestigationStore,
        *,
        authority_provider: Callable[[str], RunAuthority | None] | None = None,
        require_authority: bool = False,
        durable_repository: AuditRepository | None = None,
    ) -> None:
        self._store = store
        self._authority_provider = authority_provider
        self._require_authority = require_authority
        self._durable_repository = durable_repository

    def register_unit(self, unit: AuditUnit) -> None:
        """Register the immutable unit identity before any paid review."""

        if self._durable_repository is None:
            return
        authority = None if self._authority_provider is None else self._authority_provider(unit.run_id)
        self._durable_repository.register_unit(
            unit,
            status=AuditUnitStatus.PENDING,
            run_fence=0 if authority is None else authority.run_fence,
        )

    def publish_patch_release(
        self,
        evaluation_run_id: str,
        release: PatchReleaseRecord,
    ) -> PatchReleaseRecord:
        if self._durable_repository is None:
            raise AuditPersistenceConflict("durable patch release storage is unavailable")
        return self._durable_repository.publish_release(
            evaluation_run_id,
            release,
        ).release

    def load_patch_releases(self) -> tuple[PatchReleaseRecord, ...]:
        if self._durable_repository is None:
            return ()
        return tuple(snapshot.release for snapshot in self._durable_repository.list_releases())

    def revoke_patch_release(
        self,
        patch_release_id: str,
        reason: str,
    ) -> PatchReleaseRecord:
        if self._durable_repository is None:
            raise AuditPersistenceConflict("durable patch release storage is unavailable")
        snapshot = self._durable_repository.get_release(patch_release_id)
        if snapshot is None:
            raise KeyError(patch_release_id)
        return self._durable_repository.revoke_release(
            patch_release_id,
            expected_version=snapshot.state_version,
            reason=reason,
        ).release

    def commit_primary_verdict(
        self,
        *,
        run_id: str,
        lane: AuditLane | str,
        verdict: PrimaryVerdict,
    ) -> PersistReceipt:
        resolved_lane = AuditLane(lane)
        record = LanePrimaryVerdict.create(run_id=run_id, lane=resolved_lane, verdict=verdict)
        receipt = self._put_unit_record(
            run_id=run_id,
            lane=resolved_lane,
            unit_id=verdict.unit_id,
            object_type=_PRIMARY_OBJECT_TYPE,
            kind="primary",
            record=record,
            digest=record.record_digest,
        )
        if self._durable_repository is not None and resolved_lane is AuditLane.BASELINE:
            provider_receipt_id = verdict.receipt_id if verdict.receipt_id.startswith("receipt-") else None
            self._durable_repository.append_baseline(
                run_id,
                verdict,
                provider_receipt_id=provider_receipt_id,
            )
        return receipt

    def commit_provider_receipt(self, receipt: ProviderReceipt) -> PersistReceipt:
        """Commit a paid provider response before projecting baseline verdicts."""

        if self._durable_repository is not None:
            self._durable_repository.record_provider_receipt(receipt)

        object_id = self._stable_object_id(
            run_id=receipt.run_id,
            kind="provider-receipt",
            logical_key=receipt.receipt_id,
            version=1,
        )
        self._put(
            receipt,
            run_id=receipt.run_id,
            object_type=_PROVIDER_RECEIPT_OBJECT_TYPE,
            object_id=object_id,
            logical_key=receipt.receipt_id,
            version=1,
            digest=receipt.receipt_digest,
        )
        return PersistReceipt(
            object_id=object_id,
            run_id=receipt.run_id,
            lane=AuditLane.BASELINE,
            object_type=_PROVIDER_RECEIPT_OBJECT_TYPE,
            logical_key=receipt.receipt_id,
            version=1,
            content_digest=receipt.receipt_digest,
        )

    def load_provider_receipts(self, run_id: str) -> tuple[ProviderReceipt, ...]:
        return tuple(
            sorted(
                (
                    ProviderReceipt.model_validate(payload)
                    for payload in self._store.list_objects(run_id, _PROVIDER_RECEIPT_OBJECT_TYPE)
                ),
                key=lambda item: (item.created_at, item.receipt_id),
            )
        )

    def load_primary_verdict(
        self,
        *,
        run_id: str,
        lane: AuditLane | str,
        unit_id: str,
    ) -> PrimaryVerdict | None:
        resolved_lane = AuditLane(lane)
        for record in self.load_primary_verdicts(run_id=run_id, lane=resolved_lane):
            if record.unit_id == unit_id:
                return record.verdict
        return None

    def load_primary_verdicts(
        self,
        *,
        run_id: str,
        lane: AuditLane | str | None = None,
    ) -> tuple[LanePrimaryVerdict, ...]:
        resolved_lane = None if lane is None else AuditLane(lane)
        records = tuple(
            LanePrimaryVerdict.model_validate(payload)
            for payload in self._store.list_objects(run_id, _PRIMARY_OBJECT_TYPE)
        )
        return tuple(
            sorted(
                (record for record in records if resolved_lane is None or record.lane == resolved_lane),
                key=lambda record: (record.lane.value, record.unit_id),
            )
        )

    def commit_unit_decision(
        self,
        *,
        run_id: str,
        lane: AuditLane | str,
        decision: UnitDecision,
    ) -> PersistReceipt:
        resolved_lane = AuditLane(lane)
        record = LaneUnitDecision.create(run_id=run_id, lane=resolved_lane, decision=decision)
        receipt = self._put_unit_record(
            run_id=run_id,
            lane=resolved_lane,
            unit_id=decision.unit_id,
            object_type=_DECISION_OBJECT_TYPE,
            kind="decision",
            record=record,
            digest=record.record_digest,
        )
        if self._durable_repository is not None:
            self._durable_repository.append_decision(
                run_id,
                decision,
                lane=DecisionLane(resolved_lane.value),
                release_id=decision.patch_release_id,
            )
        return receipt

    def load_unit_decision(
        self,
        *,
        run_id: str,
        lane: AuditLane | str,
        unit_id: str,
    ) -> UnitDecision | None:
        resolved_lane = AuditLane(lane)
        for record in self.load_unit_decisions(run_id=run_id, lane=resolved_lane):
            if record.unit_id == unit_id:
                return record.decision
        return None

    def load_unit_decisions(
        self,
        *,
        run_id: str,
        lane: AuditLane | str | None = None,
    ) -> tuple[LaneUnitDecision, ...]:
        resolved_lane = None if lane is None else AuditLane(lane)
        records = tuple(
            LaneUnitDecision.model_validate(payload)
            for payload in self._store.list_objects(run_id, _DECISION_OBJECT_TYPE)
        )
        return tuple(
            sorted(
                (record for record in records if resolved_lane is None or record.lane == resolved_lane),
                key=lambda record: (record.lane.value, record.unit_id),
            )
        )

    def commit_shard_receipt(self, receipt: ReviewShardReceipt) -> PersistReceipt:
        logical_key = f"{receipt.lane.value}:{receipt.shard_key}"
        object_id = self._stable_object_id(
            run_id=receipt.run_id,
            kind="shard",
            logical_key=logical_key,
            version=receipt.attempt,
        )
        self._put(
            receipt,
            run_id=receipt.run_id,
            object_type=_SHARD_OBJECT_TYPE,
            object_id=object_id,
            logical_key=logical_key,
            version=receipt.attempt,
            digest=receipt.receipt_digest,
        )
        return PersistReceipt(
            object_id=object_id,
            run_id=receipt.run_id,
            lane=receipt.lane,
            object_type=_SHARD_OBJECT_TYPE,
            logical_key=logical_key,
            version=receipt.attempt,
            content_digest=receipt.receipt_digest,
        )

    def load_shard_receipt(
        self,
        *,
        run_id: str,
        lane: AuditLane | str,
        shard_key: str,
        attempt: int | None = None,
    ) -> ReviewShardReceipt | None:
        resolved_lane = AuditLane(lane)
        matches = [
            receipt
            for receipt in self.load_shard_receipts(run_id=run_id, lane=resolved_lane)
            if receipt.shard_key == shard_key and (attempt is None or receipt.attempt == attempt)
        ]
        if not matches:
            return None
        return max(matches, key=lambda receipt: receipt.attempt)

    def load_shard_receipts(
        self,
        *,
        run_id: str,
        lane: AuditLane | str | None = None,
    ) -> tuple[ReviewShardReceipt, ...]:
        resolved_lane = None if lane is None else AuditLane(lane)
        receipts = tuple(
            ReviewShardReceipt.model_validate(payload)
            for payload in self._store.list_objects(run_id, _SHARD_OBJECT_TYPE)
        )
        return tuple(
            sorted(
                (receipt for receipt in receipts if resolved_lane is None or receipt.lane == resolved_lane),
                key=lambda receipt: (
                    receipt.lane.value,
                    receipt.shard_key,
                    receipt.attempt,
                ),
            )
        )

    def _put_unit_record(
        self,
        *,
        run_id: str,
        lane: AuditLane,
        unit_id: str,
        object_type: str,
        kind: str,
        record: AuditContract,
        digest: str,
    ) -> PersistReceipt:
        logical_key = f"{lane.value}:{unit_id}"
        object_id = self._stable_object_id(
            run_id=run_id,
            kind=kind,
            logical_key=logical_key,
            version=1,
        )
        self._put(
            record,
            run_id=run_id,
            object_type=object_type,
            object_id=object_id,
            logical_key=logical_key,
            version=1,
            digest=digest,
        )
        return PersistReceipt(
            object_id=object_id,
            run_id=run_id,
            lane=lane,
            object_type=object_type,
            logical_key=logical_key,
            version=1,
            content_digest=digest,
        )

    def _put(
        self,
        record: AuditContract,
        *,
        run_id: str,
        object_type: str,
        object_id: str,
        logical_key: str,
        version: int,
        digest: str,
    ) -> None:
        try:
            authority = None if self._authority_provider is None else self._authority_provider(run_id)
            if authority is None:
                if self._require_authority:
                    raise AuditPersistenceConflict("a current run authority is required for audit persistence")
                self._store.put_object(
                    record,
                    run_id=run_id,
                    object_type=object_type,
                    object_id=object_id,
                    logical_key=logical_key,
                    version=version,
                    content_digest=digest,
                )
            else:
                self._store.put_object_fenced(
                    record,
                    authority=authority,
                    run_id=run_id,
                    object_type=object_type,
                    object_id=object_id,
                    logical_key=logical_key,
                    version=version,
                    content_digest=digest,
                )
        except InvestigationConflict as exc:
            raise AuditPersistenceConflict(str(exc)) from exc

    @staticmethod
    def _stable_object_id(*, run_id: str, kind: str, logical_key: str, version: int) -> str:
        identity = f"{run_id}\x00{kind}\x00{logical_key}\x00{version}".encode()
        return f"v07-{kind}-{hashlib.sha256(identity).hexdigest()}"


__all__ = [
    "AuditLane",
    "AuditPersistence",
    "AuditPersistenceConflict",
    "LanePrimaryVerdict",
    "LaneUnitDecision",
    "PersistReceipt",
    "ProviderReceipt",
    "ReviewShardReceipt",
    "ShardStatus",
]
