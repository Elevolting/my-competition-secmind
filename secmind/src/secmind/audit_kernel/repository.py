from __future__ import annotations

import hashlib
import json
import threading
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, cast

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import DateTime, Engine, Integer, String, Text, UniqueConstraint, or_, select, text, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

from secmind.audit_kernel.contracts import (
    SHA256_PATTERN,
    AuditUnit,
    GainAction,
    PrimaryVerdict,
    UnitDecision,
    content_digest,
)
from secmind.audit_kernel.patch_release import (
    PatchReleaseRecord,
    PatchReleaseStatus,
)
from secmind.audit_kernel.receipts import ProviderReceipt
from secmind.investigation.store import InvestigationStore


class AuditRepositoryConflict(RuntimeError):
    """A CAS failed or an immutable audit identity was reused."""


class AuditUnitStatus(StrEnum):
    PENDING = "pending"
    REVIEWING = "reviewing"
    BASELINE_COMMITTED = "baseline_committed"
    FINALIZED = "finalized"
    FAILED = "failed"


class DecisionLane(StrEnum):
    BASELINE = "baseline"
    FINAL = "final"
    SHADOW = "shadow"


class AuditRepositoryBase(DeclarativeBase):
    pass


class AuditUnitRow(AuditRepositoryBase):
    __tablename__ = "audit_units"
    __table_args__ = (UniqueConstraint("run_id", "unit_id", "payload_digest"),)

    run_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    unit_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    language: Mapped[str] = mapped_column(String(30))
    primary_path: Mapped[str] = mapped_column(String(1024))
    source_sha256: Mapped[str] = mapped_column(String(64))
    input_manifest_digest: Mapped[str] = mapped_column(String(64))
    profile_digest: Mapped[str] = mapped_column(String(64))
    scope_digest: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(30), index=True)
    state_version: Mapped[int] = mapped_column(Integer, default=1)
    run_fence: Mapped[int] = mapped_column(Integer, default=0)
    payload_digest: Mapped[str] = mapped_column(String(64))
    payload_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ProviderReceiptRow(AuditRepositoryBase):
    __tablename__ = "provider_receipts"
    __table_args__ = (
        UniqueConstraint("run_id", "provider_request_id"),
        UniqueConstraint("run_id", "logical_call_id", "attempt"),
    )

    receipt_id: Mapped[str] = mapped_column(String(256), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    logical_call_id: Mapped[str] = mapped_column(String(128))
    provider_request_id: Mapped[str] = mapped_column(String(128))
    attempt: Mapped[int] = mapped_column(Integer)
    model_id: Mapped[str] = mapped_column(String(128))
    prompt_version: Mapped[str] = mapped_column(String(128))
    request_digest: Mapped[str] = mapped_column(String(64))
    response_sha256: Mapped[str] = mapped_column(String(64))
    receipt_digest: Mapped[str] = mapped_column(String(64))
    payload_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class BaselineVerdictRow(AuditRepositoryBase):
    __tablename__ = "baseline_verdicts"
    __table_args__ = (UniqueConstraint("run_id", "unit_id"),)

    record_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(36), index=True)
    unit_id: Mapped[str] = mapped_column(String(80))
    provider_receipt_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    verdict: Mapped[str] = mapped_column(String(30))
    verdict_digest: Mapped[str] = mapped_column(String(64))
    payload_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class UnitDecisionRow(AuditRepositoryBase):
    __tablename__ = "unit_decisions"
    __table_args__ = (UniqueConstraint("run_id", "unit_id", "lane", "revision"),)

    decision_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(36), index=True)
    unit_id: Mapped[str] = mapped_column(String(80))
    lane: Mapped[str] = mapped_column(String(20))
    revision: Mapped[int] = mapped_column(Integer)
    release_id: Mapped[str | None] = mapped_column(String(80), nullable=True)
    action: Mapped[str] = mapped_column(String(30))
    decision_digest: Mapped[str] = mapped_column(String(64))
    payload_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class PatchReleaseRow(AuditRepositoryBase):
    __tablename__ = "patch_releases"
    __table_args__ = (UniqueConstraint("patch_type", "version"),)

    release_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(36), index=True)
    patch_type: Mapped[str] = mapped_column(String(100), index=True)
    version: Mapped[str] = mapped_column(String(64))
    profile_digest: Mapped[str] = mapped_column(String(64))
    policy_digest: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(20), index=True)
    state_version: Mapped[int] = mapped_column(Integer, default=1)
    payload_digest: Mapped[str] = mapped_column(String(64))
    payload_json: Mapped[str] = mapped_column(Text)
    revocation_reason: Mapped[str | None] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class _Record(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, use_enum_values=False)


class AuditUnitSnapshot(_Record):
    unit: AuditUnit
    status: AuditUnitStatus
    state_version: int = Field(ge=1)
    run_fence: int = Field(ge=0)
    payload_digest: str = Field(pattern=SHA256_PATTERN)


class BaselineVerdictRecord(_Record):
    record_id: str
    run_id: str
    unit_id: str
    provider_receipt_id: str | None = None
    verdict: PrimaryVerdict
    verdict_digest: str = Field(pattern=SHA256_PATTERN)


class UnitDecisionRecord(_Record):
    decision_id: str
    run_id: str
    unit_id: str
    lane: DecisionLane
    revision: int = Field(ge=1)
    release_id: str | None = None
    decision: UnitDecision


class PatchReleaseSnapshot(_Record):
    release: PatchReleaseRecord
    status: PatchReleaseStatus
    state_version: int = Field(ge=1)
    revocation_reason: str | None = None
    revoked_at: datetime | None = None


def _canonical_json(value: BaseModel | dict[str, Any]) -> str:
    payload = value.model_dump(mode="json") if isinstance(value, BaseModel) else value
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _stable_id(prefix: str, payload: dict[str, Any]) -> str:
    return f"{prefix}-{hashlib.sha256(_canonical_json(payload).encode('utf-8')).hexdigest()}"


def _aware(value: datetime | None) -> datetime | None:
    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=UTC)


class AuditRepository:
    """Transactional repository for v0.7 Direct-anchor truth.

    Immutable rows use logical-key conflict checks: replaying identical content
    returns the original row, while reusing an identity with different content
    fails closed. Mutable unit/release state is changed only by explicit CAS.
    """

    def __init__(
        self,
        source: InvestigationStore | Engine,
        *,
        initialize_schema: bool = False,
    ) -> None:
        self.engine = source.engine if isinstance(source, InvestigationStore) else source
        self._lock = threading.RLock()
        if initialize_schema:
            AuditRepositoryBase.metadata.create_all(self.engine)

    def _lock_run(self, session: Session, run_id: str) -> None:
        if self.engine.dialect.name == "postgresql":
            session.execute(
                text("SELECT pg_advisory_xact_lock(hashtext(:key))"),
                {"key": f"secmind:coordinator:{run_id}"},
            )
        elif self.engine.dialect.name == "sqlite":
            session.execute(text("BEGIN IMMEDIATE"))

    @staticmethod
    def _unit_snapshot(row: AuditUnitRow) -> AuditUnitSnapshot:
        return AuditUnitSnapshot(
            unit=AuditUnit.model_validate_json(row.payload_json),
            status=AuditUnitStatus(row.status),
            state_version=row.state_version,
            run_fence=row.run_fence,
            payload_digest=row.payload_digest,
        )

    @staticmethod
    def _release_snapshot(row: PatchReleaseRow) -> PatchReleaseSnapshot:
        return PatchReleaseSnapshot(
            release=PatchReleaseRecord.model_validate_json(row.payload_json),
            status=PatchReleaseStatus(row.status),
            state_version=row.state_version,
            revocation_reason=row.revocation_reason,
            revoked_at=_aware(row.revoked_at),
        )

    def register_unit(
        self,
        unit: AuditUnit,
        *,
        status: AuditUnitStatus = AuditUnitStatus.PENDING,
        run_fence: int = 0,
    ) -> AuditUnitSnapshot:
        if run_fence < 0:
            raise ValueError("run_fence cannot be negative")
        payload_json = _canonical_json(unit)
        digest = content_digest(unit)
        now = datetime.now(UTC)
        with self._lock, Session(self.engine, expire_on_commit=False) as session:
            self._lock_run(session, unit.run_id)
            row = session.get(AuditUnitRow, (unit.run_id, unit.unit_id))
            if row is not None:
                if row.payload_digest != digest or row.payload_json != payload_json:
                    raise AuditRepositoryConflict("audit unit identity was reused with different content")
                session.commit()
                return self._unit_snapshot(row)
            row = AuditUnitRow(
                run_id=unit.run_id,
                unit_id=unit.unit_id,
                language=unit.language,
                primary_path=unit.primary_path,
                source_sha256=unit.source_sha256,
                input_manifest_digest=unit.input_manifest_digest,
                profile_digest=unit.profile_digest,
                scope_digest=unit.scope_digest,
                status=status.value,
                state_version=1,
                run_fence=run_fence,
                payload_digest=digest,
                payload_json=payload_json,
                created_at=now,
                updated_at=now,
            )
            session.add(row)
            session.commit()
            return self._unit_snapshot(row)

    def get_unit(self, run_id: str, unit_id: str) -> AuditUnitSnapshot | None:
        with Session(self.engine) as session:
            row = session.get(AuditUnitRow, (run_id, unit_id))
            return None if row is None else self._unit_snapshot(row)

    def compare_and_set_unit(
        self,
        run_id: str,
        unit_id: str,
        *,
        expected_version: int,
        status: AuditUnitStatus,
        run_fence: int | None = None,
    ) -> AuditUnitSnapshot:
        if expected_version < 1 or (run_fence is not None and run_fence < 0):
            raise ValueError("invalid unit CAS version or fence")
        now = datetime.now(UTC)
        with self._lock, Session(self.engine, expire_on_commit=False) as session:
            self._lock_run(session, run_id)
            row = session.get(AuditUnitRow, (run_id, unit_id))
            if row is None:
                raise AuditRepositoryConflict("audit unit does not exist")
            if row.state_version != expected_version:
                raise AuditRepositoryConflict("audit unit compare-and-swap failed")
            if run_fence is not None and run_fence < row.run_fence:
                raise AuditRepositoryConflict("audit unit fence cannot move backwards")
            values: dict[str, Any] = {
                "status": status.value,
                "state_version": expected_version + 1,
                "updated_at": now,
            }
            if run_fence is not None:
                values["run_fence"] = run_fence
            result = cast(
                CursorResult[Any],
                session.execute(
                    update(AuditUnitRow)
                    .where(
                        AuditUnitRow.run_id == run_id,
                        AuditUnitRow.unit_id == unit_id,
                        AuditUnitRow.state_version == expected_version,
                    )
                    .values(**values)
                ),
            )
            if result.rowcount != 1:
                raise AuditRepositoryConflict("audit unit compare-and-swap failed")
            session.commit()
            refreshed = session.get(AuditUnitRow, (run_id, unit_id))
            if refreshed is None:
                raise AuditRepositoryConflict("audit unit disappeared after CAS")
            return self._unit_snapshot(refreshed)

    def record_provider_receipt(self, receipt: ProviderReceipt) -> ProviderReceipt:
        payload_json = _canonical_json(receipt)
        with self._lock, Session(self.engine, expire_on_commit=False) as session:
            self._lock_run(session, receipt.run_id)
            existing = session.scalars(
                select(ProviderReceiptRow).where(
                    or_(
                        (
                            (ProviderReceiptRow.run_id == receipt.run_id)
                            & (ProviderReceiptRow.receipt_id == receipt.receipt_id)
                        ),
                        (
                            (ProviderReceiptRow.run_id == receipt.run_id)
                            & (ProviderReceiptRow.provider_request_id == receipt.provider_request_id)
                        ),
                        (
                            (ProviderReceiptRow.run_id == receipt.run_id)
                            & (ProviderReceiptRow.logical_call_id == receipt.logical_call_id)
                            & (ProviderReceiptRow.attempt == receipt.attempt_count)
                        ),
                    )
                )
            ).first()
            if existing is not None:
                if existing.receipt_digest != receipt.receipt_digest or existing.payload_json != payload_json:
                    raise AuditRepositoryConflict("provider receipt identity was reused with different content")
                session.commit()
                return ProviderReceipt.model_validate_json(existing.payload_json)
            session.add(
                ProviderReceiptRow(
                    receipt_id=receipt.receipt_id,
                    run_id=receipt.run_id,
                    logical_call_id=receipt.logical_call_id,
                    provider_request_id=receipt.provider_request_id,
                    attempt=receipt.attempt_count,
                    model_id=receipt.model_id,
                    prompt_version=receipt.prompt_version,
                    request_digest=receipt.request_digest,
                    response_sha256=receipt.response_digest,
                    receipt_digest=receipt.receipt_digest,
                    payload_json=payload_json,
                    created_at=datetime.now(UTC),
                )
            )
            session.commit()
            return receipt

    def append_baseline(
        self,
        run_id: str,
        verdict: PrimaryVerdict,
        *,
        provider_receipt_id: str | None = None,
    ) -> BaselineVerdictRecord:
        payload_json = _canonical_json(verdict)
        verdict_digest = content_digest(verdict)
        identity = {
            "run_id": run_id,
            "unit_id": verdict.unit_id,
            "provider_receipt_id": provider_receipt_id,
            "verdict_digest": verdict_digest,
        }
        record_id = _stable_id("baseline", identity)
        with self._lock, Session(self.engine, expire_on_commit=False) as session:
            self._lock_run(session, run_id)
            if session.get(AuditUnitRow, (run_id, verdict.unit_id)) is None:
                raise AuditRepositoryConflict("baseline has no registered audit unit")
            if provider_receipt_id is not None:
                provider = session.get(ProviderReceiptRow, (provider_receipt_id, run_id))
                if provider is None:
                    raise AuditRepositoryConflict("baseline provider receipt is missing or belongs to another run")
                if verdict.receipt_id != provider_receipt_id:
                    raise AuditRepositoryConflict("baseline verdict does not reference its provider receipt")
            existing = session.scalars(
                select(BaselineVerdictRow).where(
                    (BaselineVerdictRow.run_id == run_id) & (BaselineVerdictRow.unit_id == verdict.unit_id)
                )
            ).first()
            if existing is not None:
                if (
                    existing.verdict_digest != verdict_digest
                    or existing.provider_receipt_id != provider_receipt_id
                    or existing.payload_json != payload_json
                ):
                    raise AuditRepositoryConflict("baseline verdict is immutable and already differs")
                session.commit()
                return BaselineVerdictRecord(
                    record_id=existing.record_id,
                    run_id=run_id,
                    unit_id=verdict.unit_id,
                    provider_receipt_id=provider_receipt_id,
                    verdict=verdict,
                    verdict_digest=verdict_digest,
                )
            session.add(
                BaselineVerdictRow(
                    record_id=record_id,
                    run_id=run_id,
                    unit_id=verdict.unit_id,
                    provider_receipt_id=provider_receipt_id,
                    verdict=verdict.verdict.value,
                    verdict_digest=verdict_digest,
                    payload_json=payload_json,
                    created_at=datetime.now(UTC),
                )
            )
            session.commit()
        return BaselineVerdictRecord(
            record_id=record_id,
            run_id=run_id,
            unit_id=verdict.unit_id,
            provider_receipt_id=provider_receipt_id,
            verdict=verdict,
            verdict_digest=verdict_digest,
        )

    def append_decision(
        self,
        run_id: str,
        decision: UnitDecision,
        *,
        lane: DecisionLane,
        revision: int = 1,
        release_id: str | None = None,
    ) -> UnitDecisionRecord:
        if revision < 1 or not decision.digest_valid():
            raise ValueError("unit decision revision or digest is invalid")
        payload_json = _canonical_json(decision)
        identity = {
            "run_id": run_id,
            "unit_id": decision.unit_id,
            "lane": lane.value,
            "revision": revision,
            "release_id": release_id,
            "decision_digest": decision.decision_digest,
        }
        decision_id = _stable_id("decision", identity)
        with self._lock, Session(self.engine, expire_on_commit=False) as session:
            self._lock_run(session, run_id)
            if session.get(AuditUnitRow, (run_id, decision.unit_id)) is None:
                raise AuditRepositoryConflict("decision has no registered audit unit")
            release = None if release_id is None else session.get(PatchReleaseRow, release_id)
            if release_id is not None and release is None:
                raise AuditRepositoryConflict("decision patch release is missing")
            if (
                release is not None
                and lane is DecisionLane.FINAL
                and release.status != PatchReleaseStatus.AUTHORITATIVE.value
            ):
                raise AuditRepositoryConflict("decision release is not authoritative")
            if decision.patch_release_id != release_id:
                raise AuditRepositoryConflict("decision patch release does not match persisted release")
            if lane is DecisionLane.FINAL and decision.action == GainAction.ACCEPT_ENHANCEMENT and release_id is None:
                raise AuditRepositoryConflict("authoritative enhancement requires an authoritative patch release")
            existing = session.scalars(
                select(UnitDecisionRow).where(
                    (UnitDecisionRow.run_id == run_id)
                    & (UnitDecisionRow.unit_id == decision.unit_id)
                    & (UnitDecisionRow.lane == lane.value)
                    & (UnitDecisionRow.revision == revision)
                )
            ).first()
            if existing is not None:
                if (
                    existing.decision_digest != decision.decision_digest
                    or existing.release_id != release_id
                    or existing.payload_json != payload_json
                ):
                    raise AuditRepositoryConflict("unit decision revision is append-only and already differs")
                session.commit()
                return UnitDecisionRecord(
                    decision_id=existing.decision_id,
                    run_id=run_id,
                    unit_id=decision.unit_id,
                    lane=lane,
                    revision=revision,
                    release_id=release_id,
                    decision=decision,
                )
            session.add(
                UnitDecisionRow(
                    decision_id=decision_id,
                    run_id=run_id,
                    unit_id=decision.unit_id,
                    lane=lane.value,
                    revision=revision,
                    release_id=release_id,
                    action=decision.action.value,
                    decision_digest=decision.decision_digest,
                    payload_json=payload_json,
                    created_at=datetime.now(UTC),
                )
            )
            session.commit()
        return UnitDecisionRecord(
            decision_id=decision_id,
            run_id=run_id,
            unit_id=decision.unit_id,
            lane=lane,
            revision=revision,
            release_id=release_id,
            decision=decision,
        )

    def publish_release(
        self,
        run_id: str,
        release: PatchReleaseRecord,
    ) -> PatchReleaseSnapshot:
        if not release.digest_valid():
            raise ValueError("patch release digest is invalid")
        payload_json = _canonical_json(release)
        now = datetime.now(UTC)
        with self._lock, Session(self.engine, expire_on_commit=False) as session:
            self._lock_run(session, run_id)
            existing = session.scalars(
                select(PatchReleaseRow).where(
                    or_(
                        PatchReleaseRow.release_id == release.patch_release_id,
                        (
                            (PatchReleaseRow.patch_type == release.identity.patch_kind)
                            & (PatchReleaseRow.version == release.patch_key)
                        ),
                    )
                )
            ).first()
            if existing is not None:
                if existing.payload_digest != release.release_digest or existing.payload_json != payload_json:
                    raise AuditRepositoryConflict("patch release identity was reused with different content")
                session.commit()
                return self._release_snapshot(existing)
            row = PatchReleaseRow(
                release_id=release.patch_release_id,
                run_id=run_id,
                patch_type=release.identity.patch_kind,
                version=release.patch_key,
                profile_digest=release.identity.target_profile_digest,
                policy_digest=release.identity.critic_model_policy_digest,
                status=release.status.value,
                state_version=1,
                payload_digest=release.release_digest,
                payload_json=payload_json,
                revocation_reason=release.revocation_reason,
                created_at=now,
                updated_at=now,
                revoked_at=release.revoked_at,
            )
            session.add(row)
            session.commit()
            return self._release_snapshot(row)

    def revoke_release(
        self,
        release_id: str,
        *,
        expected_version: int,
        reason: str,
    ) -> PatchReleaseSnapshot:
        normalized_reason = reason.strip()
        if expected_version < 1 or not normalized_reason or len(normalized_reason) > 500:
            raise ValueError("invalid release CAS version or revocation reason")
        with self._lock, Session(self.engine, expire_on_commit=False) as session:
            row = session.get(PatchReleaseRow, release_id)
            if row is None:
                raise AuditRepositoryConflict("patch release does not exist")
            self._lock_run(session, row.run_id)
            if row.status == PatchReleaseStatus.REVOKED.value:
                if row.revocation_reason != normalized_reason:
                    raise AuditRepositoryConflict("patch release was revoked with a different payload")
                session.commit()
                return self._release_snapshot(row)
            if row.state_version != expected_version:
                raise AuditRepositoryConflict("patch release compare-and-swap failed")
            now = datetime.now(UTC)
            release = PatchReleaseRecord.model_validate_json(row.payload_json)
            revoked = release.revoke(normalized_reason, revoked_at=now)
            payload_json = _canonical_json(revoked)
            result = cast(
                CursorResult[Any],
                session.execute(
                    update(PatchReleaseRow)
                    .where(
                        PatchReleaseRow.release_id == release_id,
                        PatchReleaseRow.state_version == expected_version,
                        PatchReleaseRow.status != PatchReleaseStatus.REVOKED.value,
                    )
                    .values(
                        status=PatchReleaseStatus.REVOKED.value,
                        state_version=expected_version + 1,
                        payload_digest=revoked.release_digest,
                        payload_json=payload_json,
                        revocation_reason=normalized_reason,
                        revoked_at=now,
                        updated_at=now,
                    )
                ),
            )
            if result.rowcount != 1:
                raise AuditRepositoryConflict("patch release compare-and-swap failed")
            session.commit()
            refreshed = session.get(PatchReleaseRow, release_id)
            if refreshed is None:
                raise AuditRepositoryConflict("patch release disappeared after CAS")
            return self._release_snapshot(refreshed)

    def get_release(self, release_id: str) -> PatchReleaseSnapshot | None:
        with Session(self.engine) as session:
            row = session.get(PatchReleaseRow, release_id)
            return None if row is None else self._release_snapshot(row)

    def list_releases(self) -> tuple[PatchReleaseSnapshot, ...]:
        with Session(self.engine) as session:
            rows = session.scalars(select(PatchReleaseRow).order_by(PatchReleaseRow.release_id)).all()
            return tuple(self._release_snapshot(row) for row in rows)


__all__ = [
    "AuditRepository",
    "AuditRepositoryBase",
    "AuditRepositoryConflict",
    "AuditUnitSnapshot",
    "AuditUnitStatus",
    "BaselineVerdictRecord",
    "DecisionLane",
    "PatchReleaseSnapshot",
    "PatchReleaseStatus",
    "ProviderReceipt",
    "UnitDecisionRecord",
]
