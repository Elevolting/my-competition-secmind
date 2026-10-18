from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from threading import RLock
from typing import Self

from pydantic import Field, field_validator, model_validator

from secmind.audit_kernel.contracts import (
    SHA256_PATTERN,
    AuditContract,
    AuditUnit,
    CandidateFlow,
    content_digest,
)

PATCH_RELEASE_SCHEMA_VERSION = "1.0"


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("patch release timestamps must be timezone-aware")
    return value.astimezone(UTC)


class PatchReleaseStatus(StrEnum):
    DISABLED = "disabled"
    SHADOW = "shadow"
    CANARY = "canary"
    AUTHORITATIVE = "authoritative"
    REVOKED = "revoked"


class PatchReleaseConflict(RuntimeError):
    """A patch release CAS or immutable identity check failed."""


class PatchIdentity(AuditContract):
    """Every versioned input that can change a patch's observed behaviour."""

    schema_version: str = PATCH_RELEASE_SCHEMA_VERSION
    target_profile_digest: str = Field(pattern=SHA256_PATTERN)
    cwe: int = Field(gt=0)
    patch_kind: str = Field(min_length=1, max_length=128)
    tool_name: str = Field(min_length=1, max_length=128)
    tool_version: str = Field(min_length=1, max_length=128)
    rule_bundle_digest: str = Field(pattern=SHA256_PATTERN)
    parser_name: str = Field(min_length=1, max_length=128)
    parser_digest: str = Field(pattern=SHA256_PATTERN)
    critic_prompt_version: str = Field(min_length=1, max_length=128)
    critic_model_policy_digest: str = Field(pattern=SHA256_PATTERN)
    patch_key: str = Field(pattern=SHA256_PATTERN)

    @field_validator(
        "patch_kind",
        "tool_name",
        "tool_version",
        "parser_name",
        "critic_prompt_version",
    )
    @classmethod
    def normalize_text(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("patch identity text fields cannot be blank")
        return normalized

    @model_validator(mode="after")
    def validate_patch_key(self) -> Self:
        if self.patch_key != content_digest(self.key_material()):
            raise ValueError("patch_key does not match the immutable patch identity")
        return self

    def key_material(self) -> dict[str, str | int]:
        return {
            "schema_version": self.schema_version,
            "target_profile_digest": self.target_profile_digest,
            "cwe": self.cwe,
            "patch_kind": self.patch_kind,
            "tool_name": self.tool_name,
            "tool_version": self.tool_version,
            "rule_bundle_digest": self.rule_bundle_digest,
            "parser_name": self.parser_name,
            "parser_digest": self.parser_digest,
            "critic_prompt_version": self.critic_prompt_version,
            "critic_model_policy_digest": self.critic_model_policy_digest,
        }

    def matches_candidate(self, unit: AuditUnit, flow: CandidateFlow) -> bool:
        """Bind a release identity to the immutable candidate under review."""

        return (
            self.target_profile_digest == unit.profile_digest
            and self.cwe == flow.cwe
            and self.tool_name == flow.tool_name
            and self.tool_version == flow.tool_version
            and self.rule_bundle_digest == flow.rule_bundle_digest
        )

    @classmethod
    def create(
        cls,
        *,
        target_profile_digest: str,
        cwe: int,
        patch_kind: str,
        tool_name: str,
        tool_version: str,
        rule_bundle_digest: str,
        parser_name: str,
        parser_digest: str,
        critic_prompt_version: str,
        critic_model_policy_digest: str,
    ) -> Self:
        values: dict[str, str | int] = {
            "schema_version": PATCH_RELEASE_SCHEMA_VERSION,
            "target_profile_digest": target_profile_digest,
            "cwe": cwe,
            "patch_kind": patch_kind.strip(),
            "tool_name": tool_name.strip(),
            "tool_version": tool_version.strip(),
            "rule_bundle_digest": rule_bundle_digest,
            "parser_name": parser_name.strip(),
            "parser_digest": parser_digest,
            "critic_prompt_version": critic_prompt_version.strip(),
            "critic_model_policy_digest": critic_model_policy_digest,
        }
        return cls.model_validate({**values, "patch_key": content_digest(values)})


class PatchReleaseRecord(AuditContract):
    """Auditable authorization for one exact, independently evaluated patch."""

    schema_version: str = PATCH_RELEASE_SCHEMA_VERSION
    patch_release_id: str = Field(pattern=r"^patch-release-[a-f0-9]{64}$")
    patch_key: str = Field(pattern=SHA256_PATTERN)
    identity: PatchIdentity
    status: PatchReleaseStatus
    evaluation_dataset_digest: str = Field(pattern=SHA256_PATTERN)
    baseline_arm_digest: str = Field(pattern=SHA256_PATTERN)
    candidate_arm_digest: str = Field(pattern=SHA256_PATTERN)
    sample_size: int = Field(ge=0)
    tp_fixed: int = Field(default=0, ge=0)
    fp_introduced: int = Field(default=0, ge=0)
    fn_introduced: int = Field(default=0, ge=0)
    precision: float = Field(ge=0, le=1)
    recall: float = Field(ge=0, le=1)
    f1_delta: float = Field(ge=-1, le=1)
    coverage_delta: float = Field(ge=-1, le=1)
    paired_bootstrap_ci_low: float = Field(ge=-1, le=1)
    paired_bootstrap_ci_high: float = Field(ge=-1, le=1)
    mcnemar_p: float = Field(ge=0, le=1)
    approved_by: str | None = Field(default=None, max_length=256)
    approved_at: datetime | None = None
    expires_at: datetime
    revoked_at: datetime | None = None
    revocation_reason: str | None = Field(default=None, max_length=1024)
    release_digest: str = Field(pattern=SHA256_PATTERN)

    @field_validator("approved_by", "revocation_reason")
    @classmethod
    def normalize_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None

    @field_validator("approved_at", "expires_at", "revoked_at")
    @classmethod
    def normalize_timestamp(cls, value: datetime | None) -> datetime | None:
        return None if value is None else _utc(value)

    @model_validator(mode="after")
    def validate_lifecycle(self) -> Self:
        if self.patch_key != self.identity.patch_key:
            raise ValueError("release patch_key does not match its patch identity")
        if self.patch_release_id != f"patch-release-{self.patch_key}":
            raise ValueError("patch_release_id does not match patch_key")
        if self.paired_bootstrap_ci_low > self.paired_bootstrap_ci_high:
            raise ValueError("paired bootstrap interval is inverted")
        if self.status in {
            PatchReleaseStatus.CANARY,
            PatchReleaseStatus.AUTHORITATIVE,
        } and (self.approved_by is None or self.approved_at is None):
            raise ValueError("canary and authoritative releases require approval")
        if self.status == PatchReleaseStatus.REVOKED:
            if self.revoked_at is None or self.revocation_reason is None:
                raise ValueError("revoked releases require time and reason")
        elif self.revoked_at is not None or self.revocation_reason is not None:
            raise ValueError("only revoked releases may carry revocation metadata")
        return self

    def digest_valid(self) -> bool:
        return self.release_digest == content_digest(self.model_dump(mode="json", exclude={"release_digest"}))

    def matches_all_digests(self, identity: PatchIdentity) -> bool:
        return self.digest_valid() and self.patch_key == identity.patch_key and self.identity == identity

    def is_expired(self, *, now: datetime | None = None) -> bool:
        current = datetime.now(UTC) if now is None else _utc(now)
        return self.expires_at <= current

    def revoke(self, reason: str, *, revoked_at: datetime | None = None) -> Self:
        normalized = reason.strip()
        if not normalized:
            raise ValueError("revocation reason cannot be blank")
        if self.status == PatchReleaseStatus.REVOKED:
            return self
        values = self.model_dump(mode="json", exclude={"release_digest"})
        values.update(
            {
                "status": PatchReleaseStatus.REVOKED.value,
                "revoked_at": _utc(revoked_at or datetime.now(UTC)).isoformat(),
                "revocation_reason": normalized,
            }
        )
        draft = self.model_validate({**values, "release_digest": "0" * 64})
        normalized_values = draft.model_dump(mode="json", exclude={"release_digest"})
        return self.model_validate(
            {
                **normalized_values,
                "release_digest": content_digest(normalized_values),
            }
        )

    @classmethod
    def create(
        cls,
        *,
        identity: PatchIdentity,
        status: PatchReleaseStatus | str = PatchReleaseStatus.SHADOW,
        evaluation_dataset_digest: str,
        baseline_arm_digest: str,
        candidate_arm_digest: str,
        sample_size: int,
        precision: float,
        recall: float,
        f1_delta: float,
        coverage_delta: float,
        paired_bootstrap_ci_low: float,
        paired_bootstrap_ci_high: float,
        mcnemar_p: float,
        expires_at: datetime,
        tp_fixed: int = 0,
        fp_introduced: int = 0,
        fn_introduced: int = 0,
        approved_by: str | None = None,
        approved_at: datetime | None = None,
    ) -> Self:
        resolved_status = PatchReleaseStatus(status)
        approval_time = approved_at
        if (
            resolved_status
            in {
                PatchReleaseStatus.CANARY,
                PatchReleaseStatus.AUTHORITATIVE,
            }
            and approval_time is None
        ):
            approval_time = datetime.now(UTC)
        values = {
            "schema_version": PATCH_RELEASE_SCHEMA_VERSION,
            "patch_release_id": f"patch-release-{identity.patch_key}",
            "patch_key": identity.patch_key,
            "identity": identity.model_dump(mode="json"),
            "status": resolved_status.value,
            "evaluation_dataset_digest": evaluation_dataset_digest,
            "baseline_arm_digest": baseline_arm_digest,
            "candidate_arm_digest": candidate_arm_digest,
            "sample_size": sample_size,
            "tp_fixed": tp_fixed,
            "fp_introduced": fp_introduced,
            "fn_introduced": fn_introduced,
            "precision": precision,
            "recall": recall,
            "f1_delta": f1_delta,
            "coverage_delta": coverage_delta,
            "paired_bootstrap_ci_low": paired_bootstrap_ci_low,
            "paired_bootstrap_ci_high": paired_bootstrap_ci_high,
            "mcnemar_p": mcnemar_p,
            "approved_by": approved_by,
            "approved_at": None if approval_time is None else _utc(approval_time).isoformat(),
            "expires_at": _utc(expires_at).isoformat(),
            "revoked_at": None,
            "revocation_reason": None,
        }
        draft = cls.model_validate({**values, "release_digest": "0" * 64})
        normalized_values = draft.model_dump(mode="json", exclude={"release_digest"})
        return cls.model_validate(
            {
                **normalized_values,
                "release_digest": content_digest(normalized_values),
            }
        )


class PatchReleaseRegistry:
    """Thread-safe in-memory release registry with digest-based CAS updates."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._by_id: dict[str, PatchReleaseRecord] = {}
        self._id_by_patch_key: dict[str, str] = {}

    def put(
        self,
        record: PatchReleaseRecord,
        *,
        expected_release_digest: str | None = None,
    ) -> PatchReleaseRecord:
        if not record.digest_valid():
            raise PatchReleaseConflict("patch release digest is invalid")
        with self._lock:
            existing = self._by_id.get(record.patch_release_id)
            if existing is not None and existing.release_digest == record.release_digest:
                return existing
            if existing is None:
                if expected_release_digest is not None:
                    raise PatchReleaseConflict("patch release does not exist for CAS update")
            elif expected_release_digest != existing.release_digest:
                raise PatchReleaseConflict("patch release CAS digest does not match")
            occupied = self._id_by_patch_key.get(record.patch_key)
            if occupied is not None and occupied != record.patch_release_id:
                raise PatchReleaseConflict("patch_key is already bound to another release")
            self._by_id[record.patch_release_id] = record
            self._id_by_patch_key[record.patch_key] = record.patch_release_id
            return record

    register = put

    def get(self, patch_release_id: str) -> PatchReleaseRecord | None:
        with self._lock:
            return self._by_id.get(patch_release_id)

    def resolve(self, identity: PatchIdentity) -> PatchReleaseRecord | None:
        with self._lock:
            release_id = self._id_by_patch_key.get(identity.patch_key)
            return None if release_id is None else self._by_id.get(release_id)

    def revoke(
        self,
        patch_release_id: str,
        reason: str,
        *,
        revoked_at: datetime | None = None,
    ) -> PatchReleaseRecord:
        with self._lock:
            existing = self._by_id.get(patch_release_id)
            if existing is None:
                raise KeyError(patch_release_id)
            revoked = existing.revoke(reason, revoked_at=revoked_at)
            if revoked is existing:
                return existing
            return self.put(revoked, expected_release_digest=existing.release_digest)

    def list_records(self) -> tuple[PatchReleaseRecord, ...]:
        with self._lock:
            return tuple(sorted(self._by_id.values(), key=lambda item: item.patch_release_id))


class EmpiricalGateResult(AuditContract):
    allowed: bool
    reason: str = Field(min_length=1, max_length=128)
    patch_release_id: str | None = None
    release_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)


class EmpiricalGate:
    """Fail-closed runtime check for independently qualified patch releases."""

    def __init__(self, registry: PatchReleaseRegistry | None = None) -> None:
        self._registry = registry

    def evaluate(
        self,
        identity: PatchIdentity,
        *,
        release: PatchReleaseRecord | None = None,
        now: datetime | None = None,
    ) -> EmpiricalGateResult:
        resolved = release
        if resolved is None and self._registry is not None:
            resolved = self._registry.resolve(identity)
        if resolved is None:
            return EmpiricalGateResult(allowed=False, reason="patch_release_missing")
        common = {
            "patch_release_id": resolved.patch_release_id,
            "release_digest": resolved.release_digest,
        }
        if not resolved.digest_valid():
            return EmpiricalGateResult(allowed=False, reason="patch_release_digest_invalid", **common)
        if not resolved.matches_all_digests(identity):
            return EmpiricalGateResult(allowed=False, reason="patch_release_identity_mismatch", **common)
        if resolved.status == PatchReleaseStatus.REVOKED:
            return EmpiricalGateResult(allowed=False, reason="patch_release_revoked", **common)
        if resolved.status != PatchReleaseStatus.AUTHORITATIVE:
            return EmpiricalGateResult(allowed=False, reason="patch_release_not_authoritative", **common)
        if resolved.is_expired(now=now):
            return EmpiricalGateResult(allowed=False, reason="patch_release_expired", **common)
        return EmpiricalGateResult(allowed=True, reason="authoritative_patch_release_matched", **common)


__all__ = [
    "PATCH_RELEASE_SCHEMA_VERSION",
    "EmpiricalGate",
    "EmpiricalGateResult",
    "PatchIdentity",
    "PatchReleaseConflict",
    "PatchReleaseRecord",
    "PatchReleaseRegistry",
    "PatchReleaseStatus",
]
